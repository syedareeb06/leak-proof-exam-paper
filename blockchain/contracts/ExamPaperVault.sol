// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ExamPaperVault - Leak-Proof Exam Paper Distribution
/// @notice A consortium (University + Key Custodians + Exam Centres) shares an
///         encrypted exam paper. The decryption key is split into Shamir shares
///         that custodians may only reveal on-chain AFTER the release time, and
///         only when `threshold` of them agree. Every centre that opens the
///         paper gets a unique watermark ID recorded here, so a leaked copy can
///         be traced back to the centre that leaked it.
/// @dev Nothing secret is stored on-chain before the release time: only hashes
///      (commitments) of the paper, the ciphertext and every key share.
contract ExamPaperVault {
    enum Role { None, Custodian, Centre }

    struct Member {
        Role role;
        string name;
        bool active;
    }

    struct Paper {
        string code;          // e.g. "CS743-2026"
        string title;         // e.g. "Blockchain Technology - Semester End Exam"
        bytes32 paperHash;    // sha256(plaintext paper)   - proves paper was not altered
        bytes32 cipherHash;   // sha256(encrypted paper)   - proves ciphertext was not swapped
        uint64 releaseTime;   // unix time when shares may be revealed
        uint8 threshold;      // shares needed to rebuild the key (e.g. 2 of 3)
        uint8 sharesReleased;
        bool revoked;
        uint64 createdAt;
    }

    struct Access {
        address centre;
        bytes8 watermarkId;   // random ID hidden inside the centre's copy
        bytes32 copyHash;     // sha256(watermarked copy given to the centre)
        uint64 time;
    }

    address public immutable university;

    mapping(address => Member) public members;
    address[] private memberList;

    Paper[] private papers;
    mapping(uint256 => address[]) private paperCustodians;
    mapping(uint256 => bytes32[]) private shareCommitments; // keccak256(share)
    mapping(uint256 => mapping(uint256 => bytes)) private revealedShares;
    mapping(uint256 => mapping(uint256 => bool)) private shareRevealed;
    mapping(uint256 => Access[]) private accesses;
    mapping(uint256 => mapping(address => bool)) public centreAccessed;

    struct WatermarkRef {
        uint256 paperId;
        uint256 accessIndex;
        bool exists;
    }
    mapping(bytes8 => WatermarkRef) private watermarks;

    event MemberRegistered(address indexed account, Role role, string name);
    event MemberStatusChanged(address indexed account, bool active);
    event PaperCreated(uint256 indexed paperId, string code, bytes32 paperHash, bytes32 cipherHash, uint64 releaseTime, uint8 threshold);
    event ShareReleased(uint256 indexed paperId, address indexed custodian, uint8 sharesReleased);
    event PaperUnlocked(uint256 indexed paperId, uint64 time);
    event PaperAccessed(uint256 indexed paperId, address indexed centre, bytes8 watermarkId, bytes32 copyHash);
    event PaperRevoked(uint256 indexed paperId, string reason);

    error NotUniversity();
    error NotActiveCustodian();
    error NotActiveCentre();
    error UnknownPaper(uint256 paperId);
    error InvalidMember();
    error AlreadyRegistered(address account);
    error InvalidThreshold();
    error ReleaseTimeInPast();
    error TooEarly(uint256 nowTime, uint256 releaseTime);
    error NotACustodianOfPaper();
    error ShareAlreadyReleased();
    error InvalidShare();
    error PaperIsRevoked(uint256 paperId);
    error PaperStillLocked(uint256 paperId);
    error AlreadyAccessed();
    error WatermarkInUse();

    modifier onlyUniversity() {
        if (msg.sender != university) revert NotUniversity();
        _;
    }

    modifier paperExists(uint256 paperId) {
        if (paperId >= papers.length) revert UnknownPaper(paperId);
        _;
    }

    constructor() {
        university = msg.sender;
    }

    // ------------------------------------------------------------------
    // Consortium membership (Module IV: permissioned participants)
    // ------------------------------------------------------------------

    function registerMember(address account, Role role, string calldata name) external onlyUniversity {
        if (account == address(0) || role == Role.None || bytes(name).length == 0) revert InvalidMember();
        if (members[account].role != Role.None) revert AlreadyRegistered(account);
        members[account] = Member(role, name, true);
        memberList.push(account);
        emit MemberRegistered(account, role, name);
    }

    function setMemberActive(address account, bool active) external onlyUniversity {
        if (members[account].role == Role.None) revert InvalidMember();
        members[account].active = active;
        emit MemberStatusChanged(account, active);
    }

    // ------------------------------------------------------------------
    // Paper lifecycle
    // ------------------------------------------------------------------

    /// @param custodians    the key holders, in the same order as the shares
    /// @param commitments   keccak256(share_i) for every custodian (hash commitment)
    function createPaper(
        string calldata code,
        string calldata title,
        bytes32 paperHash,
        bytes32 cipherHash,
        uint64 releaseTime,
        uint8 threshold,
        address[] calldata custodians,
        bytes32[] calldata commitments
    ) external onlyUniversity returns (uint256 paperId) {
        if (releaseTime <= block.timestamp) revert ReleaseTimeInPast();
        if (custodians.length != commitments.length || threshold < 2 || threshold > custodians.length) {
            revert InvalidThreshold();
        }
        for (uint256 i = 0; i < custodians.length; i++) {
            Member storage m = members[custodians[i]];
            if (m.role != Role.Custodian || !m.active) revert NotActiveCustodian();
        }

        paperId = papers.length;
        papers.push(Paper({
            code: code,
            title: title,
            paperHash: paperHash,
            cipherHash: cipherHash,
            releaseTime: releaseTime,
            threshold: threshold,
            sharesReleased: 0,
            revoked: false,
            createdAt: uint64(block.timestamp)
        }));
        paperCustodians[paperId] = custodians;
        shareCommitments[paperId] = commitments;

        emit PaperCreated(paperId, code, paperHash, cipherHash, releaseTime, threshold);
    }

    /// @notice A custodian reveals their key share. The smart contract enforces
    ///         the time lock and checks the share against its commitment.
    function releaseShare(uint256 paperId, bytes calldata share) external paperExists(paperId) {
        Paper storage p = papers[paperId];
        if (p.revoked) revert PaperIsRevoked(paperId);
        if (block.timestamp < p.releaseTime) revert TooEarly(block.timestamp, p.releaseTime);

        Member storage m = members[msg.sender];
        if (m.role != Role.Custodian || !m.active) revert NotActiveCustodian();

        uint256 idx = _custodianIndex(paperId, msg.sender);
        if (shareRevealed[paperId][idx]) revert ShareAlreadyReleased();
        if (keccak256(share) != shareCommitments[paperId][idx]) revert InvalidShare();

        shareRevealed[paperId][idx] = true;
        revealedShares[paperId][idx] = share;
        p.sharesReleased += 1;
        emit ShareReleased(paperId, msg.sender, p.sharesReleased);

        if (p.sharesReleased == p.threshold) {
            emit PaperUnlocked(paperId, uint64(block.timestamp));
        }
    }

    /// @notice An exam centre records that it opened the paper. The watermark ID
    ///         is embedded (invisibly) in the centre's copy.
    function recordAccess(uint256 paperId, bytes8 watermarkId, bytes32 copyHash) external paperExists(paperId) {
        Paper storage p = papers[paperId];
        if (p.revoked) revert PaperIsRevoked(paperId);
        if (p.sharesReleased < p.threshold) revert PaperStillLocked(paperId);

        Member storage m = members[msg.sender];
        if (m.role != Role.Centre || !m.active) revert NotActiveCentre();
        if (centreAccessed[paperId][msg.sender]) revert AlreadyAccessed();
        if (watermarks[watermarkId].exists) revert WatermarkInUse();

        centreAccessed[paperId][msg.sender] = true;
        accesses[paperId].push(Access(msg.sender, watermarkId, copyHash, uint64(block.timestamp)));
        watermarks[watermarkId] = WatermarkRef(paperId, accesses[paperId].length - 1, true);
        emit PaperAccessed(paperId, msg.sender, watermarkId, copyHash);
    }

    function revokePaper(uint256 paperId, string calldata reason) external onlyUniversity paperExists(paperId) {
        papers[paperId].revoked = true;
        emit PaperRevoked(paperId, reason);
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------

    function paperCount() external view returns (uint256) {
        return papers.length;
    }

    function getPaper(uint256 paperId) external view paperExists(paperId) returns (Paper memory) {
        return papers[paperId];
    }

    function getCustodians(uint256 paperId) external view paperExists(paperId) returns (address[] memory) {
        return paperCustodians[paperId];
    }

    function getCommitments(uint256 paperId) external view paperExists(paperId) returns (bytes32[] memory) {
        return shareCommitments[paperId];
    }

    /// @return shares the revealed shares (empty bytes for shares not yet revealed)
    function getRevealedShares(uint256 paperId) external view paperExists(paperId) returns (bytes[] memory shares) {
        uint256 n = paperCustodians[paperId].length;
        shares = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            if (shareRevealed[paperId][i]) shares[i] = revealedShares[paperId][i];
        }
    }

    function isShareReleased(uint256 paperId, address custodian) external view paperExists(paperId) returns (bool) {
        return shareRevealed[paperId][_custodianIndex(paperId, custodian)];
    }

    function getAccesses(uint256 paperId) external view paperExists(paperId) returns (Access[] memory) {
        return accesses[paperId];
    }

    /// @notice Leak tracing: who received the copy carrying this watermark?
    function traceWatermark(bytes8 watermarkId)
        external
        view
        returns (bool found, uint256 paperId, address centre, string memory centreName, uint64 time, bytes32 copyHash)
    {
        WatermarkRef memory ref = watermarks[watermarkId];
        if (!ref.exists) return (false, 0, address(0), "", 0, bytes32(0));
        Access memory a = accesses[ref.paperId][ref.accessIndex];
        return (true, ref.paperId, a.centre, members[a.centre].name, a.time, a.copyHash);
    }

    function getMembers() external view returns (address[] memory accounts, Member[] memory info) {
        accounts = memberList;
        info = new Member[](memberList.length);
        for (uint256 i = 0; i < memberList.length; i++) info[i] = members[memberList[i]];
    }

    function _custodianIndex(uint256 paperId, address custodian) private view returns (uint256) {
        address[] storage list = paperCustodians[paperId];
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i] == custodian) return i;
        }
        revert NotACustodianOfPaper();
    }
}
