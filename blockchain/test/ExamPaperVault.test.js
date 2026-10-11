const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time, loadFixture } = require("@nomicfoundation/hardhat-network-helpers");

const Role = { None: 0, Custodian: 1, Centre: 2 };
const sha = (text) => ethers.sha256(ethers.toUtf8Bytes(text));

describe("ExamPaperVault", function () {
  async function deployFixture() {
    const [university, c1, c2, c3, centreA, centreB, outsider] = await ethers.getSigners();
    const vault = await ethers.deployContract("ExamPaperVault", [], university);

    await vault.registerMember(c1.address, Role.Custodian, "Controller of Examinations");
    await vault.registerMember(c2.address, Role.Custodian, "State Examination Board");
    await vault.registerMember(c3.address, Role.Custodian, "Independent Observer");
    await vault.registerMember(centreA.address, Role.Centre, "Centre A");
    await vault.registerMember(centreB.address, Role.Centre, "Centre B");

    // Shares are opaque bytes to the contract; only their keccak256 commitment matters.
    const shares = ["0x01aa", "0x02bb", "0x03cc"];
    const commitments = shares.map((s) => ethers.keccak256(s));
    const releaseTime = (await time.latest()) + 3600;

    await vault.createPaper(
      "CS743-2026",
      "Blockchain Technology",
      sha("Q1. What is a hash function?"),
      sha("<ciphertext>"),
      releaseTime,
      2,
      [c1.address, c2.address, c3.address],
      commitments
    );

    return { vault, university, c1, c2, c3, centreA, centreB, outsider, shares, releaseTime };
  }

  describe("Consortium membership", function () {
    it("only the university can register members", async function () {
      const { vault, outsider } = await loadFixture(deployFixture);
      await expect(vault.connect(outsider).registerMember(outsider.address, Role.Centre, "Fake Centre"))
        .to.be.revertedWithCustomError(vault, "NotUniversity");
    });

    it("rejects duplicate registration", async function () {
      const { vault, c1 } = await loadFixture(deployFixture);
      await expect(vault.registerMember(c1.address, Role.Centre, "Again"))
        .to.be.revertedWithCustomError(vault, "AlreadyRegistered");
    });

    it("lists all members", async function () {
      const { vault } = await loadFixture(deployFixture);
      const [accounts, info] = await vault.getMembers();
      expect(accounts.length).to.equal(5);
      expect(info[0].name).to.equal("Controller of Examinations");
    });
  });

  describe("Paper creation", function () {
    it("stores only hashes and commitments", async function () {
      const { vault, releaseTime } = await loadFixture(deployFixture);
      const p = await vault.getPaper(0);
      expect(p.code).to.equal("CS743-2026");
      expect(p.releaseTime).to.equal(releaseTime);
      expect(p.threshold).to.equal(2);
      expect(await vault.getCommitments(0)).to.have.length(3);
    });

    it("rejects a release time in the past", async function () {
      const { vault, c1, c2 } = await loadFixture(deployFixture);
      const past = (await time.latest()) - 10;
      await expect(
        vault.createPaper("X", "X", ethers.ZeroHash, ethers.ZeroHash, past, 2, [c1.address, c2.address], [ethers.ZeroHash, ethers.ZeroHash])
      ).to.be.revertedWithCustomError(vault, "ReleaseTimeInPast");
    });

    it("requires a threshold of at least 2 (no single point of leak)", async function () {
      const { vault, c1, c2 } = await loadFixture(deployFixture);
      const t = (await time.latest()) + 100;
      await expect(
        vault.createPaper("X", "X", ethers.ZeroHash, ethers.ZeroHash, t, 1, [c1.address, c2.address], [ethers.ZeroHash, ethers.ZeroHash])
      ).to.be.revertedWithCustomError(vault, "InvalidThreshold");
    });

    it("only accepts registered custodians as key holders", async function () {
      const { vault, c1, centreA } = await loadFixture(deployFixture);
      const t = (await time.latest()) + 100;
      await expect(
        vault.createPaper("X", "X", ethers.ZeroHash, ethers.ZeroHash, t, 2, [c1.address, centreA.address], [ethers.ZeroHash, ethers.ZeroHash])
      ).to.be.revertedWithCustomError(vault, "NotActiveCustodian");
    });
  });

  describe("Time-locked key release", function () {
    it("blocks share release before the exam time", async function () {
      const { vault, c1, shares } = await loadFixture(deployFixture);
      await expect(vault.connect(c1).releaseShare(0, shares[0]))
        .to.be.revertedWithCustomError(vault, "TooEarly");
    });

    it("rejects a share that does not match its commitment", async function () {
      const { vault, c1, releaseTime } = await loadFixture(deployFixture);
      await time.increaseTo(releaseTime);
      await expect(vault.connect(c1).releaseShare(0, "0xdeadbeef"))
        .to.be.revertedWithCustomError(vault, "InvalidShare");
    });

    it("rejects accounts that are not custodians of the paper", async function () {
      const { vault, centreA, shares, releaseTime } = await loadFixture(deployFixture);
      await time.increaseTo(releaseTime);
      await expect(vault.connect(centreA).releaseShare(0, shares[0]))
        .to.be.revertedWithCustomError(vault, "NotActiveCustodian");
    });

    it("unlocks the paper once the threshold is reached", async function () {
      const { vault, c1, c2, shares, releaseTime } = await loadFixture(deployFixture);
      await time.increaseTo(releaseTime);

      await expect(vault.connect(c1).releaseShare(0, shares[0]))
        .to.emit(vault, "ShareReleased").withArgs(0, c1.address, 1);
      await expect(vault.connect(c1).releaseShare(0, shares[0]))
        .to.be.revertedWithCustomError(vault, "ShareAlreadyReleased");
      await expect(vault.connect(c2).releaseShare(0, shares[1]))
        .to.emit(vault, "PaperUnlocked");

      const revealed = await vault.getRevealedShares(0);
      expect(revealed[0]).to.equal(shares[0]);
      expect(revealed[1]).to.equal(shares[1]);
      expect(revealed[2]).to.equal("0x");
    });
  });

  describe("Centre access and leak tracing", function () {
    async function unlockedFixture() {
      const f = await deployFixture();
      await time.increaseTo(f.releaseTime);
      await f.vault.connect(f.c1).releaseShare(0, f.shares[0]);
      await f.vault.connect(f.c3).releaseShare(0, f.shares[2]);
      return f;
    }

    it("centres cannot open a paper that is still locked", async function () {
      const { vault, centreA } = await loadFixture(deployFixture);
      await expect(vault.connect(centreA).recordAccess(0, "0x1122334455667788", ethers.ZeroHash))
        .to.be.revertedWithCustomError(vault, "PaperStillLocked");
    });

    it("records each centre's watermarked copy and traces a leak", async function () {
      const { vault, centreA, centreB } = await loadFixture(unlockedFixture);
      const wmA = "0xaaaaaaaaaaaaaaaa";
      const wmB = "0xbbbbbbbbbbbbbbbb";
      await expect(vault.connect(centreA).recordAccess(0, wmA, sha("copy A")))
        .to.emit(vault, "PaperAccessed").withArgs(0, centreA.address, wmA, sha("copy A"));
      await vault.connect(centreB).recordAccess(0, wmB, sha("copy B"));

      const trace = await vault.traceWatermark(wmB);
      expect(trace.found).to.equal(true);
      expect(trace.centre).to.equal(centreB.address);
      expect(trace.centreName).to.equal("Centre B");

      const unknown = await vault.traceWatermark("0x0000000000000001");
      expect(unknown.found).to.equal(false);
    });

    it("a centre can open the paper only once and watermarks are unique", async function () {
      const { vault, centreA, centreB } = await loadFixture(unlockedFixture);
      await vault.connect(centreA).recordAccess(0, "0x1111111111111111", ethers.ZeroHash);
      await expect(vault.connect(centreA).recordAccess(0, "0x2222222222222222", ethers.ZeroHash))
        .to.be.revertedWithCustomError(vault, "AlreadyAccessed");
      await expect(vault.connect(centreB).recordAccess(0, "0x1111111111111111", ethers.ZeroHash))
        .to.be.revertedWithCustomError(vault, "WatermarkInUse");
    });

    it("non-centres cannot record access", async function () {
      const { vault, outsider } = await loadFixture(unlockedFixture);
      await expect(vault.connect(outsider).recordAccess(0, "0x1111111111111111", ethers.ZeroHash))
        .to.be.revertedWithCustomError(vault, "NotActiveCentre");
    });
  });

  describe("Revocation", function () {
    it("a revoked paper can no longer be released or opened", async function () {
      const { vault, c1, shares, releaseTime } = await loadFixture(deployFixture);
      await expect(vault.revokePaper(0, "Leak suspected"))
        .to.emit(vault, "PaperRevoked").withArgs(0, "Leak suspected");
      await time.increaseTo(releaseTime);
      await expect(vault.connect(c1).releaseShare(0, shares[0]))
        .to.be.revertedWithCustomError(vault, "PaperIsRevoked");
    });

    it("deactivated custodians cannot release shares", async function () {
      const { vault, c1, shares, releaseTime } = await loadFixture(deployFixture);
      await vault.setMemberActive(c1.address, false);
      await time.increaseTo(releaseTime);
      await expect(vault.connect(c1).releaseShare(0, shares[0]))
        .to.be.revertedWithCustomError(vault, "NotActiveCustodian");
    });
  });
});
