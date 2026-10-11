/* ExamShield - Leak-Proof Exam Paper Distribution System (web app) */
(function () {
  const ROLE = { None: 0, Custodian: 1, Centre: 2 };

  // Demo consortium: account 0 is the University (contract deployer).
  const CONSORTIUM = [
    [1, ROLE.Custodian, "Controller of Examinations"],
    [2, ROLE.Custodian, "State Examination Board"],
    [3, ROLE.Custodian, "Independent Observer"],
    [4, ROLE.Centre, "Centre A - City Engineering College"],
    [5, ROLE.Centre, "Centre B - Govt. Polytechnic Hall"],
    [6, ROLE.Centre, "Centre C - St. Mary's Institute"],
  ];

  const SAMPLE_PAPER = `22CS743 - BLOCKCHAIN TECHNOLOGY
Semester End Examination · Duration: 3 Hours · Max. Marks: 100
Answer any FIVE full questions, choosing ONE full question from each module.

MODULE II
1. a) Explain the properties of a cryptographic hash function with examples. (10)
   b) Compare SHA-256 and SHA-3 (Keccak). Why is SHA-3 resistant to length-extension attacks? (10)

MODULE III
2. a) Describe the Ethereum Virtual Machine and the role of gas. (10)
   b) Write a smart contract that releases funds only after a given time. (10)

MODULE IV
3. a) What is a consortium blockchain? Compare Hyperledger Fabric and Corda. (10)
   b) Explain how endorsement policies work in a permissioned network. (10)

MODULE V
4. a) Discuss the security and privacy challenges of public blockchains. (10)
   b) Design a blockchain application for exam paper security. (10)

5. Write short notes on any FOUR: (a) Merkle tree (b) Byzantine agreement
   (c) Oracles (d) ICO (e) Zero-knowledge proofs (f) 51% attack (20)`;

  const ERRORS = {
    NotUniversity: () => "only the University account can do this.",
    NotActiveCustodian: () => "this account is not an active key custodian.",
    NotActiveCentre: () => "this account is not an active exam centre.",
    UnknownPaper: (id) => `paper #${id} does not exist.`,
    InvalidMember: () => "invalid member details.",
    AlreadyRegistered: () => "this account is already a consortium member.",
    InvalidThreshold: () => "the threshold must be at least 2 and not more than the number of custodians.",
    ReleaseTimeInPast: () => "the release time must be in the future.",
    TooEarly: (now, at) =>
      `too early! Key shares can only be released at ${UI.fmtTime(at)} (${UI.fmtDuration(Number(at) - Number(now))} from now).`,
    NotACustodianOfPaper: () => "this custodian does not hold a share for this paper.",
    ShareAlreadyReleased: () => "this custodian has already released their share.",
    InvalidShare: () => "the share does not match the commitment stored on the blockchain (tampered share).",
    PaperIsRevoked: () => "this paper has been revoked.",
    PaperStillLocked: () => "the paper is still locked - not enough key shares have been released.",
    AlreadyAccessed: () => "this centre has already opened the paper.",
    WatermarkInUse: () => "watermark ID collision, try again.",
  };

  const lower = (a) => (a || "").toLowerCase();
  const sameAddr = (a, b) => lower(a) === lower(b);
  const univ = () => Chain.accounts[0];

  // ------------------------------------------------------------------
  // Data
  // ------------------------------------------------------------------
  async function load() {
    const c = Chain.contract;
    const [accts, infos] = await c.getMembers();
    const members = accts.map((a, i) => ({
      address: a,
      role: Number(infos[i].role),
      name: infos[i].name,
      active: infos[i].active,
    }));
    Chain.setName(univ(), "University");
    members.forEach((m) => Chain.setName(m.address, m.name));

    const count = Number(await c.paperCount());
    const papers = [];
    for (let id = 0; id < count; id++) {
      const [p, custodians, commitments, accesses, revealed] = await Promise.all([
        c.getPaper(id),
        c.getCustodians(id),
        c.getCommitments(id),
        c.getAccesses(id),
        c.getRevealedShares(id),
      ]);
      papers.push({
        id,
        code: p.code,
        title: p.title,
        paperHash: p.paperHash,
        cipherHash: p.cipherHash,
        releaseTime: Number(p.releaseTime),
        threshold: Number(p.threshold),
        sharesReleased: Number(p.sharesReleased),
        revoked: p.revoked,
        createdAt: Number(p.createdAt),
        custodians: [...custodians],
        commitments: [...commitments],
        revealed: [...revealed],
        accesses: accesses.map((a) => ({ centre: a.centre, watermarkId: a.watermarkId, copyHash: a.copyHash, time: Number(a.time) })),
      });
    }
    return {
      members,
      papers,
      custodians: members.filter((m) => m.role === ROLE.Custodian),
      centres: members.filter((m) => m.role === ROLE.Centre),
    };
  }

  function status(p) {
    if (p.revoked) return { key: "revoked", label: "Revoked", chip: "chip-bad" };
    if (p.sharesReleased >= p.threshold) return { key: "unlocked", label: "Unlocked", chip: "chip-ok" };
    if (Chain.now() >= p.releaseTime) return { key: "releasing", label: `Waiting for key shares`, chip: "chip-warn" };
    return { key: "sealed", label: "Sealed", chip: "chip-accent" };
  }

  const countdown = (p) =>
    Chain.now() < p.releaseTime
      ? `opens in <strong data-countdown="${p.releaseTime}" data-done-text="now">${UI.fmtDuration(p.releaseTime - Chain.now())}</strong>`
      : `opened at ${UI.fmtClock(p.releaseTime)}`;

  // Off-chain storage: the "distribution server" (encrypted papers) and each custodian's private vault.
  const ciphers = () => Chain.store.get("ciphers", {});
  const vaultOf = (addr) => (Chain.store.get("vault", {})[lower(addr)] || {});
  function putShare(addr, paperId, shareHex) {
    const v = Chain.store.get("vault", {});
    v[lower(addr)] = v[lower(addr)] || {};
    v[lower(addr)][paperId] = shareHex;
    Chain.store.set("vault", v);
  }

  // ------------------------------------------------------------------
  // Core actions
  // ------------------------------------------------------------------
  async function createPaper({ code, title, text, minutes, custodians, threshold }) {
    const s = Shell.state;
    let paperHash, key, blob, cipherHash, shareHex, commitments, result;
    const releaseTime = Chain.now() + Math.max(1, Math.round(minutes * 60));
    const host = document.getElementById("create-steps");
    const run = await UI.runSteps(host, [
      {
        title: "Hash the original paper (SHA-256)",
        run: async () => {
          paperHash = await UI.sha256(text);
          return paperHash;
        },
      },
      {
        title: "Encrypt the paper with a fresh AES-256-GCM key",
        run: async () => {
          ({ key, blob } = await ExamCrypto.aesEncrypt(text));
          cipherHash = await UI.sha256(blob);
          return `${blob.length} encrypted bytes · ciphertext hash ${UI.short(cipherHash, 8)}`;
        },
      },
      {
        title: `Split the key into ${custodians.length} shares (any ${threshold} can rebuild it)`,
        run: async () => {
          shareHex = ExamCrypto.split(key, custodians.length, threshold).map(UI.bytesToHex);
          commitments = shareHex.map((h) => ethers.keccak256(h));
          return `Share commitments (keccak256): ${commitments.map((c) => UI.short(c, 4)).join(", ")}`;
        },
      },
      {
        title: "Record hashes + commitments on the blockchain (createPaper)",
        run: async () => {
          result = await Chain.send(univ(), "createPaper", [
            code,
            title,
            paperHash,
            cipherHash,
            releaseTime,
            threshold,
            custodians,
            commitments,
          ]);
          return `Block #${result.block.number} · tx ${UI.short(result.receipt.hash, 6)}`;
        },
      },
      {
        title: "Deliver shares to custodian vaults and destroy the key",
        run: async () => {
          const id = Number(result.events.find((e) => e.name === "PaperCreated").args.paperId);
          const all = ciphers();
          all[cipherHash] = UI.bytesToBase64(blob);
          Chain.store.set("ciphers", all);
          custodians.forEach((c, i) => putShare(c, id, shareHex[i]));
          key.fill(0);
          return `Paper #${id} sealed. Nobody holds the full key now. Opens ${UI.fmtTime(releaseTime)}.`;
        },
      },
    ]);
    s.createResult = run.items;
    if (!run.ok) throw run.error;
    UI.toast(`Paper "${code}" sealed on the blockchain`, "success");
  }

  async function releaseShare(custodian, paper) {
    const share = vaultOf(custodian)[paper.id];
    if (!share) throw new Error("This custodian's vault has no share for this paper (import the share file first).");
    await Chain.send(custodian, "releaseShare", [paper.id, share]);
    UI.toast(`${Chain.label(custodian)} released their key share`, "success");
  }

  function visibleHeader(paper, centreName, wm) {
    const line = "─".repeat(60);
    return `${line}\nCONFIDENTIAL · Issued to: ${centreName}\nPaper: ${paper.code} · Copy ID: ${wm.slice(2)}\n${line}`;
  }

  async function buildCopy(paper, centreAddr, wm, plaintext) {
    return ExamCrypto.embedWatermark(plaintext, wm, visibleHeader(paper, Chain.label(centreAddr), wm));
  }

  async function decryptPaper(paper) {
    const b64 = ciphers()[paper.cipherHash];
    if (!b64) throw new Error('Encrypted paper (.enc) not found in this browser. Use "Import .enc file".');
    const blob = UI.base64ToBytes(b64);
    const shares = paper.revealed.filter((s) => s && s !== "0x").map(UI.hexToBytes);
    const key = ExamCrypto.combine(shares.slice(0, paper.threshold));
    return ExamCrypto.aesDecrypt(key, blob);
  }

  async function openPaper(centreAddr, paper) {
    const s = Shell.state;
    let blob, shares, key, text, copy, wm;
    const existing = paper.accesses.find((a) => sameAddr(a.centre, centreAddr));
    const host = document.getElementById("open-steps");
    const run = await UI.runSteps(host, [
      {
        title: "Check the paper is unlocked on the blockchain",
        run: async () => {
          if (paper.revoked) throw new Error("Paper revoked by the University");
          if (paper.sharesReleased < paper.threshold) throw new Error(`Only ${paper.sharesReleased}/${paper.threshold} key shares released`);
          return `${paper.sharesReleased} of ${paper.custodians.length} custodians released their shares`;
        },
      },
      {
        title: "Verify the encrypted paper against its on-chain hash",
        run: async () => {
          const b64 = ciphers()[paper.cipherHash];
          if (!b64) throw new Error('Encrypted paper (.enc) not found in this browser. Use "Import .enc file".');
          blob = UI.base64ToBytes(b64);
          const h = await UI.sha256(blob);
          if (h !== paper.cipherHash) throw new Error("Ciphertext hash mismatch - file was tampered with");
          return `sha256 = ${UI.short(h, 8)} ✓ matches blockchain`;
        },
      },
      {
        title: "Collect released key shares and check their commitments",
        run: async () => {
          shares = [];
          paper.revealed.forEach((hex, i) => {
            if (!hex || hex === "0x") return;
            if (ethers.keccak256(hex) !== paper.commitments[i]) throw new Error(`Share ${i + 1} does not match its commitment`);
            shares.push(UI.hexToBytes(hex));
          });
          return `${shares.length} valid shares from: ${paper.custodians
            .filter((_, i) => paper.revealed[i] && paper.revealed[i] !== "0x")
            .map((a) => Chain.label(a))
            .join(", ")}`;
        },
      },
      {
        title: `Rebuild the AES key (Shamir, ${paper.threshold}-of-${paper.custodians.length}) and decrypt`,
        run: async () => {
          key = ExamCrypto.combine(shares.slice(0, paper.threshold));
          text = await ExamCrypto.aesDecrypt(key, blob);
          key.fill(0);
          const h = await UI.sha256(text);
          if (h !== paper.paperHash) throw new Error("Decrypted paper does not match the original hash");
          return `Decrypted ${text.length} characters · paper hash ✓ matches blockchain`;
        },
      },
      existing
        ? {
            title: "Rebuild this centre's watermarked copy and verify its on-chain record",
            run: async () => {
              wm = existing.watermarkId;
              copy = await buildCopy(paper, centreAddr, wm, text);
              if ((await UI.sha256(copy)) !== existing.copyHash) throw new Error("Copy hash mismatch");
              return `Copy ID ${wm.slice(2)} · opened ${UI.fmtTime(existing.time)}`;
            },
          }
        : {
            title: "Watermark the copy for this centre and record it on the blockchain",
            run: async () => {
              wm = UI.bytesToHex(UI.randomBytes(8));
              copy = await buildCopy(paper, centreAddr, wm, text);
              const copyHash = await UI.sha256(copy);
              const r = await Chain.send(centreAddr, "recordAccess", [paper.id, wm, copyHash]);
              return `Copy ID ${wm.slice(2)} · block #${r.block.number}`;
            },
          },
    ]);
    s.opened = { paperId: paper.id, centre: centreAddr, items: run.items, copy: run.ok ? copy : null, wm };
    if (run.ok) {
      const copies = Chain.store.get("copies", {});
      copies[wm] = copy;
      Chain.store.set("copies", copies);
      if (!existing) UI.toast("Paper unlocked and watermarked for this centre", "success");
    } else throw run.error;
  }

  async function trace(text, data) {
    const found = ExamCrypto.extractWatermark(text);
    const id = found.invisible || found.visible;
    const textHash = await UI.sha256(text);
    let exact = null;
    for (const p of data.papers) for (const a of p.accesses) if (a.copyHash === textHash) exact = { paper: p, access: a };

    let hit = null;
    if (id) {
      const t = await Chain.contract.traceWatermark(id);
      if (t.found) hit = { paperId: Number(t.paperId), centre: t.centre, centreName: t.centreName, time: Number(t.time), copyHash: t.copyHash };
    }
    if (!hit && exact) hit = { paperId: exact.paper.id, centre: exact.access.centre, centreName: Chain.label(exact.access.centre), time: exact.access.time, copyHash: exact.access.copyHash };
    return { id, found, hit, exact: !!exact, invisibleCount: ExamCrypto.countInvisible(text) };
  }

  // ------------------------------------------------------------------
  // Views
  // ------------------------------------------------------------------
  const pageHead = (title, sub, actions = "") =>
    `<div class="page-head"><div><h1>${title}</h1><p>${sub}</p></div><div class="row">${actions}</div></div>`;

  function papersTable(papers, { showAccess = true } = {}) {
    if (!papers.length) return `<div class="empty">No exam papers yet. Create one as the University.</div>`;
    return `<div class="table-wrap"><table class="table">
      <thead><tr><th>Paper</th><th>Release</th><th>Status</th><th>Key shares</th>${showAccess ? "<th>Centres opened</th>" : ""}</tr></thead>
      <tbody>${papers
        .map((p) => {
          const st = status(p);
          return `<tr>
            <td data-label="Paper"><strong>${UI.esc(p.code)}</strong><div class="muted small">${UI.esc(p.title)}</div></td>
            <td data-label="Release">${UI.fmtTime(p.releaseTime)}<div class="muted small">${countdown(p)}</div></td>
            <td data-label="Status"><span class="chip ${st.chip}">${st.label}</span></td>
            <td data-label="Key shares">${p.sharesReleased} / ${p.threshold} needed <span class="muted small">(${p.custodians.length} holders)</span></td>
            ${showAccess ? `<td data-label="Centres">${p.accesses.length}</td>` : ""}
          </tr>`;
        })
        .join("")}</tbody></table></div>`;
  }

  async function viewHome(el, { data, action, go }) {
    const ps = data.papers;
    const sealed = ps.filter((p) => status(p).key === "sealed").length;
    const unlocked = ps.filter((p) => status(p).key === "unlocked").length;
    const copies = ps.reduce((n, p) => n + p.accesses.length, 0);
    const next = ps.filter((p) => !p.revoked && Chain.now() < p.releaseTime).sort((a, b) => a.releaseTime - b.releaseTime)[0];

    el.innerHTML = `
      ${pageHead(
        "Leak-Proof Exam Paper Distribution",
        "Question papers stay encrypted until exam time. The key is split between independent custodians and can only be released by a smart contract time-lock. Every centre's copy carries a hidden watermark, so a leak points straight to its source.",
        `<button class="btn" id="sample-btn">${Shell.icon("building")} Create sample paper</button>
         ${next ? `<button class="btn btn-secondary" id="jump-btn">${Shell.icon("forward")} Jump to exam time</button>` : ""}`
      )}
      <div class="grid-4" style="margin-bottom:16px">
        <div class="card stat"><span class="stat-value">${ps.length}</span><span class="stat-label">Exam papers on-chain</span></div>
        <div class="card stat"><span class="stat-value">${sealed}</span><span class="stat-label">Sealed (time-locked)</span></div>
        <div class="card stat"><span class="stat-value">${unlocked}</span><span class="stat-label">Unlocked for centres</span></div>
        <div class="card stat"><span class="stat-value">${copies}</span><span class="stat-label">Watermarked copies issued</span></div>
      </div>
      <div class="card" style="margin-bottom:16px">
        <div class="card-head"><h2>How it works</h2></div>
        <div class="flow" style="--steps:4">
          <div class="flow-step"><h3>Encrypt &amp; commit</h3><p>The paper is AES-256 encrypted. Only its SHA-256 hashes go on the blockchain.</p></div>
          <div class="flow-step"><h3>Split the key</h3><p>Shamir's Secret Sharing splits the key: any 2 of 3 custodians can rebuild it, one alone cannot.</p></div>
          <div class="flow-step"><h3>Time-locked release</h3><p>The smart contract refuses key shares before exam time and checks each share against its commitment.</p></div>
          <div class="flow-step"><h3>Watermark &amp; trace</h3><p>Each centre's copy gets a unique invisible watermark recorded on-chain. A leaked copy reveals its centre.</p></div>
        </div>
      </div>
      <div class="grid-2" style="align-items:start">
        <div class="card"><div class="card-head"><h2>Exam papers</h2><a href="#/university" class="small">Manage</a></div>${papersTable(ps)}</div>
        <div class="card">
          <div class="card-head"><h2>Demo script (5 minutes)</h2></div>
          <ol style="margin:0;padding-left:18px;display:flex;flex-direction:column;gap:6px">
            <li><a href="#/university">University</a>: create a paper that opens in 10 minutes.</li>
            <li><a href="#/custodian">Key Custodians</a>: try to release a share now. The smart contract blocks it.</li>
            <li>Click <strong>+5 min</strong> / <strong>+1 h</strong> at the top to move blockchain time to the exam.</li>
            <li>Release shares from any <strong>2</strong> custodians. The paper unlocks.</li>
            <li><a href="#/centre">Exam Centres</a>: open the paper. It is verified, decrypted and watermarked.</li>
            <li><a href="#/trace">Leak Tracer</a>: click <em>Simulate a leak</em>. The guilty centre is identified.</li>
            <li><a href="#/explorer">Blockchain Explorer</a>: show the hash-linked blocks and the audit log.</li>
          </ol>
        </div>
      </div>`;

    el.querySelector("#sample-btn").addEventListener("click", (e) => {
      Shell.state.prefill = true;
      go("university");
    });
    const jb = el.querySelector("#jump-btn");
    if (jb)
      jb.addEventListener("click", () =>
        action(jb, async () => {
          await Chain.fastForward(next.releaseTime - Chain.now() + 1);
          UI.toast(`Blockchain time is now the exam time of ${next.code}`, "success");
        })
      );
  }

  async function viewUniversity(el, { data, state, action }) {
    const prefill = state.prefill;
    state.prefill = false;
    const n = data.papers.length + 1;
    el.innerHTML = `
      ${pageHead("University · Examination Cell", `Acting as <code>${UI.esc(UI.short(univ(), 4))}</code> (contract owner). Create sealed papers and manage the consortium.`)}
      <div class="grid-2" style="align-items:start;margin-bottom:16px">
        <form class="card" id="create-form" autocomplete="off">
          <div class="card-head"><h2>Create a sealed exam paper</h2><button type="button" class="btn btn-ghost btn-sm" id="load-sample">Load sample paper</button></div>
          <div class="grid-2" style="gap:12px">
            <div class="field"><label for="f-code">Paper code</label><input id="f-code" name="code" type="text" required value="${prefill ? `22CS743-${String(n).padStart(2, "0")}` : ""}" placeholder="22CS743-01"></div>
            <div class="field"><label for="f-min">Exam starts in (minutes)</label><input id="f-min" name="minutes" type="number" min="1" step="1" value="10" required></div>
          </div>
          <div class="field"><label for="f-title">Title</label><input id="f-title" name="title" type="text" required value="${prefill ? "Blockchain Technology - Semester End Exam" : ""}" placeholder="Blockchain Technology - Semester End Exam"></div>
          <div class="field"><label>Key custodians</label>
            <div class="row">${data.custodians
              .map(
                (c) => `<label class="chip" style="cursor:pointer;padding:5px 10px"><input type="checkbox" name="cust" value="${c.address}" ${c.active ? "checked" : "disabled"}> ${UI.esc(c.name)}</label>`
              )
              .join("")}</div>
            <span class="hint">Each custodian receives one share of the key.</span>
          </div>
          <div class="field"><label for="f-th">Shares needed to unlock</label>
            <select id="f-th" name="threshold"><option value="2" selected>2 (recommended)</option><option value="3">3 (all)</option></select></div>
          <div class="field"><label for="f-text">Question paper</label><textarea id="f-text" name="text" required rows="10" placeholder="Type or paste the questions…">${prefill ? UI.esc(SAMPLE_PAPER) : ""}</textarea></div>
          <button class="btn" type="submit" id="create-btn">${Shell.icon("shield")} Encrypt &amp; seal on blockchain</button>
        </form>
        <div class="card">
          <div class="card-head"><h2>What happens</h2></div>
          <div id="create-steps">${
            state.createResult
              ? UI.checklist(state.createResult)
              : `<p class="muted">The steps run in your browser and are shown here: hashing, AES encryption, Shamir key splitting, the blockchain transaction and the hand-over to custodians.</p>`
          }</div>
        </div>
      </div>
      <div class="card" style="margin-bottom:16px">
        <div class="card-head"><h2>Papers</h2></div>
        ${
          data.papers.length
            ? `<div class="table-wrap"><table class="table"><thead><tr><th>Paper</th><th>Release</th><th>Status</th><th>Actions</th></tr></thead><tbody>
          ${data.papers
            .map((p) => {
              const st = status(p);
              return `<tr><td data-label="Paper"><strong>${UI.esc(p.code)}</strong><div class="muted small">${UI.esc(p.title)}</div></td>
              <td data-label="Release">${UI.fmtTime(p.releaseTime)}<div class="muted small">${countdown(p)}</div></td>
              <td data-label="Status"><span class="chip ${st.chip}">${st.label}</span></td>
              <td data-label="Actions"><div class="row">
                <button class="btn btn-secondary btn-sm" data-enc="${p.id}">Download .enc</button>
                ${p.revoked ? "" : `<button class="btn btn-danger btn-sm" data-revoke="${p.id}">Revoke</button>`}
              </div></td></tr>`;
            })
            .join("")}</tbody></table></div>`
            : `<div class="empty">No papers yet.</div>`
        }
      </div>
      <div class="card">
        <div class="card-head"><h2>Consortium members</h2><span class="muted small">Permissioned: only the University can add members.</span></div>
        <div class="table-wrap"><table class="table"><thead><tr><th>Name</th><th>Role</th><th>Account</th><th>Status</th><th></th></tr></thead><tbody>
        ${data.members
          .map(
            (m) => `<tr><td data-label="Name">${UI.esc(m.name)}</td>
            <td data-label="Role"><span class="chip">${m.role === ROLE.Custodian ? "Key custodian" : "Exam centre"}</span></td>
            <td data-label="Account"><code>${UI.esc(UI.short(m.address, 4))}</code></td>
            <td data-label="Status">${m.active ? `<span class="chip chip-ok">Active</span>` : `<span class="chip chip-bad">Suspended</span>`}</td>
            <td><button class="btn btn-secondary btn-sm" data-toggle="${m.address}" data-active="${m.active}">${m.active ? "Suspend" : "Activate"}</button></td></tr>`
          )
          .join("")}</tbody></table></div>
      </div>`;

    const form = el.querySelector("#create-form");
    el.querySelector("#load-sample").addEventListener("click", () => {
      form.code.value = form.code.value || `22CS743-${String(n).padStart(2, "0")}`;
      form.title.value = form.title.value || "Blockchain Technology - Semester End Exam";
      form.text.value = SAMPLE_PAPER;
    });
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const custodians = [...form.querySelectorAll('input[name="cust"]:checked')].map((i) => i.value);
      const threshold = Number(form.threshold.value);
      if (custodians.length < threshold) return UI.toast(`Select at least ${threshold} custodians`, "error");
      action(el.querySelector("#create-btn"), () =>
        createPaper({
          code: form.code.value.trim(),
          title: form.title.value.trim(),
          text: form.text.value.replace(/\r\n/g, "\n").trim(),
          minutes: Number(form.minutes.value),
          custodians,
          threshold,
        })
      );
    });
    el.querySelectorAll("[data-enc]").forEach((b) =>
      b.addEventListener("click", () => {
        const p = data.papers[Number(b.dataset.enc)];
        const b64 = ciphers()[p.cipherHash];
        if (!b64) return UI.toast("Encrypted file is not stored in this browser", "error");
        UI.download(`${p.code}.enc`, UI.base64ToBytes(b64), "application/octet-stream");
      })
    );
    el.querySelectorAll("[data-revoke]").forEach((b) =>
      b.addEventListener("click", () => {
        const reason = prompt("Reason for revoking this paper:", "Leak suspected - paper will be replaced");
        if (reason) action(b, async () => {
          await Chain.send(univ(), "revokePaper", [Number(b.dataset.revoke), reason]);
          UI.toast("Paper revoked", "success");
        });
      })
    );
    el.querySelectorAll("[data-toggle]").forEach((b) =>
      b.addEventListener("click", () =>
        action(b, () => Chain.send(univ(), "setMemberActive", [b.dataset.toggle, b.dataset.active !== "true"]))
      )
    );
  }

  async function viewCustodian(el, { data, state, action }) {
    if (!data.custodians.length) return (el.innerHTML = `<div class="empty">No custodians registered.</div>`);
    state.custodian = state.custodian && data.custodians.some((c) => sameAddr(c.address, state.custodian)) ? state.custodian : data.custodians[0].address;
    const me = data.custodians.find((c) => sameAddr(c.address, state.custodian));
    const vault = vaultOf(me.address);
    const mine = data.papers.filter((p) => p.custodians.some((a) => sameAddr(a, me.address)));

    el.innerHTML = `
      ${pageHead("Key Custodians", "Each custodian holds one share of a paper's key. The smart contract only accepts shares after the exam start time, and only shares that match the commitment recorded when the paper was sealed.")}
      <div class="segmented" style="margin-bottom:16px" role="tablist">${data.custodians
        .map((c) => `<button type="button" role="tab" data-cust="${c.address}" class="${sameAddr(c.address, me.address) ? "active" : ""}">${UI.esc(c.name)}</button>`)
        .join("")}</div>
      <div class="card" style="margin-bottom:16px">
        <div class="kv"><span>Custodian</span><strong>${UI.esc(me.name)}</strong> ${me.active ? `<span class="chip chip-ok">Active</span>` : `<span class="chip chip-bad">Suspended</span>`}</div>
        <div class="kv"><span>Account</span><code>${UI.esc(me.address)}</code></div>
        <div class="kv"><span>Private vault</span><span>${Object.keys(vault).length} key share(s) held off-chain</span></div>
      </div>
      <div class="stack">${
        mine.length
          ? mine
              .map((p) => {
                const idx = p.custodians.findIndex((a) => sameAddr(a, me.address));
                const released = p.revealed[idx] && p.revealed[idx] !== "0x";
                const has = !!vault[p.id];
                const early = Chain.now() < p.releaseTime;
                const st = status(p);
                return `<div class="card">
                  <div class="card-head"><div><h2>${UI.esc(p.code)}</h2><div class="muted small">${UI.esc(p.title)}</div></div><span class="chip ${st.chip}">${st.label}</span></div>
                  <div class="kv"><span>Release time</span><span>${UI.fmtTime(p.releaseTime)} · ${countdown(p)}</span></div>
                  <div class="kv"><span>My share</span>${
                    released ? `<span class="chip chip-ok">Released on-chain</span>` : has ? `<span class="chip chip-accent">In my vault</span>` : `<span class="chip chip-bad">Not in this browser</span>`
                  }</div>
                  <div class="kv"><span>Commitment</span><code>${UI.esc(UI.short(p.commitments[idx], 10))}</code></div>
                  <div class="kv"><span>Progress</span><span>${p.sharesReleased} of ${p.threshold} shares needed</span></div>
                  ${
                    released || p.revoked
                      ? ""
                      : `<div class="row" style="margin-top:10px">
                          ${
                            has
                              ? `<button class="btn ${early ? "btn-secondary" : ""}" data-release="${p.id}">${Shell.icon("key")} ${early ? "Try to release now (before exam)" : "Release my key share"}</button>
                                 <button class="btn btn-ghost btn-sm" data-dl="${p.id}">Download share</button>`
                              : `<label class="btn btn-secondary">Import share file<input type="file" accept=".share,.txt" data-import="${p.id}" hidden></label>`
                          }
                          ${early ? `<span class="muted small">The smart contract will refuse until ${UI.fmtClock(p.releaseTime)}.</span>` : ""}
                        </div>`
                  }
                </div>`;
              })
              .join("")
          : `<div class="card empty">This custodian holds no shares yet.</div>`
      }</div>`;

    el.querySelectorAll("[data-cust]").forEach((b) =>
      b.addEventListener("click", () => {
        state.custodian = b.dataset.cust;
        Shell.render();
      })
    );
    el.querySelectorAll("[data-release]").forEach((b) =>
      b.addEventListener("click", () => action(b, () => releaseShare(me.address, data.papers[Number(b.dataset.release)])))
    );
    el.querySelectorAll("[data-dl]").forEach((b) =>
      b.addEventListener("click", () => {
        const p = data.papers[Number(b.dataset.dl)];
        UI.download(`${p.code}-${me.name.replace(/\W+/g, "_")}.share`, vault[p.id]);
      })
    );
    el.querySelectorAll("[data-import]").forEach((inp) =>
      inp.addEventListener("change", async () => {
        const text = (await UI.readFileText(inp.files[0])).trim();
        putShare(me.address, Number(inp.dataset.import), text);
        UI.toast("Share imported into this custodian's vault", "success");
        Shell.render();
      })
    );
  }

  async function viewCentre(el, { data, state, action }) {
    if (!data.centres.length) return (el.innerHTML = `<div class="empty">No exam centres registered.</div>`);
    state.centre = state.centre && data.centres.some((c) => sameAddr(c.address, state.centre)) ? state.centre : data.centres[0].address;
    const me = data.centres.find((c) => sameAddr(c.address, state.centre));
    const opened = state.opened && sameAddr(state.opened.centre, me.address) ? state.opened : null;

    el.innerHTML = `
      ${pageHead("Exam Centres", "When enough custodians have released their shares, a centre can rebuild the key, verify and decrypt the paper. Its copy is watermarked with a unique ID that is recorded on the blockchain.")}
      <div class="segmented" style="margin-bottom:16px" role="tablist">${data.centres
        .map((c) => `<button type="button" role="tab" data-centre="${c.address}" class="${sameAddr(c.address, me.address) ? "active" : ""}">${UI.esc(c.name.split(" - ")[0])}</button>`)
        .join("")}</div>
      <div class="grid-2" style="align-items:start">
        <div class="stack">
          <div class="card">
            <div class="kv"><span>Centre</span><strong>${UI.esc(me.name)}</strong> ${me.active ? `<span class="chip chip-ok">Active</span>` : `<span class="chip chip-bad">Suspended</span>`}</div>
            <div class="kv"><span>Account</span><code>${UI.esc(me.address)}</code></div>
          </div>
          ${
            data.papers.length
              ? data.papers
                  .map((p) => {
                    const st = status(p);
                    const mine = p.accesses.find((a) => sameAddr(a.centre, me.address));
                    const hasFile = !!ciphers()[p.cipherHash];
                    return `<div class="card">
                    <div class="card-head"><div><h2>${UI.esc(p.code)}</h2><div class="muted small">${UI.esc(p.title)}</div></div><span class="chip ${st.chip}">${st.label}</span></div>
                    <div class="kv"><span>Release time</span><span>${UI.fmtTime(p.releaseTime)} · ${countdown(p)}</span></div>
                    <div class="kv"><span>Key shares</span><span>${p.sharesReleased} / ${p.threshold}</span></div>
                    <div class="kv"><span>Encrypted file</span>${hasFile ? `<span class="chip chip-ok">Received</span>` : `<span class="chip chip-warn">Missing</span>`}</div>
                    <div class="row" style="margin-top:10px">
                      ${
                        p.revoked
                          ? `<span class="muted small">Revoked by the University - do not use.</span>`
                          : st.key === "unlocked"
                          ? `<button class="btn" data-open="${p.id}">${Shell.icon("school")} ${mine ? "View my copy" : "Unlock &amp; open paper"}</button>`
                          : `<button class="btn" disabled>Locked</button><span class="muted small">${st.key === "sealed" ? "Waiting for exam time" : "Waiting for custodians"}</span>`
                      }
                      ${hasFile ? "" : `<label class="btn btn-secondary btn-sm">Import .enc file<input type="file" accept=".enc" data-encimport="${p.id}" hidden></label>`}
                    </div>
                  </div>`;
                  })
                  .join("")
              : `<div class="card empty">No exam papers yet.</div>`
          }
        </div>
        <div class="card">
          <div class="card-head"><h2>${opened ? `Paper ${UI.esc(data.papers[opened.paperId]?.code || "")}` : "Opened paper"}</h2>
            ${opened && opened.copy ? `<div class="row"><button class="btn btn-secondary btn-sm" id="copy-btn">Copy text</button><button class="btn btn-secondary btn-sm" id="dl-btn">Download .txt</button></div>` : ""}</div>
          <div id="open-steps">${opened ? UI.checklist(opened.items) : `<p class="muted">Choose an unlocked paper to verify, decrypt and watermark it.</p>`}</div>
          ${
            opened && opened.copy
              ? `<div class="paper-view" style="margin-top:14px" data-wm="${UI.esc(me.name.split(" - ")[0])} · ${UI.esc(opened.wm.slice(2, 10))}"><pre>${UI.esc(opened.copy)}</pre></div>
                 <p class="muted small" style="margin-top:8px">This copy contains ${ExamCrypto.countInvisible(opened.copy)} invisible watermark characters. They survive copy-paste and forwarding.</p>`
              : ""
          }
        </div>
      </div>`;

    el.querySelectorAll("[data-centre]").forEach((b) =>
      b.addEventListener("click", () => {
        state.centre = b.dataset.centre;
        Shell.render();
      })
    );
    el.querySelectorAll("[data-open]").forEach((b) =>
      b.addEventListener("click", () => action(b, () => openPaper(me.address, data.papers[Number(b.dataset.open)])))
    );
    el.querySelectorAll("[data-encimport]").forEach((inp) =>
      inp.addEventListener("change", async () => {
        const p = data.papers[Number(inp.dataset.encimport)];
        const bytes = await UI.readFileBytes(inp.files[0]);
        if ((await UI.sha256(bytes)) !== p.cipherHash) return UI.toast("This file does not match the paper's on-chain ciphertext hash", "error", 6000);
        const all = ciphers();
        all[p.cipherHash] = UI.bytesToBase64(bytes);
        Chain.store.set("ciphers", all);
        UI.toast("Encrypted paper imported and verified against the blockchain", "success");
        Shell.render();
      })
    );
    const cb = el.querySelector("#copy-btn");
    if (cb) cb.addEventListener("click", () => UI.copy(opened.copy));
    const db = el.querySelector("#dl-btn");
    if (db) db.addEventListener("click", () => UI.download(`${data.papers[opened.paperId].code}-copy.txt`, opened.copy));
  }

  async function viewTrace(el, { data, state, action }) {
    const r = state.trace;
    let result = `<p class="muted">Paste a leaked question paper (for example, text forwarded on WhatsApp or Telegram) and trace it.</p>`;
    if (r) {
      if (r.hit) {
        const p = data.papers[r.hit.paperId];
        result = `
          <div class="callout callout-bad" style="margin-bottom:12px"><div class="small muted">Leak source identified</div>
            <div style="font-size:1.2rem;font-weight:700">${UI.esc(r.hit.centreName)}</div></div>
          <div class="kv"><span>Centre account</span><code>${UI.esc(r.hit.centre)}</code></div>
          <div class="kv"><span>Paper</span><span>${UI.esc(p ? `${p.code} · ${p.title}` : "#" + r.hit.paperId)}</span></div>
          <div class="kv"><span>Opened at</span><span>${UI.fmtTime(r.hit.time)} (block time)</span></div>
          <div class="kv"><span>Watermark ID</span><code>${UI.esc(r.id || "-")}</code></div>
          <h3 style="margin:14px 0 8px">Evidence</h3>
          ${UI.checklist([
            { title: "Invisible watermark", status: r.found.invisible ? "ok" : "bad", detail: r.found.invisible ? `found (${r.invisibleCount} hidden characters)` : "not found (removed or text retyped)" },
            { title: "Visible copy ID header", status: r.found.visible ? "ok" : "bad", detail: r.found.visible ? "present" : "removed by the leaker" },
            { title: "Watermark registered on the blockchain", status: "ok", detail: "traceWatermark() returned the centre and time" },
            { title: "Exact copy (unchanged)", status: r.exact ? "ok" : "bad", detail: r.exact ? "sha256 matches the copy hash recorded on-chain" : "the text was edited or shortened after leaving the centre" },
          ])}
          ${p && !p.revoked ? `<button class="btn btn-danger" id="revoke-btn" style="margin-top:14px">Revoke ${UI.esc(p.code)} as University</button>` : p && p.revoked ? `<p class="small muted" style="margin-top:12px">This paper is already revoked.</p>` : ""}`;
      } else {
        result = `<div class="callout callout-warn"><strong>No watermark found.</strong> ${
          r.id ? `The ID <code>${UI.esc(r.id)}</code> is not registered on this blockchain.` : "The text carries no copy ID. It may have been retyped by hand, or it is not from this system."
        }</div>`;
      }
    }

    const canSimulate = data.papers.some((p) => p.accesses.length);
    el.innerHTML = `
      ${pageHead("Leak Tracer", "Find which exam centre leaked a paper. The tracer reads the invisible watermark and looks it up in the smart contract.")}
      <div class="grid-2" style="align-items:start">
        <form class="card" id="trace-form">
          <div class="card-head"><h2>Leaked text</h2>
            <button type="button" class="btn btn-ghost btn-sm" id="sim-btn" ${canSimulate ? "" : "disabled title='Open a paper at a centre first'"}>Simulate a leak</button></div>
          <div class="field"><textarea name="text" id="leak-text" rows="14" placeholder="Paste the leaked paper here…">${UI.esc(state.traceText || "")}</textarea></div>
          <div class="row"><button class="btn" type="submit" id="trace-btn">${Shell.icon("search")} Trace leak</button>
            <label class="btn btn-secondary">Upload .txt<input type="file" accept=".txt,text/plain" id="leak-file" hidden></label></div>
          ${canSimulate ? "" : `<p class="muted small" style="margin-top:10px">Tip: open a paper at an exam centre first, then simulate a leak.</p>`}
        </form>
        <div class="card"><div class="card-head"><h2>Result</h2></div>${result}</div>
      </div>`;

    const form = el.querySelector("#trace-form");
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const text = form.text.value;
      if (!text.trim()) return UI.toast("Paste the leaked text first", "error");
      state.traceText = text;
      action(el.querySelector("#trace-btn"), async () => {
        state.trace = await trace(text, data);
      });
    });
    el.querySelector("#leak-file").addEventListener("change", async (e) => {
      form.text.value = await UI.readFileText(e.target.files[0]);
    });
    el.querySelector("#sim-btn").addEventListener("click", (e) =>
      action(e.currentTarget, async () => {
        const all = data.papers.flatMap((p) => p.accesses.map((a) => ({ p, a })));
        const { p, a } = all[Math.floor(Math.random() * all.length)];
        let copy = Chain.store.get("copies", {})[a.watermarkId];
        if (!copy) copy = await buildCopy(p, a.centre, a.watermarkId, await decryptPaper(p));
        // The "leaker" removes the visible header and forwards only part of the paper.
        const lines = copy.split("\n").slice(4);
        const leaked = lines.slice(Math.max(0, lines.findIndex((l) => l.startsWith("MODULE")))).slice(0, 9).join("\n");
        state.traceText = `Fwd: paper for tomorrow 👀\n\n${leaked}`;
        state.trace = await trace(state.traceText, data);
        UI.toast("Simulated leak: visible header removed, only part of the paper forwarded", "info", 5000);
      })
    );
    const rb = el.querySelector("#revoke-btn");
    if (rb)
      rb.addEventListener("click", () =>
        action(rb, async () => {
          await Chain.send(univ(), "revokePaper", [r.hit.paperId, `Leak traced to ${r.hit.centreName}`]);
          UI.toast("Paper revoked. Custodians can no longer release it.", "success");
        })
      );
  }

  function formatEvent(e) {
    const a = e.args;
    switch (e.name) {
      case "MemberRegistered":
        return `${a.name} joined as ${Number(a.role) === ROLE.Custodian ? "key custodian" : "exam centre"}`;
      case "MemberStatusChanged":
        return `${Chain.label(a.account)} ${a.active ? "activated" : "suspended"}`;
      case "PaperCreated":
        return `${a.code} sealed · opens ${UI.fmtTime(a.releaseTime)} · ${a.threshold} shares needed · paper hash ${UI.short(a.paperHash, 4)}`;
      case "ShareReleased":
        return `${Chain.label(a.custodian)} released a key share for paper #${a.paperId} (${a.sharesReleased} released)`;
      case "PaperUnlocked":
        return `Paper #${a.paperId} unlocked - threshold reached`;
      case "PaperAccessed":
        return `${Chain.label(a.centre)} opened paper #${a.paperId} · watermark ${a.watermarkId}`;
      case "PaperRevoked":
        return `Paper #${a.paperId} revoked: ${a.reason}`;
      default:
        return "";
    }
  }

  async function viewExplorer(el) {
    el.innerHTML = `${pageHead("Blockchain Explorer", "Every action above is a transaction in a block. Each block stores the hash of the previous one, so changing any old record would break the chain.")}<div id="explorer-host"></div>`;
    await Explorer.render(el.querySelector("#explorer-host"), { formatEvent });
  }

  async function viewAbout(el) {
    el.innerHTML = `
      ${pageHead("About the project", "Leak-Proof Exam Paper Distribution System using blockchain, threshold cryptography and watermarking.")}
      <div class="stack">
        <div class="card">
          <h2>Problem</h2>
          <p style="margin-top:8px">Question papers are leaked before exams. Today a single person or office holds the paper, nothing technically stops early access, and when a copy leaks nobody can prove which centre it came from.</p>
          <h2 style="margin-top:14px">Solution</h2>
          <ul style="margin:8px 0 0;padding-left:18px">
            <li><strong>No early access:</strong> the paper is encrypted; the key is split so that <em>no single person</em> can decrypt it.</li>
            <li><strong>Enforced timing:</strong> a smart contract only accepts key shares after the exam start time.</li>
            <li><strong>Tamper evidence:</strong> SHA-256 hashes of the paper, the ciphertext and every share are fixed on-chain.</li>
            <li><strong>Accountability:</strong> every centre's copy carries a unique watermark recorded on the blockchain, so leaks are traceable.</li>
          </ul>
        </div>
        <div class="card">
          <h2>Syllabus mapping (22CS743)</h2>
          <div class="table-wrap" style="margin-top:8px"><table class="table"><thead><tr><th>Module</th><th>Concept</th><th>Where it is used</th></tr></thead><tbody>
            <tr><td data-label="Module">II</td><td data-label="Concept">Hash functions, hash commitments, hash-linked blocks</td><td data-label="Used in">SHA-256 of paper &amp; ciphertext, keccak256 share commitments, block explorer shows each block's previous-hash link</td></tr>
            <tr><td data-label="Module">III</td><td data-label="Concept">Ethereum, EVM, smart contracts, symmetric &amp; asymmetric crypto</td><td data-label="Used in"><code>ExamPaperVault.sol</code> enforces the time-lock and threshold; AES-256-GCM encryption; every transaction is signed with an account key</td></tr>
            <tr><td data-label="Module">IV</td><td data-label="Concept">Consortium / permissioned blockchain</td><td data-label="Used in">University, custodians and exam centres are registered members with roles; only the University can add or suspend members</td></tr>
            <tr><td data-label="Module">V</td><td data-label="Concept">Blockchain security, access control, privacy, applications</td><td data-label="Used in">Role-based access, nothing secret on-chain before release, audit log, leak tracing and revocation</td></tr>
          </tbody></table></div>
        </div>
        <div class="grid-2">
          <div class="card">
            <h2>On-chain vs off-chain</h2>
            <p class="muted small" style="margin-top:6px">Blockchains are public, so secrets never go on-chain early.</p>
            <ul style="margin:6px 0 0;padding-left:18px">
              <li><strong>On-chain:</strong> members, paper hashes, ciphertext hash, share commitments, release time, released shares (after exam start), access records, watermark IDs.</li>
              <li><strong>Off-chain:</strong> the encrypted paper file (.enc) and each custodian's private share.</li>
            </ul>
          </div>
          <div class="card">
            <h2>Technology</h2>
            <ul style="margin:6px 0 0;padding-left:18px">
              <li>Solidity 0.8.24 smart contract, Hardhat (local blockchain + tests)</li>
              <li>In-browser Ethereum chain (Ganache) for zero-install demos</li>
              <li>ethers.js v6, Web Crypto API (SHA-256, AES-256-GCM)</li>
              <li>Shamir's Secret Sharing over GF(256), zero-width text watermarking</li>
              <li>HTML, CSS and JavaScript (no build step), hosted on GitHub Pages</li>
            </ul>
          </div>
        </div>
        <div class="card callout-warn">
          <h2>Limitations</h2>
          <ul style="margin:6px 0 0;padding-left:18px">
            <li>After the exam starts the released shares are public, which is acceptable because the exam has begun.</li>
            <li>Zero-width watermarks can be defeated by retyping the paper by hand; the visible copy ID and exact-hash check help in that case. A production system would add image watermarks for printed copies.</li>
            <li>The demo keeps custodians' shares in browser storage; real custodians would use hardware tokens or wallets.</li>
          </ul>
        </div>
      </div>`;
  }

  // ------------------------------------------------------------------
  Shell.start({
    brand: { name: "ExamShield", tagline: "Leak-proof exam paper distribution on blockchain", icon: "shield" },
    timeTravel: true,
    load,
    chain: {
      storageKey: "examshield",
      artifact: window.CONTRACT_ARTIFACT,
      errors: ERRORS,
      async isSeeded(chain) {
        const [accts] = await chain.contract.getMembers();
        return accts.length > 0;
      },
      async seed(chain) {
        for (const [i, role, name] of CONSORTIUM) await chain.send(chain.accounts[0], "registerMember", [chain.accounts[i], role, name]);
      },
    },
    routes: [
      { id: "home", title: "Overview", icon: "home", render: viewHome },
      { id: "university", title: "University", icon: "building", section: "Roles", render: viewUniversity },
      { id: "custodian", title: "Key Custodians", icon: "key", section: "Roles", render: viewCustodian },
      { id: "centre", title: "Exam Centres", icon: "school", section: "Roles", render: viewCentre },
      { id: "trace", title: "Leak Tracer", icon: "search", section: "Investigate", render: viewTrace },
      { id: "explorer", title: "Blockchain Explorer", icon: "blocks", section: "Investigate", render: viewExplorer },
      { id: "about", title: "About & Syllabus", icon: "book", section: "Project", render: viewAbout },
    ],
  });

  // Exposed for automated tests.
  window.ExamApp = { createPaper, releaseShare, openPaper, trace, load, SAMPLE_PAPER };
})();
