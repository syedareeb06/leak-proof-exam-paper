/* Cryptography used by the exam paper system (all done in the browser with Web Crypto):
 *  - AES-256-GCM encryption of the paper
 *  - Shamir's Secret Sharing (k-of-n) to split the AES key between custodians
 *  - Invisible (zero-width) + visible watermark that identifies each centre's copy
 */
(function () {
  // ---------------- AES-256-GCM ----------------
  async function aesEncrypt(plaintext) {
    const key = UI.randomBytes(32);
    const iv = UI.randomBytes(12);
    const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, UI.toBytes(plaintext)));
    const blob = new Uint8Array(iv.length + ct.length);
    blob.set(iv, 0);
    blob.set(ct, iv.length);
    return { key, blob };
  }

  async function aesDecrypt(key, blob) {
    const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: blob.slice(0, 12) }, cryptoKey, blob.slice(12));
    return UI.utf8.decode(pt);
  }

  // ---------------- Shamir's Secret Sharing over GF(256) ----------------
  // Each byte of the secret is the constant term of a random polynomial of
  // degree (threshold - 1). Share i is the polynomial evaluated at x = i.
  // Any `threshold` shares rebuild the secret with Lagrange interpolation;
  // fewer shares reveal nothing about it.
  const EXP = new Uint8Array(512);
  const LOG = new Uint8Array(256);
  (function buildTables() {
    let x = 1;
    for (let i = 0; i < 255; i++) {
      EXP[i] = x;
      LOG[x] = i;
      const xtime = ((x << 1) ^ (x & 0x80 ? 0x1b : 0)) & 0xff; // multiply by 2 in AES field
      x = xtime ^ x; // multiply by generator 3
    }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  })();
  const gfMul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);
  const gfDiv = (a, b) => {
    if (b === 0) throw new Error("division by zero");
    return a === 0 ? 0 : EXP[(LOG[a] + 255 - LOG[b]) % 255];
  };

  /** @returns Uint8Array[] shares, each = [x, y_0 … y_{len-1}] */
  function split(secret, n, threshold) {
    if (threshold < 2 || threshold > n || n > 255) throw new Error("invalid threshold");
    const shares = Array.from({ length: n }, (_, i) => {
      const s = new Uint8Array(secret.length + 1);
      s[0] = i + 1;
      return s;
    });
    for (let b = 0; b < secret.length; b++) {
      const coeffs = new Uint8Array(threshold);
      coeffs[0] = secret[b];
      coeffs.set(UI.randomBytes(threshold - 1), 1);
      for (let i = 0; i < n; i++) {
        const x = i + 1;
        let y = 0;
        for (let c = threshold - 1; c >= 0; c--) y = gfMul(y, x) ^ coeffs[c]; // Horner's rule
        shares[i][b + 1] = y;
      }
    }
    return shares;
  }

  function combine(shares) {
    const len = shares[0].length - 1;
    const xs = shares.map((s) => s[0]);
    if (new Set(xs).size !== xs.length) throw new Error("duplicate shares");
    const secret = new Uint8Array(len);
    for (let b = 0; b < len; b++) {
      let acc = 0;
      for (let i = 0; i < shares.length; i++) {
        let li = 1; // Lagrange basis polynomial at x = 0
        for (let j = 0; j < shares.length; j++) {
          if (i !== j) li = gfMul(li, gfDiv(xs[j], xs[j] ^ xs[i]));
        }
        acc ^= gfMul(shares[i][b + 1], li);
      }
      secret[b] = acc;
    }
    return secret;
  }

  // ---------------- Watermark ----------------
  // The 64-bit copy ID is written as zero-width characters (invisible when
  // displayed, but kept when the text is copied or forwarded) and repeated
  // through the paper, so even a partial leak can be traced.
  const ZERO = "​";
  const ONE = "‌";
  const MARK = "⁠";

  function encodeId(idHex) {
    const bytes = UI.hexToBytes(idHex);
    let bits = "";
    for (const b of bytes) for (let i = 7; i >= 0; i--) bits += (b >> i) & 1 ? ONE : ZERO;
    return MARK + bits + MARK;
  }

  function embedWatermark(text, idHex, visibleHeader) {
    const token = encodeId(idHex);
    const lines = text.split("\n");
    let count = 0;
    const marked = lines.map((line, i) => {
      if (line.trim() && (count++ % 3 === 0 || i === lines.length - 1)) return line + token;
      return line;
    });
    return visibleHeader + "\n" + marked.join("\n");
  }

  /** @returns {{invisible: string|null, visible: string|null}} 16-hex-char copy IDs found */
  function extractWatermark(text) {
    const votes = {};
    const re = new RegExp(`${MARK}([${ZERO}${ONE}]{64})${MARK}`, "g");
    let m;
    while ((m = re.exec(text))) {
      let hex = "";
      for (let i = 0; i < 64; i += 4) {
        let nibble = 0;
        for (let j = 0; j < 4; j++) nibble = (nibble << 1) | (m[1][i + j] === ONE ? 1 : 0);
        hex += nibble.toString(16);
      }
      votes[hex] = (votes[hex] || 0) + 1;
    }
    const best = Object.entries(votes).sort((a, b) => b[1] - a[1])[0];
    const visibleMatch = text.match(/Copy ID:\s*([0-9a-fA-F]{16})/);
    return {
      invisible: best ? "0x" + best[0] : null,
      visible: visibleMatch ? "0x" + visibleMatch[1].toLowerCase() : null,
    };
  }

  const countInvisible = (text) => (text.match(new RegExp(`[${ZERO}${ONE}${MARK}]`, "g")) || []).length;

  window.ExamCrypto = { aesEncrypt, aesDecrypt, split, combine, embedWatermark, extractWatermark, countInvisible };
})();
