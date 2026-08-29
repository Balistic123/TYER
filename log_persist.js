/**
 * Debounced sessionStorage log — survives tab reload / most WebKit OOM crashes.
 * Flush on critical tags, timer, pagehide, and beforeunload.
 */
export function createCrashLog(opts) {
    const ssLog = opts.ssLog || "wk-log";
    const ssState = opts.ssState || "wk-log-state";
    const ssBuild = opts.ssBuild || "wk-log-build";
    const buildId = opts.buildId || "?";
    const maxLines = opts.maxLines != null ? opts.maxLines : 200;
    const flushMs = opts.flushMs != null ? opts.flushMs : 280;
    const criticalRe = opts.critical
        || /^(FAIL|ERROR|OOM|GIVE-UP|PRIMITIVE|NATIVE|LK-|PASS|WARN|BOOT|LOG-CLEAR|ATTEMPT|READ-PRIMITIVE|TRIM|HINT)/;

    let buf = null;
    let dirty = false;
    let timer = null;
    let intervalId = null;
    let hooked = false;

    function loadBuf() {
        if (buf) return buf;
        try {
            buf = (sessionStorage.getItem(ssLog) || "").split("\n").filter(Boolean);
        } catch (_) {
            buf = [];
        }
        while (buf.length > maxLines) buf.shift();
        return buf;
    }

    function flushSync() {
        if (!dirty || !buf) return;
        try {
            sessionStorage.setItem(ssLog, buf.join("\n"));
            sessionStorage.setItem(ssBuild, buildId);
            dirty = false;
        } catch (_) { }
    }

    function scheduleFlush(immediate) {
        dirty = true;
        if (immediate) {
            if (timer) {
                clearTimeout(timer);
                timer = null;
            }
            flushSync();
            return;
        }
        if (timer) return;
        timer = setTimeout(function () {
            timer = null;
            flushSync();
        }, flushMs);
    }

    function append(line, tag) {
        if (!line) return;
        const b = loadBuf();
        b.push(line);
        while (b.length > maxLines) b.shift();
        const t = tag || String(line.split(/\s/)[0] || "");
        scheduleFlush(criticalRe.test(t));
    }

    function appendMany(arr) {
        if (!arr || !arr.length) return;
        const b = loadBuf();
        for (let i = 0; i < arr.length; i++) {
            if (arr[i]) b.push(arr[i]);
        }
        while (b.length > maxLines) b.shift();
        scheduleFlush(true);
    }

    function persistState(msg, cls, force) {
        if (!force && !msg) return;
        try {
            sessionStorage.setItem(ssState, JSON.stringify({
                msg: msg || "",
                cls: cls || "",
                build: buildId,
                t: Date.now(),
            }));
        } catch (_) { }
    }

    function readState() {
        try {
            const raw = sessionStorage.getItem(ssState);
            return raw ? JSON.parse(raw) : null;
        } catch (_) {
            return null;
        }
    }

    function clear() {
        buf = null;
        dirty = false;
        if (timer) {
            clearTimeout(timer);
            timer = null;
        }
        try {
            sessionStorage.removeItem(ssLog);
            sessionStorage.removeItem(ssState);
            sessionStorage.removeItem(ssBuild);
        } catch (_) { }
    }

    /** Push restored lines into target array; returns true if anything restored. */
    function restoreInto(targetLines) {
        let prev = "";
        let build = "?";
        try {
            prev = sessionStorage.getItem(ssLog) || "";
            build = sessionStorage.getItem(ssBuild) || "?";
        } catch (_) {
            return false;
        }
        if (!prev) return false;
        targetLines.push("=== RESTORED (prev build=" + build + ") ===");
        const parts = prev.split("\n");
        for (let i = 0; i < parts.length; i++) {
            if (parts[i]) targetLines.push(parts[i]);
        }
        targetLines.push("=== RELOAD build=" + buildId + " ===");
        const st = readState();
        if (st && st.msg)
            targetLines.push("LAST-STATE  " + st.msg);
        loadBuf();
        return true;
    }

    function sessionMarker(label) {
        append("=== " + label + " build=" + buildId + " ===", "SESSION");
    }

    function startAutoFlush() {
        if (hooked) return;
        hooked = true;
        const onHide = function () { flushSync(); };
        window.addEventListener("beforeunload", onHide);
        window.addEventListener("pagehide", onHide);
        document.addEventListener("visibilitychange", function () {
            if (document.visibilityState === "hidden") flushSync();
        });
        intervalId = setInterval(flushSync, 2000);
    }

    return {
        append,
        appendMany,
        flushSync,
        persistState,
        readState,
        clear,
        restoreInto,
        sessionMarker,
        startAutoFlush,
    };
}
