export const GROOM_PRESETS = {
    default: { label: "default", g: [] },
    lite: {
        label: "lite",
        g: ["drain:256", "drainsz:32768", "slab:2097152"],
    },
    "384": {
        label: "384",
        g: ["drain:384", "drainsz:32768", "slab:2097152"],
    },
    "512": {
        label: "512",
        g: ["drain:512", "drainsz:32768", "slab:2097152"],
    },
    max: {
        label: "max",
        g: [
            "drain:512", "drainsz:65536", "slab:4194304",
            "bfly:528384", "early:458752", "guard:589824",
            "pred:524288", "final:524288",
        ],
    },
};

export function currentGroomKey(params) {
    const gs = params.getAll("g");
    if (gs.length === 0) return "default";
    for (const key of Object.keys(GROOM_PRESETS)) {
        if (key === "default") continue;
        const preset = GROOM_PRESETS[key];
        if (preset.g.length !== gs.length) continue;
        let match = true;
        for (let i = 0; i < preset.g.length; i++) {
            if (gs[i] !== preset.g[i]) {
                match = false;
                break;
            }
        }
        if (match) return key;
    }
    return "custom";
}

export function groomBootLine(params) {
    const key = currentGroomKey(params);
    const gs = params.getAll("g");
    if (key === "custom") return "groom=custom (" + gs.join(", ") + ")";
    if (key === "default") return "groom=default (core 384 drain)";
    return "groom=" + key;
}

export function reloadWithGroomPreset(key) {
    const preset = GROOM_PRESETS[key];
    if (!preset) return;
    const url = new URL(location.href);
    url.searchParams.delete("g");
    url.searchParams.delete("slots");
    for (const item of preset.g)
        url.searchParams.append("g", item);
    location.href = url.toString();
}

export function highlightGroomButtons(params) {
    const key = currentGroomKey(params);
    document.querySelectorAll("[data-groom]").forEach(el => {
        el.classList.toggle("active", el.getAttribute("data-groom") === key);
    });
}

export function wireGroomBar(isBusy) {
    highlightGroomButtons(new URLSearchParams(location.search));
    document.querySelectorAll("[data-groom]").forEach(el => {
        el.addEventListener("click", () => {
            if (isBusy && isBusy()) return;
            const key = el.getAttribute("data-groom");
            if (key) reloadWithGroomPreset(key);
        });
    });
}
