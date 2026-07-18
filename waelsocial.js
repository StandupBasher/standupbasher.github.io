const API_BASE = "https://api.wael.sh";

// The one true signing key. The ✓ attests authorship by THIS key specifically —
// never whatever key the response happens to carry. If a served feed presents a
// different pubkey (origin / DNS / CDN compromise), nothing is shown as verified.
const PINNED_PUBKEY = "/XKGM2r0/oyl47HkuhDK8JiH5pUJvPlRi8btV03S/mE=";

function canonicalize(entry) {
    const sourceUrl = entry.source?.url ?? "";
    const mediaHash = entry.media?.sha256 ?? "";
    return [
        "waelsocial-v1",
        `id:${entry.id}`,
        `ts:${entry.ts}`,
        `type:${entry.type}`,
        `source:${sourceUrl}`,
        `media:${mediaHash}`,
        `text:${entry.text}`,
    ].join("\n");
}

async function verifyEntry(entry, pubKey) {
    if (entry.type === "relay" || !entry.sig) return null;
    const msg = new TextEncoder().encode(canonicalize(entry));
    const sig = Uint8Array.from(atob(entry.sig), (c) => c.charCodeAt(0));
    try { return await crypto.subtle.verify({ name: "Ed25519" }, pubKey, sig, msg); }
    catch { return false; }
}

function elt(tag, className, text) {
    const n = document.createElement(tag);
    n.className = className;
    n.textContent = text;
    return n;
}

const KNOWN_TYPES = ["mine", "take", "relay"];
let renderSeq = 0;

async function renderFeed(feed, filter, host) {
    let pubKey = null;
    try {
        pubKey = await crypto.subtle.importKey(
            "raw", Uint8Array.from(atob(PINNED_PUBKEY), (c) => c.charCodeAt(0)),
            { name: "Ed25519" }, false, ["verify"]);
    } catch {
        console.warn("[waelsocial] This browser can't verify Ed25519 — entries shown unverified");
    }

    const inFilter = (e) =>
        filter === "mine" ? (e.type === "mine" || e.type === "take") :
            filter === "signal" ? (e.type === "take" || e.type === "relay") : true;

    const token = ++renderSeq;
    host.replaceChildren();
    const shown = feed.entries.filter(inFilter);
    if (shown.length === 0) { host.replaceChildren(elt("p", "ws-empty", "Nothing here yet.")); return; }

    for (const e of shown) {
        if (token !== renderSeq) return;   // a newer render (filter click) took over

        // Feed data is untrusted (relay titles come from external feeds):
        // everything is built via DOM APIs — no innerHTML anywhere in this loop.
        const el = elt("article", "ws-post", "");
        const meta = elt("div", "ws-meta", "");
        const type = KNOWN_TYPES.includes(e.type) ? e.type : "relay";
        const badge = elt("span", "ws-badge checking", "· checking…");
        meta.append(elt("span", `ws-kind ${type}`, type),
            elt("span", "ws-date", String(e.ts ?? "").slice(0, 10)),
            badge);
        el.append(meta, elt("div", "ws-body", e.text));

        if (typeof e.source?.url === "string" && /^https:\/\//i.test(e.source.url)) {
            const a = elt("a", "ws-src", `↗ ${e.source.title ?? e.source.url}`);
            a.href = e.source.url;
            a.target = "_blank";
            a.rel = "noopener";
            el.append(a);
        }
        host.appendChild(el);

        const ok = pubKey ? await verifyEntry(e, pubKey)
            : (e.type === "relay" || !e.sig) ? null : undefined;
        if (ok === null) { badge.className = "ws-badge relay"; badge.textContent = "auto · sourced"; }
        else if (ok === undefined) { badge.className = "ws-badge unknown"; badge.textContent = "unverified · browser lacks Ed25519"; }
        else if (ok) { badge.className = "ws-badge ok"; badge.textContent = "✓ verified"; }
        else { badge.className = "ws-badge bad"; badge.textContent = "✗ signature failed"; }
    }
}

async function loadFeed() {
    // No fallback: if the API is down the caller shows the honest error state.
    const r = await fetch(`${API_BASE}/api/feed`, { cache: "no-store" });
    if (!r.ok) throw new Error(`feed HTTP ${r.status}`);
    return await r.json();
}

async function initWaelSocial() {
    const host = document.getElementById("ws-feed");
    if (!host) return;
    let feed;
    try {
        feed = await loadFeed();
        if (feed?.v !== 1 || typeof feed.pubkey !== "string" || !Array.isArray(feed.entries)) {
            throw new Error("unexpected feed shape");
        }
    } catch (err) {
        console.warn("[waelsocial] feed unusable:", err);
        host.replaceChildren(elt("p", "ws-error", "Feed unavailable right now — check back soon."));
        return;
    }
    if (feed.pubkey !== PINNED_PUBKEY) {
        console.error("[waelsocial] feed pubkey does not match the pinned key — refusing to verify");
        host.replaceChildren(elt("p", "ws-error",
            "This feed was not signed by wael.sh's key — refusing to display it as verified."));
        return;
    }
    let filter = "mine";  // default view is my authored work, not the CVE ticker
    await renderFeed(feed, filter, host);
    document.querySelectorAll("[data-ws-filter]").forEach((b) =>
        b.addEventListener("click", () => {
            document.querySelectorAll("[data-ws-filter]").forEach((x) => x.classList.remove("on"));
            b.classList.add("on");
            filter = b.dataset.wsFilter;
            renderFeed(feed, filter, host);
        }));
}

document.addEventListener("DOMContentLoaded", initWaelSocial);
