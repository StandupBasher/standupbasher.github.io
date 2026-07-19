/* waelsocial console — keyboard nav, bulk select, filters.
   Signature verification is server-side (plain-http console has no secure
   context for crypto.subtle). External data only ever lands via textContent. */

"use strict";

// ── queue: selection, bulk dismiss, filter, expand, keyboard ────────
(function queueTools() {
  const bulkBar = document.getElementById("bulkBar");
  if (!bulkBar) return;

  const cards = () => [...document.querySelectorAll(".cand")].filter((c) => !c.hidden);
  const selected = () => [...document.querySelectorAll(".sel:checked")];

  function syncBulk() {
    const n = selected().length;
    bulkBar.hidden = n === 0;
    document.getElementById("bulkCount").textContent = `${n} selected`;
    document.querySelectorAll(".cand").forEach((c) =>
      c.classList.toggle("selected", c.querySelector(".sel").checked));
  }

  document.querySelectorAll(".sel").forEach((cb) => cb.addEventListener("change", syncBulk));

  document.querySelectorAll(".select-group").forEach((btn) =>
    btn.addEventListener("click", () => {
      const boxes = [...btn.closest(".group").querySelectorAll(".cand:not([hidden]) .sel")];
      const all = boxes.every((b) => b.checked);
      boxes.forEach((b) => { b.checked = !all; });
      syncBulk();
    }));

  document.getElementById("bulkClear").addEventListener("click", () => {
    selected().forEach((b) => { b.checked = false; });
    syncBulk();
  });

  bulkBar.addEventListener("submit", (ev) => {
    const sel = selected();
    if (!sel.length || !confirm(`Dismiss ${sel.length} candidate(s)?`)) {
      ev.preventDefault();
      return;
    }
    sel.forEach((b) => {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = "cve";
      input.value = b.value;
      bulkBar.appendChild(input);
    });
  });

  const filter = document.getElementById("queueFilter");
  filter.addEventListener("input", () => {
    const q = filter.value.trim().toLowerCase();
    document.querySelectorAll(".cand").forEach((c) => {
      c.hidden = q && !c.textContent.toLowerCase().includes(q);
    });
    document.querySelectorAll(".group").forEach((g) => {
      g.hidden = ![...g.querySelectorAll(".cand")].some((c) => !c.hidden);
    });
  });

  document.querySelectorAll(".cand-sum:not(.full)").forEach((p) =>
    p.addEventListener("click", () => p.classList.toggle("expanded")));

  // keyboard: j/k move, x select, d dismiss, t take
  let cur = -1;
  function focusCard(i) {
    const list = cards();
    if (!list.length) return;
    cur = Math.max(0, Math.min(i, list.length - 1));
    list[cur].focus();
    list[cur].scrollIntoView({ block: "nearest" });
  }
  window.addEventListener("keydown", (ev) => {
    if (ev.target.matches("input, textarea") || ev.metaKey || ev.ctrlKey || ev.altKey) return;
    if (ev.key === "j") focusCard(cur + 1);
    else if (ev.key === "k") focusCard(cur - 1);
    else if (ev.key === "x" && cur >= 0) {
      const cb = cards()[cur].querySelector(".sel");
      cb.checked = !cb.checked;
      syncBulk();
    } else if (ev.key === "d" && cur >= 0) {
      const card = cards()[cur];
      if (confirm(`Dismiss ${card.dataset.cve}?`)) {
        card.querySelector(".other form[action$='dismiss'] button, form[action$='dismiss'] button").click();
      }
    } else if (ev.key === "t" && cur >= 0) {
      cards()[cur].querySelector("a.btn.primary").click();
    }
  });
})();

// ── compose: live signed preview via sign-post --dry-run ────────────
(function composePreview() {
  const form = document.querySelector("form[data-preview]");
  const pane = document.getElementById("previewPane");
  if (!form || !pane) return;

  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  };

  function render(d) {
    pane.replaceChildren();
    pane.hidden = false;
    if (!d.ok) {
      pane.append(el("p", "preview-label", "preview"), el("div", "preview-err", d.error));
      return;
    }
    const e = d.entry;
    pane.append(el("p", "preview-label", "preview — nothing written yet"));
    const card = el("article", "post");
    const head = el("div", "post-head");
    head.append(el("span", "chip type " + e.type, e.type),
                el("span", "post-id", e.id),
                el("span", "post-date", e.ts),
                el("span", "badge " + (d.verified ? "ok" : "bad"),
                   d.verified ? "✓ will publish verified" : "✗ signature check failed"));
    card.append(head, el("p", "post-text", e.text));
    if (e.tags && e.tags.length) {
      const tw = el("div", "post-tags");
      e.tags.forEach((t) => tw.append(el("span", "", t)));
      card.append(tw);
    }
    if (e.source_url) card.append(el("p", "preview-src", "source: " + e.source_url));
    pane.append(card);
    const det = el("details", "canon");
    det.append(el("summary", "", "canonical string (exactly what gets signed)"),
               el("pre", "", d.canonical));
    pane.append(det);
  }

  let timer = null;
  let seq = 0;
  async function refresh() {
    const my = ++seq;
    const body = new URLSearchParams(new FormData(form));
    body.set("kind", form.dataset.preview);
    if (!body.get("text").trim()) {
      pane.hidden = true;
      return;
    }
    try {
      const r = await fetch("/preview", { method: "POST", body });
      const d = await r.json();
      if (my === seq) render(d);
    } catch (err) {
      if (my === seq) render({ ok: false, error: "preview failed: " + err.message });
    }
  }

  form.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(refresh, 700);
  });
})();

// ── published: archive-then-delete, confirmed by typing the id ──────
(function removeConfirm() {
  document.querySelectorAll(".remove-form").forEach((form) =>
    form.addEventListener("submit", (ev) => {
      const id = form.querySelector("input[name=id]").value;
      const typed = prompt(
        `Remove ${id} from the public feed?\n` +
        `The row is archived to entries_removed first (append-only), ` +
        `but it disappears from wael.sh.\n\nType the id to confirm:`);
      if (typed !== id) {
        ev.preventDefault();
        if (typed !== null) alert(`"${typed}" does not match ${id} — not removed.`);
      }
    }));
})();

// ── g-prefix view switching (all pages) ─────────────────────────────
(function viewKeys() {
  let goPrefix = false;
  const routes = { q: "/queue", p: "/published", c: "/compose" };
  window.addEventListener("keydown", (ev) => {
    if (ev.target.matches("input, textarea") || ev.metaKey || ev.ctrlKey || ev.altKey) return;
    if (goPrefix && routes[ev.key]) {
      location.href = routes[ev.key];
      goPrefix = false;
    } else {
      goPrefix = ev.key === "g";
    }
  });
})();
