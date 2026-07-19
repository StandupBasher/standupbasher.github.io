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
