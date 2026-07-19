const PAGES = ["home", "work", "feed", "writing", "about", "contact"];
const LEGACY = { "#feed": "feed", "#about": "about", "#projects": "work", "#contact": "contact" };

function currentPage() {
  const raw = location.hash;
  if (LEGACY[raw]) return LEGACY[raw];
  const name = raw.replace(/^#\/?/, "");
  return PAGES.includes(name) ? name : "home";
}

function showPage(page) {
  document.querySelectorAll("[data-page]").forEach((s) => {
    s.hidden = s.dataset.page !== page;
  });
  document.querySelectorAll("[data-nav]").forEach((a) => {
    a.classList.toggle("on", a.dataset.nav === page);
  });
}

function go(page) {
  closePalette();
  try { history.replaceState(null, "", page === "home" ? "#/" : "#/" + page); } catch (e) { }
  showPage(page);
  window.scrollTo({ top: 0 });
}

window.addEventListener("hashchange", () => { showPage(currentPage()); window.scrollTo({ top: 0 }); });
showPage(currentPage());

const yearEl = document.getElementById("year");
if (yearEl) yearEl.textContent = new Date().getFullYear();

const domains = ["wael.sh", "wael.systems", "shahadeh.dev", "waelshahadeh.com"];
const brandEl = document.getElementById("brandText");

let brandLast = -1;
let brandTarget = "";
let brandLen = 0;
let brandMode = "typing";

function renderBrand(n) {
  const partial = brandTarget.slice(0, n);
  const dot = partial.indexOf(".");
  brandEl.replaceChildren();
  if (dot >= 0) {
    brandEl.append(partial.slice(0, dot));
    const ext = document.createElement("span");
    ext.className = "accent";
    ext.textContent = partial.slice(dot);
    brandEl.append(ext);
  } else {
    brandEl.append(partial);
  }
}

function brandTick() {
  if (!brandTarget) {
    let i;
    do { i = Math.floor(Math.random() * domains.length); } while (i === brandLast);
    brandLast = i; brandTarget = domains[i]; brandLen = 0; brandMode = "typing";
  }
  if (brandMode === "typing") {
    brandLen++; renderBrand(brandLen);
    if (brandLen >= brandTarget.length) {
      setTimeout(() => { brandMode = "erasing"; brandTick(); }, 6000);
      return;
    }
    setTimeout(brandTick, 80);
    return;
  }
  brandLen = Math.max(0, brandLen - 1); renderBrand(brandLen);
  if (brandLen === 0) { brandTarget = ""; setTimeout(brandTick, 450); return; }
  setTimeout(brandTick, 35);
}
if (brandEl) brandTick();

const termBody = document.getElementById("termBody");
const termLines = document.getElementById("termLines");
const termInput = document.getElementById("termInput");
const MAX_LINES = 40;

function termLine(text, cls, withPrompt) {
  const div = document.createElement("div");
  div.className = "term-line" + (cls ? " " + cls : "");
  if (withPrompt) {
    const p = document.createElement("span"); p.className = "t-prompt"; p.textContent = "wael@portfolio";
    const s = document.createElement("span"); s.className = "t-path"; s.textContent = ":~$ ";
    div.append(p, s);
  }
  div.append(text);
  return div;
}

function termPush(nodes) {
  for (const n of nodes) termLines.appendChild(n);
  while (termLines.children.length > MAX_LINES) termLines.firstChild.remove();
  termBody.scrollTop = termBody.scrollHeight;
}

function runCommand(raw) {
  const cmd = raw.trim();
  if (cmd === "clear") { termLines.replaceChildren(); termInput.value = ""; return; }
  const out = [termLine(cmd, "", true)];
  const push = (text, cls) => out.push(termLine(text, cls || "t-muted"));

  if (cmd === "") { }
  else if (cmd === "help") push("commands: whoami · ls projects/ · cat mission.txt · cat goals.txt · open work|feed|writing|about|contact · contact · clear", "t-soft");
  else if (cmd === "whoami") push("Wael Shahadeh — cybersecurity senior at Marist. Malware research, network analysis, secure labs.");
  else if (cmd === "ls projects/" || cmd === "ls" || cmd === "ls projects") push("waelsocial-feed/  macos-backdoor-detection/  pc-reimaging/  ra-programming/", "t-accent");
  else if (cmd === "cat mission.txt") push("building & breaking to learn");
  else if (cmd === "cat goals.txt") push("1. keep learning  2. make an impact  3. keep growing");
  else if (cmd === "meow") push("meow! 🐱", "t-accent");
  else if (cmd === "evil") push("evil is a matter of perspective", "t-accent");
  else if (cmd === "contact") push("shahadehwael@gmail.com · github.com/StandupBasher · linkedin.com/in/wael-shahadeh", "t-soft");
  else if (cmd.startsWith("open ")) {
    const p = cmd.slice(5).trim();
    if (PAGES.includes(p)) {
      push("→ opening /" + p, "t-accent");
      termPush(out); termInput.value = "";
      setTimeout(() => go(p), 350);
      return;
    }
    push("no such page: " + p, "t-dim");
  }
  else if (cmd === "sudo rm -rf /") push("nice try. permission denied — this lab is isolated for a reason.", "t-dim");
  else push("command not found: " + cmd + " — try `help`", "t-dim");

  termPush(out);
  termInput.value = "";
}

if (termBody && termInput) {
  termBody.addEventListener("click", () => termInput.focus());
  termInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") runCommand(termInput.value);
  });
}

document.querySelectorAll(".case-head").forEach((head) => {
  head.addEventListener("click", () => {
    const item = head.closest(".case");
    const wasOpen = item.classList.contains("open");
    document.querySelectorAll(".case").forEach((c) => {
      c.classList.remove("open");
      c.querySelector(".case-caret").textContent = "+ expand";
    });
    if (!wasOpen) {
      item.classList.add("open");
      item.querySelector(".case-caret").textContent = "− close";
    }
  });
});

const palette = document.getElementById("palette");
const paletteBtn = document.getElementById("paletteBtn");
const paletteInput = document.getElementById("paletteInput");
const paletteHost = document.getElementById("paletteItems");
let paletteSel = 0;

const ACTIONS = [
  { icon: "→", label: "Home", hint: "page", run: () => go("home") },
  { icon: "→", label: "Work / case studies", hint: "page", run: () => go("work") },
  { icon: "→", label: "WaelSocial feed", hint: "page", run: () => go("feed") },
  { icon: "→", label: "Writing", hint: "page", run: () => go("writing") },
  { icon: "→", label: "About & skills", hint: "page", run: () => go("about") },
  { icon: "→", label: "Contact", hint: "page", run: () => go("contact") },
  { icon: "↗", label: "GitHub — StandupBasher", hint: "external", run: () => { closePalette(); window.open("https://github.com/StandupBasher", "_blank", "noopener"); } },
  { icon: "↗", label: "LinkedIn", hint: "external", run: () => { closePalette(); window.open("https://www.linkedin.com/in/wael-shahadeh/", "_blank", "noopener"); } },
  { icon: "✉", label: "Email shahadehwael@gmail.com", hint: "mailto", run: () => { closePalette(); location.href = "mailto:shahadehwael@gmail.com"; } },
];

function paletteMatches() {
  const q = paletteInput.value.trim().toLowerCase();
  return ACTIONS.filter((a) => a.label.toLowerCase().includes(q));
}

function renderPalette() {
  const items = paletteMatches();
  paletteSel = Math.min(paletteSel, Math.max(0, items.length - 1));
  paletteHost.replaceChildren();
  items.forEach((a, i) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "palette-item" + (i === paletteSel ? " sel" : "");
    const icon = document.createElement("span"); icon.className = "palette-icon"; icon.textContent = a.icon;
    const label = document.createElement("span"); label.className = "palette-label"; label.textContent = a.label;
    const hint = document.createElement("span"); hint.className = "palette-hint"; hint.textContent = a.hint;
    btn.append(icon, label, hint);
    btn.addEventListener("click", a.run);
    paletteHost.appendChild(btn);
  });
}

function openPalette() {
  palette.hidden = false;
  paletteInput.value = "";
  paletteSel = 0;
  renderPalette();
  setTimeout(() => paletteInput.focus(), 30);
}
function closePalette() {
  if (palette) palette.hidden = true;
}

if (palette) {
  paletteBtn.addEventListener("click", openPalette);
  palette.addEventListener("click", (e) => { if (e.target === palette) closePalette(); });
  paletteInput.addEventListener("input", () => { paletteSel = 0; renderPalette(); });
  paletteInput.addEventListener("keydown", (e) => {
    const items = paletteMatches();
    if (e.key === "ArrowDown") { e.preventDefault(); paletteSel = Math.min(paletteSel + 1, items.length - 1); renderPalette(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); paletteSel = Math.max(paletteSel - 1, 0); renderPalette(); }
    else if (e.key === "Enter" && items[paletteSel]) items[paletteSel].run();
  });
  window.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      palette.hidden ? openPalette() : closePalette();
    } else if (e.key === "Escape" && !palette.hidden) {
      closePalette();
    }
  });
}
