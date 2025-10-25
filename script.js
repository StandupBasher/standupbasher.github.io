// Typing effect content (change freely)
const lines = [
  "whoami            # Wael Shahadeh",
  "cat mission.txt   # building & breaking to learn",
  "ls projects/      # malware-detection  pc-repair  ra-security",
  "mkdir wael-files  # personal & work stuff",
  "nano goals.txt    # 1. keep learning 2. make an impact 3. keep growing",
];

const typingEl = document.getElementById("typing");
const yearEl = document.getElementById("year");
if (yearEl) yearEl.textContent = new Date().getFullYear();

let lineIndex = 0;
let charIndex = 0;
let current = "";
let deleting = false;

function type() {
  const full = lines[lineIndex];

  if (!deleting) {
    current = full.slice(0, ++charIndex);
    typingEl.textContent = current;
    if (charIndex === full.length) {
      deleting = true;
      setTimeout(type, 900); // pause at end of line
      return;
    }
  } else {
    current = full.slice(0, --charIndex);
    typingEl.textContent = current;
    if (charIndex === 0) {
      deleting = false;
      lineIndex = (lineIndex + 1) % lines.length;
      setTimeout(type, 400);
      return;
    }
  }
  setTimeout(type, deleting ? 20 : 28); // speed
}
type();



// --- rotating domain brand with typing effect (random order, no repeats) ---
const domains = ["wael.systems", "wael.sh", "shahadeh.dev", "waelshahadeh.com"];
const brandEl = document.getElementById("brandText");

let lastIndex = -1;
let target = "";
let shownLength = 0;
let mode = "typing"; // "typing" | "erasing" | "waiting"

const TYPE_SPEED = 75;     // ms per character while typing
const ERASE_SPEED = 35;    // ms per character while erasing
const HOLD_AFTER_TYPE = 5000; // ms hold after full word typed
const HOLD_AFTER_ERASE = 450; // ms before starting next word

function pickNewDomain() {
  let idx;
  do { idx = Math.floor(Math.random() * domains.length); } while (idx === lastIndex);
  lastIndex = idx;
  return domains[idx];
}

function renderPartial(text, n) {
  const partial = text.slice(0, n);
  const dot = partial.indexOf(".");
  if (dot >= 0) {
    const name = partial.slice(0, dot);
    const ext = partial.slice(dot); // includes the '.'
    brandEl.innerHTML = `${name}<span class="accent">${ext}</span>`;
  } else {
    brandEl.textContent = partial;
  }
}

function tick() {
  if (!target) {
    target = pickNewDomain();
    shownLength = 0;
    mode = "typing";
  }

  if (mode === "typing") {
    shownLength++;
    renderPartial(target, shownLength);

    if (shownLength >= target.length) {
      // ensure final accent wrapping is perfect
      const [name, ext] = target.split(".");
      brandEl.innerHTML = `${name}<span class="accent">.${ext}</span>`;
      mode = "waiting";
      return setTimeout(() => { mode = "erasing"; tick(); }, HOLD_AFTER_TYPE);
    }
    return setTimeout(tick, TYPE_SPEED);
  }

  if (mode === "erasing") {
    shownLength = Math.max(0, shownLength - 1);
    renderPartial(target, shownLength);

    if (shownLength === 0) {
      mode = "waiting";
      target = "";
      return setTimeout(() => { mode = "typing"; tick(); }, HOLD_AFTER_ERASE);
    }
    return setTimeout(tick, ERASE_SPEED);
  }

  // waiting (should be transitioned by timeouts above)
}

tick();
