// Typing effect content (change freely)
const lines = [
  "whoami            # Wael Shahadeh",
  "cat mission.txt   # Building & breaking to learn",
  "ls projects/      # malware-detection  pc-repair  ra-security",
  "echo \"Hello, World!\"",
  "mkdir             # 'legion of dom'",

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

// --- rotating domain brand ---
const domains = ["wael.systems", "wael.sh", "shahadeh.dev"];
const brandEl = document.getElementById("brandText");
let current = 0;

function updateBrand() {
  current = (current + 1) % domains.length;
  const [name, ext] = domains[current].split(".");
  // quick fade-out / fade-in
  brandEl.style.opacity = 0;
  setTimeout(() => {
    brandEl.innerHTML = `${name}<span class="accent">.${ext}</span>`;
    brandEl.style.opacity = 1;
  }, 300);
}

setInterval(updateBrand, 3500); // every 3.5 s
