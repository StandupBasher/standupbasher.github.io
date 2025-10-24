// Typing effect content (change freely)
const lines = [
  "whoami            # Wael Shahadeh",
  "cat mission.txt   # Building & breaking to learn",
  "ls projects/      # malware-detection  pc-repair  ra-security",
  "echo \"Hello, World!\""
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
