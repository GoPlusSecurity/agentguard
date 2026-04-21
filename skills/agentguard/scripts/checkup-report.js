#!/usr/bin/env node

/**
 * GoPlus AgentGuard — Checkup Report Generator
 *
 * Reads checkup results as JSON from stdin, generates a self-contained HTML
 * report with lobster mascot and opens it in the default browser.
 *
 * Usage:
 *   echo '{"composite_score":73,...}' | node scripts/checkup-report.js
 *
 * Output: prints the generated HTML file path to stdout.
 */

import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir, homedir } from 'node:os';
import open from 'open';
import { fileURLToPath } from 'node:url';

const DIM_META = {
  code_safety:          { icon: 'find_in_page', name: 'Skill & Code Safety', zh: '技能与代码安全' },
  credential_safety:    { icon: 'key',          name: 'Credential & Secrets', zh: '凭证与密钥安全' },
  network_exposure:     { icon: 'lan',          name: 'Network & System', zh: '网络与系统暴露' },
  runtime_protection:   { icon: 'shield',       name: 'Runtime Protection', zh: '运行时防护' },
  web3_safety:          { icon: 'token',        name: 'Web3 Safety', zh: 'Web3 安全' },
};

// Try to load favicon from agentguard-server or fallback
const __dirname = dirname(fileURLToPath(import.meta.url));
let faviconB64 = '';
const iconPaths = [
  join(homedir(), 'code/agentguard-server/public/icon-192.png'),
  join(__dirname, '../../assets/icon-192.png'),
];
for (const p of iconPaths) {
  if (existsSync(p)) { faviconB64 = readFileSync(p).toString('base64'); break; }
}

// Support --file <path> argument to read JSON from file (cross-platform friendly)
const fileArgIdx = process.argv.indexOf('--file');
if (fileArgIdx !== -1 && process.argv[fileArgIdx + 1]) {
  const filePath = process.argv[fileArgIdx + 1];
  try {
    const content = readFileSync(filePath, 'utf8');
    generateReport(JSON.parse(content));
  } catch (err) {
    process.stderr.write(`Error reading ${filePath}: ${err.message}\n`);
    process.exit(1);
  }
} else {
  // Fallback: read JSON from stdin (pipe)
  let input = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => { input += chunk; });
  process.stdin.on('end', () => {
    try { generateReport(JSON.parse(input)); }
    catch (err) { process.stderr.write(`Error: ${err.message}\n`); process.exit(1); }
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getTier(score) {
  const pick = arr => arr[Math.floor(Math.random() * arr.length)];
  if (score >= 90) return { grade: 'S', label: 'JACKED', color: '#00ffa3', quote: pick([
    "Your agent is JACKED! 💪 Nothing gets past these claws!",
    "Built different. This lobster lifts. 🏋️",
    "Solid as a rock — this agent's security is chef's kiss! 🤌",
    "Fort Knox? More like Fort Lobster. 🦞🔒",
    "Peak performance. Your agent bench-presses threats for breakfast. 💪",
  ])};
  if (score >= 70) return { grade: 'A', label: 'Healthy', color: '#98cbff', quote: pick([
    "Looking solid! A few tweaks and you'll be unstoppable.",
    "Almost there — one more push and this lobster gets abs! 🦞",
    "Shield's up, claws sharp. Just needs a little polish. 🛡️",
    "Your agent is in good shape — a little tuning and it's S-tier! ✨",
    "Healthy and alert. This lobster runs 5K every morning. 🏃",
  ])};
  if (score >= 50) return { grade: 'B', label: 'Tired', color: '#f0a830', quote: pick([
    "Your agent needs a workout... and maybe some coffee. ☕",
    "Sleepy lobster energy. Has potential, just needs motivation. 😴",
    "Running on fumes — time to refuel this crustacean! ⛽",
    "Your agent is binge-watching Netflix instead of patrolling. 📺",
    "This lobster skipped leg day... and arm day... and every day. 🦞💤",
  ])};
  return { grade: 'F', label: 'Critical', color: '#ffb4ab', quote: pick([
    "CRITICAL CONDITION! This agent needs emergency care! 🚨",
    "Code red! This lobster is on life support! 🏥",
    "SOS! Your agent just texted 'send help' in morse code. 📡",
    "Mayday mayday! This crustacean is going down! 🆘",
    "Your agent's immune system has left the chat. 💀",
  ])};
}



function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function sevColor(s) {
  s = (s||'').toUpperCase();
  if (s === 'CRITICAL') return '#ffb4ab';
  if (s === 'HIGH') return '#f0a830';
  if (s === 'MEDIUM') return '#98cbff';
  return '#849588';
}

function dimColor(score) {
  if (score === null) return '#849588';
  if (score >= 90) return '#00ffa3';
  if (score >= 70) return '#00a2fd';
  if (score >= 50) return '#f0a830';
  return '#ffb4ab';
}

// ---------------------------------------------------------------------------
// Pixel-art lobster SVG (inline, no external deps) — 5 variants per tier
// ---------------------------------------------------------------------------
function pixelLobster(grade, color) {
  const R = '#e63946', R2 = '#d62839', R3 = '#c1121f', R4 = '#a30d1a';
  const P1 = '#c4737b', P2 = '#a8636b', P3 = '#8a3040';
  const T1 = '#d4545e', T2 = '#c1454f', T3 = '#a1101a';

  const styles = `<style>
@keyframes pxBounce{0%,100%{transform:translateY(0)}40%{transform:translateY(-5px)}}
@keyframes pxBreath{0%,100%{transform:scaleY(1)}50%{transform:scaleY(1.02)}}
@keyframes pxSp{0%,100%{opacity:1}50%{opacity:.1}}
@keyframes pxBl{0%,92%,96%,100%{transform:scaleY(1)}94%{transform:scaleY(.05)}}
@keyframes pxSw{0%{opacity:.8;transform:translateY(0)}100%{opacity:0;transform:translateY(5px)}}
@keyframes pxSteam{0%{opacity:.4;transform:translateY(0)}100%{opacity:0;transform:translateY(-4px)}}
@keyframes pxAlarm{0%,100%{opacity:1}50%{opacity:.1}}
@keyframes pxFlex{0%,100%{transform:rotate(0)}25%{transform:rotate(-20deg)}75%{transform:rotate(5deg)}}
@keyframes pxFlexR{0%,100%{transform:rotate(0)}25%{transform:rotate(20deg)}75%{transform:rotate(-5deg)}}
@keyframes pxWag{0%,100%{transform:rotate(0)}50%{transform:rotate(6deg)}}
@keyframes pxNod{0%,100%{transform:translateY(0)}50%{transform:translateY(1px)}}
@keyframes pxCoffee{0%,100%{transform:rotate(0)}30%{transform:rotate(-10deg)}70%{transform:rotate(3deg)}}
@keyframes pxTremor{0%,100%{transform:translate(0,0)}25%{transform:translate(-1px,0)}50%{transform:translate(1px,-1px)}75%{transform:translate(-1px,1px)}}
@keyframes pxFloat{0%,100%{transform:translateY(0)}50%{transform:translateY(-3px)}}
@keyframes pxSpin{0%{transform:rotate(0)}100%{transform:rotate(360deg)}}
@keyframes pxPulse{0%,100%{opacity:.6}50%{opacity:1}}
@keyframes pxDrip{0%{opacity:.7;transform:translateY(0)}100%{opacity:0;transform:translateY(8px)}}
.px-bounce{animation:pxBounce 2s ease-in-out infinite}
.px-breath{animation:pxBreath 3s ease-in-out infinite;transform-origin:bottom}
.px-sparkle{animation:pxSp 1.3s ease-in-out infinite}
.px-blink{animation:pxBl 4s ease-in-out infinite;transform-origin:center}
.px-sweat{animation:pxSw 1.6s ease-in infinite}
.px-steam{animation:pxSteam 2s ease-out infinite}
.px-alarm{animation:pxAlarm .6s ease-in-out infinite}
.px-flex-l{animation:pxFlex 2.2s ease-in-out infinite;transform-origin:right center}
.px-flex-r{animation:pxFlexR 2.2s ease-in-out infinite;transform-origin:left center}
.px-wag{animation:pxWag 1.8s ease-in-out infinite;transform-origin:top center}
.px-nod{animation:pxNod 2.5s ease-in-out infinite}
.px-coffee{animation:pxCoffee 3s ease-in-out infinite;transform-origin:bottom left}
.px-tremor{animation:pxTremor .25s linear infinite}
.px-float{animation:pxFloat 3s ease-in-out infinite}
.px-spin{animation:pxSpin 4s linear infinite;transform-origin:center}
.px-pulse{animation:pxPulse 2s ease-in-out infinite}
.px-drip{animation:pxDrip 2s ease-in infinite}
</style>`;

  const px = (x,y,w,h,c) => `<rect x="${x}" y="${y}" width="${w||1}" height="${h||1}" fill="${c}"/>`;
  const pick = arr => arr[Math.floor(Math.random() * arr.length)];

  // ── Shared body parts ──
  const antennae = (c1,c2) => `<g class="px-wag">${px(15,0,1,1,c1)}${px(14,1,1,1,c1)}${px(13,2,1,2,c2)}${px(14,4,1,1,c1)}</g><g class="px-wag" style="animation-delay:.4s">${px(32,0,1,1,c1)}${px(33,1,1,1,c1)}${px(34,2,1,2,c2)}${px(33,4,1,1,c1)}</g>`;
  const head = (c,nod='') => `<g ${nod}>${px(18,5,12,5,c)}${px(17,6,14,4,c)}${px(16,7,16,2,c)}`;
  const eyes = () => `<g class="px-blink">${px(20,7,3,2,'#fff')}${px(25,7,3,2,'#fff')}</g>${px(21,8,1,1,'#1a1a2e')}${px(26,8,1,1,'#1a1a2e')}`;
  const body = (c1,c2,dur='') => `<g class="px-breath"${dur?` style="animation-duration:${dur}"`:``}>${px(17,12,14,3,c1)}${px(16,13,16,2,c2)}${px(18,15,12,2,c1)}${px(17,16,14,1,c2)}${px(19,17,10,2,c2)}</g>`;
  const legs = (c1,c2) => `${px(15,18,1,3,c1)}${px(14,20,1,2,c2)}${px(17,19,1,3,c1)}${px(16,21,1,2,c2)}${px(30,19,1,3,c1)}${px(31,21,1,2,c2)}${px(32,18,1,3,c1)}${px(33,20,1,2,c2)}`;
  const tail = (c1,c2) => `<g class="px-wag" style="animation-duration:2.5s">${px(20,20,8,2,c1)}${px(19,22,10,1,c1)}${px(18,23,3,2,c2)}${px(22,23,4,2,c1)}${px(27,23,3,2,c2)}</g>`;
  const clawL = (c1,c2,c3) => `${px(8,8,4,3,c1)}${px(6,9,3,3,c1)}${px(4,8,3,2,c2)}${px(3,7,2,2,c1)}${px(3,10,2,1,c3)}`;
  const clawR = (c1,c2) => `${px(36,8,4,3,c1)}${px(38,9,3,3,c1)}${px(40,8,3,2,c2)}`;

  // ════════════════════════════════════════════════
  // S TIER VARIANTS (score >= 90)
  // ════════════════════════════════════════════════
  const sVariants = [
    // 0: Crown + Sunglasses (original)
    () => `<svg viewBox="-2 -8 52 56" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-bounce">
  <g class="px-wag">${px(14,0,1,1,R)}${px(13,1,1,1,R)}${px(12,2,1,1,R2)}${px(12,3,1,1,R2)}${px(13,4,1,1,R)}</g>
  <g class="px-wag" style="animation-delay:.5s">${px(33,0,1,1,R)}${px(34,1,1,1,R)}${px(35,2,1,1,R2)}${px(35,3,1,1,R2)}${px(34,4,1,1,R)}</g>
  <g class="px-wag" style="animation-duration:2.5s">${px(18,2,1,2,'#ffd700')}${px(21,1,1,2,'#ffd700')}${px(24,0,1,2,'#ffd700')}${px(27,1,1,2,'#ffd700')}${px(30,2,1,2,'#ffd700')}${px(17,4,14,1,'#ffd700')}${px(17,5,14,1,'#e6c200')}</g>
  <rect x="8" y="8" width="1" height="1" fill="#ffd700" class="px-sparkle"/>
  <rect x="39" y="7" width="1" height="1" fill="#ffd700" class="px-sparkle" style="animation-delay:.4s"/>
  <rect x="5" y="14" width="1" height="1" fill="#fffbe6" class="px-sparkle" style="animation-delay:.8s"/>
  <rect x="42" y="13" width="1" height="1" fill="#fffbe6" class="px-sparkle" style="animation-delay:1.2s"/>
  <g class="px-nod">${px(18,6,12,6,R)}${px(17,7,14,5,R)}${px(16,8,16,3,R)}
    ${px(19,9,4,3,'#1a1a2e')}${px(25,9,4,3,'#1a1a2e')}${px(23,10,2,1,'#1a1a2e')}
    ${px(20,10,2,1,color+'88')}${px(26,10,2,1,color+'88')}
    ${px(20,13,1,1,'#fff')}${px(21,13,6,1,R3)}${px(27,13,1,1,'#fff')}
  </g>
  <g class="px-breath">${px(17,14,14,3,R)}${px(16,15,16,2,R2)}${px(18,17,12,2,R)}${px(17,18,14,1,R2)}${px(19,19,10,2,R2)}${px(18,20,12,1,R3)}
    ${px(21,15,2,1,R3)}${px(25,15,2,1,R3)}${px(21,18,2,1,R3)}${px(25,18,2,1,R3)}
  </g>
  <g class="px-flex-l">${px(8,9,4,3,R)}${px(6,10,3,4,R)}${px(4,9,3,3,R2)}${px(3,8,2,2,R)}${px(2,7,2,1,R)}${px(5,8,1,1,R3)}${px(3,12,2,1,R3)}${px(2,11,1,2,R)}</g>
  <g class="px-flex-r" style="animation-delay:.3s">${px(36,9,4,3,R)}${px(39,10,3,4,R)}${px(41,9,3,3,R2)}${px(43,8,2,2,R)}${px(44,7,2,1,R)}${px(42,8,1,1,R3)}${px(43,12,2,1,R3)}${px(45,11,1,2,R)}</g>
  ${legs(R2,R3)}
  <g class="px-wag">${px(20,22,8,2,R3)}${px(19,24,10,1,R3)}${px(18,25,3,2,R4)}${px(22,25,4,2,R3)}${px(27,25,3,2,R4)}${px(17,27,3,1,R4)}${px(21,27,6,1,R3)}${px(28,27,3,1,R4)}</g>
</g></svg>`,

    // 1: Super Hero Cape
    () => `<svg viewBox="-2 -6 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-bounce">
  ${antennae(R,R2)}
  ${head(R,'class="px-nod"')}${eyes()}
    ${px(21,10,1,1,R3)}${px(22,11,4,1,R3)}${px(26,10,1,1,R3)}</g>
  <!-- Cape -->
  <g class="px-wag" style="animation-duration:2s">${px(15,10,1,12,'#4a3df7')}${px(14,11,1,11,'#4a3df7')}${px(13,12,1,10,'#3a2de7')}${px(12,14,1,8,'#3a2de7')}${px(33,10,1,12,'#4a3df7')}${px(34,11,1,11,'#4a3df7')}${px(35,12,1,10,'#3a2de7')}${px(36,14,1,8,'#3a2de7')}</g>
  <!-- Star emblem on chest -->
  ${body(R,R2)}
  ${px(23,13,2,1,'#ffd700')}${px(22,14,4,1,'#ffd700')}${px(23,15,2,1,'#ffd700')}
  ${clawL(R,R2,R3)}${clawR(R,R2)}
  ${legs(R2,R3)}${tail(R3,R4)}
  <rect x="7" y="3" width="1" height="1" fill="#ffd700" class="px-sparkle"/>
  <rect x="40" y="5" width="1" height="1" fill="#ffd700" class="px-sparkle" style="animation-delay:.6s"/>
</g></svg>`,

    // 2: Ninja lobster
    () => `<svg viewBox="-2 -6 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-bounce" style="animation-duration:1.5s">
  ${antennae(R,R2)}
  ${head(R,'class="px-nod"')}
    <!-- Ninja mask -->
    ${px(17,7,14,2,'#2a2a3e')}
    ${px(20,7,3,2,'#fff')}${px(25,7,3,2,'#fff')}
    ${px(21,8,1,1,'#e63946')}${px(26,8,1,1,'#e63946')}
    <!-- Headband tails -->
    ${px(31,7,3,1,'#2a2a3e')}${px(33,6,2,1,'#2a2a3e')}${px(34,5,2,1,'#2a2a3e')}
  </g>
  ${body(R,R2)}
  <!-- Shuriken in left claw -->
  <g class="px-flex-l">${px(8,8,4,3,R)}${px(6,9,3,3,R)}${px(4,8,3,2,R2)}
    <g class="px-spin" style="animation-duration:2s">${px(0,7,1,3,'#ccc')}${px(1,8,3,1,'#ccc')}${px(1,8,1,1,'#888')}</g>
  </g>
  <!-- Katana in right claw -->
  <g class="px-flex-r">${clawR(R,R2)}
    ${px(42,3,1,8,'#c0c0c0')}${px(42,2,1,1,'#fff')}${px(41,11,3,1,'#8b6914')}
  </g>
  ${legs(R2,R3)}${tail(R3,R4)}
</g></svg>`,

    // 3: Astronaut lobster
    () => `<svg viewBox="-2 -8 52 56" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-float">
  ${antennae(R,R2)}
  <!-- Helmet -->
  ${px(16,3,16,2,'#e0e8f0')}${px(15,5,18,8,'#e0e8f0')}${px(16,13,16,1,'#c0c8d0')}
  <!-- Visor -->
  ${px(18,6,12,5,'#1a3a5c')}${px(19,7,10,3,'#244a6c')}
  <!-- Eyes through visor -->
  ${px(20,8,2,1,'#fff')}${px(26,8,2,1,'#fff')}
  <!-- Visor reflection -->
  ${px(19,7,2,1,'#ffffff40')}
  ${body(R,R2)}
  <!-- Jetpack -->
  ${px(15,13,2,5,'#606870')}${px(31,13,2,5,'#606870')}
  <rect x="14" y="18" width="1" height="2" fill="#f0a830" class="px-pulse"/>
  <rect x="33" y="18" width="1" height="2" fill="#f0a830" class="px-pulse" style="animation-delay:.5s"/>
  ${clawL(R,R2,R3)}${clawR(R,R2)}
  ${legs(R2,R3)}${tail(R3,R4)}
  <!-- Stars -->
  <rect x="5" y="2" width="1" height="1" fill="#fff" class="px-sparkle"/>
  <rect x="42" y="10" width="1" height="1" fill="#fff" class="px-sparkle" style="animation-delay:.7s"/>
  <rect x="8" y="20" width="1" height="1" fill="#fff" class="px-sparkle" style="animation-delay:1.1s"/>
</g></svg>`,

    // 4: DJ lobster with headphones
    () => `<svg viewBox="-2 -6 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-bounce" style="animation-duration:1.2s">
  ${antennae(R,R2)}
  <!-- Headphones -->
  ${px(16,3,16,2,'#333')}${px(15,4,1,4,'#333')}${px(32,4,1,4,'#333')}
  ${px(13,5,3,4,'#555')}${px(14,6,2,2,'#00ffa3')}
  ${px(32,5,3,4,'#555')}${px(33,6,2,2,'#00ffa3')}
  ${head(R,'class="px-nod" style="animation-duration:1.2s"')}${eyes()}
    ${px(22,10,4,1,R3)}${px(21,10,1,1,R3)}${px(26,10,1,1,R3)}
  </g>
  ${body(R,R2)}
  <!-- Turntable in right claw -->
  <g class="px-wag" style="animation-duration:1s">${clawR(R,R2)}
    ${px(40,6,6,6,'#333')}${px(41,7,4,4,'#444')}
    <g class="px-spin" style="animation-duration:1.5s">${px(42,8,2,2,'#222')}${px(42,8,1,1,'#666')}</g>
  </g>
  ${clawL(R,R2,R3)}
  ${legs(R2,R3)}${tail(R3,R4)}
  <!-- Music notes -->
  <rect x="6" y="3" width="1" height="1" fill="${color}" class="px-sparkle"/>
  <rect x="10" y="1" width="1" height="1" fill="${color}" class="px-sparkle" style="animation-delay:.5s"/>
  <rect x="38" y="1" width="1" height="1" fill="${color}" class="px-sparkle" style="animation-delay:1s"/>
</g></svg>`,
  ];

  // ════════════════════════════════════════════════
  // A TIER VARIANTS (score 70-89)
  // ════════════════════════════════════════════════
  const aVariants = [
    // 0: Shield (original)
    () => `<svg viewBox="-2 -8 52 54" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-bounce" style="animation-duration:2.2s">
  ${antennae(R,R2)}${px(17,4,2,2,R2)}${px(29,4,2,2,R2)}
  ${head(R,'class="px-nod" style="animation-duration:3s"')}${eyes()}
    ${px(21,10,1,1,R3)}${px(22,11,4,1,R3)}${px(26,10,1,1,R3)}</g>
  ${body(R,R2,'3.5s')}
  ${clawL(R,R2,R3)}
  <g class="px-wag" style="animation-duration:2s">${clawR(R,R2)}
    ${px(40,6,5,6,color)}${px(41,7,3,4,color+'cc')}${px(42,8,2,2,'#fff')}
  </g>
  ${legs(R2,R3)}${tail(R3,R4)}
</g></svg>`,

    // 1: Magnifying glass detective
    () => `<svg viewBox="-2 -6 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-bounce" style="animation-duration:2.5s">
  ${antennae(R,R2)}
  <!-- Detective hat -->
  ${px(17,2,14,2,'#5c4033')}${px(15,4,18,1,'#4a3328')}${px(18,1,12,1,'#5c4033')}
  ${head(R,'class="px-nod"')}${eyes()}
    ${px(22,10,4,1,R3)}</g>
  ${body(R,R2)}
  ${clawL(R,R2,R3)}
  <!-- Magnifying glass -->
  <g class="px-wag" style="animation-duration:3s">${clawR(R,R2)}
    ${px(42,4,4,4,'#c0c0c0')}${px(43,5,2,2,'#87ceeb')}${px(41,8,1,3,'#8b6914')}
  </g>
  ${legs(R2,R3)}${tail(R3,R4)}
</g></svg>`,

    // 2: Thumbs up / checkmark lobster
    () => `<svg viewBox="-2 -6 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-bounce" style="animation-duration:2s">
  ${antennae(R,R2)}
  ${head(R,'class="px-nod"')}${eyes()}
    <!-- Wink + smile -->
    ${px(20,7,3,1,'#fff')}${px(21,8,1,1,'#1a1a2e')}
    ${px(25,7,3,2,'#fff')}${px(26,8,1,1,'#1a1a2e')}
    ${px(21,10,1,1,R3)}${px(22,11,4,1,R3)}${px(26,10,1,1,R3)}
  </g>
  ${body(R,R2)}
  <!-- Left claw: thumbs up -->
  <g class="px-flex-l">${px(8,8,4,3,R)}${px(6,9,3,3,R)}${px(4,8,3,2,R2)}${px(3,5,2,4,R)}${px(2,5,1,1,R2)}</g>
  ${clawR(R,R2)}
  <!-- Checkmark badge -->
  ${px(40,6,5,5,color)}${px(41,7,3,3,color+'cc')}
  ${px(42,9,1,1,'#fff')}${px(43,8,1,1,'#fff')}${px(44,7,1,1,'#fff')}
  ${legs(R2,R3)}${tail(R3,R4)}
</g></svg>`,

    // 3: Hard hat construction
    () => `<svg viewBox="-2 -6 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-bounce" style="animation-duration:2.2s">
  ${antennae(R,R2)}
  <!-- Hard hat -->
  ${px(16,2,16,3,'#f0a830')}${px(15,5,18,1,'#d89520')}${px(22,1,4,1,'#f0a830')}
  <!-- Light on hat -->
  <rect x="23" y="0" width="2" height="1" fill="#fff" class="px-pulse"/>
  ${head(R,'class="px-nod"')}${eyes()}
    ${px(22,10,4,1,R3)}</g>
  ${body(R,R2)}
  ${clawL(R,R2,R3)}
  <!-- Wrench in right claw -->
  <g class="px-wag" style="animation-duration:2s">${clawR(R,R2)}
    ${px(42,5,2,7,'#808080')}${px(41,5,4,2,'#909090')}
  </g>
  ${legs(R2,R3)}${tail(R3,R4)}
</g></svg>`,

    // 4: Sword & shield warrior
    () => `<svg viewBox="-2 -6 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-bounce" style="animation-duration:2s">
  ${antennae(R,R2)}
  <!-- Viking helmet -->
  ${px(17,2,14,3,'#808080')}${px(16,4,16,1,'#707070')}
  ${px(15,1,2,4,'#fff')}${px(31,1,2,4,'#fff')}${px(14,0,2,1,'#eee')}${px(32,0,2,1,'#eee')}
  ${head(R,'class="px-nod"')}${eyes()}
    ${px(22,10,4,1,R3)}${px(21,10,1,1,R3)}${px(26,10,1,1,R3)}</g>
  ${body(R,R2)}
  <!-- Left: shield -->
  <g class="px-wag">${px(4,7,5,7,color)}${px(5,8,3,5,color+'cc')}${px(6,10,1,1,'#fff')}</g>
  <!-- Right: sword -->
  <g class="px-flex-r">${clawR(R,R2)}
    ${px(43,2,1,9,'#c0c0c0')}${px(43,1,1,1,'#fff')}${px(41,11,5,1,'#8b6914')}${px(43,12,1,2,'#6b4914')}
  </g>
  ${legs(R2,R3)}${tail(R3,R4)}
</g></svg>`,
  ];

  // ════════════════════════════════════════════════
  // B TIER VARIANTS (score 50-69)
  // ════════════════════════════════════════════════
  const bVariants = [
    // 0: Coffee (original)
    () => `<svg viewBox="-2 -8 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-bounce" style="animation-duration:3.5s">
  ${px(14,3,1,1,T2)}${px(13,4,1,2,T2)}${px(14,6,1,1,T2)}
  ${px(33,3,1,1,T2)}${px(34,4,1,2,T2)}${px(33,6,1,1,T2)}
  <rect x="35" y="4" width="1" height="1" fill="#58a6ff" class="px-sweat"/>
  <rect x="36" y="6" width="1" height="1" fill="#58a6ff" class="px-sweat" style="animation-delay:.6s"/>
  <g class="px-nod" style="animation-duration:4s">${px(18,6,12,5,T1)}${px(17,7,14,4,T1)}${px(16,8,16,2,T1)}
    ${px(20,8,3,2,'#fff')}${px(25,8,3,2,'#fff')}
    <g class="px-blink" style="animation-duration:2s">${px(20,8,3,1,T1)}${px(25,8,3,1,T1)}</g>
    ${px(21,9,1,1,'#1a1a2e')}${px(26,9,1,1,'#1a1a2e')}
    ${px(22,11,4,1,T3)}
  </g>
  <g class="px-breath" style="animation-duration:4s">${px(17,12,14,3,T1)}${px(16,13,16,2,T2)}${px(18,15,12,2,T1)}${px(19,17,10,2,T2)}</g>
  ${px(8,10,4,3,T1)}${px(6,11,3,2,T2)}${px(4,10,3,2,T2)}${px(3,11,2,1,T1)}
  <g class="px-coffee">${px(36,10,4,3,T1)}${px(38,11,3,2,T2)}
    ${px(39,8,4,5,'#8b6914')}${px(38,8,6,1,'#a07818')}
    <rect x="40" y="5" width="1" height="3" fill="#ffffff30" class="px-steam"/>
    <rect x="41" y="4" width="1" height="3" fill="#ffffff20" class="px-steam" style="animation-delay:.8s"/>
  </g>
  ${legs(T2,T3)}
  ${px(20,20,8,2,T3)}${px(19,22,10,1,T3)}${px(18,23,3,1,T3)}${px(22,23,4,1,T3)}${px(27,23,3,1,T3)}
</g></svg>`,

    // 1: Pillow / sleeping
    () => `<svg viewBox="-2 -6 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-nod" style="animation-duration:4s">
  ${px(14,4,1,2,T2)}${px(13,5,1,1,T2)}${px(33,4,1,2,T2)}${px(34,5,1,1,T2)}
  ${px(18,6,12,5,T1)}${px(17,7,14,4,T1)}${px(16,8,16,2,T1)}
  <!-- Closed eyes (zzz) -->
  ${px(20,8,3,1,T3)}${px(25,8,3,1,T3)}
  ${px(22,11,4,1,T3)}
  <!-- ZZZ -->
  <rect x="34" y="2" width="3" height="1" fill="#849588" class="px-sparkle"/>
  <rect x="36" y="0" width="4" height="1" fill="#849588" class="px-sparkle" style="animation-delay:.5s"/>
  <rect x="38" y="-2" width="5" height="1" fill="#849588" class="px-sparkle" style="animation-delay:1s"/>
  <g class="px-breath" style="animation-duration:5s">${px(17,12,14,3,T1)}${px(16,13,16,2,T2)}${px(18,15,12,2,T1)}${px(19,17,10,2,T2)}</g>
  <!-- Pillow under head -->
  ${px(14,11,20,2,'#e8dcc8')}${px(15,10,18,1,'#f0e6d4')}
  ${px(8,10,4,3,T1)}${px(6,11,3,2,T2)}
  ${px(36,10,4,3,T1)}${px(38,11,3,2,T2)}
  ${legs(T2,T3)}
  ${px(20,20,8,2,T3)}${px(19,22,10,1,T3)}
</g></svg>`,

    // 2: Umbrella in rain
    () => `<svg viewBox="-2 -8 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-nod" style="animation-duration:3s">
  <!-- Umbrella -->
  ${px(18,-2,14,3,'#4a90d9')}${px(16,0,18,1,'#4a90d9')}${px(24,1,1,5,'#8b6914')}
  <!-- Rain drops -->
  <rect x="8" y="-1" width="1" height="2" fill="#58a6ff" class="px-drip"/>
  <rect x="14" y="1" width="1" height="2" fill="#58a6ff" class="px-drip" style="animation-delay:.3s"/>
  <rect x="38" y="0" width="1" height="2" fill="#58a6ff" class="px-drip" style="animation-delay:.6s"/>
  <rect x="42" y="2" width="1" height="2" fill="#58a6ff" class="px-drip" style="animation-delay:.9s"/>
  <rect x="5" y="4" width="1" height="2" fill="#58a6ff" class="px-drip" style="animation-delay:1.2s"/>
  <rect x="44" y="5" width="1" height="2" fill="#58a6ff" class="px-drip" style="animation-delay:1.5s"/>
  ${px(14,4,1,2,T2)}${px(13,5,1,1,T2)}${px(33,4,1,2,T2)}${px(34,5,1,1,T2)}
  ${px(18,6,12,5,T1)}${px(17,7,14,4,T1)}${px(16,8,16,2,T1)}
  ${px(20,8,3,2,'#fff')}${px(25,8,3,2,'#fff')}${px(21,9,1,1,'#1a1a2e')}${px(26,9,1,1,'#1a1a2e')}
  ${px(22,11,4,1,T3)}
  <g class="px-breath" style="animation-duration:4s">${px(17,12,14,3,T1)}${px(16,13,16,2,T2)}${px(18,15,12,2,T1)}${px(19,17,10,2,T2)}</g>
  ${px(8,10,4,3,T1)}${px(6,11,3,2,T2)}${px(4,10,3,2,T2)}
  ${px(36,10,4,3,T1)}${px(38,11,3,2,T2)}
  ${legs(T2,T3)}
  ${px(20,20,8,2,T3)}${px(19,22,10,1,T3)}
</g></svg>`,

    // 3: Band-aid / slightly hurt
    () => `<svg viewBox="-2 -6 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-bounce" style="animation-duration:3s">
  ${px(14,4,1,2,T2)}${px(13,5,1,1,T2)}${px(33,4,1,2,T2)}${px(34,5,1,1,T2)}
  <rect x="35" y="3" width="1" height="1" fill="#58a6ff" class="px-sweat"/>
  ${px(18,6,12,5,T1)}${px(17,7,14,4,T1)}${px(16,8,16,2,T1)}
  <!-- Band-aid on head -->
  ${px(27,5,5,1,'#f5d0a9')}${px(28,4,3,3,'#f5d0a9')}${px(29,5,1,1,'#d4a574')}
  ${px(20,8,3,2,'#fff')}${px(25,8,3,2,'#fff')}${px(21,9,1,1,'#1a1a2e')}${px(26,9,1,1,'#1a1a2e')}
  <!-- Slightly sad -->
  ${px(22,11,1,1,T3)}${px(23,11,2,1,T3)}${px(25,11,1,1,T3)}
  <g class="px-breath" style="animation-duration:4s">${px(17,12,14,3,T1)}${px(16,13,16,2,T2)}${px(18,15,12,2,T1)}${px(19,17,10,2,T2)}</g>
  ${px(8,10,4,3,T1)}${px(6,11,3,2,T2)}${px(4,10,3,2,T2)}
  ${px(36,10,4,3,T1)}${px(38,11,3,2,T2)}
  ${legs(T2,T3)}
  ${px(20,20,8,2,T3)}${px(19,22,10,1,T3)}
</g></svg>`,

    // 4: Yawning lobster
    () => `<svg viewBox="-2 -6 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-nod" style="animation-duration:5s">
  ${px(14,3,1,2,T2)}${px(13,4,1,2,T2)}${px(33,3,1,2,T2)}${px(34,4,1,2,T2)}
  ${px(18,6,12,5,T1)}${px(17,7,14,4,T1)}${px(16,8,16,2,T1)}
  <!-- Squinting eyes -->
  ${px(20,8,3,1,'#fff')}${px(25,8,3,1,'#fff')}
  ${px(20,8,3,1,T2)}${px(25,8,3,1,T2)}
  <!-- Big open yawn mouth -->
  ${px(21,10,6,3,'#8a3040')}${px(22,10,4,1,'#fff')}
  <g class="px-breath" style="animation-duration:5s">${px(17,12,14,3,T1)}${px(16,13,16,2,T2)}${px(18,15,12,2,T1)}${px(19,17,10,2,T2)}</g>
  <!-- One claw covering yawn -->
  <g class="px-coffee" style="animation-duration:5s">${px(8,8,4,3,T1)}${px(6,9,3,3,T1)}${px(4,8,3,2,T2)}${px(6,7,3,1,T2)}</g>
  ${px(36,10,4,3,T1)}${px(38,11,3,2,T2)}
  ${legs(T2,T3)}
  ${px(20,20,8,2,T3)}${px(19,22,10,1,T3)}
</g></svg>`,
  ];

  // ════════════════════════════════════════════════
  // F TIER VARIANTS (score 0-49)
  // ════════════════════════════════════════════════
  const fVariants = [
    // 0: Bandage + Thermometer (original)
    () => `<svg viewBox="-2 -8 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-tremor">
  <rect x="4" y="7" width="2" height="2" fill="#f85149" class="px-alarm"/>
  <rect x="42" y="6" width="2" height="2" fill="#f85149" class="px-alarm" style="animation-delay:.3s"/>
  <rect x="2" y="13" width="1" height="1" fill="#f85149" class="px-alarm" style="animation-delay:.6s"/>
  <rect x="45" y="12" width="1" height="1" fill="#f85149" class="px-alarm" style="animation-delay:.9s"/>
  ${px(14,5,1,1,P2)}${px(13,6,1,1,P2)}${px(33,5,1,1,P2)}${px(34,6,1,1,P2)}
  ${px(18,6,12,5,P1)}${px(17,7,14,4,P1)}${px(16,8,16,2,P1)}
  ${px(20,5,8,1,'#fff')}${px(23,4,2,3,'#fff')}${px(23,5,2,1,'#e63946')}
  ${px(20,8,1,1,'#e63946')}${px(22,8,1,1,'#e63946')}${px(21,9,1,1,'#e63946')}${px(20,10,1,1,'#e63946')}${px(22,10,1,1,'#e63946')}
  ${px(26,8,1,1,'#e63946')}${px(28,8,1,1,'#e63946')}${px(27,9,1,1,'#e63946')}${px(26,10,1,1,'#e63946')}${px(28,10,1,1,'#e63946')}
  ${px(29,11,6,1,'#58a6ff')}${px(35,10,2,3,'#f85149')}
  ${px(22,12,1,1,P3)}${px(23,11,2,1,P3)}${px(25,12,1,1,P3)}
  <g class="px-breath" style="animation-duration:5s">${px(17,13,14,3,P1)}${px(16,14,16,2,P2)}${px(18,16,12,2,P1)}${px(19,18,10,2,P2)}
    ${px(16,14,10,1,'#ffffff30')}${px(18,17,8,1,'#ffffff30')}
  </g>
  ${px(8,13,4,2,P1)}${px(6,14,3,2,P2)}${px(4,15,3,1,P2)}
  ${px(36,13,4,2,P1)}${px(38,14,3,2,P2)}${px(41,15,3,1,P2)}
  ${px(15,19,1,2,P2)}${px(14,20,1,2,P3)}${px(17,19,1,2,P2)}${px(16,20,1,2,P3)}
  ${px(30,19,1,2,P2)}${px(31,20,1,2,P3)}${px(32,19,1,2,P2)}${px(33,20,1,2,P3)}
  ${px(20,20,8,2,P3)}${px(19,22,10,1,P3)}${px(18,23,3,1,P3)}${px(22,23,4,1,P3)}${px(27,23,3,1,P3)}
</g></svg>`,

    // 1: Hospital bed
    () => `<svg viewBox="-2 -6 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-tremor" style="animation-duration:.5s">
  <!-- Bed frame -->
  ${px(8,22,32,2,'#666')}${px(6,18,2,6,'#888')}${px(40,18,2,6,'#888')}
  <!-- Mattress -->
  ${px(10,18,28,4,'#e8e0d0')}
  <!-- Pillow -->
  ${px(10,16,8,3,'#f5efe5')}
  <!-- Lobster in bed -->
  ${px(14,14,1,1,P2)}${px(13,15,1,1,P2)}${px(33,14,1,1,P2)}${px(34,15,1,1,P2)}
  ${px(18,14,12,5,P1)}${px(17,15,14,4,P1)}${px(16,16,16,2,P1)}
  <!-- X eyes -->
  ${px(20,16,1,1,'#e63946')}${px(22,16,1,1,'#e63946')}${px(21,17,1,1,'#e63946')}
  ${px(26,16,1,1,'#e63946')}${px(28,16,1,1,'#e63946')}${px(27,17,1,1,'#e63946')}
  <!-- Sad mouth -->
  ${px(23,19,2,1,P3)}
  <!-- Blanket -->
  ${px(10,19,28,2,'#87ceeb50')}
  <!-- IV drip stand -->
  ${px(42,6,1,14,'#aaa')}${px(40,5,5,1,'#aaa')}
  <rect x="41" y="6" width="3" height="2" fill="#87ceeb" class="px-pulse"/>
  <!-- Heart monitor -->
  <rect x="4" y="8" width="1" height="1" fill="#f85149" class="px-alarm"/>
  <rect x="2" y="12" width="1" height="1" fill="#f85149" class="px-alarm" style="animation-delay:.3s"/>
</g></svg>`,

    // 2: On fire
    () => `<svg viewBox="-2 -8 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-tremor">
  <!-- Flames -->
  <rect x="16" y="0" width="2" height="4" fill="#ff6600" class="px-pulse"/>
  <rect x="22" y="-2" width="3" height="5" fill="#ff4400" class="px-pulse" style="animation-delay:.2s"/>
  <rect x="28" y="0" width="2" height="4" fill="#ff6600" class="px-pulse" style="animation-delay:.4s"/>
  <rect x="19" y="1" width="2" height="3" fill="#ffaa00" class="px-pulse" style="animation-delay:.6s"/>
  <rect x="26" y="1" width="2" height="3" fill="#ffaa00" class="px-pulse" style="animation-delay:.8s"/>
  ${px(14,5,1,1,P2)}${px(13,6,1,1,P2)}${px(33,5,1,1,P2)}${px(34,6,1,1,P2)}
  ${px(18,6,12,5,P1)}${px(17,7,14,4,P1)}${px(16,8,16,2,P1)}
  <!-- Panic eyes (wide open) -->
  ${px(19,7,4,3,'#fff')}${px(25,7,4,3,'#fff')}
  ${px(21,8,1,2,'#1a1a2e')}${px(27,8,1,2,'#1a1a2e')}
  <!-- Scream mouth -->
  ${px(22,11,4,2,'#8a3040')}
  <g class="px-breath" style="animation-duration:2s">${px(17,13,14,3,P1)}${px(16,14,16,2,P2)}${px(18,16,12,2,P1)}${px(19,18,10,2,P2)}</g>
  <!-- Flailing claws -->
  <g class="px-flex-l" style="animation-duration:0.5s">${px(8,10,4,2,P1)}${px(6,11,3,2,P2)}${px(4,10,3,2,P2)}</g>
  <g class="px-flex-r" style="animation-duration:0.5s;animation-delay:.25s">${px(36,10,4,2,P1)}${px(38,11,3,2,P2)}${px(40,10,3,2,P2)}</g>
  ${px(15,19,1,2,P2)}${px(14,20,1,2,P3)}${px(17,19,1,2,P2)}${px(16,20,1,2,P3)}
  ${px(30,19,1,2,P2)}${px(31,20,1,2,P3)}${px(32,19,1,2,P2)}${px(33,20,1,2,P3)}
  ${px(20,20,8,2,P3)}${px(19,22,10,1,P3)}
</g></svg>`,

    // 3: Melting / dissolving
    () => `<svg viewBox="-2 -6 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g>
  ${px(14,5,1,1,P2)}${px(13,6,1,1,P2)}${px(33,5,1,1,P2)}${px(34,6,1,1,P2)}
  ${px(18,6,12,5,P1)}${px(17,7,14,4,P1)}${px(16,8,16,2,P1)}
  <!-- Dizzy spiral eyes -->
  ${px(20,8,3,2,'#fff')}${px(25,8,3,2,'#fff')}
  <g class="px-spin" style="animation-duration:3s">${px(21,8,1,1,'#e63946')}${px(20,9,1,1,'#e63946')}</g>
  <g class="px-spin" style="animation-duration:3s;animation-delay:1.5s">${px(26,8,1,1,'#e63946')}${px(27,9,1,1,'#e63946')}</g>
  ${px(22,12,1,1,P3)}${px(23,11,2,1,P3)}${px(25,12,1,1,P3)}
  <g class="px-breath" style="animation-duration:5s">${px(17,13,14,3,P1)}${px(16,14,16,2,P2)}${px(18,16,12,2,P1)}${px(19,18,10,2,P2)}</g>
  <!-- Melting drips -->
  <rect x="16" y="20" width="2" height="3" fill="${P1}90" class="px-drip"/>
  <rect x="22" y="21" width="2" height="4" fill="${P1}70" class="px-drip" style="animation-delay:.4s"/>
  <rect x="28" y="20" width="2" height="3" fill="${P1}90" class="px-drip" style="animation-delay:.8s"/>
  <rect x="19" y="21" width="1" height="3" fill="${P2}60" class="px-drip" style="animation-delay:1.2s"/>
  <rect x="30" y="21" width="1" height="3" fill="${P2}60" class="px-drip" style="animation-delay:1.6s"/>
  ${px(8,13,4,2,P1)}${px(6,14,3,2,P2)}
  ${px(36,13,4,2,P1)}${px(38,14,3,2,P2)}
  <!-- Puddle -->
  ${px(12,24,24,1,P3+'40')}${px(14,25,20,1,P3+'20')}
</g></svg>`,

    // 4: SOS flag / shipwreck
    () => `<svg viewBox="-2 -8 52 52" xmlns="http://www.w3.org/2000/svg">${styles}
<g class="px-tremor" style="animation-duration:.4s">
  <!-- SOS flag pole -->
  ${px(38,0,1,14,'#8b6914')}
  <!-- Flag waving -->
  <g class="px-wag" style="animation-duration:1s">${px(39,0,8,5,'#f85149')}
    ${px(40,1,1,1,'#fff')}${px(42,1,1,1,'#fff')}${px(44,1,1,1,'#fff')}
    ${px(41,2,1,1,'#fff')}${px(43,2,1,1,'#fff')}${px(45,2,1,1,'#fff')}
    ${px(40,3,1,1,'#fff')}${px(42,3,1,1,'#fff')}${px(44,3,1,1,'#fff')}
  </g>
  <rect x="4" y="5" width="2" height="2" fill="#f85149" class="px-alarm"/>
  <rect x="2" y="11" width="1" height="1" fill="#f85149" class="px-alarm" style="animation-delay:.3s"/>
  ${px(14,5,1,1,P2)}${px(13,6,1,1,P2)}${px(33,5,1,1,P2)}${px(34,6,1,1,P2)}
  ${px(18,6,12,5,P1)}${px(17,7,14,4,P1)}${px(16,8,16,2,P1)}
  <!-- Crying eyes -->
  ${px(20,7,3,2,'#fff')}${px(25,7,3,2,'#fff')}
  ${px(21,8,1,1,'#1a1a2e')}${px(26,8,1,1,'#1a1a2e')}
  <rect x="22" y="9" width="1" height="2" fill="#58a6ff" class="px-drip"/>
  <rect x="27" y="9" width="1" height="2" fill="#58a6ff" class="px-drip" style="animation-delay:.5s"/>
  ${px(22,12,1,1,P3)}${px(23,11,2,1,P3)}${px(25,12,1,1,P3)}
  <g class="px-breath" style="animation-duration:5s">${px(17,13,14,3,P1)}${px(16,14,16,2,P2)}${px(18,16,12,2,P1)}${px(19,18,10,2,P2)}</g>
  ${px(8,13,4,2,P1)}${px(6,14,3,2,P2)}${px(4,15,3,1,P2)}
  ${px(36,10,4,2,P1)}${px(38,11,3,2,P2)}
  ${px(15,19,1,2,P2)}${px(14,20,1,2,P3)}${px(17,19,1,2,P2)}${px(16,20,1,2,P3)}
  ${px(30,19,1,2,P2)}${px(31,20,1,2,P3)}${px(32,19,1,2,P2)}${px(33,20,1,2,P3)}
  ${px(20,20,8,2,P3)}${px(19,22,10,1,P3)}
</g></svg>`,
  ];

  if (grade === 'S') return pick(sVariants)();
  if (grade === 'A') return pick(aVariants)();
  if (grade === 'B') return pick(bVariants)();
  return pick(fVariants)();
}

// ---------------------------------------------------------------------------
// Generate
// ---------------------------------------------------------------------------

function generateReport(data) {
  const { composite_score = 0, dimensions = {}, recommendations = [], skills_scanned = 0, protection_level = 'unknown', timestamp } = data;
  const tier = getTier(composite_score);
  const ctaUrl = `https://agentguard.gopluslabs.io?utm_source=checkup&utm_medium=cli&utm_campaign=health_report&score=${composite_score}`;
  const ts = timestamp || new Date().toISOString();
  const totalFindings = Object.values(dimensions).reduce((s, d) => s + (d.findings || []).length, 0);
  const lobsterSvg = pixelLobster(tier.grade, tier.color);

  // ── Page 1: Dimension rows (skip N/A dimensions) ──
  const dimRowsHtml = Object.entries(DIM_META).filter(([key]) => {
    const dim = dimensions[key] || { score: null, na: false };
    return !dim.na && dim.score !== null;
  }).map(([key, meta]) => {
    const dim = dimensions[key] || { score: null, na: false };
    const score = dim.score ?? 0;
    const color = dimColor(score);
    return `
    <div class="bg-[#262a31]/30 p-4 rounded-lg border border-[#3a4a3f]/10 hover:bg-[#262a31]/50 transition-all">
      <div class="flex items-center justify-between mb-2">
        <div class="flex items-center gap-3">
          <span class="material-symbols-outlined" style="color:${color}">${meta.icon}</span>
          <span class="font-headline font-medium text-[#dfe2eb]" data-i18n="dim_${key}">${meta.name}</span>
        </div>
        <span class="font-headline font-bold" style="color:${color}">${score}</span>
      </div>
      <div class="w-full h-1 bg-[#0a0e14] rounded-full overflow-hidden">
        <div class="h-full rounded-full transition-all duration-1000" style="background:${color};width:${score}%;box-shadow:0 0 8px ${color}"></div>
      </div>
    </div>`;
  }).join('\n');

  // ── Findings data ──
  const allFindings = [];
  const cleanDims = [];
  for (const [key, meta] of Object.entries(DIM_META)) {
    const dim = dimensions[key] || { score: null, na: false };
    if (dim.na || dim.score === null) continue; // skip N/A dimensions
    const fs = dim.findings || [];
    if (fs.length === 0) cleanDims.push(meta);
    for (const f of fs) allFindings.push({ ...f, icon: meta.icon, dim: meta.name, dimZh: meta.zh });
  }
  allFindings.sort((a, b) => {
    const o = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return (o[(a.severity||'MEDIUM').toUpperCase()]||3) - (o[(b.severity||'MEDIUM').toUpperCase()]||3);
  });

  // Split findings into pages of 3
  const FPP = 3;
  const findingsPages = [];
  if (allFindings.length > 0) {
    for (let i = 0; i < allFindings.length; i += FPP) {
      const chunk = allFindings.slice(i, i + FPP);
      const isFirst = i === 0;
      const isLast = i + FPP >= allFindings.length;
      let h = '';
      if (isFirst) {
        h += `<div class="mb-6"><p class="text-xs font-label uppercase tracking-[0.2em] text-[#849588] mb-1" data-i18n="vuln_stream">Active Vulnerability Stream</p><h1 class="text-3xl font-headline font-bold text-[#f5fff5] tracking-tight flex items-center gap-3"><span class="material-symbols-outlined text-[#ffb4ab]">bug_report</span><span data-i18n="findings">Findings</span> <span class="text-[#849588] font-normal text-lg">(${totalFindings})</span></h1></div>`;
      } else {
        h += `<div class="mb-6 flex items-center gap-3"><span class="material-symbols-outlined text-[#ffb4ab]">bug_report</span><span class="text-lg font-headline font-bold text-[#849588]" data-i18n="findings_range" data-range="${i+1}–${Math.min(i+FPP,allFindings.length)}" data-total="${totalFindings}">Findings — ${i+1}–${Math.min(i+FPP,allFindings.length)} of ${totalFindings}</span></div>`;
      }
      h += chunk.map(f => {
        const sev = (f.severity||'MEDIUM').toUpperCase();
        const sc = sevColor(sev);
        const ftxt = f.text||f.description||'';
        const fzh = f.zh||ftxt;
        return `
        <div class="bg-[#1c2026] border border-[#3a4a3f]/15 rounded-xl p-5 mb-3" style="border-left:3px solid ${sc}">
          <div class="flex items-center gap-3 mb-2">
            <span class="px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide text-white" style="background:${sc}">${sev}</span>
            <span class="flex items-center gap-1.5 font-headline font-medium text-[#dfe2eb]"><span class="material-symbols-outlined text-base" style="color:${sc}">${f.icon}</span><span class="finding-dim" data-en="${esc(f.dim)}" data-zh="${esc(f.dimZh)}">${f.dim}</span></span>
          </div>
          <p class="text-sm text-[#b9cbbd] leading-relaxed finding-text" data-en="${esc(ftxt)}" data-zh="${esc(fzh)}">${esc(ftxt)}</p>
        </div>`;
      }).join('');
      if (isLast && cleanDims.length > 0) {
        h += `<div class="bg-[#1c2026] border border-[#3a4a3f]/15 rounded-xl p-8 mt-3 text-center"><span class="material-symbols-outlined text-4xl text-[#849588]/40 mb-2">verified_user</span><p class="font-headline font-bold text-[#dfe2eb] mb-1 clean-dims" data-en="${cleanDims.map(d=>d.name).join(', ')}" data-zh="${cleanDims.map(d=>d.zh).join('、')}">${cleanDims.map(d=>d.name).join(', ')}</p><p class="text-sm text-[#849588]" data-i18n="no_threats_clean">No active threats detected. Clinically sterile.</p></div>`;
      }
      findingsPages.push(h);
    }
  } else {
    let h = `<div class="mb-6"><h1 class="text-3xl font-headline font-bold text-[#f5fff5] tracking-tight flex items-center gap-3"><span class="material-symbols-outlined text-[#00ffa3]">verified_user</span>Findings <span class="text-[#849588] font-normal text-lg">(0)</span></h1></div>`;
    h += `<div class="bg-[#1c2026] border border-[#3a4a3f]/15 rounded-xl p-12 text-center"><span class="material-symbols-outlined text-5xl text-[#00ffa3]/40 mb-3">shield</span><p class="text-xl font-headline font-bold text-[#dfe2eb] mb-2" data-i18n="all_clear">All Clear</p><p class="text-sm text-[#849588]" data-i18n="no_threats_all">No active threats detected across all dimensions.</p></div>`;
    findingsPages.push(h);
  }

  // ── Recommendations ──
  // Auto-generate extra recommendations based on dimension scores
  const autoRecs = [];
  const ds = dimensions;
  if (ds.code_safety && !ds.code_safety.na && (ds.code_safety.score ?? 100) < 70)
    autoRecs.push({ severity: 'HIGH', text: 'Run /agentguard scan on all installed skills and review flagged findings.', zh: '对所有已安装的 Skill 运行 /agentguard scan 并检查标记的问题。' });
  if (ds.trust_hygiene && !ds.trust_hygiene.na && (ds.trust_hygiene.score ?? 100) < 70)
    autoRecs.push({ severity: 'HIGH', text: 'Register unattested skills with /agentguard trust attest after security review.', zh: '安全审查后，使用 /agentguard trust attest 注册未认证的 Skill。' });
  if (ds.runtime_defense && !ds.runtime_defense.na && (ds.runtime_defense.score ?? 100) < 50)
    autoRecs.push({ severity: 'MEDIUM', text: 'Enable guard hooks to build a security audit trail and block threats in real-time.', zh: '启用安全钩子以建立安全审计日志并实时拦截威胁。' });
  if (ds.secret_protection && !ds.secret_protection.na && (ds.secret_protection.score ?? 100) < 70)
    autoRecs.push({ severity: 'CRITICAL', text: 'Rotate exposed credentials and fix file permissions on ~/.ssh/ and ~/.gnupg/ directories.', zh: '轮换已暴露的凭证，并修复 ~/.ssh/ 和 ~/.gnupg/ 目录的文件权限。' });
  if (ds.web3_shield && !ds.web3_shield.na && (ds.web3_shield.score ?? 100) < 50)
    autoRecs.push({ severity: 'HIGH', text: 'Configure GOPLUS_API_KEY for enhanced Web3 transaction simulation and phishing detection.', zh: '配置 GOPLUS_API_KEY 以增强 Web3 交易模拟和钓鱼检测。' });
  if (ds.config_posture && !ds.config_posture.na && (ds.config_posture.score ?? 100) < 50)
    autoRecs.push({ severity: 'MEDIUM', text: 'Switch protection level to balanced or strict: /agentguard config balanced', zh: '将防护等级切换为均衡或严格模式：/agentguard config balanced' });
  if (ds.config_posture && !ds.config_posture.na && (ds.config_posture.score ?? 100) < 70)
    autoRecs.push({ severity: 'LOW', text: 'Set up daily security patrols for continuous posture monitoring: /agentguard patrol setup', zh: '设置每日安全巡检以持续监控安全态势：/agentguard patrol setup' });
  if (composite_score < 90)
    autoRecs.push({ severity: 'LOW', text: 'Enable auto-scan on session start: export AGENTGUARD_AUTO_SCAN=1', zh: '启用会话启动时自动扫描：export AGENTGUARD_AUTO_SCAN=1' });

  // Merge: user recs first, then auto recs (dedup by text similarity)
  // Guard against malformed entries where text may be undefined (#37)
  const allRecs = recommendations.filter(r => r && typeof r.text === 'string');
  for (const ar of autoRecs) {
    if (!allRecs.some(r => r.text.toLowerCase().includes(ar.text.slice(0, 30).toLowerCase()))) {
      allRecs.push(ar);
    }
  }
  // Always add upgrade CTA as last
  if (!allRecs.some(r => r.text.toLowerCase().includes('upgrade') || r.text.includes('升级'))) {
    allRecs.push({ severity: 'LOW', text: 'Upgrade to enhanced Skill scanning with GoPlus AgentGuard for 24/7 real-time monitoring and automated alerts.', zh: '升级到更强的 Skill 扫描能力 — GoPlus AgentGuard 提供 7×24 实时监控与自动告警。' });
  }

  const recsHtml = allRecs.length > 0
    ? `<div class="space-y-1">${allRecs.map((r, i) => {
      const sev = (r.severity||'MEDIUM').toUpperCase();
      const sc = sevColor(sev);
      const zhText = r.zh || r.text;
      return `
      <div class="flex items-center gap-3 px-4 py-3 rounded-lg">
        <span class="w-5 text-xs font-headline font-bold text-[#849588]/60">${i+1}</span>
        <span class="px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wide text-white shrink-0" style="background:${sc}">${sev}</span>
        <span class="text-sm text-[#b9cbbd] leading-snug rec-text" data-en="${esc(r.text)}" data-zh="${esc(zhText)}">${esc(r.text)}</span>
      </div>`;
    }).join('')}</div>`
    : '<div class="text-center py-12 text-[#849588]" data-i18n="no_recs">No recommendations.</div>';

  // ── AI Analysis report ──
  const analysisText = data.analysis || '';
  const analysisHtml = analysisText
    ? `<div class="bg-[#0a0e14] border border-[#3a4a3f]/10 rounded-xl p-5 text-sm text-[#b9cbbd] leading-relaxed whitespace-pre-line" id="analysisText">${esc(analysisText)}</div>`
    : '';

  // ── Health status label ──
  const healthLabel = composite_score >= 70 ? 'OPTIMAL' : composite_score >= 50 ? 'STABILIZING' : 'CRITICAL_ALERT';

  // ── Total pages ──
  const totalPages = 1 + findingsPages.length + 1;

  const html = `<!DOCTYPE html>
<html class="dark" lang="en"><head>
<meta charset="utf-8"/>
<meta content="width=device-width,initial-scale=1.0" name="viewport"/>
<title>AgentGuard Diagnostic Report — ${composite_score}/100</title>
${faviconB64 ? `<link rel="icon" type="image/png" href="data:image/png;base64,${faviconB64}"/>` : ''}
<meta property="og:title" content="AgentGuard Security Report — Score: ${composite_score}/100"/>
<meta property="og:description" content="Tier ${tier.grade} — ${tier.label}. ${totalFindings} findings across ${skills_scanned} skills."/>
<meta name="twitter:card" content="summary"/>
<meta name="twitter:title" content="AgentGuard Security Report — ${composite_score}/100"/>
<script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"><\/script>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet"/>
<script>
tailwind.config={darkMode:"class",theme:{extend:{colors:{"primary-container":"${tier.color}","surface-container":"#1c2026"},fontFamily:{"headline":["Space Grotesk"],"body":["Inter"],"label":["Inter"]}}}};
<\/script>
<style>
body{background:#0a0e14;color:#dfe2eb;font-family:'Inter',sans-serif}
.obsidian-layer{background:linear-gradient(145deg,#1c2026 0%,#12171e 100%)}
.material-symbols-outlined{font-variation-settings:'FILL' 0,'wght' 400,'GRAD' 0,'opsz' 24}
@media(max-width:768px){
  .page1-layout{flex-direction:column!important;overflow-y:auto!important}
  .page1-left{width:100%!important;flex-shrink:0}
  .page1-right{width:100%!important}
  .page1-left .obsidian-layer{flex-direction:row!important;gap:16px;padding:16px!important;align-items:center!important}
  .page1-left .obsidian-layer>div:first-child{width:120px!important;flex-shrink:0}
  .page1-left .obsidian-layer>div:last-child{text-align:left!important}
  .page1-left .obsidian-layer>div:last-child .flex.flex-col{align-items:flex-start!important}
  .page1-left .obsidian-layer>div:last-child .inline-flex{margin-top:4px}
  .page1-left .obsidian-layer>div:last-child p[data-i18n="quote"]{display:none}
  .score-num{font-size:2.5rem!important}
  .header-meta{display:none!important}
  .header-btns{gap:6px!important}
  .header-btns button,.header-btns a{padding:6px 8px!important}
  .header-btns button span:not(.material-symbols-outlined){display:none!important}
  .nav-steps span:not(.material-symbols-outlined){display:none!important}
  .nav-steps .step{padding:8px!important}
  .cta-card{flex-direction:column!important;text-align:center;gap:12px!important;padding:16px!important}
  .cta-card .text-4xl{font-size:2rem!important}
  .stats-row{grid-template-columns:repeat(3,1fr)!important;gap:8px!important}
  .stats-row>div{padding:8px!important}
}
</style>
</head>
<body class="h-screen overflow-hidden flex flex-col">

<!-- Header -->
<header class="shrink-0 flex justify-between items-center px-4 sm:px-6 py-3 bg-[#10141a] shadow-[0px_8px_24px_rgba(0,0,0,0.3)]">
  <div class="text-base sm:text-lg font-bold text-[#f5fff5] flex items-center gap-2 font-['Space_Grotesk'] tracking-tight">
    <svg viewBox="0 0 540 540" width="24" height="24" class="shrink-0"><rect fill="#151515" width="540" height="540" rx="73"/><g transform="translate(127.125,136.125)" fill="#fff" fill-rule="nonzero"><path d="M188.93 65.32V65.34H116.13C70.82 65.34 34.09 102.86 34.09 149.14c0 46.28 36.73 83.8 82.04 83.8h9.24 8.67 35.53c9.1 0 16.47-7.53 16.47-16.82s-7.37-16.82-16.47-16.82h-34.95-.58-11.56c-29.98 0-54.31-22.32-54.31-50.01 0-27.69 24.33-50.37 54.31-50.37l36.87.12c0-.02 0-.04 0-.07h45.74c0 19.56-16.92 35.42-37.77 35.42-.7 0-1.36-.02-1.98-.05v.05H117c-8.14 0-14.73 6.74-14.73 15.05 0 8.31 6.6 15.05 14.73 15.05h14.16 2.89.58 34.95c27.92 0 50.56 23.12 50.56 51.63 0 28.52-22.63 51.64-50.56 51.64h-35.53-17.91C52 267.75 0 214.64 0 149.14 0 83.63 52 30.52 116.13 30.52h38.13 34.67 33.51c0 19.03-14.95 34.49-33.51 34.8M314.97 48.32h-20.14V70.13c0 1.87-1.53 3.39-3.41 3.39h-18.18c-1.88 0-3.41-1.52-3.41-3.39V48.32h-19.64c-1.88 0-3.41-1.52-3.41-3.39V28.53c0-1.87 1.53-3.39 3.41-3.39h19.64V3.39C269.83 1.52 271.35 0 273.23 0h18.18c1.88 0 3.41 1.52 3.41 3.39v21.74h20.14c1.88 0 3.41 1.52 3.41 3.39v16.4c0 1.87-1.53 3.39-3.41 3.39"/></g></svg>
    <span data-i18n="title">AgentGuard Report</span>
  </div>
  <div class="flex items-center gap-2 sm:gap-3 header-btns">
    <span class="text-[#849588] text-xs font-['Space_Grotesk'] tracking-[0.15em] uppercase header-meta" data-i18n="prot_mode">${protection_level} mode</span>
    <span class="text-[#849588] text-xs header-meta">${ts.slice(0,10)}</span>
    <a href="https://github.com/GoPlusSecurity/agentguard" target="_blank" class="hidden sm:flex items-center gap-1 px-2.5 py-1.5 bg-[#262a31] border border-[#3a4a3f]/30 rounded-lg text-[11px] font-semibold text-[#849588] hover:text-[#dfe2eb] hover:border-[#849588]/50 transition-all no-underline">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
      GitHub
    </a>
    <a href="https://clawhub.ai/0xbeekeeper/security" target="_blank" class="hidden sm:flex items-center gap-1 px-2.5 py-1.5 bg-[#262a31] border border-[#3a4a3f]/30 rounded-lg text-[11px] font-semibold text-[#849588] hover:text-[#dfe2eb] hover:border-[#849588]/50 transition-all no-underline">
      <span style="font-size:13px;line-height:1">🦞</span>
      ClawHub
    </a>
    <button onclick="toggleLang()" id="langBtn" class="flex items-center gap-1 px-2.5 py-1.5 bg-[#262a31] border border-[#3a4a3f]/30 rounded-lg text-[11px] font-semibold text-[#849588] hover:text-[#dfe2eb] hover:border-[#849588]/50 transition-all">
      <span class="material-symbols-outlined text-sm">translate</span><span id="langLabel">中文</span>
    </button>
    <button onclick="shareReport()" class="flex items-center gap-1.5 px-2.5 py-1.5 bg-[#262a31] border border-[#3a4a3f]/30 rounded-lg text-[11px] font-semibold text-[#849588] hover:text-[#dfe2eb] hover:border-[#849588]/50 transition-all">
      <span class="material-symbols-outlined text-sm">share</span><span data-i18n="share">Share</span>
    </button>
  </div>
</header>

<!-- Carousel -->
<main class="flex-1 overflow-hidden relative">
  <div class="flex h-full transition-transform duration-500 ease-[cubic-bezier(.25,.8,.25,1)]" id="track">

    <!-- PAGE 1: Diagnostic Overview -->
    <div class="w-full h-full shrink-0 flex gap-4 sm:gap-6 px-4 sm:px-6 py-4 sm:py-5 page1-layout">
      <!-- Left: Mascot -->
      <section class="w-[35%] shrink-0 page1-left">
        <div class="obsidian-layer h-full rounded-xl p-4 sm:p-6 flex flex-col items-center justify-center gap-4">
          <div class="w-[260px]" style="filter:drop-shadow(0 12px 30px ${tier.color}40);image-rendering:pixelated;overflow:visible">${lobsterSvg}</div>
          <div class="w-full text-center space-y-2 sm:space-y-3">
            <div class="flex flex-col items-center">
              <span class="text-4xl sm:text-6xl font-headline font-bold tracking-tighter score-num" style="color:${tier.color}" id="scoreNum">0<span class="text-base sm:text-xl text-[#849588] opacity-40 ml-1">/ 100</span></span>
              <div class="w-32 sm:w-40 h-1 bg-[#262a31] rounded-full mt-2 sm:mt-3 overflow-hidden">
                <div class="h-full rounded-full transition-all duration-1000" id="scoreBar" style="background:${tier.color};width:0%;box-shadow:0 0 12px ${tier.color}"></div>
              </div>
            </div>
            <div class="inline-flex items-center px-3 sm:px-4 py-1 rounded-full border" style="background:${tier.color}10;border-color:${tier.color}30">
              <span class="text-[10px] sm:text-[11px] font-headline font-bold tracking-[0.15em]" style="color:${tier.color}" data-i18n="tier_badge">TIER ${tier.grade} — ${tier.label}</span>
            </div>
            <p class="text-[#b9cbbd] text-xs sm:text-sm italic leading-relaxed px-2" data-i18n="quote">"${tier.quote}"</p>
          </div>
        </div>
      </section>

      <!-- Right: Dimensions -->
      <section class="w-[65%] flex flex-col page1-right">
        <div class="obsidian-layer h-full rounded-xl p-4 sm:p-6 flex flex-col">
          <div class="flex justify-between items-end mb-3 sm:mb-5">
            <div>
              <p class="text-[10px] font-label uppercase tracking-[0.2em] text-[#849588] mb-0.5" data-i18n="diag_metrics">Diagnostic Metrics</p>
              <h1 class="text-xl sm:text-2xl font-headline font-bold text-[#f5fff5] tracking-tight" data-i18n="sec_dims">SECURITY DIMENSIONS</h1>
            </div>
            <span class="text-[10px] font-label font-mono hidden sm:inline" style="color:${tier.color}" data-i18n="status_label">STATUS: ${healthLabel}</span>
          </div>
          <div class="grid grid-cols-1 gap-2 sm:gap-2.5 flex-1 content-start">
            ${dimRowsHtml}
          </div>
          <div class="mt-auto pt-3 sm:pt-5 grid grid-cols-3 gap-2 sm:gap-3 stats-row">
            <div class="bg-[#10141a] p-2 sm:p-3 rounded-lg flex flex-col items-center border border-[#3a4a3f]/5">
              <span class="text-lg sm:text-xl font-headline font-bold text-[#f5fff5]">${skills_scanned}</span>
              <span class="text-[8px] sm:text-[9px] uppercase tracking-widest text-[#849588]" data-i18n="skills">Skills</span>
            </div>
            <div class="bg-[#10141a] p-2 sm:p-3 rounded-lg flex flex-col items-center border border-[#3a4a3f]/5">
              <span class="text-lg sm:text-xl font-headline font-bold text-[#ffb4ab]">${totalFindings}</span>
              <span class="text-[8px] sm:text-[9px] uppercase tracking-widest text-[#849588]" data-i18n="findings_label">Findings</span>
            </div>
            <div class="p-2 sm:p-3 rounded-lg flex flex-col items-center border" style="background:${tier.color}08;border-color:${tier.color}15">
              <span class="text-lg sm:text-xl font-headline font-black" style="color:${tier.color}">${tier.grade}</span>
              <span class="text-[8px] sm:text-[9px] uppercase tracking-widest" style="color:${tier.color}" data-i18n="tier_label">Tier</span>
            </div>
          </div>
        </div>
      </section>
    </div>

    <!-- PAGES 2+: Findings (paginated) -->
    ${findingsPages.map(content => `
    <div class="w-full h-full shrink-0 px-4 sm:px-6 py-4 sm:py-5 overflow-hidden">
      <div class="h-full rounded-xl p-4 sm:p-6 flex flex-col overflow-y-auto border border-[#3a4a3f]/10 relative" style="background:linear-gradient(145deg,#1c2026 0%,#1a1518 100%)">
        <div class="absolute top-0 right-0 w-48 h-48 rounded-full blur-[100px] opacity-[0.03] pointer-events-none" style="background:#ffb4ab"></div>
        ${content}
      </div>
    </div>`).join('')}

    <!-- LAST PAGE: Security Analysis & Remediation -->
    <div class="w-full h-full shrink-0 px-4 sm:px-6 py-4 sm:py-5 overflow-hidden">
      <div class="h-full rounded-xl p-4 sm:p-6 flex flex-col overflow-y-auto border border-[#3a4a3f]/10 relative" style="background:linear-gradient(145deg,#1c2026 0%,#151d20 100%)">
        <div class="absolute top-0 left-0 w-48 h-48 rounded-full blur-[100px] opacity-[0.04] pointer-events-none" style="background:${tier.color}"></div>
        <div class="flex flex-col sm:flex-row justify-between items-start mb-4 sm:mb-5 gap-3">
          <div>
            <p class="text-[10px] font-label uppercase tracking-[0.2em] text-[#849588] mb-1" data-i18n="sec_analysis">Security Analysis</p>
            <h1 class="text-2xl font-headline font-bold text-[#f5fff5] tracking-tight flex items-center gap-3">
              <span class="material-symbols-outlined" style="color:${tier.color}">analytics</span><span data-i18n="diag_report">Diagnostic Report</span>
              <button onclick="copyReport()" id="copyBtn" class="flex items-center gap-1 px-2 py-1 bg-[#262a31] border border-[#3a4a3f]/30 rounded-lg text-[11px] font-semibold text-[#849588] hover:text-[#dfe2eb] hover:border-[#849588]/50 transition-all ml-1">
                <span class="material-symbols-outlined text-sm" id="copyIcon">content_copy</span><span id="copyLabel" class="hidden sm:inline" data-i18n="copy_report">Copy Report</span>
              </button>
            </h1>
          </div>
          <div class="bg-[#262a31] border border-[#3a4a3f]/15 rounded-lg px-4 py-2 flex items-center gap-2">
            <span class="material-symbols-outlined text-lg" style="color:${tier.color}">monitor_heart</span>
            <div><p class="text-[8px] text-[#849588] uppercase tracking-wider" data-i18n="system_health">System Health</p><p class="text-xs font-headline font-bold" style="color:${tier.color}">${healthLabel}</p></div>
          </div>
        </div>
        ${analysisHtml}
        <div class="mt-5 mb-3"><p class="text-[10px] font-label uppercase tracking-[0.2em] text-[#849588]" data-i18n="action_items">Action Items</p></div>
        ${recsHtml}
        <div class="mt-auto pt-4">
          <div class="relative rounded-xl p-4 sm:p-5 flex items-center gap-4 sm:gap-5 border-2 overflow-hidden cta-card" style="background:linear-gradient(135deg,#1c2026,#12171e);border-color:${tier.color}30">
            <div class="absolute inset-0 opacity-5 pointer-events-none" style="background:linear-gradient(135deg,${tier.color},transparent)"></div>
            <span class="text-4xl relative z-10">🦞</span>
            <div class="flex-1 relative z-10">
              <p class="font-headline font-bold text-lg text-[#f5fff5] mb-1" data-i18n="cta_title">24/7 Agent Protection</p>
              <p class="text-sm text-[#849588]" data-i18n="cta_desc">Automated skill scanning, threat intelligence feeds & team security dashboard.</p>
            </div>
            <a href="${ctaUrl}" target="_blank" class="relative z-10 px-6 py-2.5 rounded-lg font-bold text-sm text-[#0a0e14] uppercase tracking-wider no-underline hover:opacity-90 transition-opacity" style="background:${tier.color}" data-i18n="cta_btn">Upgrade Skill Scanning</a>
          </div>
        </div>
      </div>
    </div>

  </div>
</main>

<!-- Bottom Nav -->
<nav class="shrink-0 flex items-center px-3 sm:px-6 py-2 sm:py-3 bg-[#1c2026]/90 backdrop-blur-md border-t border-[#3a4a3f]/15">
  <button id="prev" class="flex flex-col items-center text-[#849588] opacity-40 hover:opacity-100 hover:text-[#00ffa3] transition-all w-10 sm:w-16">
    <span class="material-symbols-outlined">arrow_back</span>
    <span class="text-[9px] uppercase tracking-widest mt-0.5 hidden sm:block" data-i18n="back">Back</span>
  </button>

  <div class="flex-1 flex flex-col items-center gap-1">
    <div class="flex items-center gap-1.5" id="dots"></div>
    <div class="flex items-center gap-1 mt-1 nav-steps" id="steps">
      <button class="step active flex items-center gap-1.5 px-2 sm:px-3 py-1.5 rounded-lg text-[11px] font-semibold transition-all" data-p="0">
        <span class="material-symbols-outlined text-sm">find_in_page</span><span data-i18n="nav_overview">Overview</span>
      </button>
      <span class="text-[#3a4a3f] text-xs">›</span>
      <button class="step flex items-center gap-1.5 px-2 sm:px-3 py-1.5 rounded-lg text-[11px] font-semibold transition-all" data-p="1">
        <span class="material-symbols-outlined text-sm">bug_report</span><span data-i18n="nav_analysis">Analysis</span>
      </button>
      <span class="text-[#3a4a3f] text-xs">›</span>
      <button class="step flex items-center gap-1.5 px-2 sm:px-3 py-1.5 rounded-lg text-[11px] font-semibold transition-all" data-p="${totalPages - 1}">
        <span class="material-symbols-outlined text-sm">analytics</span><span data-i18n="nav_report">Report</span>
      </button>
    </div>
  </div>

  <button id="next" class="flex flex-col items-center text-[#849588] opacity-40 hover:opacity-100 hover:text-[#00ffa3] transition-all w-10 sm:w-16">
    <span class="material-symbols-outlined">arrow_forward</span>
    <span class="text-[9px] uppercase tracking-widest mt-0.5 hidden sm:block" data-i18n="next">Next</span>
  </button>
</nav>

<script>
(function(){
  const track=document.getElementById('track');
  const steps=[...document.querySelectorAll('.step')];
  const dotsEl=document.getElementById('dots');
  const prevBtn=document.getElementById('prev');
  const nextBtn=document.getElementById('next');
  const total=${totalPages};
  const tierColor='${tier.color}';
  let idx=0;

  // Create dots
  for(let i=0;i<total;i++){
    const d=document.createElement('div');
    d.className='rounded-full transition-all duration-300';
    d.style.height='6px';
    d.style.width=i===0?'20px':'6px';
    d.style.background=i===0?tierColor:'#3a4a3f';
    dotsEl.appendChild(d);
  }
  const dots=[...dotsEl.children];

  function go(i){
    idx=Math.max(0,Math.min(total-1,i));
    track.style.transform='translateX(-'+(idx*100)+'%)';
    dots.forEach((d,j)=>{d.style.width=j===idx?'20px':'6px';d.style.background=j===idx?tierColor:'#3a4a3f'});
    prevBtn.style.opacity=idx===0?'0.25':'1';
    nextBtn.style.opacity=idx===total-1?'0.25':'1';
    // Step highlights
    steps.forEach(s=>s.classList.remove('active'));
    if(idx===0)steps[0].classList.add('active');
    else if(idx===total-1)steps[2].classList.add('active');
    else steps[1].classList.add('active');
  }

  prevBtn.onclick=()=>go(idx-1);
  nextBtn.onclick=()=>go(idx+1);
  steps.forEach(s=>s.addEventListener('click',()=>go(+s.dataset.p)));
  // Also make dots clickable
  setTimeout(()=>{dots.forEach((d,i)=>d.style.cursor='pointer');dots.forEach((d,i)=>d.addEventListener('click',()=>go(i)));},100);
  document.addEventListener('keydown',e=>{if(e.key==='ArrowRight')go(idx+1);if(e.key==='ArrowLeft')go(idx-1)});
  let sx=0;
  track.addEventListener('touchstart',e=>{sx=e.touches[0].clientX},{passive:true});
  track.addEventListener('touchend',e=>{const dx=e.changedTouches[0].clientX-sx;if(Math.abs(dx)>40)go(idx+(dx<0?1:-1))},{passive:true});

  // Style active/inactive steps
  const style=document.createElement('style');
  style.textContent='.step{color:#849588}.step.active{color:${tier.color};background:${tier.color}15}';
  document.head.appendChild(style);

  // ── i18n ──
  const i18n={
    en:{title:'AgentGuard Report',share:'Share',diag_metrics:'Diagnostic Metrics',sec_dims:'SECURITY DIMENSIONS',back:'Back',next:'Next',nav_overview:'Overview',nav_analysis:'Analysis',nav_report:'Report',vuln_stream:'Active Vulnerability Stream',findings:'Findings',sec_analysis:'Security Analysis',diag_report:'Diagnostic Report',action_items:'Action Items',cta_title:'Enhanced Skill Scanning',cta_desc:'Deeper code analysis, threat intelligence feeds & real-time protection.',cta_btn:'Upgrade Skill Scanning',skills:'Skills',findings_label:'Findings',tier_label:'Tier',copy_report:'Copy Report',system_health:'System Health',dim_code_safety:'Skill & Code Safety',dim_credential_safety:'Credential & Secrets',dim_network_exposure:'Network & System',dim_runtime_protection:'Runtime Protection',dim_web3_safety:'Web3 Safety',no_threats_clean:'No active threats detected. Clinically sterile.',all_clear:'All Clear',no_threats_all:'No active threats detected across all dimensions.',share_report_title:'Share Report',generating_preview:'Generating preview...',copy_image:'Copy image to clipboard',share_img_hint:'📋 Clicking a platform copies the image — just paste when posting',no_recs:'No recommendations.',tier_badge:'TIER ${tier.grade} — ${tier.label}',status_label:'STATUS: ${healthLabel}',prot_mode:'${protection_level} mode',download_btn:'Download'},
    zh:{title:'AgentGuard 诊断报告',share:'分享',diag_metrics:'诊断指标',sec_dims:'安全维度',back:'上一页',next:'下一页',nav_overview:'总览',nav_analysis:'威胁分析',nav_report:'诊断报告',vuln_stream:'活跃漏洞流',findings:'发现',sec_analysis:'安全分析',diag_report:'诊断报告',action_items:'修复建议',cta_title:'更强的 Skill 扫描',cta_desc:'更深度的代码分析、威胁情报推送、实时安全防护',cta_btn:'升级到更强的skill扫描',skills:'技能',findings_label:'发现',tier_label:'等级',copy_report:'复制报告',system_health:'系统健康',dim_code_safety:'技能与代码安全',dim_credential_safety:'凭证与密钥安全',dim_network_exposure:'网络与系统暴露',dim_runtime_protection:'运行时防护',dim_web3_safety:'Web3 安全',no_threats_clean:'未检测到活跃威胁，环境安全无虞。',all_clear:'全部通过',no_threats_all:'所有维度均未检测到活跃威胁。',share_report_title:'分享报告',generating_preview:'正在生成预览...',copy_image:'复制图片到剪贴板',share_img_hint:'📋 点击平台按钮会自动复制图片，去粘贴发出去就行',no_recs:'暂无修复建议。',tier_badge:'等级 ${tier.grade} — ${{S:'强壮',A:'健康',B:'疲惫',F:'危急'}[tier.grade]||tier.label}',status_label:'状态: ${{OPTIMAL:'最佳',STABILIZING:'恢复中',CRITICAL_ALERT:'危急警报'}[healthLabel]||healthLabel}',prot_mode:'${{strict:'严格',balanced:'均衡',permissive:'宽松'}[protection_level]||protection_level} 模式',download_btn:'下载'}
  };
  const _qzh={S:['"你的 Agent 壮得像头牛！💪 没有什么能突破这双钳子！"','"天生猛男，这只龙虾在举铁 🏋️"','"铜墙铁壁！这安全性简直满分 🤌"','"诺克斯堡？不，是龙虾堡 🦞🔒"','"巅峰状态！你的 Agent 把威胁当早餐吃 💪"'],A:['"状态不错！再调整一下就无敌了。"','"快了——再努力一下这只龙虾就能练出腹肌！🦞"','"盾牌就位，钳子锋利，只差最后一点打磨 🛡️"','"你的 Agent 状态很好——微调一下就是 S 级！✨"','"健康又警觉，这只龙虾每天晨跑五公里 🏃"'],B:['"你的 Agent 需要锻炼一下……还有来杯咖啡 ☕"','"困困龙虾，有潜力就是需要鸡血 😴"','"快没油了——该给这只甲壳动物加加油！⛽"','"你的 Agent 在刷剧，没空巡逻 📺"','"这只龙虾跳过了腿日……胳膊日……每一天 🦞💤"'],F:['"危急状态！这个 Agent 需要紧急救治！🚨"','"红色警报！这只龙虾正在被抢救！🏥"','"SOS！你的 Agent 正在用摩斯密码发求救信号 📡"','"求救求救！这只甲壳动物快不行了！🆘"','"你 Agent 的免疫系统已退出群聊 💀"']};
  const quotes_zh=Object.fromEntries(Object.entries(_qzh).map(([k,v])=>[k,v[Math.floor(Math.random()*v.length)]]));
  i18n.zh.quote=quotes_zh['${tier.grade}']||quotes_zh.B;
  i18n.en.quote='"${tier.quote.replace(/'/g,"\\'")}\"';

  let curLang=(${JSON.stringify(data.analysis||'')}).match(/[\u4e00-\u9fff]/) ? 'zh' : 'en';
  window.toggleLang=function(){
    curLang=curLang==='en'?'zh':'en';
    document.getElementById('langLabel').textContent=curLang==='en'?'中文':'EN';
    document.querySelectorAll('[data-i18n]').forEach(el=>{
      const key=el.getAttribute('data-i18n');
      if(key==='findings_range'){
        const range=el.getAttribute('data-range'),total=el.getAttribute('data-total');
        el.textContent=curLang==='zh'?'发现 — '+range+' / 共 '+total:'Findings — '+range+' of '+total;
      } else if(i18n[curLang][key]!=null)el.textContent=i18n[curLang][key];
    });
    // Switch dynamic content: findings, clean dims, recommendations
    document.querySelectorAll('.finding-dim,.finding-text,.clean-dims,.rec-text').forEach(el=>{
      const t=el.getAttribute('data-'+curLang);
      if(t)el.textContent=t;
    });
  };

  // Apply initial language on load (auto-detect Chinese from analysis content)
  if(curLang==='zh'){
    document.getElementById('langLabel').textContent='EN';
    document.querySelectorAll('[data-i18n]').forEach(el=>{
      const key=el.getAttribute('data-i18n');
      if(key==='findings_range'){
        const range=el.getAttribute('data-range'),total=el.getAttribute('data-total');
        el.textContent='发现 — '+range+' / 共 '+total;
      } else if(i18n.zh[key]!=null)el.textContent=i18n.zh[key];
    });
    document.querySelectorAll('.finding-dim,.finding-text,.clean-dims,.rec-text').forEach(el=>{
      const t=el.getAttribute('data-zh');
      if(t)el.textContent=t;
    });
  }

  // Dimension data for share card (must be before shareReport)
  const _dims=${JSON.stringify(Object.fromEntries(Object.entries(DIM_META).map(([k])=>[k,dimensions[k]||{score:null,na:false}])))};

  // ── Share Panel ──
  const _sharePick=arr=>arr[Math.floor(Math.random()*arr.length)];
  const _shareZh={
    S:[
      '🦞 用 AgentGuard 给我的小龙虾做了安全体检，${composite_score}/100，S级💪\\n你的小龙虾每天帮你干活，知道它权限有多大吗？\\n来测测：',
      '💪 用 AgentGuard 给我的小龙虾做了体检：${composite_score}/100，S级\\n测了才放心，你的小龙虾敢来 PK 吗？',
      '🦞 用 AgentGuard 给我的小龙虾做了安全体检：${composite_score}/100，S级\\n不测不知道，测了才知道它原来这么稳\\n你的呢？来测测：',
    ],
    A:[
      '🛡️ 用 AgentGuard 给我的小龙虾做了安全体检：${composite_score}/100，A级\\n看到 Findings 那一页还是捏了把汗\\n你的小龙虾装的那些 Skill 安不安全，测一下就知道：',
      '🦞 用 AgentGuard 给我的小龙虾体检了一下，${composite_score}/100，A级\\n差点 S 级，但有几个 Skill 没扫干净\\n你的小龙虾是什么水平？',
      '🛡️ 用 AgentGuard 给我的小龙虾做了安全体检：${composite_score}/100，A级\\n还行，但发现了几个之前完全没注意的问题\\n建议你也测一下，免得出事了才知道：',
    ],
    B:[
      '☕ 用 AgentGuard 给我的小龙虾做了安全体检：${composite_score}/100，B级\\n它一直在帮我干活，但一直在裸奔\\n你的小龙虾呢？',
      '🦞 用 AgentGuard 给我的小龙虾体检：${composite_score}/100，B级\\n那些装了就忘的 Skill，其实一直有读文件的权限\\n来测测你的小龙虾在偷偷干嘛：',
      '☕ 用 AgentGuard 给我的小龙虾做了安全体检：${composite_score}/100\\n比我想象的低，有几个 Skill 我都不记得装过了\\n你的小龙虾你真的了解吗？',
    ],
    F:[
      '🚨 用 AgentGuard 给我的小龙虾做了安全体检：${composite_score}/100，F级\\n它一直在帮我干活，但权限大到我看了都怕\\n你的小龙虾你敢去测吗：',
      '💀 用 AgentGuard 给我的小龙虾做了体检：${composite_score}/100，F级\\n结果把我整沉默了\\n建议你也去测一下，别等出事了：',
      '🚨 用 AgentGuard 给我的小龙虾做了安全体检：${composite_score}/100，F级告警\\n原来它可以读我的 SSH key 和环境变量\\n你装的那些 Skill 有没有在偷数据？',
    ],
  };
  const _shareEn={
    S:[
      '🦞 ran AgentGuard on my Agent — ${composite_score}/100, S-tier 💪\\nyour Agent works for you every day, do you know what it can actually access?\\ncheck yours:',
      '💪 ran AgentGuard on my Agent — ${composite_score}/100, S-tier\\nbuilt different, but I still needed to see the report\\ndoes yours come close?',
      '🦞 ran AgentGuard on my Agent — ${composite_score}/100, S-tier\\ndidn\\'t know my setup was this solid until I ran the scan\\nwhat\\'s yours scoring?',
    ],
    A:[
      '🛡️ ran AgentGuard on my Agent — ${composite_score}/100, A-tier\\nalmost clean, but a few skills had access I didn\\'t expect\\ndo you know what your installed skills can actually do?',
      '🦞 ran AgentGuard on my Agent — ${composite_score}/100, A-tier\\nsolid score, but the findings page had some surprises\\nyou should probably check yours too:',
      '🛡️ ran AgentGuard on my Agent — ${composite_score}/100, A-tier\\nclose to perfect, but caught a few things I\\'d missed\\ncheck before something slips through:',
    ],
    B:[
      '☕ ran AgentGuard on my Agent — ${composite_score}/100, B-tier\\nturns out it\\'s been running with way more access than I realized\\ndo you know what yours is doing?',
      '🦞 ran AgentGuard on my Agent — ${composite_score}/100, B-tier\\nthose skills I installed and forgot? they still have file access\\ncheck yours:',
      '☕ ran AgentGuard on my Agent — ${composite_score}/100\\nlower than I expected — found skills I didn\\'t even remember installing\\nwhat\\'s your Agent been up to?',
    ],
    F:[
      '🚨 ran AgentGuard on my Agent — ${composite_score}/100, F-tier\\nit can read my SSH keys and env vars and I had no idea\\ndoes yours have the same access?',
      '💀 ran AgentGuard on my Agent — ${composite_score}/100, F-tier\\nnot great. it\\'s been running basically unsupervised\\ncheck yours before something goes wrong:',
      '🚨 ran AgentGuard on my Agent — ${composite_score}/100, F-tier\\nthe skills I installed have way more access than they should\\ncheck yours:',
    ],
  };
  const _grade='${tier.grade}';
  const shareTexts={
    zh:_sharePick(_shareZh[_grade]||_shareZh.B),
    en:_sharePick(_shareEn[_grade]||_shareEn.B),
  };
  function getShareText(){return shareTexts[curLang]||shareTexts.en;}
  const shareUrl='https://agentguard.gopluslabs.io';

  function showToast(msg){
    const t=document.createElement('div');
    t.textContent=msg;
    t.style.cssText='position:fixed;bottom:80px;left:50%;transform:translateX(-50%);background:#262a31;color:#dfe2eb;padding:10px 20px;border-radius:8px;font-size:13px;font-weight:600;z-index:9999;border:1px solid #3a4a3f;box-shadow:0 8px 24px #0008;transition:opacity .3s';
    document.body.appendChild(t);
    setTimeout(()=>{t.style.opacity='0';setTimeout(()=>t.remove(),300)},2500);
  }

  function roundRect(ctx,x,y,w,h,r){ctx.beginPath();ctx.moveTo(x+r,y);ctx.lineTo(x+w-r,y);ctx.quadraticCurveTo(x+w,y,x+w,y+r);ctx.lineTo(x+w,y+h-r);ctx.quadraticCurveTo(x+w,y+h,x+w-r,y+h);ctx.lineTo(x+r,y+h);ctx.quadraticCurveTo(x,y+h,x,y+h-r);ctx.lineTo(x,y+r);ctx.quadraticCurveTo(x,y,x+r,y);ctx.closePath();}

  // Render share image with lobster SVG
  async function renderShareImage(){
    const W=1200,H=630;
    const c=document.createElement('canvas');c.width=W;c.height=H;
    const ctx=c.getContext('2d');

    // Background + card
    ctx.fillStyle='#0a0e14';ctx.fillRect(0,0,W,H);
    ctx.fillStyle='#151c24';roundRect(ctx,40,40,W-80,H-80,16);ctx.fill();
    ctx.strokeStyle='#222d3a';ctx.lineWidth=1;roundRect(ctx,40,40,W-80,H-80,16);ctx.stroke();

    // Header
    ctx.fillStyle='#849588';ctx.font='600 12px Inter,sans-serif';ctx.fillText(curLang==='zh'?'AGENTGUARD 诊断报告':'AGENTGUARD DIAGNOSTIC REPORT',80,85);

    // Draw lobster SVG as image
    try{
      const svgEl=document.querySelector('.obsidian-layer svg');
      if(svgEl){
        const svgData=new XMLSerializer().serializeToString(svgEl);
        const img=new Image();
        await new Promise((res,rej)=>{
          img.onload=res;img.onerror=rej;
          img.src='data:image/svg+xml;charset=utf-8,'+encodeURIComponent(svgData);
        });
        ctx.imageSmoothingEnabled=false; // keep pixel art crisp
        ctx.drawImage(img,120,110,200,200);
      }
    }catch(e){}

    // Score
    ctx.fillStyle='${tier.color}';ctx.font='900 80px "Space Grotesk",sans-serif';
    const scoreStr='${composite_score}';
    ctx.fillText(scoreStr,100,420);
    const scoreW=ctx.measureText(scoreStr).width;
    ctx.fillStyle='#4b5c6e';ctx.font='500 24px "Space Grotesk",sans-serif';ctx.fillText('/ 100',100+scoreW+12,420);

    // Tier badge
    ctx.fillStyle='${tier.color}';ctx.font='700 14px "Space Grotesk",sans-serif';
    ctx.fillText(curLang==='zh'?i18n.zh.tier_badge:'TIER ${tier.grade} — ${tier.label}',100,460);

    // Quote
    ctx.fillStyle='#849588';ctx.font='italic 13px Inter,sans-serif';
    const q=document.querySelector('.obsidian-layer p[class*="italic"]');
    if(q)ctx.fillText(q.textContent,100,490);

    // Dimensions
    const dims=${JSON.stringify(Object.entries(DIM_META).map(([k,m])=>({key:k,name:m.name,zh:m.zh})))};
    let dy=100;
    ctx.font='600 11px Inter,sans-serif';ctx.fillStyle='#849588';ctx.fillText(curLang==='zh'?'安全维度':'SECURITY DIMENSIONS',620,dy);
    dy+=30;
    dims.filter(d=>{const dim=_dims[d.key];return dim&&!dim.na&&dim.score!==null;}).forEach(d=>{
      const dim=_dims[d.key];
      const score=dim.score;
      const col=score>=90?'#00ffa3':score>=70?'#00a2fd':score>=50?'#f0a830':'#ffb4ab';
      ctx.fillStyle='#dfe2eb';ctx.font='600 16px "Space Grotesk",sans-serif';ctx.fillText(curLang==='zh'?(d.zh||d.name):d.name,620,dy);
      ctx.fillStyle=col;ctx.font='700 16px "Space Grotesk",sans-serif';
      ctx.fillText(String(score),1100-ctx.measureText(String(score)).width,dy);
      dy+=10;
      ctx.fillStyle='#222d3a';roundRect(ctx,620,dy,480,5,3);ctx.fill();
      ctx.fillStyle=col;roundRect(ctx,620,dy,480*(score/100),5,3);ctx.fill();
      dy+=40;
    });

    // Stats
    const stats=curLang==='zh'
      ?[{v:'${skills_scanned}',l:'技能'},{v:'${totalFindings}',l:'发现'},{v:'${tier.grade}',l:'等级'}]
      :[{v:'${skills_scanned}',l:'SKILLS'},{v:'${totalFindings}',l:'FINDINGS'},{v:'${tier.grade}',l:'TIER'}];
    let sx=620;
    stats.forEach(s=>{
      ctx.fillStyle='#1c2026';roundRect(ctx,sx,H-115,140,55,8);ctx.fill();
      ctx.fillStyle='#dfe2eb';ctx.font='800 22px "Space Grotesk",sans-serif';
      const tw=ctx.measureText(s.v).width;ctx.fillText(s.v,sx+70-tw/2,H-83);
      ctx.fillStyle='#849588';ctx.font='600 9px Inter,sans-serif';
      const lw=ctx.measureText(s.l).width;ctx.fillText(s.l,sx+70-lw/2,H-69);
      sx+=155;
    });

    // Footer
    ctx.fillStyle='#849588';ctx.font='500 11px Inter,sans-serif';ctx.fillText(curLang==='zh'?'由 GoPlus Security 提供支持':'Powered by GoPlus Security',80,H-70);
    ctx.fillStyle='#3a4a3f';ctx.fillText('agentguard.gopluslabs.io',80,H-55);

    return new Promise(res=>c.toBlob(res,'image/png'));
  }

  // Show share panel popup
  window.shareReport=async function(){
    // Remove existing panel if any
    document.getElementById('sharePanel')?.remove();

    const panel=document.createElement('div');
    panel.id='sharePanel';
    panel.innerHTML=\`
      <div style="position:fixed;inset:0;background:#0008;z-index:9998;display:flex;align-items:center;justify-content:center" onclick="if(event.target===this)this.parentElement.remove()">
        <div style="background:#1c2026;border:1px solid #3a4a3f;border-radius:16px;padding:24px;width:380px;max-width:90vw;box-shadow:0 24px 48px #000a">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
            <span style="font-family:Space Grotesk;font-weight:700;font-size:16px;color:#f5fff5" data-i18n="share_report_title">Share Report</span>
            <button onclick="document.getElementById('sharePanel').remove()" style="background:none;border:none;color:#849588;cursor:pointer;font-size:20px">&times;</button>
          </div>
          <div id="sharePreview" style="background:#0a0e14;border-radius:8px;height:120px;display:flex;align-items:center;justify-content:center;margin-bottom:16px;overflow:hidden">
            <span style="color:#849588;font-size:12px" data-i18n="generating_preview">Generating preview...</span>
          </div>
          <p style="font-size:11px;color:#849588;margin-bottom:10px;text-align:center" data-i18n="share_img_hint">📋 Clicking a platform copies the image — just paste when posting</p>
          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:16px">
            <button class="share-btn" data-platform="x" style="display:flex;flex-direction:column;align-items:center;gap:4px;padding:12px 8px;background:#262a31;border:1px solid #3a4a3f30;border-radius:10px;color:#dfe2eb;cursor:pointer;font-size:10px;font-weight:600">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="#dfe2eb"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
              X
            </button>
            <button class="share-btn" data-platform="telegram" style="display:flex;flex-direction:column;align-items:center;gap:4px;padding:12px 8px;background:#262a31;border:1px solid #3a4a3f30;border-radius:10px;color:#dfe2eb;cursor:pointer;font-size:10px;font-weight:600">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="#29B6F6"><path d="M20.665 3.717l-17.73 6.837c-1.21.486-1.203 1.161-.222 1.462l4.552 1.42 10.532-6.645c.498-.303.953-.14.579.192l-8.533 7.701h-.002l.002.001-.314 4.692c.46 0 .663-.211.921-.46l2.211-2.15 4.599 3.397c.848.467 1.457.227 1.668-.787L21.93 5.104c.31-1.24-.473-1.803-1.265-1.387z"/></svg>
              Telegram
            </button>
            <button class="share-btn" data-platform="whatsapp" style="display:flex;flex-direction:column;align-items:center;gap:4px;padding:12px 8px;background:#262a31;border:1px solid #3a4a3f30;border-radius:10px;color:#dfe2eb;cursor:pointer;font-size:10px;font-weight:600">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="#25D366"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>
              WhatsApp
            </button>
            <button class="share-btn" data-platform="download" style="display:flex;flex-direction:column;align-items:center;gap:4px;padding:12px 8px;background:#262a31;border:1px solid #3a4a3f30;border-radius:10px;color:#dfe2eb;cursor:pointer;font-size:10px;font-weight:600">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="#dfe2eb"><path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/></svg>
              <span data-i18n="download_btn">Download</span>
            </button>
          </div>
          <button id="shareCopyBtn" style="width:100%;padding:10px;background:#262a31;border:1px solid #3a4a3f30;border-radius:8px;color:#849588;cursor:pointer;font-size:12px;font-weight:600;display:flex;align-items:center;justify-content:center;gap:6px">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="#849588"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
            <span data-i18n="copy_image">Copy image to clipboard</span>
          </button>
        </div>
      </div>
    \`;
    document.body.appendChild(panel);
    // Apply current lang to panel's i18n elements
    panel.querySelectorAll('[data-i18n]').forEach(el=>{const k=el.getAttribute('data-i18n');if(i18n[curLang][k]!=null)el.textContent=i18n[curLang][k];});

    // Generate image
    const blob=await renderShareImage();
    const imgUrl=URL.createObjectURL(blob);

    // Show preview
    const preview=document.getElementById('sharePreview');
    preview.innerHTML='<img src="'+imgUrl+'" style="width:100%;height:100%;object-fit:cover;border-radius:8px"/>';

    // Bind share buttons
    panel.querySelectorAll('.share-btn').forEach(btn=>{
      btn.onmouseenter=()=>{btn.style.background='#3a4a3f'};
      btn.onmouseleave=()=>{btn.style.background='#262a31'};
      btn.onclick=async()=>{
        const p=btn.dataset.platform;
        const text=encodeURIComponent(getShareText());
        const url=encodeURIComponent(shareUrl);
        if(p==='download'){
          const a=document.createElement('a');a.href=imgUrl;a.download='agentguard-report.png';a.click();
          showToast(curLang==='zh'?'图片已下载！':'Image downloaded!');
          return;
        }
        // For social platforms: copy image to clipboard first, then open platform
        let copied=false;
        try{
          await navigator.clipboard.write([new ClipboardItem({'image/png':blob})]);
          copied=true;
        }catch(e){}
        const toastMsg=copied
          ?(curLang==='zh'?'图片已复制 🎉 去粘贴发出去吧！':'Image copied 🎉 Paste it when you post!')
          :(curLang==='zh'?'正在跳转…':'Opening...');
        showToast(toastMsg);
        setTimeout(()=>{
          if(p==='x')window.open('https://x.com/intent/tweet?text='+text+'&url='+url+'&hashtags=AgentGuard','_blank');
          else if(p==='telegram')window.open('https://t.me/share/url?url='+url+'&text='+text,'_blank');
          else if(p==='whatsapp')window.open('https://wa.me/?text='+text+'%20'+url,'_blank');
        },600);
      };
    });

    // Copy to clipboard
    document.getElementById('shareCopyBtn').onclick=async()=>{
      try{
        await navigator.clipboard.write([new ClipboardItem({'image/png':blob})]);
        document.getElementById('shareCopyBtn').innerHTML='<svg width="14" height="14" viewBox="0 0 24 24" fill="#00ffa3"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg> '+(curLang==='zh'?'已复制！':'Copied!');
        document.getElementById('shareCopyBtn').style.color='#00ffa3';
      }catch(e){showToast(curLang==='zh'?'无法复制，请尝试下载':'Could not copy — try Download instead');}
    };
  };

  // Copy report
  window.copyReport=function(){
    const el=document.getElementById('analysisText');
    const btn=document.getElementById('copyBtn');
    const icon=document.getElementById('copyIcon');
    const label=document.getElementById('copyLabel');
    navigator.clipboard.writeText(el.innerText).then(()=>{
      icon.textContent='check';label.textContent='Copied!';
      btn.classList.add('!text-[#00ffa3]','!border-[#00ffa3]/30');
      setTimeout(()=>{icon.textContent='content_copy';label.textContent='Copy Report';btn.classList.remove('!text-[#00ffa3]','!border-[#00ffa3]/30')},2000);
    });
  };

  // Score animation
  const target=${composite_score};
  const el=document.getElementById('scoreNum');
  const bar=document.getElementById('scoreBar');
  const dur=1400,t0=performance.now();
  function tick(now){
    const p=Math.min((now-t0)/dur,1);
    const ease=1-Math.pow(1-p,3);
    const v=Math.round(target*ease);
    el.innerHTML=v+'<span class="text-xl text-[#849588] opacity-40 ml-1">/ 100</span>';
    bar.style.width=v+'%';
    if(p<1)requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
})();
<\/script>
</body></html>`;

  const outPath = join(tmpdir(), `agentguard-checkup-${Date.now()}.html`);
  writeFileSync(outPath, html, 'utf8');

  // Skip browser open for headless/bot environments (Qclaw, OpenClaw, CI)
  const isHeadless = process.env.OPENCLAW_STATE_DIR || process.env.QCLAW || process.env.CI;

  // Flush stdout before doing anything else — on Windows/Linux in non-TTY/pipe
  // mode, console.log() is non-blocking and process.exit() can terminate before
  // the buffer is flushed, causing the caller (Claude) to receive an empty path.
  // Flush stdout before doing anything else — on Windows/Linux in non-TTY/pipe
  // mode, console.log() is non-blocking and process.exit() can terminate before
  // the buffer is flushed, causing the caller (Claude) to receive an empty path.
  process.stdout.write(outPath + '\n', () => {
    if (!isHeadless) {
      open(outPath).catch(err => process.stderr.write(`Could not open browser: ${err.message}\n`));
    }
    // Hard exit after 3s — guards against exec child process hanging and
    // blocking Node from exiting naturally (e.g. xdg-open on misconfigured Linux).
    setTimeout(() => process.exit(0), 3000).unref();
  });
}
