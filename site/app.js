(() => {
'use strict';
const NS = 'http://www.w3.org/2000/svg';
const reduce = matchMedia('(prefers-reduced-motion: reduce)');
const EGG = 'M50 4C74 4 92 42 92 72C92 104 74 126 50 126C26 126 8 104 8 72C8 42 26 4 50 4Z';
const FIXFOR = {22: '22.23.4', 24: '24.22.1', 26: '26.12.1'};
let uid = 0;

function rng(seed) { let s = seed >>> 0 || 1; return () => (s = (s * 1664525 + 1013904223) >>> 0) / 4294967296; }
function esc(s) { return String(s).replace(/[&<>"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c])); }
function vlt(a, b) { a = a.split('.').map(Number); b = b.split('.').map(Number); for (let i = 0; i < 3; i++) { if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) < (b[i] || 0); } return false; }
function naiveFlag(stamp) {
  const m = /^NODE (\d+)\.(\d+\.\d+)/.exec(stamp || ''); if (!m) return false;
  const fix = FIXFOR[m[1]]; return !fix || vlt(m[1] + '.' + m[2], fix);
}
function bad(s) { return s === 'BEHIND' || s === 'NO-FIX-LINE'; }

/* One egg, two layers: an opaque shell and an interior that only shows where the light is. */
function eggSVG(o) {
  const id = 'e' + (++uid), r = rng(o.seed || uid * 97);
  let specks = '';
  for (let i = 0; i < 26; i++) specks += `<circle cx="${(r() * 110 - 5).toFixed(1)}" cy="${(r() * 130).toFixed(1)}" r="${(0.5 + r() * 0.9).toFixed(2)}" fill="#8b8576" opacity="${(0.05 + r() * 0.07).toFixed(2)}"/>`;
  let inside;
  if (o.status === 'UNKNOWN') {
    inside = `<rect x="0" y="0" width="100" height="130" fill="#c9c4b8"/><ellipse cx="50" cy="132" rx="50" ry="40" fill="#b8b2a4"/><ellipse cx="50" cy="132" rx="30" ry="22" fill="#a69f90"/>`;
  } else if (o.status === 'EMPTY') {
    inside = `<ellipse cx="50" cy="128" rx="52" ry="54" fill="#d9711c"/><ellipse cx="50" cy="128" rx="42" ry="42" fill="#f7a43a"/><ellipse cx="50" cy="128" rx="30" ry="28" fill="#ffd27a"/>`;
  } else if (o.glow) {
    inside = `<rect x="0" y="0" width="100" height="130" fill="#d9711c"/><ellipse cx="50" cy="132" rx="56" ry="84" fill="#f7a43a"/><ellipse cx="50" cy="134" rx="36" ry="44" fill="#ffd27a"/>` +
      `<circle cx="47" cy="74" r="16" fill="#c4600f"/><circle cx="47" cy="74" r="13" fill="#d9711c"/>`;
    if (bad(o.status)) inside += `<circle cx="64" cy="64" r="5" fill="#7a1030"/><circle cx="70" cy="70" r="2" fill="#7a1030"/>`;
  } else {
    inside = `<ellipse cx="50" cy="128" rx="52" ry="54" fill="#d9711c"/><ellipse cx="50" cy="128" rx="42" ry="42" fill="#f7a43a"/><ellipse cx="50" cy="128" rx="30" ry="28" fill="#ffd27a"/>` +
      `<circle cx="46" cy="88" r="15" fill="#d9711c"/><circle cx="46" cy="88" r="12.5" fill="#e0761b"/><circle cx="42" cy="84" r="3.6" fill="#f7a43a"/>`;
    if (bad(o.status)) inside += `<circle cx="63" cy="77" r="4.6" fill="#7a1030"/><circle cx="68.5" cy="82" r="1.8" fill="#7a1030"/>`;
  }
  const full = o.reveal === 'full';
  const maskRect = full ? `<rect x="-20" y="-10" width="140" height="150" fill="#fff"/>` : `<rect class="mr" x="-200" y="-10" width="0" height="150" fill="#fff"/>`;
  const stamp = o.stamp ? `<g transform="rotate(-8 50 ${o.sy || 50})" class="stamp"><text x="50" y="${o.sy || 50}" text-anchor="middle" font-family="Sometype Mono, monospace" font-weight="700" font-size="${o.fs || 8.6}" fill="#23605c" letter-spacing="-.2">${esc(o.stamp)}</text>` +
    `<line class="strike" x1="${50 - o.stamp.length * 2.7}" x2="${50 + o.stamp.length * 2.7}" y1="${(o.sy || 50) - 3}" y2="${(o.sy || 50) - 3}" stroke="#c0264b" stroke-width="1.6" stroke-linecap="round" opacity="${o.strike ? 1 : 0}"/>` +
    (o.sub ? `<text x="50" y="${(o.sy || 50) + 11}" text-anchor="middle" font-family="Sometype Mono, monospace" font-weight="700" font-size="${(o.fs || 8.6) * .82}" fill="#23605c" class="subst" opacity="${o.strike ? 1 : 0}">${esc(o.sub)}</text>` : '') + `</g>` : '';
  return `<defs><clipPath id="${id}c"><path d="${EGG}"/></clipPath><mask id="${id}m" maskUnits="userSpaceOnUse" x="-20" y="-10" width="140" height="150">${maskRect}</mask></defs>` +
    `<g clip-path="url(#${id}c)"><rect x="0" y="0" width="100" height="130" fill="#f2f0eb"/><g class="spk">${specks}</g>` +
    `<g mask="url(#${id}m)">${inside}</g></g>` +
    `<path d="${EGG}" fill="none" stroke="${o.line || '#0c1540'}" stroke-width="${o.lw || 2.2}"/>` + stamp;
}

/* ---------- rollers ---------- */
function rollers(svg, gap) {
  const w = svg.getBoundingClientRect().width || innerWidth, n = Math.ceil(w / gap) + 1;
  let s = '';
  for (let i = 0; i < n; i++) {
    const cx = i * gap + gap / 2;
    s += `<g transform="translate(${cx} 15)"><circle r="12" fill="#2c3d86"/><g class="rh"><rect x="-12" y="-3" width="24" height="6" fill="#4a5aa6"/><rect x="-3" y="-12" width="6" height="24" fill="#22347a"/></g><circle r="3" fill="#121c4c"/></g>`;
  }
  svg.setAttribute('viewBox', `0 0 ${w} 30`);
  svg.innerHTML = s;
  return [...svg.querySelectorAll('.rh')];
}

/* ---------- the belt ---------- */
const belt = document.getElementById('belt');
const eggsEl = document.getElementById('eggs');
const ledger = document.getElementById('ledger');
const tally = document.getElementById('tally');
let data = null, run = 0, rh = [];

function slip(egg, e) {
  hideSlip();
  const c = document.createElement('div');
  c.className = 'slipcard'; c.id = 'slipcard';
  c.innerHTML = `<b>${esc(e.status)}</b> · ${esc(e.name)}<br><code>${esc(e.path)}</code><br>` +
    (e.runtime ? esc(e.runtime) + '<br>' : '') + `decoder: ${esc(e.decoder)}` +
    (e.version_says ? `<br>version: ${esc(e.version_says)}${e.but ? ' · but ' + esc(e.but) : ''}` : '') +
    (e.used_by && e.used_by.length ? `<br>used by: ${esc(e.used_by[0].replace(/\s+/g, ' '))}` : '') +
    (e.fix ? `<br>fix: ${esc(e.fix)}${e.who ? ' · who: ' + esc(e.who) : ''}` : '');
  belt.appendChild(c);
  const b = belt.getBoundingClientRect(), r = egg.getBoundingClientRect();
  let x = r.left - b.left + r.width / 2 - c.offsetWidth / 2;
  x = Math.max(8, Math.min(b.width - c.offsetWidth - 8, x));
  c.style.left = x + 'px'; c.style.top = '10px';
}
function hideSlip() { const c = document.getElementById('slipcard'); if (c) c.remove(); }

function build(set) {
  const myRun = ++run;
  hideSlip();
  const lot = data.sets[set];
  document.getElementById('settitle').textContent = lot.title;
  eggsEl.innerHTML = ''; ledger.innerHTML = ''; tally.innerHTML = '&nbsp;';
  const eggs = lot.eggs.map((e, i) => {
    const misled = /^NODE /.test(e.stamp) && naiveFlag(e.stamp) !== bad(e.status);
    const sub = misled && e.status === 'FIXED' ? (/Electron/.test(e.runtime) ? 'CHROMIUM DEC.' : /Bun/.test(e.runtime) ? e.runtime.toUpperCase().slice(0, 12) : 'FIXED CODE') : '';
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'egg';
    b.setAttribute('aria-label', `${e.name}: stamp says ${e.stamp}; candling grade ${e.status}`);
    b.innerHTML = `<span class="tag ${e.status}">${e.status === 'FIXED' ? 'FIXED · BLOCK_SWITCH' : e.status}</span><svg viewBox="0 0 100 130">${eggSVG({status: e.status, stamp: e.stamp, sub, glow: true, seed: i * 31 + 7})}</svg><span class="who">${esc(e.name.replace(/ \(.*\)$/, '').slice(0, 22))}</span>`;
    b.addEventListener('mouseenter', () => slip(b, e));
    b.addEventListener('focus', () => slip(b, e));
    b.addEventListener('mouseleave', hideSlip);
    b.addEventListener('blur', hideSlip);
    eggsEl.appendChild(b);
    const li = document.createElement('li');
    li.innerHTML = `<span class="nm">${esc(e.name)}</span><span class="st">stamp: ${misled ? '<s>' + esc(e.stamp) + '</s>' : esc(e.stamp)}</span><br>` +
      `light: ${esc(e.runtime || e.decoder)} · <span class="gr ${e.status}">${e.status}</span>${e.who && bad(e.status) ? ` · who: ${esc(e.who)}` : ''}` +
      (bad(e.status) && !/^NODE /.test(e.stamp) ? '<br><span class="st">no Node version here for a version check to read</span>' : '');
    ledger.appendChild(li);
    return {e, b, li, misled, svg: b.querySelector('svg'), mr: b.querySelector('.mr'), spk: b.querySelector('.spk'),
      strike: b.querySelector('.strike'), subst: b.querySelector('.subst'), graded: false, recalled: false};
  });
  const N = eggs.length, flagged = lot.eggs.filter(e => naiveFlag(e.stamp)).length,
    right = lot.eggs.filter(e => naiveFlag(e.stamp) && bad(e.status)).length,
    missed = lot.eggs.filter(e => !naiveFlag(e.stamp) && bad(e.status)).length,
    behind = lot.eggs.filter(e => bad(e.status)).length;
  const finalTally = `Version stamps flagged <span class="n">${flagged}</span> of ${N}` +
    (flagged ? ` (${right ? right + ' correctly' : 'all wrongly'})` : '') + (missed ? ` and missed ${missed}` : '') +
    `. The light found <span class="n${behind ? '' : ' ok'}">${behind}</span> behind.`;

  const W = () => belt.clientWidth, slotX = () => belt.querySelector('.slot').offsetLeft + 34;
  const eggW = () => eggs[0].b.offsetWidth;
  const pitch = () => Math.max(eggW() + 24, Math.min(170, W() / 6.5));
  rh = rollers(document.getElementById('rollers'), 34);

  function grade(x) {
    if (x.graded) return; x.graded = true;
    x.b.classList.add('graded'); x.li.classList.add('on');
    if (x.strike) x.strike.setAttribute('opacity', x.misled ? 1 : 0);
    if (x.subst) x.subst.setAttribute('opacity', 1);
  }
  function place(k) {
    const sx = slotX(), p = pitch(), w = eggW();
    eggs.forEach((x, i) => {
      if (x.recalled) return;
      const left = sx + (k - i) * p - w / 2;
      const ang = ((k - i) * p) / (w * 0.45) * 57.3;
      x.b.style.transform = `translateX(${left.toFixed(1)}px)`;
      // passed eggs fade out before they reach the recall tray, so the tray only ever holds the bad ones
      const edge = W() - document.getElementById('tray').offsetWidth - 8;
      x.b.style.opacity = Math.max(0, Math.min(1, (edge - left - w) / (w * 0.7) + 1)).toFixed(2);
      x.spk.setAttribute('transform', `rotate(${ang.toFixed(1)} 50 72)`);
      // a narrow band of light while the egg rolls over the slot; the whole egg lights up while it sits on it
      const lit = Math.max(0, 1 - Math.abs(k - i) * 2.4), bw = 34 + lit * lit * w * 1.3, scale = 100 / w;
      x.mr.setAttribute('x', ((sx - bw / 2 - left) * scale).toFixed(1));
      x.mr.setAttribute('width', (bw * scale).toFixed(1));
    });
    rh.forEach(g => g.setAttribute('transform', `rotate(${(k * p / 12 * 57.3 % 360).toFixed(1)})`));
  }
  function recall(x, slotIdx) {
    x.recalled = true;
    const w = eggW(), tray = document.getElementById('tray');
    const nBad = eggs.filter(y => bad(y.e.status)).length, gap = Math.min(w * 0.8, (tray.offsetWidth - 20) / Math.max(nBad, 1));
    const tx = W() - 10 - w / 2 - gap / 2 - slotIdx * gap;
    x.b.style.transition = 'transform .8s cubic-bezier(.5,0,.6,1)';
    x.b.classList.add('recalled'); x.b.style.opacity = 1;
    x.b.style.transform = `translateX(${tx}px) translateY(${tray.offsetHeight - 6 + w * 0.35}px) rotate(84deg) scale(.6)`;
    // recalled eggs stay lit so the spot is visible in the tray
    x.mr.setAttribute('x', -20); x.mr.setAttribute('width', 140);
  }

  if (reduce.matches) {
    const p = Math.min(pitch(), (W() - 20) / N);
    eggs.forEach((x, i) => {
      const w = eggW();
      x.b.style.transform = `translateX(${(W() - N * p) / 2 + i * p + (p - w) / 2}px)`;
      x.mr.setAttribute('x', -20); x.mr.setAttribute('width', 140);
      grade(x);
    });
    tally.innerHTML = finalTally;
    return;
  }

  // a stepping indexer: move one pitch, hold over the light, grade, move on
  const MOVE = 950, HOLD = 1400;
  let t0 = null, recalls = 0;
  const ease = t => t < .5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
  const total = (N + 4) * (MOVE + HOLD);
  function frame(ts) {
    if (myRun !== run) return;
    if (t0 === null) t0 = ts;
    const t = ts - t0, step = Math.floor(t / (MOVE + HOLD)), inStep = t % (MOVE + HOLD);
    const k = step - 2 + (inStep < MOVE ? ease(inStep / MOVE) : 1);
    place(k);
    eggs.forEach((x, i) => {
      if (!x.graded && inStep > MOVE + HOLD * 0.45 && Math.abs(k - i) < 0.05) grade(x);
      if (x.graded && !x.recalled && bad(x.e.status) && k - i > 0.95) recall(x, recalls++);
    });
    if (t < total) requestAnimationFrame(frame);
    else tally.innerHTML = finalTally;
  }
  requestAnimationFrame(frame);
}

/* ---------- big egg & plates ---------- */
function bigEgg() {
  const svg = document.getElementById('bigegg');
  svg.setAttribute('viewBox', '0 0 400 500');
  svg.innerHTML =
    // the candling lamp: a dark housing, a lit ring where the egg sits (flat bands, no glow)
    `<ellipse cx="196" cy="452" rx="150" ry="34" fill="#2c3d86"/>` +
    `<ellipse cx="196" cy="446" rx="96" ry="22" fill="#ffd27a" opacity=".28"/>` +
    `<ellipse cx="196" cy="444" rx="66" ry="15" fill="#ffd27a" opacity=".5"/>` +
    `<ellipse cx="196" cy="442" rx="40" ry="9" fill="#ffd27a"/>` +
    `<g transform="translate(36 8) rotate(-10 160 220) scale(3.2)">${eggSVG({status: 'FIXED', stamp: 'NODE 24.19.0', sub: 'CURSOR 3.27.12', seed: 5, lw: 1.6, line: '#0c1540', sy: 46, fs: 9})}</g>`;
  const mr = svg.querySelector('.mr'), strike = svg.querySelector('.strike');
  const subst = svg.querySelector('.subst');
  subst.setAttribute('opacity', 1);
  const label = document.createElementNS(NS, 'g');
  label.innerHTML = `<rect x="226" y="58" width="150" height="30" rx="6" fill="#6fd08c"/><text x="301" y="78" text-anchor="middle" font-family="Sometype Mono, monospace" font-weight="700" font-size="13" fill="#0d2a17">FIXED · 17 names</text>`;
  label.setAttribute('opacity', 0); svg.appendChild(label);
  if (reduce.matches) { mr.setAttribute('x', -20); mr.setAttribute('width', 140); strike.setAttribute('opacity', 1); label.setAttribute('opacity', 1); return; }
  // the light sweeps across the egg once, then rests on it
  let t0 = null;
  function f(ts) {
    if (t0 === null) t0 = ts;
    const t = Math.min(1, (ts - t0 - 500) / 2600);
    if (t < 0) { requestAnimationFrame(f); return; }
    const e = 1 - Math.pow(1 - t, 3);
    const w = 20 + e * 120, x = 50 - w / 2;
    mr.setAttribute('x', x.toFixed(1)); mr.setAttribute('width', w.toFixed(1));
    if (t > .55) { strike.setAttribute('opacity', 1); label.setAttribute('opacity', Math.min(1, (t - .55) * 4)); }
    if (t < 1) requestAnimationFrame(f);
  }
  requestAnimationFrame(f);
}

function plates() {
  const P = {
    'fixed-table': () => `<g transform="translate(20 10) scale(3.2)">${eggSVG({status: 'FIXED', stamp: 'NODE 24.22.1', reveal: 'full', seed: 11, sy: 46})}</g>` +
      `<g font-family="Sometype Mono, monospace" font-size="15" font-weight="700"><rect x="196" y="300" width="150" height="34" rx="6" fill="#6fd08c"/><text x="271" y="322" text-anchor="middle" fill="#0d2a17">17 / 17 names</text></g>`,
    'bun': () => `<g transform="translate(20 10) scale(3.2)">${eggSVG({status: 'FIXED', stamp: 'NODE 26.3.0', sub: 'BUN 1.4.4', strike: true, reveal: 'full', seed: 12, sy: 46})}</g>`,
    'electron': () => `<g transform="translate(20 10) scale(3.2)">${eggSVG({status: 'FIXED', stamp: 'NODE 24.19.0', sub: 'CHROMIUM DEC.', strike: true, reveal: 'full', seed: 13, sy: 46})}</g>`,
    'shared': () => `<g transform="translate(0 0) scale(2.5)">${eggSVG({status: 'EMPTY', stamp: '/usr/bin/node', reveal: 'full', seed: 14, sy: 46, fs: 8})}</g>` +
      `<path d="M190 250 C 250 250 250 330 262 340" fill="none" stroke="#f7a43a" stroke-width="3" stroke-dasharray="2 7" stroke-linecap="round"/>` +
      `<g transform="translate(200 270) scale(1.5)">${eggSVG({status: 'BEHIND', stamp: 'libbrotli1', sub: '1.1.0-2+b7', strike: false, reveal: 'full', seed: 15, sy: 44, fs: 10})}</g>`,
    'vendor': () => `<g transform="translate(20 10) scale(3.2)">${eggSVG({status: 'BEHIND', stamp: 'vsce-sign', reveal: 'full', seed: 16, sy: 46})}</g>`,
  };
  document.querySelectorAll('[data-egg]').forEach(s => { s.innerHTML = P[s.dataset.egg](); });
  document.querySelectorAll('.plate-egg .subst').forEach(s => s.setAttribute('opacity', 1));
  document.querySelectorAll('[data-mini]').forEach((s, i) => {
    const st = s.dataset.mini;
    s.innerHTML = `<g transform="translate(6 6) scale(1.08)">${eggSVG({status: st, stamp: st === 'NO-FIX-LINE' ? 'NODE 20' : '', reveal: 'full', seed: 40 + i, lw: 2.6, sy: 44, fs: 11})}</g>`;
  });
  const names = ['EXUBERANT_NIBBLE', 'RESERVED', 'EXUBERANT_META_NIBBLE', 'SIMPLE_HUFFMAN_ALPHABET', 'SIMPLE_HUFFMAN_SAME', 'CL_SPACE', 'HUFFMAN_SPACE', 'CONTEXT_MAP_REPEAT', 'BLOCK_LENGTH_1', 'BLOCK_LENGTH_2', 'TRANSFORM', 'DICTIONARY', 'WINDOW_BITS', 'PADDING_1', 'PADDING_2', 'DISTANCE'];
  const tb = document.getElementById('names');
  let rows = names.map((n, i) => `<tr><td>${-(i + 1)}</td><td>FORMAT_${n}</td></tr>`).join('');
  rows += `<tr class="new"><td>-17</td><td>FORMAT_BLOCK_SWITCH ← the fix</td></tr>`;
  tb.innerHTML = rows;
}

/* ---------- wiring ---------- */
document.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', async () => {
  const t = document.getElementById(b.dataset.copy).textContent;
  try { await navigator.clipboard.writeText(t); b.textContent = 'Copied'; } catch { b.textContent = 'Select it'; }
  setTimeout(() => (b.textContent = 'Copy'), 1600);
}));
let current = 'tools';
document.querySelectorAll('[data-set]').forEach(b => b.addEventListener('click', () => {
  current = b.dataset.set;
  document.querySelectorAll('[data-set]').forEach(x => x.setAttribute('aria-pressed', String(x === b)));
  build(current);
}));
document.getElementById('replay').addEventListener('click', () => build(current));
const fr = document.getElementById('footrollers');
if (fr) rollers(fr, 34);
let rt; addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(() => { if (fr) rollers(fr, 34); build(current); }, 250); });

bigEgg(); plates();
fetch('demo.json').then(r => r.json()).then(d => { data = d; build(current); })
  .catch(() => { tally.textContent = 'Could not load demo.json. Open it directly: it holds the real scan.'; });
})();
