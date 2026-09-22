'use strict';

/* ---------- i18n ---------- */
const I18N = {
  en: {
    siteTitle: 'Sentinel',
    liveBadge: 'Serverless · Runs on-device',
    heading: 'Inspect any file, privately.',
    subheading: 'Hashing happens entirely in your browser. Your file never leaves this device — only its fingerprint does.',
    dropText: 'Drop your file here or click to browse',
    dropHint: 'No file size limits — inspect any size locally',
    apiKeyLabel: 'VirusTotal API key (optional)',
    apiKeyPlaceholder: 'Paste your API key to raise the query limit',
    apiKeyHint: 'Used only to raise your VirusTotal query limit — never required.',
    progressReading: 'Reading file...',
    progressDone: 'Done',
    resultTitle: 'Scan result',
    fileNameLabel: 'File name',
    fileSizeLabel: 'Size',
    detectionsLabel: 'Detections',
    aboutTitle: 'How it works',
    card1Title: '100% local scanning',
    card1Text: 'Your file is read in streamed chunks and never uploaded anywhere.',
    card2Title: 'Instant SHA-256',
    card2Text: 'A cryptographic fingerprint is computed on-device, even for huge files.',
    card3Title: 'Smart lookup, no upload',
    card3Text: 'Only the fingerprint is checked against threat databases like VirusTotal.',
    serverlessBadge: 'Serverless / Local',
    footerText: 'Built by',
    statusNew: 'New / not scanned',
    statusUnknown: 'Unknown to VirusTotal',
    statusMalicious: 'Malicious',
    statusSuspicious: 'Suspicious',
    statusSafe: 'Safe',
    noApiKey: 'No API key entered — copy the hash and check manually on VirusTotal.',
    vtError: 'Could not query VirusTotal: ',
    vtErrorHint: ' (this may be a browser CORS restriction — try a proxy if needed).',
    badResponse: 'Unexpected response from the service'
  },
  ar: {
    siteTitle: 'سنتينل',
    liveBadge: 'بدون سيرفر · يعمل على جهازك',
    heading: 'افحص أي ملف بخصوصية تامة.',
    subheading: 'حساب البصمة يتم بالكامل داخل متصفحك. ملفك لا يغادر جهازك أبداً — فقط بصمته الرقمية.',
    dropText: 'اسحب ملفك هنا أو انقر للاختيار',
    dropHint: 'بلا حدود لحجم الملفات — افحص أي حجم محلياً',
    apiKeyLabel: 'مفتاح VirusTotal API (اختياري)',
    apiKeyPlaceholder: 'ضع مفتاحك هنا لرفع حد الاستعلامات',
    apiKeyHint: 'يُستخدم فقط لرفع حد استعلامات VirusTotal — غير مطلوب أبداً.',
    progressReading: 'جاري القراءة...',
    progressDone: 'اكتمل الحساب',
    resultTitle: 'نتيجة الفحص',
    fileNameLabel: 'اسم الملف',
    fileSizeLabel: 'الحجم',
    detectionsLabel: 'محركات الكشف',
    aboutTitle: 'كيف يعمل الموقع؟',
    card1Title: 'فحص محلي 100%',
    card1Text: 'يُقرأ ملفك على شكل أجزاء متتالية ولا يُرفع لأي مكان أبداً.',
    card2Title: 'حساب SHA-256 فوري',
    card2Text: 'تُحسب البصمة الرقمية على جهازك مباشرة، حتى للملفات الضخمة جداً.',
    card3Title: 'استعلام ذكي بدون رفع',
    card3Text: 'فقط البصمة تُفحص عبر قواعد بيانات التهديدات مثل VirusTotal.',
    serverlessBadge: 'بدون سيرفر / محلي',
    footerText: 'تطوير',
    statusNew: 'جديد / غير مفحوص',
    statusUnknown: 'غير معروف لدى VirusTotal',
    statusMalicious: 'خبيث',
    statusSuspicious: 'مشبوه',
    statusSafe: 'آمن',
    noApiKey: 'لم يتم إدخال مفتاح API — يمكنك نسخ البصمة والتحقق يدوياً عبر VirusTotal.',
    vtError: 'تعذر الاستعلام من VirusTotal: ',
    vtErrorHint: ' (قد يكون السبب قيود CORS في المتصفح — جرّب عبر خادم وسيط إن لزم).',
    badResponse: 'استجابة غير متوقعة من الخدمة'
  }
};

let currentLang = 'en';

function applyLang(lang) {
  currentLang = lang;
  const dict = I18N[lang];
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
  document.documentElement.classList.toggle('lang-ar', lang === 'ar');
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (dict[key]) el.textContent = dict[key];
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (dict[key]) el.placeholder = dict[key];
  });
  localStorage.setItem('fi_lang', lang);
}

function applyTheme(theme) {
  const html = document.documentElement;
  if (theme === 'light') {
    html.classList.remove('dark');
    document.body.classList.add('light');
    themeIcon.textContent = '🌙';
  } else {
    html.classList.add('dark');
    document.body.classList.remove('light');
    themeIcon.textContent = '☀️';
  }
  localStorage.setItem('fi_theme', theme);
}

/* ---------- Incremental SHA-256 (pure JS, streaming, low memory) ----------
   Web Crypto's subtle.digest has no update()/final() API, so it cannot hash
   in chunks without holding the whole file in memory. This is a standard
   incremental SHA-256 implementation used instead. */
class SHA256Stream {
  constructor() {
    this.h = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    this.k = new Uint32Array([
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ]);
    this.buffer = new Uint8Array(64);
    this.bufferLen = 0;
    this.totalLen = 0;
  }

  _rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  _processBlock(block) {
    const w = new Uint32Array(64);
    for (let i = 0; i < 16; i++) {
      w[i] = (block[i*4] << 24) | (block[i*4+1] << 16) | (block[i*4+2] << 8) | block[i*4+3];
    }
    for (let i = 16; i < 64; i++) {
      const s0 = this._rotr(w[i-15],7) ^ this._rotr(w[i-15],18) ^ (w[i-15] >>> 3);
      const s1 = this._rotr(w[i-2],17) ^ this._rotr(w[i-2],19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }
    let [a,b,c,d,e,f,g,h] = this.h;
    for (let i = 0; i < 64; i++) {
      const S1 = this._rotr(e,6) ^ this._rotr(e,11) ^ this._rotr(e,25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + this.k[i] + w[i]) | 0;
      const S0 = this._rotr(a,2) ^ this._rotr(a,13) ^ this._rotr(a,22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0;
      d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    this.h[0] = (this.h[0] + a) | 0; this.h[1] = (this.h[1] + b) | 0;
    this.h[2] = (this.h[2] + c) | 0; this.h[3] = (this.h[3] + d) | 0;
    this.h[4] = (this.h[4] + e) | 0; this.h[5] = (this.h[5] + f) | 0;
    this.h[6] = (this.h[6] + g) | 0; this.h[7] = (this.h[7] + h) | 0;
  }

  update(chunk) {
    this.totalLen += chunk.length;
    let offset = 0;
    if (this.bufferLen > 0) {
      const need = 64 - this.bufferLen;
      const take = Math.min(need, chunk.length);
      this.buffer.set(chunk.subarray(0, take), this.bufferLen);
      this.bufferLen += take;
      offset += take;
      if (this.bufferLen === 64) {
        this._processBlock(this.buffer);
        this.bufferLen = 0;
      }
    }
    while (offset + 64 <= chunk.length) {
      this._processBlock(chunk.subarray(offset, offset + 64));
      offset += 64;
    }
    if (offset < chunk.length) {
      const rest = chunk.subarray(offset);
      this.buffer.set(rest, 0);
      this.bufferLen = rest.length;
    }
  }

  digestHex() {
    const bitLenHigh = Math.floor(this.totalLen / 0x20000000);
    const bitLenLow = (this.totalLen << 3) >>> 0;
    const padLen = (this.bufferLen < 56) ? (56 - this.bufferLen) : (120 - this.bufferLen);
    const pad = new Uint8Array(padLen + 8);
    pad[0] = 0x80;
    pad[padLen]   = (bitLenHigh >>> 24) & 0xff;
    pad[padLen+1] = (bitLenHigh >>> 16) & 0xff;
    pad[padLen+2] = (bitLenHigh >>> 8) & 0xff;
    pad[padLen+3] = bitLenHigh & 0xff;
    pad[padLen+4] = (bitLenLow >>> 24) & 0xff;
    pad[padLen+5] = (bitLenLow >>> 16) & 0xff;
    pad[padLen+6] = (bitLenLow >>> 8) & 0xff;
    pad[padLen+7] = bitLenLow & 0xff;
    const savedTotal = this.totalLen;
    this._feedFinal(pad);
    this.totalLen = savedTotal;
    return Array.from(this.h).map(x => x.toString(16).padStart(8,'0')).join('');
  }

  _feedFinal(data) {
    let offset = 0;
    if (this.bufferLen > 0) {
      const need = 64 - this.bufferLen;
      const take = Math.min(need, data.length);
      this.buffer.set(data.subarray(0, take), this.bufferLen);
      this.bufferLen += take;
      offset += take;
      if (this.bufferLen === 64) { this._processBlock(this.buffer); this.bufferLen = 0; }
    }
    while (offset + 64 <= data.length) {
      this._processBlock(data.subarray(offset, offset + 64));
      offset += 64;
    }
    if (offset < data.length) {
      this.buffer.set(data.subarray(offset), 0);
      this.bufferLen = data.length - offset;
    }
  }
}

/* ---------- UI wiring ---------- */
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const progressWrap = document.getElementById('progressWrap');
const progressBar = document.getElementById('progressBar');
const progressLabel = document.getElementById('progressLabel');
const progressStats = document.getElementById('progressStats');
const resultCard = document.getElementById('resultCard');
const statusBadge = document.getElementById('statusBadge');
const rFileName = document.getElementById('rFileName');
const rFileSize = document.getElementById('rFileSize');
const rHash = document.getElementById('rHash');
const rDetections = document.getElementById('rDetections');
const rDetCount = document.getElementById('rDetCount');
const rError = document.getElementById('rError');
const apiKeyInput = document.getElementById('apiKey');
const langToggle = document.getElementById('langToggle');
const themeToggle = document.getElementById('themeToggle');
const themeIcon = document.getElementById('themeIcon');

/* init theme + lang */
const savedTheme = localStorage.getItem('fi_theme') || 'dark';
applyTheme(savedTheme);
const savedLang = localStorage.getItem('fi_lang') || 'en';
applyLang(savedLang);

langToggle.addEventListener('click', () => applyLang(currentLang === 'en' ? 'ar' : 'en'));
themeToggle.addEventListener('click', () => {
  const isDark = document.documentElement.classList.contains('dark');
  applyTheme(isDark ? 'light' : 'dark');
});

dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drop-active'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drop-active'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drop-active');
  if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', () => {
  if (fileInput.files.length) handleFile(fileInput.files[0]);
});

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B','KB','MB','GB','TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + units[i];
}

async function handleFile(file) {
  const dict = I18N[currentLang];
  resultCard.classList.add('hidden');
  rError.classList.add('hidden');
  rDetections.classList.add('hidden');
  progressWrap.classList.remove('hidden');
  progressLabel.textContent = dict.progressReading;
  progressBar.style.width = '0%';

  const hasher = new SHA256Stream();
  const total = file.size;
  let processed = 0;
  const startTime = performance.now();

  const stream = file.stream();
  const reader = stream.getReader();

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      hasher.update(value);
      processed += value.length;

      const pct = total > 0 ? (processed / total) * 100 : 0;
      progressBar.style.width = pct.toFixed(1) + '%';
      const elapsed = (performance.now() - startTime) / 1000;
      const speed = elapsed > 0 ? processed / elapsed : 0;
      progressStats.textContent =
        `${formatBytes(processed)} / ${formatBytes(total)} — ${formatBytes(speed)}/s`;
    }

    const hex = hasher.digestHex();
    progressLabel.textContent = dict.progressDone;
    progressBar.style.width = '100%';

    rFileName.textContent = file.name;
    rFileSize.textContent = formatBytes(file.size);
    rHash.textContent = hex;
    resultCard.classList.remove('hidden');
    setBadge(dict.statusNew, 'bg-white/10 text-slate-200');

    await lookupHash(hex);
  } catch (err) {
    rError.textContent = err.message;
    rError.classList.remove('hidden');
    resultCard.classList.remove('hidden');
  }
}

function setBadge(text, cls) {
  statusBadge.textContent = text;
  statusBadge.className = 'text-xs px-2.5 py-1 rounded-full font-medium ' + cls;
}

/* Sends ONLY the SHA-256 hash to VirusTotal — the file itself never leaves
   the browser. Note: VirusTotal's public API may block direct browser
   requests via CORS; if it fails, the hash is still shown for manual lookup. */
async function lookupHash(hex) {
  const dict = I18N[currentLang];
  const apiKey = apiKeyInput.value.trim();
  if (!apiKey) {
    rError.textContent = dict.noApiKey;
    rError.classList.remove('hidden');
    return;
  }
  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/files/${hex}`, {
      headers: { 'x-apikey': apiKey }
    });
    if (res.status === 404) {
      setBadge(dict.statusUnknown, 'bg-white/10 text-slate-200');
      return;
    }
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const stats = data?.data?.attributes?.last_analysis_stats;
    if (!stats) throw new Error(dict.badResponse);

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const totalEngines = Object.values(stats).reduce((a,b) => a+b, 0);

    rDetections.classList.remove('hidden');
    rDetCount.textContent = `${malicious} / ${suspicious} / ${totalEngines}`;

    if (malicious > 0) setBadge(dict.statusMalicious, 'bg-red-500/15 text-red-300');
    else if (suspicious > 0) setBadge(dict.statusSuspicious, 'bg-amber-500/15 text-amber-300');
    else setBadge(dict.statusSafe, 'bg-emerald-500/15 text-emerald-300');
  } catch (err) {
    rError.textContent = dict.vtError + err.message + dict.vtErrorHint;
    rError.classList.remove('hidden');
  }
}
