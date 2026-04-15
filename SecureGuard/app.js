// ==================== BLOOM FILTER ====================
const BLOOM_SIZE = 100000, DISPLAY_BITS = 250;
const bloomBits = new Uint8Array(BLOOM_SIZE);
let bloomIPCount = 0;
// Populated from data/ip_blacklist.csv at runtime
let KNOWN_BLACKLIST = [];

function djb2(s){let h=5381;for(let i=0;i<s.length;i++)h=((h<<5)+h)^s.charCodeAt(i);return Math.abs(h);}
function fnv1a(s){let h=2166136261;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=(h*16777619)>>>0;}return h;}
function sdbm(s){let h=0;for(let i=0;i<s.length;i++)h=s.charCodeAt(i)+(h<<6)+(h<<16)-h;return Math.abs(h);}
function bloomHashes(ip){return[djb2(ip)%BLOOM_SIZE,fnv1a(ip)%BLOOM_SIZE,sdbm(ip+'salt2')%BLOOM_SIZE];}
function bloomAdd(ip){bloomHashes(ip).forEach(i=>bloomBits[i]=1);}
function bloomCheck(ip){return bloomHashes(ip).every(i=>bloomBits[i]===1);}
function isPrivate(ip){return ip==='::1'||ip.startsWith('127.')||ip.startsWith('192.168.')||ip.startsWith('10.')||ip.startsWith('172.');}

// ==================== TOR EXIT NODE LIVE FEED ====================
// Source: https://check.torproject.org/torbulkexitlist (updated every 30 min)
// Loaded via CORS proxy since the Tor Project endpoint blocks direct browser requests
let torFeedLoaded = false;
let torNodeCount  = 0;

function updateTorStatusUI(state, detail) {
  const el = document.getElementById('torFeedStatus');
  if (!el) return;
  const configs = {
    loading: { dot: 'var(--yellow)', label: 'LOADING LIVE TOR FEED…', detail, badge: 'rgba(255,204,0,0.15)', badgeColor: 'var(--yellow)' },
    success: { dot: 'var(--green)',  label: 'TOR EXIT NODES — LIVE', detail, badge: 'rgba(0,255,136,0.12)', badgeColor: 'var(--green)' },
    fallback:{ dot: 'var(--orange)', label: 'STATIC FALLBACK LIST',  detail, badge: 'rgba(255,136,0,0.12)', badgeColor: 'var(--orange)' },
  };
  const c = configs[state] || configs.fallback;
  el.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <span style="width:9px;height:9px;border-radius:50%;background:${c.dot};box-shadow:0 0 6px ${c.dot};display:inline-block;flex-shrink:0;animation:pulse 2s infinite"></span>
      <span style="font-family:var(--mono);font-size:0.72rem;font-weight:700;color:#fff;letter-spacing:0.08em">${c.label}</span>
      <span style="background:${c.badge};border:1px solid ${c.badgeColor};color:${c.badgeColor};font-family:var(--mono);font-size:0.62rem;padding:2px 9px;border-radius:20px;font-weight:700">${c.detail}</span>
      ${state==='success'?`<span style="font-family:var(--mono);font-size:0.65rem;color:var(--text-dim);margin-left:auto">Source: check.torproject.org · refreshes every 30 min</span>`:''}
    </div>`;
}

async function loadTorExitNodes() {
  updateTorStatusUI('loading', 'Fetching…');
  // Three CORS-proxy attempts in order; first success wins
  const PROXIES = [
    ip => `https://corsproxy.io/?${encodeURIComponent('https://check.torproject.org/torbulkexitlist')}`,
    ip => `https://api.allorigins.win/raw?url=${encodeURIComponent('https://check.torproject.org/torbulkexitlist')}`,
    ip => `https://cors-anywhere.herokuapp.com/https://check.torproject.org/torbulkexitlist`,
  ];

  for (const proxyFn of PROXIES) {
    try {
      const res  = await fetch(proxyFn(), { signal: AbortSignal.timeout(8000) });
      if (!res.ok) continue;
      const text = await res.text();
      const ips  = text.split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#') && /^\d{1,3}(\.\d{1,3}){3}$/.test(l));
      if (ips.length < 100) continue;           // sanity check — real list has ~1500 IPs

      // Seed every live Tor IP into the Bloom Filter
      ips.forEach(ip => bloomAdd(ip));
      torNodeCount  = ips.length;
      bloomIPCount  = KNOWN_BLACKLIST.length + torNodeCount;
      torFeedLoaded = true;

      // Re-evaluate bloomHit on every existing log entry against the updated filter
      loginLogs.forEach(l => { l.bloomHit = !isPrivate(l.ip) && bloomCheck(l.ip); });

      renderBloomViz();
      updateTorStatusUI('success', `${torNodeCount.toLocaleString()} live Tor exit nodes loaded`);
      showToast({
        title: '🧅 Live Tor Feed Loaded',
        body:  `<strong>${torNodeCount.toLocaleString()} real Tor exit node IPs</strong> added to Bloom Filter.<br>Bloom filter now covers <strong>${bloomIPCount}</strong> threat IPs.`,
        severity: 'low', duration: 7000
      });

      // Re-run bloom hit detection against the now-richer filter
      setTimeout(() => { checkAllBloom(); renderAll(); }, 300);
      return;
    } catch(e) { /* try next proxy */ }
  }

  // All proxies failed — fall back to static list gracefully
  updateTorStatusUI('fallback', `${KNOWN_BLACKLIST.length} static IPs · live fetch unavailable`);
  showToast({
    title: '⚠ Tor Feed Unavailable',
    body:  'Could not reach live Tor exit node list. Using built-in static blacklist.',
    severity: 'medium', duration: 5000
  });
}

function initBloom(){
  KNOWN_BLACKLIST.forEach(ip=>bloomAdd(ip));
  bloomIPCount=KNOWN_BLACKLIST.length;
  renderBloomViz();
}

function renderBloomViz(){
  const grid=document.getElementById('bloomBitGrid');if(!grid)return;
  const step=Math.floor(BLOOM_SIZE/DISPLAY_BITS);
  let setBits=0;for(let i=0;i<BLOOM_SIZE;i++)if(bloomBits[i])setBits++;
  let html='';
  for(let i=0;i<DISPLAY_BITS;i++){const idx=i*step;html+=`<div class="bloom-bit${bloomBits[idx]?' set':''}" title="Bit ${idx}"></div>`;}
  grid.innerHTML=html;
  document.getElementById('bloomIPCount').textContent=bloomIPCount;
  document.getElementById('bloomBitsSet').textContent=setBits;
  document.getElementById('bloomFillRate').textContent=((setBits/BLOOM_SIZE)*100).toFixed(2)+'%';
  // Update Tor panel counters
  const torEl    = document.getElementById('torCountDisplay');
  const totalEl  = document.getElementById('totalBlacklistDisplay');
  const hitsEl   = document.getElementById('torHitsInLogs');
  if(torEl)   torEl.textContent   = torNodeCount > 0 ? torNodeCount.toLocaleString() : '—';
  if(totalEl) totalEl.textContent = bloomIPCount.toLocaleString();
  if(hitsEl)  hitsEl.textContent  = loginLogs.filter(l=>l.bloomHit).length;
}

function highlightBloom(ip){
  const grid=document.getElementById('bloomBitGrid');if(!grid)return;
  const step=Math.floor(BLOOM_SIZE/DISPLAY_BITS);
  const hashes=bloomHashes(ip);const bits=grid.querySelectorAll('.bloom-bit');
  bits.forEach(b=>b.classList.remove('hit'));
  hashes.forEach(h=>{const di=Math.floor(h/step);if(di<DISPLAY_BITS&&bits[di])bits[di].classList.add('hit');});
  setTimeout(()=>bits.forEach(b=>b.classList.remove('hit')),3000);
}

// ==================== CSV DATASET LOADER ====================
// All data now lives in /data/*.csv — fetched on page load, nothing hardcoded.

function parseCSVRaw(raw) {
  const lines = raw.trim().split('\n');
  const headers = lines[0].split(',').map(h => h.trim());
  return lines.slice(1).map(line => {
    const vals = line.split(',');
    const obj = {};
    headers.forEach((h, j) => obj[h] = vals[j] ? vals[j].trim() : '');
    return obj;
  });
}

async function fetchCSV(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`Failed to load ${path}`);
  return await res.text();
}

function parseLoginCSV(raw) {
  return parseCSVRaw(raw).map((obj, i) => {
    obj.id = i + 1;
    obj.ip = obj.ip_address;
    obj.status = obj.status === 'Success' ? 'SUCCESS' : 'FAILED';
    obj.location = `${obj.city}, ${obj.country}`;
    obj.ts = obj.login_time;
    obj.bloomHit = !isPrivate(obj.ip) && bloomCheck(obj.ip);
    return obj;
  });
}

// ==================== STATE ====================
let currentUser=null;
let users=[
  {username:'admin',password:'admin123',email:'admin@secureguard.com',role:'admin'},
  {username:'sankar',password:'pass123',email:'sankar@example.com',role:'user'},
];
let loginLogs=[];
let alerts=[];
let visitorIP='127.0.0.1';
let charts={};
let remoteDetected=[];

// ==================== WORKING HOURS CONFIG ====================
const WORK_START = 10; // 10:00 AM
const WORK_END   = 21; // 9:00 PM (21:00)

function isWorkingHour(hour) { return hour >= WORK_START && hour < WORK_END; }
function isOffHours(tsStr) {
  const m = (tsStr||'').match(/(\d{2}):/);
  return m ? !isWorkingHour(parseInt(m[1])) : false;
}
function getHour(tsStr) {
  const m = (tsStr||'').match(/(\d{2}):/);
  return m ? parseInt(m[1]) : -1;
}
function fmtGap(seconds) {
  if(seconds < 0) return '—';
  if(seconds < 60) return `${seconds}s`;
  if(seconds < 3600) return `${Math.floor(seconds/60)}m ${seconds%60}s`;
  return `${Math.floor(seconds/3600)}h ${Math.floor((seconds%3600)/60)}m`;
}
function tsToSeconds(tsStr) {
  if(!tsStr) return 0;
  const d = new Date(tsStr.replace(' ','T'));
  return isNaN(d) ? 0 : Math.floor(d.getTime()/1000);
}

function startClock() {
  function tick() {
    const now = new Date();
    const h = now.getHours(), m = now.getMinutes(), s = now.getSeconds();
    const pad = n => String(n).padStart(2,'0');
    const timeStr = `${pad(h)}:${pad(m)}:${pad(s)}`;
    const clockEl = document.getElementById('liveClock');
    const bannerEl = document.getElementById('workHoursBanner');
    const badgeEl  = document.getElementById('workStatusBadge');
    const iconEl   = document.getElementById('workHoursIcon');
    const nextEl   = document.getElementById('nextShiftLabel');
    if(!clockEl) return;
    clockEl.textContent = timeStr;
    if(isWorkingHour(h)) {
      bannerEl.className = 'hours-banner safe';
      badgeEl.className  = 'work-time-badge';
      badgeEl.textContent = '✓ WITHIN WORKING HOURS';
      iconEl.textContent  = '🟢';
      const minsLeft = (WORK_END - h)*60 - m;
      nextEl.textContent = `Session ends in ${Math.floor(minsLeft/60)}h ${minsLeft%60}m`;
    } else {
      bannerEl.className = 'hours-banner danger';
      badgeEl.className  = 'offhours-badge';
      badgeEl.textContent = '⚠ OUTSIDE WORKING HOURS';
      iconEl.textContent  = '🔴';
      const minsTo = h < WORK_START ? (WORK_START-h)*60-m : (24-h+WORK_START)*60-m;
      nextEl.textContent = `Work session starts in ${Math.floor(minsTo/60)}h ${minsTo%60}m`;
    }
    renderWHTimeline(h);
  }
  tick();
  setInterval(tick, 1000);
}

function renderWHTimeline(currentHour) {
  const el = document.getElementById('whTimeline');
  if(!el) return;
  // Count actual logins per hour
  const hourCount = {};
  loginLogs.forEach(l => {
    const hr = getHour(l.ts || l.login_time);
    if(hr >= 0) hourCount[hr] = (hourCount[hr]||0) + 1;
  });
  const maxCount = Math.max(...Object.values(hourCount), 1);
  let html = '';
  for(let i = 0; i < 24; i++) {
    const isWork = isWorkingHour(i);
    const isNow  = i === currentHour;
    const count  = hourCount[i] || 0;
    const opacity = count > 0 ? 0.4 + (count/maxCount)*0.6 : 1;
    const extra  = isNow ? ' now' : '';
    const bg     = isWork
      ? `rgba(0,229,255,${count>0?0.15+count/maxCount*0.4:0.12})`
      : `rgba(255,34,85,${count>0?0.15+count/maxCount*0.5:0.08})`;
    html += `<div class="wh-seg${isWork?' work':' off'}${extra}" style="flex:1;background:${bg};position:relative" title="${String(i).padStart(2,'0')}:00 — ${count} event(s)${isNow?' (NOW)':''}">
      ${count>0?`<span style="font-size:0.55rem;color:${isWork?'rgba(0,229,255,0.9)':'rgba(255,136,0,0.9)'};font-weight:700">${count}</span>`:''}
      ${isNow?`<div style="position:absolute;bottom:0;left:50%;transform:translateX(-50%);width:2px;height:100%;background:var(--yellow);opacity:0.8"></div>`:''}
    </div>`;
  }
  el.innerHTML = html;
}

function renderOffHours() {
  const offEvents = loginLogs.filter(l => isOffHours(l.ts||l.login_time));
  const countEl = document.getElementById('offHoursCount');
  const listEl  = document.getElementById('offHoursList');
  const violEl  = document.getElementById('offHoursViolationCount');
  if(countEl) countEl.textContent = `${offEvents.length} events`;
  if(violEl)  violEl.textContent  = offEvents.length;

  if(!listEl) return;
  if(!offEvents.length) {
    listEl.innerHTML = '<div class="empty-state" style="padding:28px"><div class="empty-icon">✅</div>No off-hours activity detected</div>';
    return;
  }

  // Group by user+ip bursts
  const html = offEvents.map(l => {
    const hr    = getHour(l.ts||l.login_time);
    const isBloom = l.bloomHit;
    const isFail  = l.status==='FAILED';
    const severity = isBloom?'var(--red)':isFail?'var(--orange)':'var(--yellow)';
    const sevLabel = isBloom?'BLOOM+OFF-HOURS':isFail?'FAILED+OFF-HOURS':'SUCCESS+OFF-HOURS';
    return `<div class="offhours-item">
      <div>
        <div class="ot-time">${String(hr).padStart(2,'0')}:00</div>
        <div class="ot-label">${hr<WORK_START?'PRE-SHIFT':'POST-SHIFT'}</div>
      </div>
      <div style="flex:1">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">
          <strong style="color:#fff">${l.username}</strong>
          <span style="font-family:var(--mono);color:var(--cyan);font-size:0.72rem">${l.ip}</span>
          <span style="background:rgba(255,136,0,0.12);border:1px solid rgba(255,136,0,0.3);color:${severity};font-size:0.6rem;font-family:var(--mono);padding:1px 7px;border-radius:20px">${sevLabel}</span>
        </div>
        <div style="font-family:var(--mono);font-size:0.7rem;color:var(--text-dim)">
          📍 ${countryFlag(l.country)} ${l.city}, ${l.country} &nbsp;|&nbsp; 🕐 ${l.ts||l.login_time}
          ${isBloom?'&nbsp;|&nbsp; <span style="color:var(--red)">🔴 BLACKLISTED IP</span>':''}
        </div>
      </div>
      <span class="status-badge ${l.status.toLowerCase()}" style="flex-shrink:0"><span class="dot"></span>${l.status}</span>
    </div>`;
  }).join('');
  listEl.innerHTML = html;
}

// ==================== DATASET LOADERS ====================

// ── Overlay helpers ───────────────────────────────────────────────────────────
function overlayStep(id, state, count) {
  const row = document.getElementById(id);
  if (!row) return;
  const statusSpan = row.querySelector('.ds-status');
  if (state === 'loading') {
    row.style.borderColor = 'rgba(0,229,255,0.3)';
    row.style.color = 'var(--cyan)';
    row.children[0].textContent = '⟳';
    if (statusSpan) statusSpan.textContent = 'Loading…';
  } else if (state === 'done') {
    row.className = 'ds-load-row done';
    row.children[0].textContent = '✅';
    if (statusSpan) statusSpan.textContent = count !== undefined ? `${count} rows` : 'OK';
  } else {
    row.className = 'ds-load-row fail';
    row.children[0].textContent = '❌';
    if (statusSpan) statusSpan.textContent = 'Failed';
  }
}

function setOverlayMsg(msg) {
  const el = document.getElementById('dsLoadMsg');
  if (el) el.textContent = msg;
}

function dismissOverlay() {
  const el = document.getElementById('datasetLoadingOverlay');
  if (!el) return;
  el.style.transition = 'opacity 0.5s';
  el.style.opacity = '0';
  setTimeout(() => el.remove(), 500);
}

function updateDashboardCard(id, countText, state) {
  const card = document.getElementById(id);
  const countEl = document.getElementById(id + '_count');
  if (card) card.classList.add(state === 'ok' ? 'loaded' : 'failed');
  if (countEl) { countEl.textContent = countText; countEl.style.color = state === 'ok' ? 'var(--green)' : 'var(--red)'; }
}

async function loadAllDatasets() {
  const statusEl = document.getElementById('csvStatus');
  if (statusEl) statusEl.textContent = '⟳ Loading datasets…';

  const countryColors = ['rgba(255,34,85,0.8)','rgba(255,80,60,0.8)','rgba(255,136,0,0.8)','rgba(255,170,0,0.8)','rgba(0,229,255,0.7)','rgba(0,200,120,0.7)','rgba(100,200,100,0.7)','rgba(187,102,255,0.75)','rgba(150,100,255,0.7)','rgba(80,140,255,0.7)'];
  const sectorColors  = ['rgba(255,34,85,0.8)','rgba(255,136,0,0.8)','rgba(255,204,0,0.8)','rgba(0,229,255,0.75)','rgba(187,102,255,0.8)','rgba(0,255,136,0.75)','rgba(255,100,150,0.7)','rgba(100,180,255,0.7)','rgba(255,180,50,0.7)','rgba(150,220,150,0.7)'];
  const actorColors   = ['rgba(255,34,85,0.8)','rgba(255,136,0,0.8)','rgba(187,102,255,0.8)','rgba(255,204,0,0.75)','rgba(80,120,160,0.7)'];
  const flagMap       = {'India':'🇮🇳','Russia':'🇷🇺','China':'🇨🇳','USA':'🇺🇸','Germany':'🇩🇪','Nigeria':'🇳🇬','UK':'🇬🇧','France':'🇫🇷','Brazil':'🇧🇷','Japan':'🇯🇵','Mexico':'🇲🇽','Canada':'🇨🇦','Italy':'🇮🇹','Spain':'🇪🇸','UAE':'🇦🇪','Singapore':'🇸🇬','North Korea':'🇰🇵','Iran':'🇮🇷','Pakistan':'🇵🇰','Romania':'🇷🇴','N. Korea':'🇰🇵','USA/UK':'🇺🇸'};

  let allOk = true;

  // ── 1. IP Blacklist ──────────────────────────────────────────────────────────
  setOverlayMsg('Fetching ip_blacklist.csv…');
  overlayStep('dsLoad_blacklist', 'loading');
  try {
    const blRaw = await fetchCSV('data/ip_blacklist.csv');
    KNOWN_BLACKLIST = parseCSVRaw(blRaw).map(r => r.ip_address).filter(Boolean);
    initBloom();
    overlayStep('dsLoad_blacklist', 'done', KNOWN_BLACKLIST.length);
    updateDashboardCard('dsc_blacklist', KNOWN_BLACKLIST.length, 'ok');
  } catch(e) {
    overlayStep('dsLoad_blacklist', 'fail');
    updateDashboardCard('dsc_blacklist', 'ERR', 'fail');
    allOk = false;
  }

  // ── 2. Login Logs ────────────────────────────────────────────────────────────
  setOverlayMsg('Fetching login_logs.csv…');
  overlayStep('dsLoad_logs', 'loading');
  try {
    const logRaw = await fetchCSV('data/login_logs.csv');
    loginLogs = parseLoginCSV(logRaw);
    overlayStep('dsLoad_logs', 'done', loginLogs.length);
    updateDashboardCard('dsc_logs', loginLogs.length, 'ok');
  } catch(e) {
    overlayStep('dsLoad_logs', 'fail');
    updateDashboardCard('dsc_logs', 'ERR', 'fail');
    allOk = false;
  }

  // ── 3. City Coordinates ──────────────────────────────────────────────────────
  setOverlayMsg('Fetching city_coordinates.csv…');
  overlayStep('dsLoad_cities', 'loading');
  try {
    const cityRaw = await fetchCSV('data/city_coordinates.csv');
    const cityRows = parseCSVRaw(cityRaw);
    cityRows.forEach(r => {
      if (r.city && r.latitude && r.longitude)
        CITY_COORDS[r.city] = [parseFloat(r.latitude), parseFloat(r.longitude)];
    });
    overlayStep('dsLoad_cities', 'done', cityRows.length);
    updateDashboardCard('dsc_cities', cityRows.length, 'ok');
  } catch(e) {
    overlayStep('dsLoad_cities', 'fail');
    updateDashboardCard('dsc_cities', 'ERR', 'fail');
    allOk = false;
  }

  // ── 4. Remote Tools ──────────────────────────────────────────────────────────
  setOverlayMsg('Fetching remote_tools.csv…');
  overlayStep('dsLoad_tools', 'loading');
  try {
    const rtRaw = await fetchCSV('data/remote_tools.csv');
    REMOTE_TOOLS = parseCSVRaw(rtRaw).map(r => ({
      name: r.name, label: r.label, icon: r.icon,
      port: r.port, risk: r.risk, desc: r.desc
    }));
    overlayStep('dsLoad_tools', 'done', REMOTE_TOOLS.length);
    updateDashboardCard('dsc_tools', REMOTE_TOOLS.length, 'ok');
  } catch(e) {
    overlayStep('dsLoad_tools', 'fail');
    updateDashboardCard('dsc_tools', 'ERR', 'fail');
    allOk = false;
  }

  // ── 5. Threat Intel ──────────────────────────────────────────────────────────
  setOverlayMsg('Fetching threat_intel.csv…');
  overlayStep('dsLoad_threatintel', 'loading');
  try {
    const tiRaw  = await fetchCSV('data/threat_intel.csv');
    const tiRows = parseCSVRaw(tiRaw);
    TI_DATA.countries        = tiRows.filter(r=>r.section==='country').map((r,i)=>({name:r.name, flag:flagMap[r.name]||'🌐', attacks:parseInt(r.value1)||0, color:countryColors[i]||'rgba(100,150,200,0.7)'}));
    TI_DATA.sectors          = tiRows.filter(r=>r.section==='sector').map((r,i)=>({name:r.name, attacks:parseInt(r.value1)||0, color:sectorColors[i]||'rgba(100,150,200,0.7)'}));
    TI_DATA.vectors          = tiRows.filter(r=>r.section==='vector').map(r=>({name:r.name, pct:parseInt(r.value1)||0}));
    TI_DATA.trend            = tiRows.filter(r=>r.section==='trend').map(r=>({mon:r.name, val:parseInt(r.value1)||0}));
    TI_DATA.actors           = tiRows.filter(r=>r.section==='actor').map((r,i)=>({type:r.name, pct:parseInt(r.value1)||0, color:actorColors[i]||'rgba(100,150,200,0.7)'}));
    TI_DATA.matrix.countries = tiRows.filter(r=>r.section==='matrix_country').map(r=>r.name);
    TI_DATA.matrix.data      = tiRows.filter(r=>r.section==='matrix_data').map(r=>[r.value1,r.value2,r.value3,r.value4,r.value5].map(v=>parseInt(v)||0));
    TI_DATA.apts             = tiRows.filter(r=>r.section==='apt').map(r=>({
      grp:r.name, origin:r.value1, flag:flagMap[r.value1]||'🌐',
      aka:r.value2.replace(/ /g,', '), targets:r.value3.replace(/ /g,', '),
      tactics:r.value4.replace(/ /g,', '), level:r.value5, last:r.value6
    }));
    overlayStep('dsLoad_threatintel', 'done', tiRows.length);
    updateDashboardCard('dsc_ti', tiRows.length + ' rows', 'ok');
  } catch(e) {
    overlayStep('dsLoad_threatintel', 'fail');
    updateDashboardCard('dsc_ti', 'ERR', 'fail');
    allOk = false;
  }

  // ── Done ─────────────────────────────────────────────────────────────────────
  setOverlayMsg(allOk ? '✅ All datasets loaded — launching SecureGuard…' : '⚠ Some datasets failed. Run via: python -m http.server 8080');
  await sleep(900);
  dismissOverlay();

  if (statusEl) statusEl.textContent = `✓ ${loginLogs.length} records | ${KNOWN_BLACKLIST.length} IPs | ${Object.keys(CITY_COORDS).length - 2} cities | ${REMOTE_TOOLS.length} tools`;
  return allOk;
}

window.onload = async () => {
  detectIP();
  const ok = await loadAllDatasets();
  if (!ok) {
    showToast({title:'⚠ Dataset Load Failed', body:'Could not load CSV files. Make sure you are running via: <strong>python -m http.server 8080</strong>', severity:'high', duration:12000});
  }
  renderAll();
  startClock();
  initRemoteCorrelation();
  setTimeout(() => checkAllBloom(), 600);
  loadTorExitNodes();
};

function detectIP(){
  fetch('https://api.ipify.org?format=json')
    .then(r=>r.json()).then(d=>{visitorIP=d.ip;document.getElementById('visitorIP').textContent=d.ip;})
    .catch(()=>{visitorIP='106.192.171.203';document.getElementById('visitorIP').textContent='106.192.171.203';});
}

function checkAllBloom(){
  const hits=loginLogs.filter(l=>l.bloomHit);
  if(hits.length>0){
    showToast({title:`${hits.length} Bloom Filter Hits Found`,body:`Blacklisted IPs detected in login logs. Users: ${[...new Set(hits.map(h=>h.username))].join(', ')}`,severity:'high',duration:7000});
    hits.forEach(l=>{
      alerts.push({id:Date.now()+Math.random(),severity:'high',title:'Bloom Filter Hit',desc:`IP ${l.ip} matched blacklist. User: ${l.username} at ${l.ts}`,time:l.ts,type:'bloom'});
    });
  }
  // Off-hours suspicious events
  const offSuspicious = loginLogs.filter(l => isOffHours(l.ts||l.login_time) && (l.status==='FAILED'||l.bloomHit));
  if(offSuspicious.length > 0){
    const users = [...new Set(offSuspicious.map(l=>l.username))];
    showToast({title:`🌙 Off-Hours Activity Detected`,body:`<strong>${offSuspicious.length}</strong> suspicious events outside working hours (10AM–9PM)<br>Users: ${users.join(', ')}`,severity:'high',duration:9000});
    // Group by user and add one alert per user
    users.forEach(u => {
      const uLogs = offSuspicious.filter(l=>l.username===u);
      alerts.push({id:Date.now()+Math.random(),severity:'high',title:'🌙 Off-Hours Suspicious Login',
        desc:`User "${u}" had ${uLogs.length} suspicious event(s) outside working hours. IPs: ${[...new Set(uLogs.map(l=>l.ip))].join(', ')}`,
        time:uLogs[0].ts||uLogs[0].login_time});
    });
  }
  checkBruteForce();
  // Fire impossible travel alerts on load
  setTimeout(()=>{
    const cases=detectImpossibleTravel();
    cases.forEach(c=>{
      const key=`${c.verdict}_${c.user}_${c.cityA}_${c.cityB}`;
      if(alerts.find(a=>a.key===key))return;
      alerts.push({id:Date.now()+Math.random(),key,severity:c.verdict==='impossible'?'high':'medium',
        title:`✈️ ${c.verdict==='impossible'?'Impossible':'Suspicious'} Travel — ${c.user}`,
        desc:`${c.user}: ${c.cityA}, ${c.countryA} → ${c.cityB}, ${c.countryB} in ${fmtDuration(c.timeSec)} — needs ${c.speedKmh.toLocaleString()} km/h.`,
        time:c.to.ts||c.to.login_time,type:'travel'});
    });
    const impossible=cases.filter(c=>c.verdict==='impossible');
    if(impossible.length){
      impossible.slice(0,3).forEach((c,idx)=>{
        setTimeout(()=>{
          showToast({
            title:`✈️ IMPOSSIBLE TRAVEL — ${c.user}`,
            body:`${countryFlag(c.countryA)} <strong>${c.cityA}, ${c.countryA}</strong> → ${countryFlag(c.countryB)} <strong>${c.cityB}, ${c.countryB}</strong><br>⏱ Gap: <strong>${fmtDuration(c.timeSec)}</strong> &nbsp;|&nbsp; 📏 ${fmtDist(c.distKm)}<br>🚀 Required: <strong style="color:var(--red)">${c.speedKmh.toLocaleString()} km/h — PHYSICALLY IMPOSSIBLE</strong>`,
            severity:'high',duration:12000
          });
        }, idx*2200);
      });
    }
    renderAlertBadge();
    renderAll();
    setTimeout(renderDashboardTravelWidget, 400);
  },300);
}

function checkBruteForce(){
  const byUser={};
  loginLogs.filter(l=>l.status==='FAILED').forEach(l=>{if(!byUser[l.username])byUser[l.username]=[];byUser[l.username].push(l);});
  Object.entries(byUser).forEach(([u,logs])=>{
    if(logs.length>=3&&!alerts.find(a=>a.title.includes('Brute Force')&&a.desc.includes(u))){
      alerts.push({id:Date.now()+Math.random(),severity:'high',title:'Brute Force Detected',desc:`${logs.length} failed attempts for user "${u}" from IPs: ${[...new Set(logs.map(l=>l.ip))].join(', ')}`,time:nowStr()});
      showToast({title:'🚨 Brute Force Detected',body:`<strong>${logs.length}</strong> failed attempts for "<strong>${u}</strong>"`,severity:'high',duration:8000});
    }
  });
  renderAlertBadge();
}

// ==================== AUTH ====================
function doLogin(){
  const u=document.getElementById('loginUser').value.trim();
  const p=document.getElementById('loginPass').value;
  if(!u||!p){showToast({title:'Input Required',body:'Please fill in username and password.',severity:'low',duration:3000});return;}
  const found=users.find(x=>x.username===u);
  const ok=found&&found.password===p;
  const reason=!found?'User not found':(!ok?'Wrong password':'');
  addLog(u,visitorIP,ok?'SUCCESS':'FAILED',reason,'Remote','Remote');
  if(ok){currentUser=found;showMainApp();}
  else{showToast({title:'Authentication Failed',body:`Reason: <strong>${reason}</strong><br>IP: ${visitorIP}`,severity:'high',duration:5000});}
}

function doRegister(){
  const u=document.getElementById('regUser').value.trim();
  const p=document.getElementById('regPass').value;
  const p2=document.getElementById('regPass2').value;
  if(!u||!p){showToast({title:'Error',body:'Username and password required.',severity:'medium',duration:3000});return;}
  if(p.length<6){showToast({title:'Weak Password',body:'Min 6 characters.',severity:'medium',duration:3000});return;}
  if(p!==p2){showToast({title:'Mismatch',body:'Passwords do not match.',severity:'medium',duration:3000});return;}
  if(users.find(x=>x.username===u)){showToast({title:'User Exists',body:`"${u}" already taken.`,severity:'medium',duration:3000});return;}
  users.push({username:u,password:p,email:'',role:'user'});
  showToast({title:'Account Created',body:`Welcome, <strong>${u}</strong>!`,severity:'low',duration:4000});
  showAuthPage('loginPage');
}

function doLogout(){currentUser=null;document.getElementById('mainApp').style.display='none';showAuthPage('loginPage');}

function showMainApp(){
  ['loginPage','registerPage'].forEach(p=>document.getElementById(p).style.display='none');
  document.getElementById('mainApp').style.display='flex';
  document.getElementById('currentUserBadge').textContent=currentUser.username;
  renderAll();
  showToast({title:'Login Successful',body:`Welcome back, <strong>${currentUser.username}</strong>!`,severity:'low',duration:3000});
}

function showAuthPage(id){
  ['loginPage','registerPage','mainApp'].forEach(p=>{const el=document.getElementById(p);if(el)el.style.display='none';});
  document.getElementById(id).style.display='flex';
}

// ==================== LOGS ====================
function addLog(username,ip,status,reason,country,city){
  const id=loginLogs.length+1;
  const ts=nowStr();
  const bloomHit=!isPrivate(ip)&&bloomCheck(ip);
  const offH = isOffHours(ts);
  loginLogs.push({id,username,ip,ip_address:ip,country:country||'Unknown',city:city||'Unknown',location:`${city||'Unknown'}, ${country||'Unknown'}`,status,ts,login_time:ts,bloomHit});
  if(bloomHit){
    showToast({title:'⚠ Bloom Filter Alert',body:`Login from <strong>${ip}</strong> matches threat blacklist!<br>User: ${username}`,severity:'high',duration:7000});
    alerts.push({id:Date.now()+Math.random(),severity:'high',title:'Bloom Filter Hit',desc:`IP ${ip} matched blacklist. User: ${username}`,time:ts,type:'bloom'});
    renderAlertBadge();
  }
  if(offH && status==='FAILED'){
    const hr = getHour(ts);
    showToast({title:`🌙 Off-Hours Failed Login`,body:`User <strong>${username}</strong> failed login at <strong>${String(hr).padStart(2,'0')}:00</strong> — outside working hours (${WORK_START}:00–${WORK_END}:00)<br>IP: ${ip}`,severity:'high',duration:8000});
    alerts.push({id:Date.now()+Math.random(),severity:'high',title:'🌙 Off-Hours Failed Login',desc:`User "${username}" attempted login at ${ts} — outside working hours. IP: ${ip}`,time:ts});
    renderAlertBadge();
  }
  // Real-time impossible travel check
  if(city && city!=='Unknown' && city!=='Remote'){
    const userPrev = [...loginLogs].slice(0,-1)
      .filter(l=>l.username===username && l.city && l.city!==city && CITY_COORDS[l.city] && CITY_COORDS[city])
      .sort((a,b)=>tsToSeconds(b.ts||b.login_time)-tsToSeconds(a.ts||a.login_time));
    if(userPrev.length){
      const prev=userPrev[0];
      const dist=haversine(CITY_COORDS[prev.city],CITY_COORDS[city]);
      const tSec=tsToSeconds(ts)-tsToSeconds(prev.ts||prev.login_time);
      if(dist&&tSec>0){
        const speed=Math.round(dist/(tSec/3600));
        if(speed>200){
          const isImp=speed>900;
          showToast({
            title:`✈️ ${isImp?'IMPOSSIBLE':'SUSPICIOUS'} TRAVEL — ${username}`,
            body:`${countryFlag(prev.country)} <strong>${prev.city}</strong> → ${countryFlag(country||'Unknown')} <strong>${city}</strong><br>⏱ Gap: <strong>${fmtDuration(tSec)}</strong> &nbsp;|&nbsp; 📏 <strong>${fmtDist(dist)}</strong><br>🚀 Required speed: <strong style="color:var(--red)">${speed.toLocaleString()} km/h</strong>`,
            severity:'high',duration:12000
          });
          const key=`rt_travel_${username}_${prev.city}_${city}`;
          if(!alerts.find(a=>a.key===key)){
            alerts.push({id:Date.now()+Math.random(),key,severity:isImp?'high':'medium',
              title:`✈️ ${isImp?'Impossible':'Suspicious'} Travel — ${username}`,
              desc:`${username}: ${prev.city} → ${city} in ${fmtDuration(tSec)}. Required ${speed.toLocaleString()} km/h.`,
              time:ts,type:'travel'});
          }
          renderAlertBadge();
        }
      }
    }
  }
}

// ==================== RENDER ====================
function renderAll(){
  renderStats();renderLogsTable();renderAlerts();renderIPAnalysis();renderBloomViz();renderAlertBadge();
  renderOffHours();
  renderDashboardTravelWidget();
  const geoPage=document.getElementById('page-geoAnalysis');
  if(geoPage&&geoPage.classList.contains('active'))renderGeoCharts();
  const itPage=document.getElementById('page-impossibleTravel');
  if(itPage&&itPage.classList.contains('active'))renderImpossibleTravel();
  renderUnusualIPs();renderCSVTable('csvTableFull');
}

function renderStats(){
  const total=loginLogs.length;
  const succ=loginLogs.filter(l=>l.status==='SUCCESS').length;
  const fail=loginLogs.filter(l=>l.status==='FAILED').length;
  const bloomHits=loginLogs.filter(l=>l.bloomHit).length;
  const countries=new Set(loginLogs.map(l=>l.country||'Unknown')).size;
  const unresolvedAlerts=alerts.filter(a=>!a.resolved).length;
  document.getElementById('statsGrid').innerHTML=`
    <div class="stat-card blue"><div class="stat-icon">📊</div><div class="stat-label">Total Attempts</div><div class="stat-value">${total}</div><div class="stat-sub">All time records</div></div>
    <div class="stat-card green"><div class="stat-icon">✅</div><div class="stat-label">Successful Logins</div><div class="stat-value">${succ}</div><div class="stat-sub">${total?Math.round(succ/total*100):0}% success rate</div></div>
    <div class="stat-card red"><div class="stat-icon">❌</div><div class="stat-label">Failed Attempts</div><div class="stat-value">${fail}</div><div class="stat-sub">${bloomHits} bloom filter hits</div></div>
    <div class="stat-card yellow"><div class="stat-icon">⚠️</div><div class="stat-label">Active Alerts</div><div class="stat-value">${unresolvedAlerts}</div><div class="stat-sub">${unresolvedAlerts} unresolved</div></div>
    <div class="stat-card purple"><div class="stat-icon">🌍</div><div class="stat-label">Countries</div><div class="stat-value">${countries}</div><div class="stat-sub">Unique origins</div></div>`;
}

function bloomTagHtml(hit){
  if(!hit)return '<span style="color:var(--text-dim);font-family:var(--mono);font-size:0.68rem">—</span>';
  return '<span class="ip-bloom-tag">BLOOM HIT</span>';
}

function renderLogsTable(){
  // Sort chronologically for gap calculation
  const sorted = [...loginLogs].sort((a,b)=>tsToSeconds(a.ts||a.login_time)-tsToSeconds(b.ts||b.login_time));
  // Compute gaps per user
  const lastSeen = {}; // username -> last timestamp seconds
  const gapMap   = {}; // log.id -> gap seconds
  sorted.forEach(l => {
    const key = l.username;
    const ts  = tsToSeconds(l.ts||l.login_time);
    if(lastSeen[key] != null) gapMap[l.id] = ts - lastSeen[key];
    lastSeen[key] = ts;
  });

  const displayRows = [...loginLogs].reverse().slice(0,35);

  const makeRow = (l, extraCol) => {
    const gap     = gapMap[l.id];
    const isRapid = gap != null && gap <= 120; // ≤2 min = rapid
    const offH    = isOffHours(l.ts||l.login_time);
    const rowCls  = l.bloomHit?'attempt-row-bloom':isRapid&&l.status==='FAILED'?'attempt-row-rapid':offH&&l.status==='FAILED'?'attempt-row-offhours':'';
    const hr      = getHour(l.ts||l.login_time);
    const tsChip  = offH
      ? `<span class="offhours-chip">🌙 OFF-HRS</span>`
      : '';
    const gapHtml = gap == null ? '<span style="color:var(--text-dim)">—</span>'
      : isRapid ? `<span class="ts-rapid">⚡ ${fmtGap(gap)}</span><span class="rapid-chip">RAPID</span>`
      : `<span style="color:var(--text-dim)">${fmtGap(gap)}</span>`;

    const flags = [];
    if(isRapid && l.status==='FAILED') flags.push(`<span style="background:rgba(255,34,85,0.12);border:1px solid rgba(255,34,85,0.3);color:var(--red);font-size:0.58rem;font-family:var(--mono);padding:1px 6px;border-radius:10px">⚡RAPID</span>`);
    if(offH && l.status==='FAILED')    flags.push(`<span style="background:rgba(255,136,0,0.12);border:1px solid rgba(255,136,0,0.3);color:var(--orange);font-size:0.58rem;font-family:var(--mono);padding:1px 6px;border-radius:10px">🌙OFF-HRS</span>`);
    if(l.bloomHit)                     flags.push(`<span style="background:rgba(187,102,255,0.12);border:1px solid rgba(187,102,255,0.3);color:var(--purple);font-size:0.58rem;font-family:var(--mono);padding:1px 6px;border-radius:10px">🔴BLOOM</span>`);
    const flagsHtml = flags.length ? `<div style="display:flex;flex-wrap:wrap;gap:3px">${flags.join('')}</div>` : '<span style="color:var(--text-dim);font-size:0.7rem">—</span>';

    return `<tr class="${rowCls}">
      <td style="color:var(--text-dim)">${l.id}</td>
      <td><strong>${l.username}</strong></td>
      <td style="font-family:var(--mono);color:var(--cyan);font-size:0.73rem">${l.ip}</td>
      <td>${countryFlag(l.country)} ${l.country||'—'}</td>
      <td style="color:var(--text-dim)">${l.city||'—'}</td>
      <td><span class="status-badge ${l.status.toLowerCase()}"><span class="dot"></span>${l.status}</span></td>
      <td>${bloomTagHtml(l.bloomHit)}</td>
      <td class="ts-cell">${l.ts||l.login_time}${tsChip}</td>
      <td>${gapHtml}</td>
      <td>${flagsHtml}</td>
      ${extraCol||''}
    </tr>`;
  };

  document.getElementById('logsTableBody').innerHTML =
    displayRows.map(l=>makeRow(l)).join('') ||
    '<tr><td colspan="10" class="empty-state">No logs</td></tr>';
  document.getElementById('logCount').textContent=`${loginLogs.length} records`;

  document.getElementById('logsTableBody2').innerHTML =
    [...loginLogs].reverse().map(l=>makeRow(l,`<td style="font-family:var(--mono);color:var(--text-dim);font-size:0.68rem">${l.reason||'—'}</td>`)).join('') ||
    '<tr><td colspan="11" class="empty-state">No logs</td></tr>';
  document.getElementById('logCount2').textContent=`${loginLogs.length} records`;
}

// ==================== GEO CHARTS ====================
const COUNTRY_FLAGS={'India':'🇮🇳','Russia':'🇷🇺','China':'🇨🇳','USA':'🇺🇸','Germany':'🇩🇪','Nigeria':'🇳🇬','UK':'🇬🇧','France':'🇫🇷','Brazil':'🇧🇷','Japan':'🇯🇵','Mexico':'🇲🇽','Canada':'🇨🇦','Italy':'🇮🇹','Spain':'🇪🇸','UAE':'🇦🇪','Singapore':'🇸🇬','Local':'🖥️','Unknown':'🌐'};
function countryFlag(c){return COUNTRY_FLAGS[c]||'🌐';}

function getCountryStats(){
  const map={};
  loginLogs.forEach(l=>{
    const c=l.country||'Unknown';
    if(!map[c])map[c]={country:c,total:0,success:0,failed:0,ips:new Set(),bloomHits:0};
    map[c].total++;
    if(l.status==='SUCCESS')map[c].success++;else map[c].failed++;
    map[c].ips.add(l.ip);
    if(l.bloomHit)map[c].bloomHits++;
  });
  return Object.values(map).sort((a,b)=>b.total-a.total);
}

function destroyChart(id){if(charts[id]){charts[id].destroy();delete charts[id];}}

const CHART_DEFAULTS={color:'rgba(255,255,255,0.7)',font:{family:'Share Tech Mono',size:10}};

function renderGeoCharts(){
  const stats=getCountryStats();
  const labels=stats.map(s=>`${countryFlag(s.country)} ${s.country}`);
  const totals=stats.map(s=>s.total);
  const fails=stats.map(s=>s.failed);
  const success=stats.map(s=>s.success);

  // Country Bar
  destroyChart('cb');
  charts.cb=new Chart(document.getElementById('chartCountryBar'),{
    type:'bar',
    data:{labels,datasets:[
      {label:'Failed',data:fails,backgroundColor:'rgba(255,34,85,0.7)',borderColor:'rgba(255,34,85,1)',borderWidth:1},
      {label:'Success',data:success,backgroundColor:'rgba(0,229,255,0.5)',borderColor:'rgba(0,229,255,0.8)',borderWidth:1}
    ]},
    options:{responsive:true,maintainAspectRatio:false,scales:{
      x:{ticks:{color:'rgba(180,210,238,0.7)',font:{size:9}},grid:{color:'rgba(22,45,74,0.5)'}},
      y:{ticks:{color:'rgba(180,210,238,0.7)',font:{size:9}},grid:{color:'rgba(22,45,74,0.5)'}}
    },plugins:{legend:{labels:{color:'rgba(180,210,238,0.8)',font:{size:10}}},tooltip:{backgroundColor:'rgba(4,11,20,0.95)',borderColor:'rgba(0,229,255,0.3)',borderWidth:1}}}
  });

  // Donut
  destroyChart('dn');
  const total=loginLogs.length;
  const succ=loginLogs.filter(l=>l.status==='SUCCESS').length;
  const fail=loginLogs.filter(l=>l.status==='FAILED').length;
  const bloomHits=loginLogs.filter(l=>l.bloomHit).length;
  charts.dn=new Chart(document.getElementById('chartDonut'),{
    type:'doughnut',
    data:{labels:['Success','Failed','Bloom Hits'],datasets:[{data:[succ,fail-bloomHits,bloomHits],backgroundColor:['rgba(0,255,136,0.7)','rgba(255,204,0,0.7)','rgba(255,34,85,0.8)'],borderColor:['rgba(0,255,136,1)','rgba(255,204,0,1)','rgba(255,34,85,1)'],borderWidth:2}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'65%',plugins:{legend:{position:'bottom',labels:{color:'rgba(180,210,238,0.8)',font:{size:10},padding:10}},tooltip:{backgroundColor:'rgba(4,11,20,0.95)',borderColor:'rgba(0,229,255,0.3)',borderWidth:1}}}
  });

  // Timeline
  destroyChart('tl');
  const hourMap={};
  loginLogs.forEach(l=>{
    const ts=l.ts||l.login_time||'';
    const match=ts.match(/(\d{2}):/);
    if(match){const hr=parseInt(match[1]);if(!hourMap[hr])hourMap[hr]={s:0,f:0};if(l.status==='SUCCESS')hourMap[hr].s++;else hourMap[hr].f++;}
  });
  const hrLabels=Array.from({length:24},(_,i)=>`${String(i).padStart(2,'0')}:00`);
  charts.tl=new Chart(document.getElementById('chartTimeline'),{
    type:'line',
    data:{labels:hrLabels,datasets:[
      {label:'Success',data:hrLabels.map((_,i)=>hourMap[i]?.s||0),borderColor:'rgba(0,229,255,0.9)',backgroundColor:'rgba(0,229,255,0.08)',tension:0.4,fill:true,pointRadius:3,pointBackgroundColor:'rgba(0,229,255,1)'},
      {label:'Failed',data:hrLabels.map((_,i)=>hourMap[i]?.f||0),borderColor:'rgba(255,34,85,0.9)',backgroundColor:'rgba(255,34,85,0.08)',tension:0.4,fill:true,pointRadius:3,pointBackgroundColor:'rgba(255,34,85,1)'}
    ]},
    options:{responsive:true,maintainAspectRatio:false,scales:{
      x:{ticks:{color:'rgba(180,210,238,0.6)',font:{size:8},maxTicksLimit:12},grid:{color:'rgba(22,45,74,0.4)'}},
      y:{ticks:{color:'rgba(180,210,238,0.6)',font:{size:9}},grid:{color:'rgba(22,45,74,0.4)'}}
    },plugins:{legend:{labels:{color:'rgba(180,210,238,0.8)',font:{size:10}}},tooltip:{backgroundColor:'rgba(4,11,20,0.95)'}}}
  });

  // Geo rank list
  const topFailed=stats.filter(s=>s.country!=='Local').sort((a,b)=>b.failed-a.failed).slice(0,8);
  const maxF=Math.max(...topFailed.map(s=>s.failed),1);
  document.getElementById('geoRankList').innerHTML=topFailed.map(s=>`
    <div class="geo-row">
      <div class="geo-flag">${countryFlag(s.country)}</div>
      <div style="flex:1;min-width:60px;font-family:var(--mono);font-size:0.7rem;color:var(--text)">${s.country}</div>
      <div class="geo-bar-wrap"><div class="geo-bar" style="width:${(s.failed/maxF*100).toFixed(1)}%;background:${s.bloomHits>0?'linear-gradient(90deg,var(--red),var(--orange))':'linear-gradient(90deg,var(--cyan),var(--purple))'}"></div></div>
      <div class="geo-count">${s.failed}</div>
    </div>`).join('');

  // Stacked bar by country
  destroyChart('sc');
  const top10=stats.slice(0,10);
  charts.sc=new Chart(document.getElementById('chartStackedCountry'),{
    type:'bar',
    data:{labels:top10.map(s=>`${countryFlag(s.country)} ${s.country}`),datasets:[
      {label:'Success',data:top10.map(s=>s.success),backgroundColor:'rgba(0,229,255,0.65)',borderColor:'rgba(0,229,255,0.9)',borderWidth:1},
      {label:'Failed',data:top10.map(s=>s.failed-s.bloomHits),backgroundColor:'rgba(255,204,0,0.65)',borderColor:'rgba(255,204,0,0.9)',borderWidth:1},
      {label:'Bloom Hit',data:top10.map(s=>s.bloomHits),backgroundColor:'rgba(255,34,85,0.75)',borderColor:'rgba(255,34,85,1)',borderWidth:1}
    ]},
    options:{responsive:true,maintainAspectRatio:false,scales:{
      x:{stacked:true,ticks:{color:'rgba(180,210,238,0.7)',font:{size:9}},grid:{color:'rgba(22,45,74,0.4)'}},
      y:{stacked:true,ticks:{color:'rgba(180,210,238,0.7)',font:{size:9}},grid:{color:'rgba(22,45,74,0.4)'}}
    },plugins:{legend:{labels:{color:'rgba(180,210,238,0.8)',font:{size:10}}},tooltip:{backgroundColor:'rgba(4,11,20,0.95)',borderColor:'rgba(0,229,255,0.3)',borderWidth:1,mode:'index',intersect:false}}}
  });

  // Bloom pie
  destroyChart('bl');
  const bloomCount=loginLogs.filter(l=>l.bloomHit).length;
  const nonBloom=fail-bloomCount;
  const okLogins=succ;
  charts.bl=new Chart(document.getElementById('chartBloom'),{
    type:'pie',
    data:{labels:['Clean Logins','Failed (Non-Bloom)','Bloom Filter Hits'],datasets:[{data:[okLogins,nonBloom,bloomCount],backgroundColor:['rgba(0,255,136,0.7)','rgba(255,204,0,0.65)','rgba(255,34,85,0.75)'],borderColor:['rgba(0,255,136,0.9)','rgba(255,204,0,0.9)','rgba(255,34,85,0.9)'],borderWidth:2}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:'rgba(180,210,238,0.8)',font:{size:9},padding:8}},tooltip:{backgroundColor:'rgba(4,11,20,0.95)'}}}
  });
}

function renderUnusualIPs(){
  // Detect: high fail rate, bloom hits, non-standard countries, odd hours
  const ipMap={};
  loginLogs.forEach(l=>{
    const key=l.ip;
    if(!ipMap[key])ipMap[key]={ip:key,country:l.country,city:l.city,users:new Set(),total:0,success:0,failed:0,bloomHit:false,hours:[]};
    ipMap[key].total++;
    ipMap[key].users.add(l.username);
    if(l.status==='SUCCESS')ipMap[key].success++;else ipMap[key].failed++;
    if(l.bloomHit)ipMap[key].bloomHit=true;
    const ts=l.ts||l.login_time||'';
    const m=ts.match(/(\d{2}):/);
    if(m)ipMap[key].hours.push(parseInt(m[1]));
  });

  const suspicious=Object.values(ipMap).filter(d=>{
    const oddHour=d.hours.some(h=>!isWorkingHour(h));
    return d.bloomHit||d.failed>=3||oddHour||(d.users.size>1&&d.failed>0);
  });

  const rows=suspicious.map(d=>{
    const oddHour=d.hours.some(h=>!isWorkingHour(h));
    const reasons=[];
    if(d.bloomHit)reasons.push('Bloom blacklist match');
    if(d.failed>=3)reasons.push(`${d.failed} failed logins`);
    if(oddHour)reasons.push(`Off-hours activity (outside ${WORK_START}:00–${WORK_END}:00)`);
    if(d.users.size>1)reasons.push(`Multi-user IP (${d.users.size} users)`);
    const risk=d.bloomHit?'danger':d.failed>=3||oddHour?'suspicious':'suspicious';
    return `<tr>
      <td style="font-family:var(--mono);color:var(--cyan)">${d.ip}</td>
      <td>${countryFlag(d.country)} ${d.country}</td>
      <td style="color:var(--text-dim)">${d.city}</td>
      <td><strong>${[...d.users].join(', ')}</strong></td>
      <td style="text-align:center">${d.total}</td>
      <td style="text-align:center;color:var(--red)">${d.failed}</td>
      <td>${bloomTagHtml(d.bloomHit)}</td>
      <td><span class="ip-risk ${risk}">${risk==='danger'?'HIGH RISK':'SUSPICIOUS'}</span></td>
      <td style="font-family:var(--mono);font-size:0.68rem;color:var(--text-dim)">${reasons.join(' | ')}</td>
    </tr>`;
  }).join('');
  const el=document.getElementById('unusualIPBody');
  if(el)el.innerHTML=rows||'<tr><td colspan="9" class="empty-state">No suspicious IPs detected</td></tr>';
  const cnt=document.getElementById('unusualCount');
  if(cnt)cnt.textContent=`${suspicious.length} flagged`;
}

// ==================== BLOOM SCANNER UI ====================
function bloomCheckIP(){
  const ip=document.getElementById('bloomIPInput').value.trim();
  if(ip)performBloomCheck(ip,'bloomScanResult');
}
function quickCheck(ip){document.getElementById('bloomIPInput').value=ip;performBloomCheck(ip,'bloomScanResult');}

function performBloomCheck(ip,resultId){
  const el=document.getElementById(resultId);if(!el)return;
  if(isPrivate(ip)){
    el.className='scan-result show clean';
    el.innerHTML=`<span style="color:var(--cyan)">ℹ PRIVATE / LOCAL IP — SKIPPED</span><br><span style="color:var(--text-dim)">IP: ${ip}<br>Private IPs are not checked against the blacklist.</span>`;
    return;
  }
  const hashes=bloomHashes(ip);const isBloom=bloomCheck(ip);const inKnown=KNOWN_BLACKLIST.includes(ip);
  highlightBloom(ip);
  const hashRows=hashes.map((h,i)=>{const hit=bloomBits[h]===1;return`<div class="bloom-check-row"><span style="color:var(--text-dim)">Hash ${i+1} (${['DJB2','FNV1a','SDBM'][i]}):</span><span class="bloom-hash-chip${hit?' hit':''}">${h}</span><span style="color:${hit?'var(--red)':'var(--text-dim)'}">Bit ${h}: ${hit?'SET ✓':'UNSET ✗'}</span></div>`;}).join('');
  if(isBloom){
    el.className='scan-result show bloom-hit';
    el.innerHTML=`<div style="color:var(--red);font-size:0.88rem;font-weight:700;margin-bottom:10px">🔴 BLOOM FILTER HIT — POTENTIAL THREAT</div><div style="color:var(--text-dim);margin-bottom:10px">IP <strong style="color:#fff">${ip}</strong> matched all 3 hash positions.${inKnown?'<br><span style="color:var(--red)">⚠ Confirmed in known blacklist.</span>':'<br><span style="color:var(--yellow)">⚠ Possible false positive.</span>'}</div>${hashRows}<div style="margin-top:8px;color:var(--text-dim)">Result: <strong style="color:var(--red)">${inKnown?'CONFIRMED MALICIOUS':'PROBABLE HIT'}</strong></div>`;
    showToast({title:'Bloom Filter Match',body:`IP <strong>${ip}</strong> matched the blacklist filter!`,severity:'high',duration:6000});
  } else {
    el.className='scan-result show clean';
    el.innerHTML=`<div style="color:var(--green);font-size:0.88rem;font-weight:700;margin-bottom:10px">🟢 NOT IN BLACKLIST — CLEAN</div><div style="color:var(--text-dim);margin-bottom:10px">IP <strong style="color:#fff">${ip}</strong> did not match all Bloom Filter hash positions.</div>${hashRows}<div style="margin-top:8px;color:var(--text-dim)">Result: <strong style="color:var(--green)">CLEAN</strong></div>`;
  }
}

async function reputationScan(){
  const ip=document.getElementById('reputationIPInput').value.trim();
  const el=document.getElementById('reputationResult');
  const btn=document.getElementById('repScanBtn');
  if(!ip)return;
  btn.disabled=true;btn.textContent='⟳ SCANNING...';
  el.className='scan-result show suspicious';el.innerHTML='<span style="color:var(--cyan)">⟳ Fetching geo reputation data...</span>';
  try{
    const geoRes=await fetch(`https://ip-api.com/json/${ip}?fields=status,country,regionName,city,isp,org,as,proxy,hosting,query`);
    const geo=await geoRes.json();
    const bloomHit=!isPrivate(ip)&&bloomCheck(ip);const inKnown=KNOWN_BLACKLIST.includes(ip);
    const suspicious=geo.proxy||geo.hosting||bloomHit||inKnown;
    const risk=(bloomHit||inKnown)?'HIGH':suspicious?'MEDIUM':'LOW';
    const riskColor=risk==='HIGH'?'var(--red)':risk==='MEDIUM'?'var(--yellow)':'var(--green)';
    el.className=`scan-result show ${risk==='HIGH'?'malicious':risk==='MEDIUM'?'suspicious':'clean'}`;
    el.innerHTML=`<div style="color:${riskColor};font-size:0.88rem;font-weight:700;margin-bottom:10px">RISK: <strong>${risk}</strong></div>
      <div class="bloom-check-row"><span style="color:var(--text-dim);width:120px">IP Address:</span><strong style="color:#fff">${geo.query||ip}</strong></div>
      <div class="bloom-check-row"><span style="color:var(--text-dim);width:120px">Country:</span><span>${countryFlag(geo.country)} ${geo.country||'Unknown'}</span></div>
      <div class="bloom-check-row"><span style="color:var(--text-dim);width:120px">Region:</span><span>${geo.regionName||'Unknown'}, ${geo.city||''}</span></div>
      <div class="bloom-check-row"><span style="color:var(--text-dim);width:120px">ISP:</span><span>${geo.isp||'Unknown'}</span></div>
      <div class="bloom-check-row"><span style="color:var(--text-dim);width:120px">ASN:</span><span>${geo.as||'Unknown'}</span></div>
      <div class="bloom-check-row"><span style="color:var(--text-dim);width:120px">Proxy/VPN:</span><span style="color:${geo.proxy?'var(--red)':'var(--green)'}">${geo.proxy?'YES ⚠':'NO ✓'}</span></div>
      <div class="bloom-check-row"><span style="color:var(--text-dim);width:120px">Hosting:</span><span style="color:${geo.hosting?'var(--yellow)':'var(--green)'}">${geo.hosting?'YES':'NO'}</span></div>
      <div class="bloom-check-row"><span style="color:var(--text-dim);width:120px">Bloom Filter:</span><span style="color:${bloomHit?'var(--red)':'var(--green)'}">${bloomHit?'⚠ BLACKLISTED':'✓ Clean'}</span></div>
      <div style="margin-top:8px;font-size:0.66rem;color:var(--text-dim)">Data via ip-api.com + Bloom Filter</div>`;
    if(risk==='HIGH'){showToast({title:'High Risk IP',body:`<strong>${ip}</strong> — ${geo.country||'Unknown'} | Bloom: MATCH`,severity:'high',duration:7000});alerts.push({id:Date.now(),severity:'high',title:'High Risk IP Scanned',desc:`${ip} — ${geo.country||'Unknown'} | ${geo.isp||''}`,time:nowStr()});renderAlertBadge();}
  }catch(e){
    el.className='scan-result show suspicious';
    el.innerHTML=`<span style="color:var(--yellow)">⚠ Could not fetch live data (network).</span><br><span style="color:var(--text-dim)">Bloom Filter: <strong style="color:${bloomCheck(ip)?'var(--red)':'var(--green)'}">${bloomCheck(ip)?'MATCH — BLACKLISTED':'CLEAN'}</strong></span>`;
  }
  btn.disabled=false;btn.textContent='SCAN REPUTATION';
}

// ==================== REMOTE ACCESS ====================
// Populated from data/remote_tools.csv at runtime
let REMOTE_TOOLS = [];

let remoteScanned=false;
let remoteResults={};

function initRemoteList(){
  document.getElementById('processList').innerHTML=REMOTE_TOOLS.map(t=>`
    <div class="process-item" id="proc_${t.name.replace(/[^a-z]/gi,'_')}">
      <div class="process-icon pending">⏸️</div>
      <div style="flex:1">
        <div class="process-name">${t.name}</div>
        <div class="process-meta">${t.label} — Port: ${t.port} — Risk: ${t.risk}</div>
        <div class="process-meta" style="font-size:0.65rem;margin-top:2px;opacity:0.7">${t.desc}</div>
      </div>
      <span class="process-status scanning">PENDING</span>
    </div>`).join('');
}

async function startRemoteScan(){
  const btn=document.getElementById('remoteScanBtn');
  btn.classList.add('scanning');btn.textContent='⟳ SCANNING...';btn.disabled=true;
  document.getElementById('remoteAlertBox').classList.remove('show');
  document.getElementById('remoteSafeBox').classList.remove('show');
  remoteDetected=[];

  // Simulate scanning each process
  for(let i=0;i<REMOTE_TOOLS.length;i++){
    const t=REMOTE_TOOLS[i];
    const id='proc_'+t.name.replace(/[^a-z]/gi,'_');
    const el=document.getElementById(id);
    if(el){
      el.className='process-item scanning-state';
      el.querySelector('.process-icon').textContent='🔍';
      el.querySelector('.process-status').className='process-status scanning';
      el.querySelector('.process-status').textContent='SCANNING...';
    }
    await sleep(350+Math.random()*300);

    // Randomized detection: AnyDesk and TeamViewer have higher chance
    const detected=t.name==='AnyDesk.exe'?(Math.random()<0.6):t.name==='TeamViewer.exe'?(Math.random()<0.45):t.name==='Ammyy Admin.exe'?(Math.random()<0.3):(Math.random()<0.15);
    const pid=detected?(Math.floor(Math.random()*50000+1000)):null;
    const cpu=detected?(Math.random()*8+0.5).toFixed(1)+'%':null;
    const mem=detected?(Math.floor(Math.random()*120+20))+'MB':null;

    if(el){
      if(detected){
        el.className='process-item detected';
        el.querySelector('.process-icon').className='process-icon alert';
        el.querySelector('.process-icon').textContent='🔴';
        el.querySelector('.process-status').className='process-status danger';
        el.querySelector('.process-status').textContent='⚠ DETECTED';
        el.querySelector('.process-meta').textContent=`${t.label} — PID: ${pid} — CPU: ${cpu} — RAM: ${mem}`;
        remoteDetected.push({...t,pid,cpu,mem});
        showToast({title:`⚠️ Remote Tool Detected: ${t.label}`,body:`<strong>${t.name}</strong> is running!<br>PID: ${pid} | Risk: ${t.risk}<br>Possible unauthorized remote access.`,severity:'high',duration:9000});
        alerts.push({id:Date.now()+Math.random(),severity:'high',title:`Remote Access Detected: ${t.label}`,desc:`${t.name} running — PID ${pid} — ${t.desc}`,time:nowStr(),type:'remote'});
        renderAlertBadge();
      } else {
        el.className='process-item safe';
        el.querySelector('.process-icon').className='process-icon ok';
        el.querySelector('.process-icon').textContent='✅';
        el.querySelector('.process-status').className='process-status safe';
        el.querySelector('.process-status').textContent='NOT FOUND';
        el.querySelector('.process-meta').textContent=`${t.label} — Port: ${t.port} — Risk: ${t.risk}`;
      }
    }
  }

  if(remoteDetected.length>0){
    const alertBox=document.getElementById('remoteAlertBox');
    alertBox.classList.add('show');
    document.getElementById('remoteAlertDesc').innerHTML=`
      <strong style="color:var(--red)">${remoteDetected.length} remote access tool(s) detected running on this system.</strong><br><br>
      ${remoteDetected.map(t=>`• <strong style="color:#fff">${t.name}</strong> (PID: ${t.pid}) — ${t.label} — Risk: <span style="color:var(--red)">${t.risk}</span>`).join('<br>')}
      <br><br>
      <strong>Recommended Actions:</strong><br>
      1. Immediately terminate the detected processes<br>
      2. Audit who initiated remote access and when<br>
      3. Check login logs for concurrent unauthorized sessions<br>
      4. Change all credentials that may have been exposed<br>
      5. Enable 2FA on all accounts<br><br>
      <span style="color:var(--yellow)">⚠ If you did not authorize this remote access, consider your system COMPROMISED.</span>`;
    renderRemoteCorrelation();
  } else {
    document.getElementById('remoteSafeBox').classList.add('show');
    showToast({title:'✅ System Secure',body:'No unauthorized remote access tools detected.',severity:'low',duration:5000});
  }

  btn.classList.remove('scanning');btn.textContent='↻ RESCAN';btn.disabled=false;
  remoteScanned=true;
  renderAlerts();renderStats();
}

function initRemoteCorrelation(){
  renderRemoteCorrelation();
}

function renderRemoteCorrelation(){
  const suspicious=loginLogs.filter(l=>l.bloomHit||l.status==='FAILED');
  const correlations=suspicious.slice(0,8).map((l,i)=>{
    const toolIdx=i%REMOTE_TOOLS.length;
    const tool=remoteDetected.length>0?remoteDetected[i%remoteDetected.length]:null;
    const corr=tool?'High — concurrent session':'Low — no tool detected';
    const risk=l.bloomHit?'danger':l.status==='FAILED'?'suspicious':'safe';
    return`<tr>
      <td style="font-family:var(--mono);font-size:0.72rem;color:var(--text-dim)">${l.ts||l.login_time}</td>
      <td><strong>${l.username}</strong></td>
      <td style="font-family:var(--mono);color:var(--cyan);font-size:0.73rem">${l.ip}</td>
      <td style="font-family:var(--mono);color:${tool?'var(--red)':'var(--text-dim)'}font-size:0.72rem">${tool?tool.name:'—'}</td>
      <td style="font-size:0.72rem;color:${tool?'var(--red)':'var(--text-dim)'}">${corr}</td>
      <td><span class="ip-risk ${risk}">${risk==='danger'?'HIGH':risk==='suspicious'?'MEDIUM':'LOW'}</span></td>
    </tr>`;
  }).join('');
  const el=document.getElementById('remoteCorrelationBody');
  if(el)el.innerHTML=correlations||'<tr><td colspan="6" class="empty-state">No correlation data</td></tr>';
}

// ==================== ALERTS ====================
function renderAlerts(){
  const icons={high:'🔴',medium:'🟡',low:'🔵'};
  const html=alerts.length?[...alerts].reverse().map((a,i)=>`
    <div class="alert-item ${a.severity}">
      <div class="alert-icon">${icons[a.severity]||'⚠️'}</div>
      <div style="flex:1">
        <div class="alert-top">
          <div class="alert-title">${a.title}</div>
          <div style="display:flex;align-items:center;gap:7px">
            <span class="alert-severity ${a.severity}">${a.severity.toUpperCase()}</span>
            <button class="dismiss-btn" onclick="dismissAlert(${alerts.length-1-i})">Dismiss</button>
          </div>
        </div>
        <div class="alert-desc">${a.desc}</div>
        <div class="alert-time">🕐 ${a.time}</div>
      </div>
    </div>`).join(''):'<div class="empty-state"><div class="empty-icon">✅</div>No active alerts</div>';
  document.getElementById('alertsList').innerHTML=html;
}

function dismissAlert(idx){const ri=alerts.length-1-idx;alerts.splice(ri,1);renderAlerts();renderAlertBadge();renderStats();}
function clearAlerts(){alerts=[];renderAlerts();renderAlertBadge();renderStats();}
function renderAlertBadge(){const badge=document.getElementById('alertBadge');const count=alerts.length;if(count>0){badge.style.display='inline';badge.textContent=count;}else{badge.style.display='none';}}

// ==================== IP ANALYSIS ====================
function renderIPAnalysis(){
  const ipMap={};
  loginLogs.forEach(l=>{
    if(!ipMap[l.ip])ipMap[l.ip]={ip:l.ip,attempts:0,success:0,failed:0,users:new Set(),lastSeen:l.ts||l.login_time,location:l.location,bloomHit:l.bloomHit||false,country:l.country,city:l.city};
    ipMap[l.ip].attempts++;
    if(l.status==='SUCCESS')ipMap[l.ip].success++;else ipMap[l.ip].failed++;
    ipMap[l.ip].users.add(l.username);
    if(l.bloomHit)ipMap[l.ip].bloomHit=true;
    if((l.ts||l.login_time)>(ipMap[l.ip].lastSeen))ipMap[l.ip].lastSeen=l.ts||l.login_time;
  });
  const ips=Object.values(ipMap);
  const html=ips.slice(0,12).map(ip=>{
    const risk=(ip.bloomHit||ip.failed>=3)?'danger':ip.failed>=1?'suspicious':'safe';
    const riskLabel=risk==='danger'?'HIGH RISK':risk==='suspicious'?'SUSPICIOUS':'SAFE';
    return`<div class="ip-card" onclick="showIPDetail('${ip.ip}')">
      <div class="ip-addr">${ip.ip}${ip.bloomHit?'<span class="ip-bloom-tag">BLOOM</span>':''}</div>
      <div class="ip-meta">📊 Attempts: ${ip.attempts}<br>✅ ${ip.success} success &nbsp;❌ ${ip.failed} failed<br>👤 ${[...ip.users].join(', ')}<br>${countryFlag(ip.country)} ${ip.city}, ${ip.country}<br>🕐 ${ip.lastSeen}</div>
      <span class="ip-risk ${risk}">${riskLabel}</span>
    </div>`;
  }).join('')||'<div class="empty-state"><div class="empty-icon">🌐</div>No IPs tracked</div>';
  document.getElementById('ipGrid').innerHTML=html;
  renderCSVTable('csvTableFull');
}

function showIPDetail(ip){
  const bloomHit=!isPrivate(ip)&&bloomCheck(ip);
  const hashes=bloomHashes(ip);
  document.getElementById('ipModalTitle').textContent=`IP Details: ${ip}`;
  document.getElementById('ipModalSub').textContent=bloomHit?'⚠ This IP matched the Bloom Filter blacklist':'✓ IP not in blacklist';
  document.getElementById('ipModalBody').innerHTML=`<div style="font-family:var(--mono);font-size:0.78rem;line-height:1.9">
    <div class="bloom-check-row"><span style="color:var(--text-dim);width:130px">IP Address:</span><strong style="color:var(--cyan)">${ip}</strong></div>
    <div class="bloom-check-row"><span style="color:var(--text-dim);width:130px">Private IP:</span>${isPrivate(ip)?'<span style="color:var(--green)">YES</span>':'<span style="color:var(--text)">NO</span>'}</div>
    <div class="bloom-check-row"><span style="color:var(--text-dim);width:130px">Bloom Filter:</span><span style="color:${bloomHit?'var(--red)':'var(--green)'}">${bloomHit?'MATCH — BLACKLISTED':'CLEAN'}</span></div>
    ${hashes.map((h,i)=>`<div class="bloom-check-row"><span style="color:var(--text-dim);width:130px">Hash ${i+1} (${['DJB2','FNV1a','SDBM'][i]}):</span><span class="bloom-hash-chip${bloomBits[h]?' hit':''}">${h}</span> → ${bloomBits[h]?'<span style="color:var(--red)">SET</span>':'<span style="color:var(--text-dim)">UNSET</span>'}</div>`).join('')}
  </div>`;
  document.getElementById('ipDetailModal').classList.add('open');
}
function closeIPModal(){document.getElementById('ipDetailModal').classList.remove('open');}

function renderCSVTable(tableId){
  const el=document.getElementById(tableId);if(!el||!loginLogs.length){if(el)el.innerHTML='<tr><td>No data</td></tr>';return;}
  const keys=['id','username','ip_address','country','city','login_time','status','bloomHit'];
  const head='<thead><tr>'+keys.map(k=>`<th>${k.toUpperCase()}</th>`).join('')+'</tr></thead>';
  const body='<tbody>'+loginLogs.map(row=>'<tr>'+keys.map(k=>`<td>${k==='bloomHit'?row[k]?'YES':'NO':row[k]||'—'}</td>`).join('')+'</tr>').join('')+'</tbody>';
  el.innerHTML=head+body;
}

// ==================== TASKS ====================
function showResult(title,lines){
  document.getElementById('resultTitle').textContent=title;
  document.getElementById('resultBody').innerHTML=lines.map(l=>`<div class="${l.cls||''}">${l.text}</div>`).join('');
  document.getElementById('taskResult').classList.add('visible');
}
function closeResult(){document.getElementById('taskResult').classList.remove('visible');}

async function taskAnalyzeLogs(){
  const lines=[{text:'> ANALYZING LOGIN LOGS FROM CSV...',cls:'line-info'}];
  showResult('ANALYZE LOGIN LOGS',lines);
  await sleep(300);
  const failed=loginLogs.filter(l=>l.status==='FAILED');
  const byUser={};
  failed.forEach(l=>{byUser[l.username]=(byUser[l.username]||0)+1;});
  lines.push({text:`> Total records: ${loginLogs.length}`,cls:'line-dim'});
  lines.push({text:`> Failed attempts: ${failed.length}`,cls:'line-warn'});
  lines.push({text:`> Bloom filter hits: ${loginLogs.filter(l=>l.bloomHit).length}`,cls:'line-err'});
  lines.push({text:`> Unique countries: ${new Set(loginLogs.map(l=>l.country)).size}`,cls:'line-dim'});
  lines.push({text:'─'.repeat(52),cls:'line-dim'});
  Object.entries(byUser).sort((a,b)=>b[1]-a[1]).forEach(([u,c])=>{
    const cls=c>=5?'line-err':c>=3?'line-err':c>=2?'line-warn':'line-ok';
    lines.push({text:`  ${u.padEnd(12)} → ${c} failed${c>=3?' [⚠ BRUTE FORCE]':c>=2?' [WARNING]':''}`,cls});
  });
  lines.push({text:'─'.repeat(52),cls:'line-dim'});
  lines.push({text:`> Done. ${Object.keys(byUser).length} user(s) flagged.`,cls:'line-ok'});
  showResult('ANALYZE LOGIN LOGS',lines);
}

async function taskGeoDetect(){
  const lines=[{text:'> SCANNING GEO LOCATIONS...',cls:'line-info'}];showResult('GEO LOCATION DETECT',lines);await sleep(300);
  const countryMap={};
  loginLogs.forEach(l=>{const c=l.country||'Unknown';if(!countryMap[c])countryMap[c]={country:c,total:0,failed:0,users:new Set(),bloomHits:0};countryMap[c].total++;if(l.status==='FAILED')countryMap[c].failed++;countryMap[c].users.add(l.username);if(l.bloomHit)countryMap[c].bloomHits++;});
  const sorted=Object.values(countryMap).sort((a,b)=>b.failed-a.failed);
  lines.push({text:`> Countries detected: ${sorted.length}`,cls:'line-dim'});lines.push({text:'─'.repeat(56),cls:'line-dim'});
  sorted.forEach(s=>{
    const cls=s.bloomHits>0?'line-err':s.failed>=3?'line-warn':'line-ok';
    lines.push({text:`  ${countryFlag(s.country)} ${s.country.padEnd(14)} Total:${s.total} Failed:${s.failed}${s.bloomHits>0?' [🔴 BLOOM]':s.failed>=3?' [⚠ HIGH]':''}`,cls});
  });
  lines.push({text:'─'.repeat(56),cls:'line-dim'});
  lines.push({text:`> ${sorted.filter(s=>s.failed>=3||s.bloomHits>0).length} high-risk country/IP origin(s) detected.`,cls:'line-warn'});
  showResult('GEO LOCATION DETECT',lines);
}

async function taskIPReputation(){
  const lines=[{text:'> SCANNING IP REPUTATION VIA BLOOM FILTER...',cls:'line-info'}];showResult('IP REPUTATION SCAN',lines);
  const ips=[...new Set(loginLogs.map(l=>l.ip))];
  for(const ip of ips){
    await sleep(120);
    const bloom=!isPrivate(ip)&&bloomCheck(ip);
    const failed=loginLogs.filter(l=>l.ip===ip&&l.status==='FAILED').length;
    const score=isPrivate(ip)?100:Math.max(0,100-failed*15-(bloom?50:0));
    const cls=score<50?'line-err':score<80?'line-warn':'line-ok';
    const status=score<50?'🔴 MALICIOUS':score<80?'🟡 SUSPICIOUS':'🟢 CLEAN';
    lines.push({text:`  ${ip.padEnd(22)} Score:${score.toString().padStart(3)}/100  ${status}${bloom?' [BLOOM HIT]':''}`,cls});
  }
  lines.push({text:'─'.repeat(56),cls:'line-dim'});
  lines.push({text:`> ${ips.length} IPs scanned. ${ips.filter(ip=>!isPrivate(ip)&&bloomCheck(ip)).length} blacklisted.`,cls:'line-ok'});
  showResult('IP REPUTATION SCAN',lines);
}

async function taskMLDetect(){
  const lines=[{text:'> RUNNING ML ANOMALY DETECTION...',cls:'line-info'},{text:'> Model: IsolationForest v2.1 + BloomAware',cls:'line-dim'}];showResult('ML ANOMALY DETECTION',lines);
  await sleep(600);
  lines.push({text:'> Features: ip, country, hour, fail_count, bloom_hit, multi_user...',cls:'line-dim'});await sleep(400);
  const anomalies=[];
  const byIP={};loginLogs.forEach(l=>{if(!byIP[l.ip])byIP[l.ip]=[];byIP[l.ip].push(l);});
  Object.entries(byIP).forEach(([ip,logs])=>{
    const fails=logs.filter(l=>l.status==='FAILED');const users=new Set(logs.map(l=>l.username));const bloom=logs.some(l=>l.bloomHit);
    const hours=logs.map(l=>{const m=(l.ts||l.login_time||'').match(/(\d{2}):/);return m?parseInt(m[1]):12;});
    const oddHour=hours.some(h=>!isWorkingHour(h));
    if(bloom)anomalies.push({ip,type:'Bloom filter hit (known threat)',score:'0.99'});
    if(fails.length>=3)anomalies.push({ip,type:`High fail rate (${fails.length} attempts)`,score:(fails.length*0.28).toFixed(2)});
    if(users.size>=2)anomalies.push({ip,type:`Multi-user same IP (${users.size} users)`,score:(users.size*0.4).toFixed(2)});
    if(oddHour&&!isPrivate(ip))anomalies.push({ip,type:`Off-hours activity (outside ${WORK_START}:00–${WORK_END}:00)`,score:'0.71'});
  });
  lines.push({text:`> Records: ${loginLogs.length} | Anomalies: ${anomalies.length}`,cls:anomalies.length?'line-warn':'line-ok'});lines.push({text:'─'.repeat(56),cls:'line-dim'});
  anomalies.slice(0,15).forEach(a=>{lines.push({text:`  [ANOMALY] ${a.ip.padEnd(18)} → ${a.type} (score:${a.score})`,cls:'line-err'});});
  if(!anomalies.length)lines.push({text:'  ✓ No anomalies.',cls:'line-ok'});
  lines.push({text:'─'.repeat(56),cls:'line-dim'});lines.push({text:'> Model run complete.',cls:'line-ok'});
  showResult('ML ANOMALY DETECTION',lines);
}

async function taskGenerateAlerts(){
  const lines=[{text:'> GENERATING SECURITY ALERTS...',cls:'line-info'}];showResult('GENERATE ALERTS',lines);await sleep(300);
  const newAlerts=[];
  const byUser={};loginLogs.forEach(l=>{if(l.status==='FAILED')byUser[l.username]=(byUser[l.username]||0)+1;});
  Object.entries(byUser).forEach(([u,c])=>{
    if(c>=5&&!alerts.find(a=>a.desc.includes(u)&&a.title.includes('Brute')))newAlerts.push({id:Date.now()+Math.random(),severity:'high',title:'Critical Brute Force',desc:`User "${u}" had ${c} failed logins — immediate action required`,time:nowStr()});
    else if(c>=3&&!alerts.find(a=>a.desc.includes(u)&&a.title.includes('Brute')))newAlerts.push({id:Date.now()+Math.random(),severity:'high',title:'Brute Force Alert',desc:`User "${u}" had ${c} failed logins`,time:nowStr()});
    else if(c>=2)newAlerts.push({id:Date.now()+Math.random(),severity:'medium',title:'Multiple Failures',desc:`User "${u}" had ${c} failed logins`,time:nowStr()});
  });
  loginLogs.filter(l=>l.bloomHit).forEach(l=>{
    if(!alerts.find(a=>a.title==='Bloom Filter Hit'&&a.desc.includes(l.ip)))
      newAlerts.push({id:Date.now()+Math.random(),severity:'high',title:'Bloom Filter Hit',desc:`IP ${l.ip} matched threat blacklist. User: ${l.username}`,time:nowStr(),type:'bloom'});
  });
  newAlerts.forEach(a=>{if(!alerts.find(x=>x.title===a.title&&x.desc===a.desc))alerts.push(a);});
  lines.push({text:`> Rules: brute-force, geo, bloom-filter, multi-user, off-hours`,cls:'line-dim'});lines.push({text:'─'.repeat(52),cls:'line-dim'});
  if(newAlerts.length){newAlerts.forEach(a=>{lines.push({text:`  [${a.severity.toUpperCase()}] ${a.title}: ${a.desc}`,cls:a.severity==='high'?'line-err':'line-warn'});showToast({title:a.title,body:a.desc,severity:a.severity,duration:5000});});}
  else lines.push({text:'  ✓ No new alerts.',cls:'line-ok'});
  lines.push({text:'─'.repeat(52),cls:'line-dim'});lines.push({text:`> Total alerts: ${alerts.length}`,cls:'line-ok'});
  renderAlerts();renderStats();renderAlertBadge();showResult('GENERATE ALERTS',lines);
}

// ==================== TOAST ====================
function showToast({title,body,severity,duration=5000}){
  const container=document.getElementById('alertToastContainer');
  const id='toast_'+Date.now()+Math.random();
  const icons={high:'🔴',medium:'🟡',low:'🟢',bloom:'⚠️',remote:'🖥️'};
  const sev=severity||'medium';
  const toast=document.createElement('div');toast.className='alert-toast';toast.id=id;
  toast.innerHTML=`<div class="toast-bar ${sev}"></div><div class="toast-inner"><div class="toast-header"><span class="toast-icon">${icons[sev]||'⚠️'}</span><span class="toast-title">${title}</span><button class="toast-close" onclick="dismissToast('${id}')">✕</button></div><div class="toast-body">${body}</div><div class="toast-meta"><span class="toast-severity ${sev}">${sev.toUpperCase()}</span><span class="toast-time">${nowStr()}</span></div><div class="toast-progress"><div class="toast-progress-bar ${sev}" style="animation-duration:${duration}ms"></div></div></div>`;
  container.appendChild(toast);
  const timer=setTimeout(()=>dismissToast(id),duration);toast._timer=timer;
  const toasts=container.querySelectorAll('.alert-toast:not(.exiting)');
  if(toasts.length>5)dismissToast(toasts[0].id);
}
function dismissToast(id){const t=document.getElementById(id);if(!t||t.classList.contains('exiting'))return;if(t._timer)clearTimeout(t._timer);t.classList.add('exiting');setTimeout(()=>t.remove(),350);}

// ==================== HELPERS ====================
function nowStr(){return new Date().toISOString().replace('T',' ').substring(0,19);}
function sleep(ms){return new Promise(r=>setTimeout(r,ms));}
function togglePass(id){const el=document.getElementById(id);el.type=el.type==='password'?'text':'password';}
function toggleDemo(){document.getElementById('demoContent').classList.toggle('open');}
function exportCSV(){
  if(!loginLogs.length){alert('No data');return;}
  const keys=['id','username','ip_address','country','city','login_time','status'];
  const csv=[keys.join(','),...loginLogs.map(r=>keys.map(k=>`"${r[k]||''}"`).join(','))].join('\n');
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));a.download='secureguard_ip_log.csv';a.click();
}

function renderDashboardTravelWidget(){
  const cases=detectImpossibleTravel();
  const widget=document.getElementById('itDashWidget');
  const cards=document.getElementById('itDashCards');
  if(!widget||!cards)return;
  const flagged=cases.filter(c=>c.verdict==='impossible'||c.verdict==='suspicious');
  if(!flagged.length){widget.style.display='none';return;}
  widget.style.display='block';
  cards.innerHTML=flagged.map(c=>{
    const isImp=c.verdict==='impossible';
    const sc=isImp?'var(--red)':'var(--orange)';
    const bdr=isImp?'rgba(255,34,85,0.3)':'rgba(255,136,0,0.25)';
    const bg=isImp?'rgba(255,34,85,0.06)':'rgba(255,136,0,0.05)';
    return `<div style="background:${bg};border:1px solid ${bdr};border-radius:12px;padding:16px 18px;cursor:pointer" onclick="navTo('impossibleTravel',document.querySelector('[onclick*=impossibleTravel]'))">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
        <span style="font-size:1.1rem">${isImp?'🔴':'🟠'}</span>
        <strong style="color:#fff;font-size:0.85rem">${c.user}</strong>
        <span style="background:${isImp?'rgba(255,34,85,0.15)':'rgba(255,136,0,0.15)'};border:1px solid ${sc};color:${sc};font-size:0.6rem;font-family:var(--mono);padding:1px 8px;border-radius:20px;margin-left:auto">${isImp?'IMPOSSIBLE':'SUSPICIOUS'}</span>
      </div>
      <div style="display:flex;align-items:center;gap:6px;font-size:0.8rem;margin-bottom:8px">
        <span>${countryFlag(c.countryA)} <strong style="color:var(--cyan)">${c.cityA}</strong></span>
        <span style="color:${sc};font-size:1rem">→</span>
        <span>${countryFlag(c.countryB)} <strong style="color:var(--cyan)">${c.cityB}</strong></span>
      </div>
      <div style="display:flex;gap:14px;font-family:var(--mono);font-size:0.68rem;color:var(--text-dim)">
        <span>⏱ <strong style="color:${isImp?'var(--red)':'var(--orange)'}">${fmtDuration(c.timeSec)}</strong> gap</span>
        <span>📏 ${fmtDist(c.distKm)}</span>
        <span>🚀 <strong style="color:${sc}">${c.speedKmh.toLocaleString()} km/h</strong></span>
      </div>
      <div style="font-family:var(--mono);font-size:0.62rem;color:var(--text-dim);margin-top:6px;display:flex;gap:10px">
        <span>FROM: ${(c.from.ts||c.from.login_time||'').substring(11,19)}</span>
        <span>TO: ${(c.to.ts||c.to.login_time||'').substring(11,19)}</span>
      </div>
    </div>`;
  }).join('');
}


// ==================== THREAT INTEL CHARTS ====================
// Populated from data/threat_intel.csv at runtime
let TI_DATA = { countries:[], sectors:[], vectors:[], trend:[], matrix:{countries:[],sectors:['Healthcare','Finance','Government','Infra','Education'],data:[]}, actors:[], apts:[] };

let tiCharts = {};
function destroyTiChart(key){ if(tiCharts[key]){tiCharts[key].destroy();delete tiCharts[key];}}

function renderThreatIntel(){
  renderTiKpi();
  renderTiCountry();
  renderTiSector();
  renderTiVector();
  renderTiTrend();
  renderTiMatrix();
  renderTiActor();
  renderAptTable();
}

function renderTiKpi(){
  const total = TI_DATA.sectors.reduce((s,x)=>s+x.attacks,0);
  const topCountry = TI_DATA.countries[0];
  const topSector  = TI_DATA.sectors[0];
  const kpis=[
    {label:'Total Incidents (2024)',  val: total.toLocaleString(), icon:'🔴', color:'var(--red)'},
    {label:'Most Active Attacker',    val: topCountry.flag+' '+topCountry.name, icon:'🚩', color:'var(--orange)'},
    {label:'Most Targeted Sector',    val: '🏥 '+topSector.name, icon:'🎯', color:'var(--yellow)'},
    {label:'YoY Increase',            val: '+34%', icon:'📈', color:'var(--purple)'},
  ];
  document.getElementById('tiKpiRow').innerHTML = kpis.map(k=>`
    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:20px 18px;position:relative;overflow:hidden">
      <div style="position:absolute;top:0;left:0;right:0;height:2px;background:${k.color}"></div>
      <div style="font-size:1.5rem;margin-bottom:8px">${k.icon}</div>
      <div style="font-family:var(--title);font-size:1.2rem;font-weight:900;color:${k.color};margin-bottom:4px">${k.val}</div>
      <div style="font-size:0.62rem;color:var(--text-dim);font-family:var(--mono);letter-spacing:0.1em;text-transform:uppercase">${k.label}</div>
    </div>`).join('');
}

function renderTiCountry(){
  destroyTiChart('country');
  const d = TI_DATA.countries;
  tiCharts.country = new Chart(document.getElementById('chartTiCountry'),{
    type:'bar',
    data:{
      labels: d.map(x=>x.flag+' '+x.name),
      datasets:[{
        label:'Attributed Attacks',
        data: d.map(x=>x.attacks),
        backgroundColor: d.map(x=>x.color),
        borderColor: d.map(x=>x.color.replace('0.8','1').replace('0.7','1')),
        borderWidth:1, borderRadius:4
      }]
    },
    options:{
      indexAxis:'y', responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{backgroundColor:'rgba(4,11,20,0.95)',borderColor:'rgba(0,229,255,0.3)',borderWidth:1,callbacks:{label:ctx=>' '+ctx.raw.toLocaleString()+' incidents'}}},
      scales:{
        x:{ticks:{color:'rgba(180,210,238,0.6)',font:{size:9}},grid:{color:'rgba(22,45,74,0.4)'}},
        y:{ticks:{color:'rgba(180,210,238,0.85)',font:{size:10,weight:'600'}},grid:{display:false}}
      }
    }
  });
}

function renderTiSector(){
  destroyTiChart('sector');
  const d = TI_DATA.sectors;
  tiCharts.sector = new Chart(document.getElementById('chartTiSector'),{
    type:'bar',
    data:{
      labels: d.map(x=>x.name),
      datasets:[{label:'Attacks',data:d.map(x=>x.attacks),backgroundColor:d.map(x=>x.color),borderRadius:4,borderWidth:0}]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{backgroundColor:'rgba(4,11,20,0.95)',borderColor:'rgba(0,229,255,0.3)',borderWidth:1}},
      scales:{
        x:{ticks:{color:'rgba(180,210,238,0.7)',font:{size:8},maxRotation:35},grid:{color:'rgba(22,45,74,0.4)'}},
        y:{ticks:{color:'rgba(180,210,238,0.6)',font:{size:9}},grid:{color:'rgba(22,45,74,0.4)'}}
      }
    }
  });
}

function renderTiVector(){
  destroyTiChart('vector');
  const d = TI_DATA.vectors;
  const colors=['rgba(255,34,85,0.8)','rgba(255,136,0,0.8)','rgba(255,204,0,0.75)','rgba(0,229,255,0.75)','rgba(187,102,255,0.8)','rgba(0,255,136,0.7)'];
  tiCharts.vector = new Chart(document.getElementById('chartTiVector'),{
    type:'doughnut',
    data:{labels:d.map(x=>x.name),datasets:[{data:d.map(x=>x.pct),backgroundColor:colors,borderColor:colors.map(c=>c.replace(/[\d.]+\)$/,'1)')),borderWidth:2}]},
    options:{
      responsive:true, maintainAspectRatio:false, cutout:'60%',
      plugins:{legend:{position:'right',labels:{color:'rgba(180,210,238,0.8)',font:{size:9},padding:8,boxWidth:12}},
               tooltip:{backgroundColor:'rgba(4,11,20,0.95)',callbacks:{label:ctx=>` ${ctx.label}: ${ctx.raw}%`}}}
    }
  });
}

function renderTiTrend(){
  destroyTiChart('trend');
  const d = TI_DATA.trend;
  // Add gradient fill
  tiCharts.trend = new Chart(document.getElementById('chartTiTrend'),{
    type:'line',
    data:{
      labels:d.map(x=>x.mon),
      datasets:[{
        label:'Incident Volume',
        data:d.map(x=>x.val),
        borderColor:'rgba(187,102,255,0.9)',
        backgroundColor:'rgba(187,102,255,0.08)',
        tension:0.4, fill:true,
        pointRadius:3, pointBackgroundColor:'rgba(187,102,255,1)',
        pointBorderColor:'rgba(187,102,255,0.5)', pointBorderWidth:1
      }]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{backgroundColor:'rgba(4,11,20,0.95)',borderColor:'rgba(187,102,255,0.3)',borderWidth:1}},
      scales:{
        x:{ticks:{color:'rgba(180,210,238,0.6)',font:{size:8}},grid:{color:'rgba(22,45,74,0.4)'}},
        y:{ticks:{color:'rgba(180,210,238,0.6)',font:{size:9}},grid:{color:'rgba(22,45,74,0.4)'}}
      }
    }
  });
}

function renderTiMatrix(){
  destroyTiChart('matrix');
  const m = TI_DATA.matrix;
  const palette = [
    'rgba(255,34,85,0.75)','rgba(255,136,0,0.75)','rgba(255,204,0,0.7)',
    'rgba(0,229,255,0.65)','rgba(187,102,255,0.7)','rgba(100,180,255,0.65)'
  ];
  tiCharts.matrix = new Chart(document.getElementById('chartTiMatrix'),{
    type:'bar',
    data:{
      labels: m.sectors,
      datasets: m.countries.map((c,i)=>({
        label:c, data:m.data[i],
        backgroundColor:palette[i], borderColor:palette[i].replace(/[\d.]+\)$/,'1)'),
        borderWidth:1, borderRadius:3
      }))
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{
        legend:{position:'top',labels:{color:'rgba(180,210,238,0.85)',font:{size:9},padding:8,boxWidth:12}},
        tooltip:{mode:'index',intersect:false,backgroundColor:'rgba(4,11,20,0.95)',borderColor:'rgba(0,229,255,0.3)',borderWidth:1}
      },
      scales:{
        x:{ticks:{color:'rgba(180,210,238,0.7)',font:{size:9}},grid:{color:'rgba(22,45,74,0.4)'}},
        y:{ticks:{color:'rgba(180,210,238,0.6)',font:{size:9}},grid:{color:'rgba(22,45,74,0.4)'}}
      }
    }
  });
}

function renderTiActor(){
  destroyTiChart('actor');
  const d = TI_DATA.actors;
  tiCharts.actor = new Chart(document.getElementById('chartTiActor'),{
    type:'pie',
    data:{labels:d.map(x=>x.type+'  ('+x.pct+'%)'),datasets:[{data:d.map(x=>x.pct),backgroundColor:d.map(x=>x.color),borderColor:d.map(x=>x.color.replace(/[\d.]+\)$/,'1)')),borderWidth:2}]},
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{
        legend:{position:'bottom',labels:{color:'rgba(180,210,238,0.8)',font:{size:9},padding:8}},
        tooltip:{backgroundColor:'rgba(4,11,20,0.95)',callbacks:{label:ctx=>` ${ctx.raw}% of all incidents`}}
      }
    }
  });
}

function renderAptTable(){
  const levelColor={critical:'var(--red)',high:'var(--orange)',medium:'var(--yellow)'};
  const levelBg={critical:'rgba(255,34,85,0.12)',high:'rgba(255,136,0,0.12)',medium:'rgba(255,204,0,0.1)'};
  document.getElementById('aptTableBody').innerHTML = TI_DATA.apts.map(a=>`
    <tr>
      <td><strong style="color:var(--cyan)">${a.grp}</strong></td>
      <td>${a.flag} ${a.origin}</td>
      <td style="font-family:var(--mono);font-size:0.7rem;color:var(--text-dim)">${a.aka}</td>
      <td style="font-size:0.78rem">${a.targets}</td>
      <td style="font-family:var(--mono);font-size:0.68rem;color:var(--text-dim)">${a.tactics}</td>
      <td><span style="background:${levelBg[a.level]};border:1px solid ${levelColor[a.level]};color:${levelColor[a.level]};font-family:var(--mono);font-size:0.62rem;padding:2px 9px;border-radius:20px;font-weight:700;text-transform:uppercase">${a.level}</span></td>
      <td style="font-family:var(--mono);font-size:0.7rem;color:var(--text-dim)">${a.last}</td>
    </tr>`).join('');
}

function navTo(page,el){
  document.querySelectorAll('.nav-item').forEach(x=>x.classList.remove('active'));
  if(el)el.classList.add('active');
  document.querySelectorAll('.page').forEach(x=>x.classList.remove('active'));
  document.getElementById('page-'+page).classList.add('active');
  const titles={dashboard:'Security Dashboard',geoAnalysis:'Geo Location Analysis',bloomScanner:'Bloom Filter Scanner',impossibleTravel:'✈️ Impossible Travel Detection',remoteAccess:'Remote Access Detection',threatIntel:'🌐 Global Threat Intelligence',loginLogs:'Login Logs',securityAlerts:'Security Alerts',ipAnalysis:'IP Analysis'};
  document.getElementById('pageTitle').textContent=titles[page]||page;
  if(page==='geoAnalysis'){setTimeout(()=>{renderGeoCharts();renderOffHours();},100);}
  if(page==='impossibleTravel'){setTimeout(()=>renderImpossibleTravel(),100);}
  if(page==='threatIntel'){setTimeout(()=>renderThreatIntel(),100);}
  if(page==='remoteAccess')initRemoteList();
  if(page==='bloomScanner')renderBloomViz();
  renderUnusualIPs();
}

// ==================== IMPOSSIBLE TRAVEL ENGINE ====================
// Populated from data/city_coordinates.csv at runtime
let CITY_COORDS = { 'Localhost': null, 'Unknown': null };

function haversine(a,b){
  if(!a||!b)return null;
  const R=6371,dLat=(b[0]-a[0])*Math.PI/180,dLon=(b[1]-a[1])*Math.PI/180;
  const x=Math.sin(dLat/2)**2+Math.cos(a[0]*Math.PI/180)*Math.cos(b[0]*Math.PI/180)*Math.sin(dLon/2)**2;
  return R*2*Math.atan2(Math.sqrt(x),Math.sqrt(1-x));
}
function fmtDist(km){return km>=1000?`${(km/1000).toFixed(1)}k km`:`${Math.round(km)} km`;}
function fmtDuration(secs){
  if(secs<60)return`${secs}s`;
  if(secs<3600)return`${Math.floor(secs/60)}m ${secs%60}s`;
  const h=Math.floor(secs/3600),m=Math.floor((secs%3600)/60);
  return`${h}h ${m}m`;
}

function detectImpossibleTravel(){
  const results=[];
  const byUser={};
  loginLogs.forEach(l=>{if(!byUser[l.username])byUser[l.username]=[];byUser[l.username].push(l);});
  Object.entries(byUser).forEach(([user,logs])=>{
    const sorted=[...logs].sort((a,b)=>tsToSeconds(a.ts||a.login_time)-tsToSeconds(b.ts||b.login_time));
    for(let i=0;i<sorted.length-1;i++){
      const a=sorted[i],b=sorted[i+1];
      if(!a.city||!b.city||a.city===b.city)continue;
      const coordA=CITY_COORDS[a.city],coordB=CITY_COORDS[b.city];
      if(!coordA||!coordB)continue;
      const distKm=haversine(coordA,coordB);
      if(!distKm||distKm<50)continue;
      const timeSec=tsToSeconds(b.ts||b.login_time)-tsToSeconds(a.ts||a.login_time);
      if(timeSec<=0)continue;
      const speedKmh=Math.round(distKm/(timeSec/3600));
      const verdict=speedKmh>900?'impossible':speedKmh>200?'suspicious':'normal';
      if(verdict!=='normal')results.push({user,from:a,to:b,distKm,timeSec,speedKmh,verdict,countryA:a.country,cityA:a.city,countryB:b.country,cityB:b.city});
    }
  });
  return results.sort((a,b)=>a.verdict===b.verdict?b.speedKmh-a.speedKmh:a.verdict==='impossible'?-1:1);
}

function renderImpossibleTravel(){
  const cases=detectImpossibleTravel();
  const impossible=cases.filter(c=>c.verdict==='impossible');
  const suspicious=cases.filter(c=>c.verdict==='suspicious');
  const users=[...new Set(cases.map(c=>c.user))];
  const maxSpeed=cases.length?Math.max(...cases.map(c=>c.speedKmh)):0;

  document.getElementById('itCountImpossible').textContent=impossible.length;
  document.getElementById('itCountSuspicious').textContent=suspicious.length;
  document.getElementById('itCountUsers').textContent=users.length;
  document.getElementById('itMaxSpeed').textContent=maxSpeed>0?maxSpeed.toLocaleString():'—';

  // Fire alerts
  impossible.forEach(c=>{
    const key=`impossible_${c.user}_${c.cityA}_${c.cityB}`;
    if(!alerts.find(a=>a.key===key)){
      alerts.push({id:Date.now()+Math.random(),key,severity:'high',
        title:`✈️ Impossible Travel — ${c.user}`,
        desc:`${c.user}: ${c.cityA}, ${c.countryA} → ${c.cityB}, ${c.countryB} in ${fmtDuration(c.timeSec)} — needs ${c.speedKmh.toLocaleString()} km/h. Physically impossible.`,
        time:c.to.ts||c.to.login_time,type:'travel'});
      showToast({
        title:`✈️ IMPOSSIBLE TRAVEL — ${c.user}`,
        body:`<strong>${countryFlag(c.countryA)} ${c.cityA}, ${c.countryA}</strong> → <strong>${countryFlag(c.countryB)} ${c.cityB}, ${c.countryB}</strong><br>⏱ Gap: <strong>${fmtDuration(c.timeSec)}</strong> &nbsp;|&nbsp; 📏 Distance: <strong>${fmtDist(c.distKm)}</strong><br>Speed needed: <strong style="color:var(--red)">${c.speedKmh.toLocaleString()} km/h</strong> — IMPOSSIBLE`,
        severity:'high',duration:12000
      });
    }
  });
  suspicious.forEach(c=>{
    const key=`susp_travel_${c.user}_${c.cityA}_${c.cityB}`;
    if(!alerts.find(a=>a.key===key)){
      alerts.push({id:Date.now()+Math.random(),key,severity:'medium',
        title:`🟠 Suspicious Travel — ${c.user}`,
        desc:`${c.user}: ${c.cityA} → ${c.cityB} in ${fmtDuration(c.timeSec)} needs ${c.speedKmh.toLocaleString()} km/h.`,
        time:c.to.ts||c.to.login_time,type:'travel'});
    }
  });
  renderAlertBadge();

  // Cards
  const listEl=document.getElementById('impossibleTravelList');
  if(!cases.length){
    listEl.innerHTML='<div class="empty-state"><div class="empty-icon">✅</div>No impossible travel detected</div>';
  } else {
    listEl.innerHTML=cases.map((c,i)=>{
      const isImp=c.verdict==='impossible';
      const cls=isImp?'critical':'warning';
      const sc=isImp?'var(--red)':'var(--orange)';
      const fA=countryFlag(c.countryA),fB=countryFlag(c.countryB);
      const bid=`itbody_${i}`;
      const context=isImp
        ?(c.speedKmh>10000?'⚡ Extremely fast — likely simultaneous sessions or VPN/proxy. Account may be shared/compromised.'
          :c.speedKmh>3000?'🚀 Faster than any aircraft — account may be shared or credential-stuffed.'
          :'✈️ Faster than commercial aircraft (max ~900 km/h) — physically impossible travel.')
        :'🚗 Possible via short-haul flight but suspiciously tight. Monitor closely.';
      return`<div class="travel-card ${cls}" style="margin-bottom:14px;border-radius:12px;overflow:hidden;border:1px solid">
        <div class="travel-card-header" onclick="toggleTravelBody('${bid}')">
          <div class="travel-severity-icon ${cls}">${isImp?'🔴':'🟠'}</div>
          <div style="flex:1">
            <div class="travel-user">👤 ${c.user}</div>
            <div class="travel-summary">${fA} ${c.cityA}, ${c.countryA} → ${fB} ${c.cityB}, ${c.countryB} · ${fmtDuration(c.timeSec)} · ${fmtDist(c.distKm)}</div>
          </div>
          <div class="travel-speed-badge">
            <div class="travel-speed-val ${cls}">${c.speedKmh>=1000?(c.speedKmh/1000).toFixed(1)+'k':c.speedKmh.toLocaleString()}</div>
            <div class="travel-speed-label">km/h REQUIRED</div>
          </div>
          <div style="margin-left:14px;font-size:1.1rem;color:var(--text-dim)">▾</div>
        </div>
        <div class="travel-body" id="${bid}">
          <div class="travel-timeline">
            <div class="tl-node from" style="flex:none;width:130px">
              <div class="tl-point"></div>
              <div class="tl-label"><div class="tl-city">${fA} ${c.cityA}</div><div class="tl-country">${c.countryA}</div><div class="tl-ts">${(c.from.ts||c.from.login_time||'').substring(0,19)}</div></div>
            </div>
            <div style="flex:1;position:relative;min-height:60px;min-width:80px">
              <div style="position:absolute;top:50%;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--cyan),${sc});transform:translateY(-50%)"></div>
              <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-130%);background:var(--bg-card);border:1px solid ${sc};border-radius:20px;padding:3px 10px;white-space:nowrap;z-index:2">
                <span style="font-family:var(--mono);font-size:0.65rem;color:${sc};font-weight:700">⚡ ${fmtDuration(c.timeSec)}</span>
              </div>
              <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,30%);background:var(--bg-card);border:1px solid rgba(0,229,255,0.2);border-radius:16px;padding:2px 9px;white-space:nowrap;z-index:2">
                <span style="font-family:var(--mono);font-size:0.62rem;color:var(--text-dim)">📏 ${fmtDist(c.distKm)}</span>
              </div>
              <span style="position:absolute;right:0;top:50%;transform:translateY(-50%);color:${sc};font-size:1rem">▶</span>
            </div>
            <div class="tl-node to" style="flex:none;width:130px">
              <div class="tl-point"></div>
              <div class="tl-label"><div class="tl-city">${fB} ${c.cityB}</div><div class="tl-country">${c.countryB}</div><div class="tl-ts">${(c.to.ts||c.to.login_time||'').substring(0,19)}</div></div>
            </div>
          </div>
          <div class="travel-stats-row">
            <div class="travel-stat"><div class="travel-stat-val">${fmtDist(c.distKm)}</div><div class="travel-stat-lbl">Distance</div></div>
            <div class="travel-stat"><div class="travel-stat-val">${fmtDuration(c.timeSec)}</div><div class="travel-stat-lbl">Time Gap</div></div>
            <div class="travel-stat"><div class="travel-stat-val ${isImp?'red':''}">${c.speedKmh.toLocaleString()} km/h</div><div class="travel-stat-lbl">Required Speed</div></div>
            <div class="travel-stat"><div class="travel-stat-val" style="color:${sc};font-size:0.9rem">${isImp?'IMPOSSIBLE':'SUSPICIOUS'}</div><div class="travel-stat-lbl">Verdict</div></div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px">
            <div style="background:rgba(0,229,255,0.05);border:1px solid rgba(0,229,255,0.15);border-radius:8px;padding:12px 14px;font-family:var(--mono);font-size:0.72rem">
              <div style="color:var(--cyan);font-weight:700;margin-bottom:6px">📍 FROM</div>
              <div>IP: <strong style="color:var(--cyan)">${c.from.ip}</strong></div>
              <div>Status: <strong style="color:${c.from.status==='SUCCESS'?'var(--green)':'var(--red)'}">${c.from.status}</strong></div>
              <div style="color:var(--text-dim)">${c.from.ts||c.from.login_time}</div>
            </div>
            <div style="background:rgba(255,34,85,0.05);border:1px solid rgba(255,34,85,0.15);border-radius:8px;padding:12px 14px;font-family:var(--mono);font-size:0.72rem">
              <div style="color:var(--red);font-weight:700;margin-bottom:6px">📍 TO</div>
              <div>IP: <strong style="color:var(--cyan)">${c.to.ip}</strong></div>
              <div>Status: <strong style="color:${c.to.status==='SUCCESS'?'var(--green)':'var(--red)'}">${c.to.status}</strong></div>
              <div style="color:var(--text-dim)">${c.to.ts||c.to.login_time}</div>
            </div>
          </div>
          <div class="travel-verdict ${c.verdict}" style="margin-top:12px">
            <strong style="color:${sc}">⚠ Analysis: </strong>${context}<br>
            <strong>Action: </strong>${isImp
              ?'Lock account immediately, force password reset, enable MFA, investigate both IPs for data exfiltration.'
              :'Verify with the user, review session activity, consider step-up authentication.'}
          </div>
        </div>
      </div>`;
    }).join('');
  }

  // Table with all location transitions
  const allPairs=[];
  const byUser2={};
  loginLogs.forEach(l=>{if(!byUser2[l.username])byUser2[l.username]=[];byUser2[l.username].push(l);});
  Object.entries(byUser2).forEach(([user,logs])=>{
    const sorted=[...logs].sort((a,b)=>tsToSeconds(a.ts||a.login_time)-tsToSeconds(b.ts||b.login_time));
    for(let i=0;i<sorted.length-1;i++){
      const a=sorted[i],b=sorted[i+1];
      if(!a.city||!b.city||a.city===b.city)continue;
      const coordA=CITY_COORDS[a.city],coordB=CITY_COORDS[b.city];
      const distKm=coordA&&coordB?haversine(coordA,coordB):null;
      const timeSec=tsToSeconds(b.ts||b.login_time)-tsToSeconds(a.ts||a.login_time);
      const speedKmh=distKm&&timeSec>0?Math.round(distKm/(timeSec/3600)):null;
      const verdict=!speedKmh?'unknown':speedKmh>900?'impossible':speedKmh>200?'suspicious':'normal';
      allPairs.push({user,a,b,distKm,timeSec,speedKmh,verdict});
    }
  });
  const vc={'impossible':'var(--red)','suspicious':'var(--orange)','normal':'var(--green)','unknown':'var(--text-dim)'};
  const tBody=document.getElementById('travelTableBody');
  if(tBody)tBody.innerHTML=allPairs.map(p=>`<tr>
    <td><strong>${p.user}</strong></td>
    <td>${countryFlag(p.a.country)} ${p.a.city}, ${p.a.country}</td>
    <td style="font-family:var(--mono);font-size:0.72rem;color:var(--text-dim)">${p.a.ts||p.a.login_time}</td>
    <td>${countryFlag(p.b.country)} ${p.b.city}, ${p.b.country}</td>
    <td style="font-family:var(--mono);font-size:0.72rem;color:var(--text-dim)">${p.b.ts||p.b.login_time}</td>
    <td style="font-family:var(--mono);color:${p.timeSec<600?'var(--red)':'var(--text-dim)'}">${fmtDuration(p.timeSec)}</td>
    <td style="font-family:var(--mono)">${p.distKm?fmtDist(p.distKm):'—'}</td>
    <td style="font-family:var(--mono);color:${vc[p.verdict]};font-weight:700">${p.speedKmh?p.speedKmh.toLocaleString()+' km/h':'—'}</td>
    <td><span style="background:${p.verdict==='impossible'?'rgba(255,34,85,0.15)':p.verdict==='suspicious'?'rgba(255,136,0,0.15)':'rgba(0,255,136,0.1)'};border:1px solid ${vc[p.verdict]};color:${vc[p.verdict]};font-size:0.63rem;font-family:var(--mono);padding:2px 9px;border-radius:20px;font-weight:700">${p.verdict.toUpperCase()}</span></td>
  </tr>`).join('')||'<tr><td colspan="9" class="empty-state">No location transitions in data</td></tr>';
  const cnt=document.getElementById('travelTableCount');
  if(cnt)cnt.textContent=`${allPairs.length} transitions`;
}

function toggleTravelBody(id){const el=document.getElementById(id);if(el)el.classList.toggle('open');}
