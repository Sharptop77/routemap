'use strict';

const VPN = {
  wireguard: { color: '#8b5cf6', label: 'WireGuard' }, ipsec: { color: '#f59e0b', label: 'IPsec' },
  l2tp: { color: '#06b6d4', label: 'L2TP' }, ovpn: { color: '#14b8a6', label: 'OpenVPN' },
  sstp: { color: '#0ea5e9', label: 'SSTP' }, pptp: { color: '#94a3b8', label: 'PPTP' },
  gre: { color: '#d946ef', label: 'GRE' }, ipip: { color: '#c026d3', label: 'IPIP' },
  eoip: { color: '#7c3aed', label: 'EoIP' }, vxlan: { color: '#0891b2', label: 'VXLAN' },
};
const PROTO = {
  static: { color: '#3b82f6', label: 'static' }, ospf: { color: '#f97316', label: 'OSPF' },
  bgp: { color: '#ec4899', label: 'BGP' }, rip: { color: '#84cc16', label: 'RIP' },
  dynamic: { color: '#64748b', label: 'dynamic' }, blackhole: { color: '#475569', label: 'blackhole' },
  ipsec: { color: '#f59e0b', label: 'IPsec-политики' },
};
const STATE_TEXT = { up: 'UP', down: 'DOWN', idle: 'IDLE', partial: 'частично' };
const POS_KEY = 'routemap.positions.v1';
const FILTER_KEY = 'routemap.filters.v1';

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* приватный режим */ } },
};

const state = {
  data: null, cy: null, timer: null, traced: false,
  filters: Object.assign({ tables: null, protocols: null, inactive: true, default: true, labels: true, vpnonly: false, downpeers: false },
    store.get(FILTER_KEY, {})),
};

// ------------------------------------------------------------------ стили графа
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();

function cyStyle() {
  const text = css('--text'), muted = css('--muted'), canvas = css('--canvas'), border = css('--border');
  return [
    { selector: 'node', style: {
      label: 'data(label)', 'text-wrap': 'wrap', 'font-size': 11, color: text, 'text-valign': 'center',
      'text-halign': 'center', 'border-width': 1.5, 'min-zoomed-font-size': 6 } },
    { selector: 'node[kind="router"]', style: {
      shape: 'round-rectangle', width: 150, height: 46, 'background-color': '#1e3a8a', 'border-color': '#1e40af',
      color: '#fff', 'font-size': 12, 'font-weight': 600 } },
    { selector: 'node[kind="router"][!ok]', style: { 'background-color': '#991b1b', 'border-color': '#7f1d1d' } },
    { selector: 'node[kind="network"]', style: {
      shape: 'round-rectangle', width: 128, height: 30, 'background-color': '#dcfce7', 'border-color': '#16a34a',
      color: '#14532d' } },
    { selector: 'node[kind="network"][role="wan"]', style: { 'background-color': '#fef3c7', 'border-color': '#d97706', color: '#78350f' } },
    { selector: 'node[kind="network"][role="remote"]', style: {
      'background-color': '#e0f2fe', 'border-color': '#0284c7', color: '#0c4a6e', 'border-style': 'dashed' } },
    { selector: 'node[kind="internet"]', style: {
      shape: 'ellipse', width: 110, height: 54, 'background-color': '#cbd5e1', 'border-color': '#64748b',
      color: '#0f172a', 'font-weight': 600 } },
    { selector: 'node[kind="vpn-peer"]', style: {
      shape: 'diamond', width: 34, height: 34, 'background-color': 'data(color)', 'border-color': canvas,
      'text-valign': 'bottom', 'text-margin-y': 5, color: text } },
    { selector: 'node[kind="gateway"]', style: {
      shape: 'round-triangle', width: 24, height: 22, 'background-color': '#94a3b8', 'border-color': '#64748b',
      'text-valign': 'bottom', 'text-margin-y': 4, 'font-size': 10, color: muted } },

    { selector: 'edge', style: {
      width: 1.5, 'curve-style': 'bezier', 'line-color': border, 'font-size': 10, color: text,
      'text-background-color': canvas, 'text-background-opacity': 0.85, 'text-background-padding': 2,
      'text-rotation': 'autorotate', 'min-zoomed-font-size': 7 } },
    { selector: 'edge[kind="connected"]', style: { width: 2, 'line-color': '#94a3b8' } },
    { selector: 'edge[kind="lan"]', style: { width: 1.5, 'line-color': '#94a3b8', 'line-style': 'dotted' } },
    { selector: 'edge[kind="tunnel"]', style: {
      width: 5, 'line-color': 'data(color)', 'line-cap': 'round' } },
    { selector: 'edge[kind="tunnel"][state="idle"], edge[kind="tunnel"][state="partial"]', style: { 'line-style': 'dashed', 'line-dash-pattern': [10, 5] } },
    { selector: 'edge[kind="tunnel"][state="down"]', style: { 'line-style': 'dashed', 'line-color': '#dc2626', opacity: 0.75 } },
    { selector: 'edge[kind="route"]', style: {
      width: 2.5, 'line-color': 'data(color)', 'target-arrow-shape': 'triangle', 'target-arrow-color': 'data(color)',
      'arrow-scale': 1.1 } },
    { selector: 'edge[kind="route"][!active]', style: { 'line-style': 'dashed', opacity: 0.55 } },
    { selector: 'edge[transit]', style: { 'source-arrow-shape': 'none' } },
    { selector: 'edge[kind="tunnel"], edge[kind="route"]', style: { label: 'data(display)' } },
    { selector: 'edge.nolabel', style: { label: '' } },

    { selector: '.faded', style: { opacity: 0.12 } },
    { selector: 'node.hl', style: { 'border-width': 4, 'border-color': '#facc15', opacity: 1 } },
    { selector: 'edge.hl', style: { width: 7, opacity: 1, 'z-index': 10, 'line-style': 'solid' } },
    { selector: ':selected', style: { 'overlay-color': '#2563eb', 'overlay-opacity': 0.18, 'overlay-padding': 6 } },
  ];
}

// ------------------------------------------------------------------ данные → элементы
function edgeColor(e) {
  if (e.kind === 'tunnel') return (VPN[e.vpn] || {}).color || '#8b5cf6';
  if (e.kind === 'route') {
    if (e.via_vpn) return (VPN[e.via_vpn] || {}).color || '#8b5cf6';
    return (PROTO[(e.protocols || [])[0]] || PROTO.static).color;
  }
  return null;
}

function edgeDisplay(e) {
  if (e.kind === 'tunnel') {
    const n = (e.routes || []).length;
    return `${e.label}${e.state !== 'up' ? ' · ' + STATE_TEXT[e.state] : ''}${n ? ` · ${n} маршр.` : ''}`;
  }
  return e.label || '';
}

function toElements(data) {
  let nodes = data.nodes, edges = data.edges;
  if (state.filters.vpnonly) {
    const keep = new Set();
    for (const e of edges) {
      if (e.kind === 'tunnel') { keep.add(e.source); keep.add(e.target); (e.routes || []).forEach((r) => keep.add(r.dst === '0.0.0.0/0' ? 'internet' : 'n:' + r.dst)); }
      if (e.kind === 'route' && e.via_vpn) { keep.add(e.source); keep.add(e.target); }
    }
    nodes.filter((n) => n.kind === 'router').forEach((n) => keep.add(n.id));
    nodes = nodes.filter((n) => keep.has(n.id));
    edges = edges.filter((e) => keep.has(e.source) && keep.has(e.target) && (e.kind !== 'route' || e.via_vpn));
  }
  return [
    ...nodes.map((n) => ({ group: 'nodes', data: { ...n, color: n.kind === 'vpn-peer' ? (VPN[n.vpn] || {}).color || '#8b5cf6' : undefined } })),
    ...edges.map((e) => ({ group: 'edges', data: { ...e, color: edgeColor(e), display: edgeDisplay(e) } })),
  ];
}

// ------------------------------------------------------------------ граф
function initCy() {
  if (window.cytoscapeFcose) {
    try { cytoscape.use(window.cytoscapeFcose); } catch { /* уже зарегистрирован */ }
  }
  state.cy = cytoscape({
    container: $('#cy'), style: cyStyle(), minZoom: 0.15, maxZoom: 3,
    boxSelectionEnabled: false,
  });
  const cy = state.cy;
  cy.on('tap', 'node, edge', (ev) => showDetails(ev.target));
  cy.on('tap', (ev) => { if (ev.target === cy) hideDetails(); });
  cy.on('dragfree', 'node', savePositions);
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => cy.style(cyStyle()));
}

function savePositions() {
  const pos = store.get(POS_KEY, {});
  state.cy.nodes().forEach((n) => { pos[n.id()] = n.position(); });
  store.set(POS_KEY, pos);
}

function runLayout(fit = true) {
  const cy = state.cy;
  const hasFcose = !!window.cytoscapeFcose;
  const opts = hasFcose
    ? { name: 'fcose', quality: 'proof', randomize: true, animate: false, nodeRepulsion: () => 25000,
        idealEdgeLength: (e) => (e.data('kind') === 'tunnel' ? 260 : e.data('kind') === 'connected' ? 110 : 160),
        edgeElasticity: () => 0.35, nodeSeparation: 90, packComponents: true, fit, padding: 40 }
    : { name: 'cose', animate: false, nodeRepulsion: () => 400000, idealEdgeLength: () => 120, fit, padding: 40 };
  const l = cy.layout(opts);
  l.one('layoutstop', savePositions);
  l.run();
}

function applyData(data) {
  const cy = state.cy;
  const els = toElements(data);
  const ids = new Set(els.map((e) => e.data.id));
  const saved = store.get(POS_KEY, {});
  const fresh = [];
  cy.batch(() => {
    cy.elements().filter((e) => !ids.has(e.id())).remove();
    const toAdd = [];
    for (const el of els) {
      const ex = cy.getElementById(el.data.id);
      if (ex.nonempty()) ex.data(el.data);
      else {
        if (el.group === 'nodes' && saved[el.data.id]) el.position = saved[el.data.id];
        else if (el.group === 'nodes') fresh.push(el.data.id);
        toAdd.push(el);
      }
    }
    cy.add(toAdd.filter((e) => e.group === 'nodes'));
    cy.add(toAdd.filter((e) => e.group === 'edges'));
  });
  setLabels();

  if (fresh.length && fresh.length === cy.nodes().length) {
    runLayout();
  } else if (fresh.length) {
    // новые узлы — рядом с уже размещённым соседом
    for (const id of fresh) {
      const n = cy.getElementById(id);
      const nb = n.neighborhood('node').filter((m) => !fresh.includes(m.id()));
      const base = nb.nonempty() ? nb[0].position() : { x: 0, y: 0 };
      n.position({ x: base.x + (Math.random() - 0.5) * 160, y: base.y + 70 + Math.random() * 60 });
    }
    savePositions();
  }
}

function setLabels() {
  state.cy.edges().toggleClass('nolabel', !state.filters.labels);
}

// ------------------------------------------------------------------ загрузка
async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${r.status} ${(await r.text()).slice(0, 200)}`);
  return r.json();
}

function query(refresh) {
  const f = state.filters, p = new URLSearchParams();
  if (refresh) p.set('refresh', '1');
  if (f.tables) p.set('tables', f.tables.join(','));
  if (f.protocols) p.set('protocols', f.protocols.join(','));
  p.set('inactive', f.inactive ? '1' : '0');
  p.set('default', f.default ? '1' : '0');
  if (f.downpeers) p.set('down_peers', '1');
  return '/api/topology?' + p;
}

async function load(refresh = false) {
  const btn = $('#btn-refresh');
  btn.disabled = true;
  $('#status').textContent = refresh ? 'опрос роутеров…' : 'загрузка…';
  try {
    const data = await api(query(refresh));
    state.data = data;
    $('#error').hidden = true;
    $('#demo-badge').hidden = !data.demo;
    applyData(data);
    renderFilters();
    renderTunnels();
    renderRouters();
    renderStatus();
    $('#hidden-peers').textContent = data.hidden_peers ? `(скрыто ${data.hidden_peers})` : '';
    if (state.traced) runTrace(true);
  } catch (e) {
    $('#error').textContent = 'Ошибка: ' + e.message;
    $('#error').hidden = false;
    $('#status').textContent = 'ошибка загрузки';
  } finally {
    btn.disabled = false;
  }
}

function renderStatus() {
  const d = state.data;
  const bad = d.routers.filter((r) => !r.ok).length;
  const tUp = d.tunnels.filter((t) => t.state === 'up').length;
  const time = new Date(d.updated * 1000).toLocaleTimeString();
  $('#status').innerHTML = `роутеров: ${d.routers.length}${bad ? ` (<span style="color:var(--down)">недоступно ${bad}</span>)` : ''}`
    + ` · туннелей: ${tUp}/${d.tunnels.length} up · опрос в ${esc(time)}`;
}

// ------------------------------------------------------------------ фильтры
function saveFilters() { store.set(FILTER_KEY, state.filters); }

function chip(label, checked, color, onChange) {
  const el = document.createElement('label');
  el.className = 'chip';
  el.innerHTML = `<input type="checkbox" ${checked ? 'checked' : ''}>${color ? `<span class="dot" style="background:${color}"></span>` : ''}${esc(label)}`;
  el.querySelector('input').addEventListener('change', (e) => onChange(e.target.checked));
  return el;
}

function renderFilters() {
  const d = state.data, f = state.filters;
  const tbox = $('#f-tables');
  tbox.replaceChildren();
  for (const t of d.tables) {
    tbox.append(chip(t, !f.tables || f.tables.includes(t), null, (on) => {
      const cur = new Set(f.tables || d.tables);
      on ? cur.add(t) : cur.delete(t);
      f.tables = cur.size === d.tables.length ? null : [...cur];
      saveFilters(); load();
    }));
  }
  const pbox = $('#f-protocols');
  pbox.replaceChildren();
  for (const p of d.protocols) {
    pbox.append(chip((PROTO[p] || {}).label || p, !f.protocols || f.protocols.includes(p), (PROTO[p] || {}).color, (on) => {
      const cur = new Set(f.protocols || d.protocols);
      on ? cur.add(p) : cur.delete(p);
      f.protocols = cur.size === d.protocols.length ? null : [...cur];
      saveFilters(); load();
    }));
  }
  const sel = $('#t-router'), keep = sel.value;
  sel.innerHTML = d.routers.map((r) => `<option value="${esc(r.name)}" ${r.ok ? '' : 'disabled'}>${esc(r.identity)} (${esc(r.host)})</option>`).join('');
  if (keep) sel.value = keep;
  const tsel = $('#t-table'), tkeep = tsel.value;
  tsel.innerHTML = '<option value="">авто (по правилам)</option>' + d.tables.map((t) => `<option>${esc(t)}</option>`).join('');
  tsel.value = tkeep;
}

function renderLegend() {
  const line = (color, dash = '', arrow = false, w = 4) => `<svg width="34" height="12"><line x1="2" y1="6" x2="${arrow ? 26 : 32}" y2="6" stroke="${color}" stroke-width="${w}" stroke-dasharray="${dash}" stroke-linecap="round"/>${arrow ? `<path d="M26 1 L33 6 L26 11 Z" fill="${color}"/>` : ''}</svg>`;
  const box = (bg, bd, dash = '') => `<svg width="34" height="16"><rect x="2" y="2" width="30" height="12" rx="4" fill="${bg}" stroke="${bd}" stroke-width="1.5" stroke-dasharray="${dash}"/></svg>`;
  const rows = [
    [box('#1e3a8a', '#1e40af'), 'маршрутизатор (опрашивается)'],
    [box('#991b1b', '#7f1d1d'), 'маршрутизатор недоступен'],
    [box('#dcfce7', '#16a34a'), 'подключённая сеть (LAN)'],
    [box('#fef3c7', '#d97706'), 'WAN-сеть (шлюз по умолчанию)'],
    [box('#e0f2fe', '#0284c7', '3 2'), 'удалённая сеть (из маршрутов)'],
    ['<svg width="34" height="20"><path d="M17 2 L30 10 L17 18 L4 10 Z" fill="#8b5cf6"/></svg>', 'неуправляемая сторона VPN'],
    ...Object.entries(VPN).slice(0, 7).map(([, v]) => [line(v.color), `туннель ${v.label}`]),
    [line('#8b5cf6', '8 4'), 'туннель idle / частично поднят'],
    [line('#dc2626', '8 4'), 'туннель DOWN'],
    [line('#3b82f6', '', true, 2.5), 'маршрут (цвет — протокол / VPN)'],
    [line('#3b82f6', '5 4', true, 2.5), 'маршрут неактивен'],
  ];
  $('#legend').innerHTML = rows.map(([i, t]) => `<div>${i}</div><div>${esc(t)}</div>`).join('');
}

// ------------------------------------------------------------------ туннели / роутеры
function renderTunnels() {
  const list = [...state.data.tunnels].sort((a, b) => ['down', 'partial', 'idle', 'up'].indexOf(a.state) - ['down', 'partial', 'idle', 'up'].indexOf(b.state));
  $('#tunnels').innerHTML = list.length ? list.map((t) => `
    <div class="card" data-edge="${esc(t.edge_id)}">
      <div class="top"><span class="dot" style="background:${(VPN[t.vpn] || {}).color}"></span>${esc(t.kind_label)}${t.ipsec && t.vpn !== 'ipsec' ? ' + IPsec' : ''}
        <span class="state ${t.state}">${STATE_TEXT[t.state]}</span></div>
      <div class="sub">${esc(t.a)} <code>${esc(t.a_iface)}</code> ⇄ ${esc(t.b)}${t.b_iface ? ` <code>${esc(t.b_iface)}</code>` : ''}</div>
      ${t.routed_nets.length ? `<div class="sub">сети: ${esc(t.routed_nets.join(', '))}</div>` : ''}
    </div>`).join('') : '<p class="hint">VPN-туннелей не найдено.</p>';
  document.querySelectorAll('#tunnels .card').forEach((c) => c.addEventListener('click', () => focusElement(c.dataset.edge)));
}

function renderRouters() {
  $('#routers').innerHTML = state.data.routers.map((r) => `
    <div class="card" data-router="${esc(r.name)}">
      <div class="top">${esc(r.identity)}<span class="state ${r.ok ? 'up' : 'down'}">${r.ok ? 'OK' : 'ОШИБКА'}</span></div>
      <div class="sub">${esc(r.host)} · ${esc(r.transport)}${r.version ? ' · RouterOS ' + esc(r.version) : ''}${r.poll_ms != null ? ` · ${r.poll_ms} мс` : ''}</div>
      ${r.error ? `<div class="sub" style="color:var(--down)">${esc(r.error)}</div>` : ''}
      ${(r.warnings || []).map((w) => `<div class="warn">⚠ ${esc(w)}</div>`).join('')}
    </div>`).join('');
  document.querySelectorAll('#routers .card').forEach((c) => c.addEventListener('click', () => {
    document.querySelectorAll('#routers .card').forEach((x) => x.classList.toggle('selected', x === c));
    focusElement('r:' + c.dataset.router);
    loadRouterDetail(c.dataset.router);
  }));
}

async function loadRouterDetail(name) {
  const box = $('#router-detail');
  box.innerHTML = '<p class="hint">загрузка…</p>';
  try {
    const s = await api('/api/router/' + encodeURIComponent(name));
    if (!s.ok) { box.innerHTML = ''; return; }
    const vpnIf = new Set(s.tunnels.map((t) => t.interface).filter(Boolean));
    const routes = s.routes.filter((r) => r.protocol !== 'connected')
      .sort((a, b) => a.table.localeCompare(b.table) || b.prefix - a.prefix);
    box.innerHTML = `
      <h3>Маршруты ${esc(s.identity)}</h3>
      <table><tr><th>сеть</th><th>шлюз</th><th>прот.</th><th>табл.</th></tr>
      ${routes.map((r) => `<tr class="${r.active ? '' : 'inactive'}"><td>${esc(r.dst)}</td>
        <td>${r.hops.map((h) => esc(h.gateway || h.interface || '—') + (h.interface && vpnIf.has(h.interface) ? ` <span class="dot" title="через VPN" style="background:${(VPN[(s.interfaces[h.interface] || {}).vpn?.replace(/-(client|server)$/, '')] || VPN.wireguard).color}"></span>` : '')).join('<br>')}</td>
        <td>${esc(r.protocol)}/${r.distance}</td><td>${esc(r.table)}</td></tr>`).join('')}
      </table>
      ${s.rules.length ? `<h3>Правила маршрутизации</h3><table><tr><th>src</th><th>dst</th><th>действие</th></tr>
        ${s.rules.map((r) => `<tr><td>${esc(r.src || r.mark || r.interface || 'любой')}</td><td>${esc(r.dst || 'любой')}</td><td>${esc(r.action)} → ${esc(r.table)}</td></tr>`).join('')}</table>` : ''}`;
  } catch (e) {
    box.innerHTML = `<p class="warn">${esc(e.message)}</p>`;
  }
}

function focusElement(id) {
  const el = state.cy.getElementById(id);
  if (el.empty()) return;
  state.cy.elements().unselect();
  el.select();
  state.cy.animate({ fit: { eles: el.union(el.connectedNodes()), padding: 120 }, duration: 350 });
  showDetails(el);
}

// ------------------------------------------------------------------ детали
function dl(obj) {
  const rows = Object.entries(obj).filter(([, v]) => v !== '' && v != null && !(Array.isArray(v) && !v.length));
  return `<dl>${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(Array.isArray(v) ? v.join(', ') : v)}</dd>`).join('')}</dl>`;
}

function routesTable(routes) {
  if (!routes || !routes.length) return '';
  return `<h3>Маршруты</h3><table><tr><th>роутер</th><th>сеть</th><th>шлюз</th><th>прот.</th></tr>
    ${routes.map((r) => `<tr class="${r.active ? '' : 'inactive'}"><td>${esc(routerName(r.router))}</td><td>${esc(r.dst)}${r.table !== 'main' ? ` <code>${esc(r.table)}</code>` : ''}</td>
      <td>${esc(r.gateway)}${r.tunnel ? `<br><span class="muted">туннель ${esc(r.tunnel)}</span>` : ''}</td><td>${esc(r.protocol)}/${r.distance}</td></tr>`).join('')}</table>`;
}

function routerName(name) {
  const r = state.data.routers.find((x) => x.name === name);
  return r ? r.identity : name;
}

function showDetails(el) {
  const d = el.data();
  let html = '';
  if (el.isNode()) {
    if (d.kind === 'router') {
      html = `<h2>${esc(d.identity)}</h2>` + dl({ хост: d.host, транспорт: d.transport, RouterOS: d.version, модель: d.board,
        маршрутов: d.routes, туннелей: d.ok ? `${d.tunnels_up} up из ${d.tunnels}` : '', ошибка: d.error });
      html += (d.warnings || []).map((w) => `<div class="warn">⚠ ${esc(w)}</div>`).join('');
    } else if (d.kind === 'network') {
      const into = state.cy.edges(`[target = "${d.id}"]`).filter((e) => e.data('kind') === 'route');
      html = `<h2>${esc(d.cidr)}</h2>` + dl({ тип: { lan: 'подключённая', wan: 'WAN', remote: 'удалённая' }[d.role], интерфейсы: d.attached });
      html += routesTable(into.map((e) => e.data('routes')).flat());
    } else if (d.kind === 'vpn-peer') {
      html = `<h2>${esc(d.label)}</h2><p class="muted">Удалённая сторона ${esc((VPN[d.vpn] || {}).label || d.vpn)}, не опрашивается приложением.</p>`;
    } else if (d.kind === 'gateway') {
      html = `<h2>Шлюз ${esc(d.label)}</h2><p class="muted">Следующий хоп, не являющийся опрашиваемым роутером (например, провайдер).</p>`;
    } else {
      html = `<h2>${esc(d.label)}</h2>`;
    }
  } else if (d.kind === 'tunnel') {
    html = `<h2>${esc(d.label)} <span class="state ${d.state}">${STATE_TEXT[d.state]}</span></h2>`;
    for (const s of d.sides) {
      html += `<h3>${esc(routerName(s.router))} · ${esc(s.interface || s.label)}</h3>` + dl({
        тип: s.kind, состояние: STATE_TEXT[s.state], 'удалённый хост': s.remote_host, 'адреса в туннеле': s.local_ips,
        'сети за туннелем': s.routed_nets, ...s.details });
    }
    if (d.sides.length === 1) html += '<p class="muted">Вторая сторона не опрашивается или не сопоставлена.</p>';
    html += routesTable(d.routes);
  } else {
    html = `<h2>${esc({ route: 'Маршрут', connected: 'Подключение', lan: 'Сегмент LAN' }[d.kind] || d.kind)}</h2>`;
    if (d.kind === 'connected') html += dl({ роутер: routerName(d.router), интерфейс: d.interface, адрес: d.ip, состояние: d.up ? 'running' : 'не running' });
    if (d.via_vpn) html += `<p>Через VPN: <b style="color:${(VPN[d.via_vpn] || {}).color}">${esc((VPN[d.via_vpn] || {}).label)}</b></p>`;
    html += routesTable(d.routes);
  }
  $('#details-body').innerHTML = html;
  $('#details').hidden = false;
}

function hideDetails() { $('#details').hidden = true; }

// ------------------------------------------------------------------ трассировка
async function runTrace(silent = false) {
  const router = $('#t-router').value, dst = $('#t-dst').value.trim(), src = $('#t-src').value.trim(), table = $('#t-table').value;
  if (!router || !dst) return;
  const p = new URLSearchParams({ router, dst });
  if (src) p.set('src', src);
  if (table) p.set('table', table);
  const out = $('#t-result');
  try {
    const r = await api('/api/trace?' + p);
    state.traced = true;
    out.innerHTML = r.steps.map((s) => `<li><span class="r">${esc(s.router)}</span>: <span class="${['no-route', 'blackhole', 'loop', 'error', 'tunnel-down'].includes(s.action) || (s.state && s.state !== 'up') ? 'bad' : ''}">${esc(s.text)}${s.state && s.state !== 'up' ? ` — туннель ${STATE_TEXT[s.state]}` : ''}</span></li>`).join('')
      + `<p class="${r.ok ? 'result-ok' : 'result-bad'}">${r.ok ? '✓ адрес достижим (по таблицам маршрутизации)' : '✗ пакет не доходит'}</p>`;
    highlight(r.path, r.tunnel_edges);
  } catch (e) {
    if (!silent) out.innerHTML = `<p class="result-bad">${esc(e.message)}</p>`;
  }
}

function highlight(path, tunnelEdges) {
  const cy = state.cy;
  cy.elements().removeClass('hl faded');
  if (!path || !path.length) return;
  const tset = new Set(tunnelEdges);
  let hl = cy.collection();
  path.forEach((id) => { hl = hl.union(cy.getElementById(id)); });
  for (let i = 0; i < path.length - 1; i++) {
    const a = path[i], b = path[i + 1];
    let between = cy.edges().filter((e) => (e.source().id() === a && e.target().id() === b) || (e.source().id() === b && e.target().id() === a));
    const tun = between.filter((e) => tset.has(e.id()));
    if (tun.nonempty()) between = tun;
    hl = hl.union(between);
  }
  cy.elements().addClass('faded');
  hl.removeClass('faded').addClass('hl');
  cy.animate({ fit: { eles: hl, padding: 80 }, duration: 350 });
}

function clearTrace() {
  state.traced = false;
  state.cy.elements().removeClass('hl faded');
  $('#t-result').innerHTML = '';
}

// ------------------------------------------------------------------ события
function bind() {
  document.querySelectorAll('.tabs button').forEach((b) => b.addEventListener('click', () => {
    document.querySelectorAll('.tabs button').forEach((x) => x.classList.toggle('active', x === b));
    document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.id === 'tab-' + b.dataset.tab));
  }));
  $('#btn-refresh').addEventListener('click', () => load(true));
  $('#btn-fit').addEventListener('click', () => state.cy.fit(undefined, 40));
  $('#btn-layout').addEventListener('click', () => { store.set(POS_KEY, {}); runLayout(); });
  $('#details-close').addEventListener('click', hideDetails);
  for (const [id, key] of [['#f-inactive', 'inactive'], ['#f-default', 'default'], ['#f-labels', 'labels'], ['#f-vpnonly', 'vpnonly'], ['#f-downpeers', 'downpeers']]) {
    const el = $(id);
    el.checked = state.filters[key];
    el.addEventListener('change', () => {
      state.filters[key] = el.checked;
      saveFilters();
      if (key === 'labels') setLabels();
      else if (key === 'vpnonly') applyData(state.data);
      else load();
    });
  }
  $('#t-run').addEventListener('click', () => runTrace());
  $('#t-dst').addEventListener('keydown', (e) => { if (e.key === 'Enter') runTrace(); });
  $('#t-src').addEventListener('keydown', (e) => { if (e.key === 'Enter') runTrace(); });
  $('#t-clear').addEventListener('click', clearTrace);
  const auto = $('#auto');
  auto.value = String(store.get('routemap.auto', 0));
  const setAuto = () => {
    clearInterval(state.timer);
    const sec = +auto.value;
    store.set('routemap.auto', sec);
    if (sec) state.timer = setInterval(() => load(true), sec * 1000);
  };
  auto.addEventListener('change', setAuto);
  setAuto();
}

initCy();
bind();
renderLegend();
load();
