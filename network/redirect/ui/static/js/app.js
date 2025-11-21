const topologyRoot = document.getElementById('topology-root');
const pathRoot = document.getElementById('path-root');
const statusEl = document.getElementById('test-status');
const runBtn = document.getElementById('run-test-btn');
const scenarioSelect = document.getElementById('scenario-select');

// iface DOM에 ns/if 키를 심어서 path highlight에 사용
function ifaceDomId(nsName, ifaceName) {
  return `iface-${nsName}-${ifaceName}`;
}

function clearActiveHops() {
  document.querySelectorAll('.iface.active-hop').forEach(el => {
    el.classList.remove('active-hop');
  });
}

async function loadTopology() {
  try {
    const res = await fetch('/api/topology');
    if (!res.ok) {
      throw new Error('failed to load topology');
    }
    const data = await res.json();
    renderTopology(data.endpoints);
  } catch (err) {
    console.error(err);
    topologyRoot.innerHTML =
      '<div style="color:#fca5a5; font-size:0.8rem;">Failed to load topology</div>';
  }
}

function createHookLine(programs, direction) {
  const line = document.createElement('div');
  line.className = 'hook-line';
  line.innerHTML = `<span class="hook-label">${direction}:</span>`;

  programs
    .filter(p => p.direction === direction)
    .forEach(p => {
      const tag = document.createElement('span');
      tag.className = 'tag';
      tag.textContent = p.name;
      line.appendChild(tag);
    });

  return line;
}

function createInterfaceBlock(ep, highlightPeer = true) {
  const ifaceDiv = document.createElement('div');
  ifaceDiv.className = 'iface';
  ifaceDiv.id = ifaceDomId(ep.namespace, ep.name);

  const headerRow = document.createElement('div');
  headerRow.className = 'iface-header';

  const nameSpan = document.createElement('div');
  nameSpan.className = 'iface-name';
  nameSpan.textContent = ep.name;

  const peerSpan = document.createElement('div');
  peerSpan.className = 'iface-peer';
  peerSpan.textContent = `peer: ${ep.peer || '-'}`;

  headerRow.appendChild(nameSpan);
  headerRow.appendChild(peerSpan);
  ifaceDiv.appendChild(headerRow);

  const hookList = document.createElement('div');
  hookList.className = 'hook-list';
  hookList.appendChild(createHookLine(ep.programs || [], 'ingress'));
  hookList.appendChild(createHookLine(ep.programs || [], 'egress'));

  if (highlightPeer && ep.namespace !== 'root') {
    ifaceDiv.addEventListener('mouseenter', () => {
      const hostId = ifaceDomId('root', ep.peer);
      const hostEl = document.getElementById(hostId);
      if (hostEl) hostEl.classList.add('linked-peer');
    });

    ifaceDiv.addEventListener('mouseleave', () => {
      const hostId = ifaceDomId('root', ep.peer);
      const hostEl = document.getElementById(hostId);
      if (hostEl) hostEl.classList.remove('linked-peer');
    });
  }

  ifaceDiv.appendChild(hookList);
  return ifaceDiv;
}

function createNamespaceCard(nsLabel, endpoints = [], {highlightPeer = true} = {}) {
  const card = document.createElement('div');
  card.className = 'ns-card';

  const header = document.createElement('div');
  header.className = 'ns-header';
  header.textContent = `Namespace (${nsLabel})`;
  card.appendChild(header);

  if (!endpoints.length) {
    const empty = document.createElement('div');
    empty.className = 'iface iface-empty';
    empty.textContent = 'No interface data';
    card.appendChild(empty);
    return card;
  }

  endpoints.forEach(ep => {
    card.appendChild(createInterfaceBlock(ep, highlightPeer));
  });

  return card;
}

function drawPeerConnections(svg, container, endpoints) {
  const ns = 'http://www.w3.org/2000/svg';
  svg.innerHTML = '';

  const bounds = container.getBoundingClientRect();
  svg.setAttribute('width', bounds.width);
  svg.setAttribute('height', bounds.height);

  const defs = document.createElementNS(ns, 'defs');
  const marker = document.createElementNS(ns, 'marker');
  marker.setAttribute('id', 'peer-arrow');
  marker.setAttribute('viewBox', '0 0 10 10');
  marker.setAttribute('refX', '8');
  marker.setAttribute('refY', '5');
  marker.setAttribute('markerWidth', '6');
  marker.setAttribute('markerHeight', '6');
  marker.setAttribute('orient', 'auto-start-reverse');

  const markerPath = document.createElementNS(ns, 'path');
  markerPath.setAttribute('d', 'M 0 0 L 10 5 L 0 10 z');
  markerPath.setAttribute('fill', '#60a5fa');
  marker.appendChild(markerPath);
  defs.appendChild(marker);
  svg.appendChild(defs);

  const rootEndpoints = endpoints.filter(
    ep => ep.namespace === 'root' || ep.isRoot
  );
  const peerEndpoints = endpoints.filter(ep => !(ep.namespace === 'root' || ep.isRoot));

  rootEndpoints.forEach(host => {
    const hostEl = document.getElementById(ifaceDomId(host.namespace, host.name));
    if (!hostEl) return;

    const peers = peerEndpoints.filter(ep => ep.peer === host.name);
    peers.forEach(peer => {
      const peerEl = document.getElementById(ifaceDomId(peer.namespace, peer.name));
      if (!peerEl) return;

      const hostRect = hostEl.getBoundingClientRect();
      const peerRect = peerEl.getBoundingClientRect();

      const startX = hostRect.right - bounds.left;
      const startY = hostRect.top + hostRect.height / 2 - bounds.top;
      const endX = peerRect.left - bounds.left;
      const endY = peerRect.top + peerRect.height / 2 - bounds.top;

      const path = document.createElementNS(ns, 'path');
      const controlOffset = Math.max(24, Math.abs(endX - startX) * 0.2);
      path.setAttribute(
        'd',
        `M ${startX} ${startY} C ${startX + controlOffset} ${startY} ${endX - controlOffset} ${endY} ${endX} ${endY}`
      );
      path.setAttribute('fill', 'none');
      path.setAttribute('stroke', '#93c5fd');
      path.setAttribute('stroke-width', '2');
      path.setAttribute('stroke-dasharray', '');
      path.setAttribute('marker-end', 'url(#peer-arrow)');

      svg.appendChild(path);
    });
  });
}

let resizeHandler = null;
let resizeObserver = null;

function renderTopology(endpoints) {
  topologyRoot.innerHTML = '';

  const wrapper = document.createElement('div');
  wrapper.className = 'topology-wrapper';

  const rootNsName = 'root';
  const rootEndpoints = endpoints.filter(
    ep => ep.namespace === rootNsName || ep.isRoot
  );

  const nonRootEndpoints = endpoints.filter(
    ep => !(ep.namespace === rootNsName || ep.isRoot)
  );

  const nsMap = new Map();
  nonRootEndpoints.forEach(ep => {
    const nsName = ep.namespace || 'root';
    if (!nsMap.has(nsName)) {
      nsMap.set(nsName, []);
    }
    nsMap.get(nsName).push(ep);
  });

  const grid = document.createElement('div');
  grid.className = 'ns-grid ns-grid-surface';

  const rootSection = document.createElement('div');
  rootSection.className = 'ns-grid-section';
  const rootHeader = document.createElement('div');
  rootHeader.className = 'ns-grid-header';
  rootHeader.textContent = 'Namespace (root)';
  rootSection.appendChild(rootHeader);
  rootSection.appendChild(
    createNamespaceCard(rootNsName, rootEndpoints, { highlightPeer: false })
  );

  const nsSection = document.createElement('div');
  nsSection.className = 'ns-grid-section';
  const nsHeader = document.createElement('div');
  nsHeader.className = 'ns-grid-header';
  nsHeader.textContent = 'Namespaces';
  nsSection.appendChild(nsHeader);

  const nsList = document.createElement('div');
  nsList.className = 'ns-list';

  if (!nsMap.size) {
    const emptyNs = document.createElement('div');
    emptyNs.className = 'iface iface-empty';
    emptyNs.textContent = 'No namespaces';
    nsList.appendChild(emptyNs);
  }

  for (const [nsName, eps] of nsMap.entries()) {
    nsList.appendChild(createNamespaceCard(nsName, eps));
  }

  nsSection.appendChild(nsList);

  grid.appendChild(rootSection);
  grid.appendChild(nsSection);

  wrapper.appendChild(grid);

  const svgLayer = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svgLayer.classList.add('peer-graph');
  wrapper.appendChild(svgLayer);

  topologyRoot.appendChild(wrapper);
  const redrawConnections = () => drawPeerConnections(svgLayer, wrapper, endpoints);

  // Draw once after layout settles so the positions match the rendered cards.
  requestAnimationFrame(redrawConnections);

  if (resizeHandler) {
    window.removeEventListener('resize', resizeHandler);
  }
  resizeHandler = redrawConnections;
  window.addEventListener('resize', resizeHandler);

  if (resizeObserver) {
    resizeObserver.disconnect();
  }
  resizeObserver = new ResizeObserver(() => redrawConnections());
  resizeObserver.observe(wrapper);
}

function renderPath(result) {
  pathRoot.innerHTML = '';

  if (!result.path || result.path.length === 0) {
    pathRoot.innerHTML =
      '<div style="font-size:0.8rem; color:#9ca3af;">No path data.</div>';
    return;
  }

  result.path.forEach(step => {
    const stepDiv = document.createElement('div');
    stepDiv.className = 'path-step';

    const header = document.createElement('div');
    header.className = 'path-step-header';

    const label = document.createElement('div');
    label.className = 'path-step-label';
    label.textContent = `#${step.step} ${step.ns}/${step.if}`;

    const meta = document.createElement('div');
    meta.className = 'path-step-meta';
    meta.textContent = `${step.hook} • ${step.prog}`;

    header.appendChild(label);
    header.appendChild(meta);

    const note = document.createElement('div');
    note.style.fontSize = '0.75rem';
    note.textContent = step.note || '';

    stepDiv.appendChild(header);
    stepDiv.appendChild(note);

    pathRoot.appendChild(stepDiv);
  });

  // 좌측 토폴로지 하이라이트
  clearActiveHops();
  result.path.forEach(step => {
    const id = ifaceDomId(step.ns, step.if);
    const el = document.getElementById(id);
    if (el) {
      el.classList.add('active-hop');
    }
  });
}

async function runTest() {
  const scenario = scenarioSelect.value;
  statusEl.textContent = `Running ${scenario}...`;
  clearActiveHops();

  try {
    const res = await fetch('/api/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario })
    });

    if (!res.ok) {
      throw new Error('test failed');
    }

    const data = await res.json();
    renderPath(data);
    statusEl.textContent = `Scenario "${data.scenario}" finished: ${data.from.ns}/${data.from.if} -> ${data.to.ns}/${data.to.if}`;
  } catch (err) {
    console.error(err);
    statusEl.textContent = 'Error while running test.';
    pathRoot.innerHTML =
      '<div style="color:#fca5a5; font-size:0.8rem;">Failed to run test</div>';
  }
}

runBtn.addEventListener('click', runTest);
loadTopology();
