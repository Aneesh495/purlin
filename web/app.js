/**
 * Purlin Clos Fabric Visualizer & Live Control Plane Console
 * Real-time SVG topology graph, link failure injection, and RIB/FIB sync.
 */

// Initial Topology Definition
const TOPOLOGY = {
  nodes: [
    { id: "spine1", name: "Spine-1", role: "spine", asn: 65100, ip: "10.0.0.1", x: 260, y: 70 },
    { id: "spine2", name: "Spine-2", role: "spine", asn: 65100, ip: "10.0.0.2", x: 540, y: 70 },
    { id: "leaf1",  name: "Leaf-1",  role: "leaf",  asn: 65011, ip: "10.0.0.11", x: 160, y: 280 },
    { id: "leaf2",  name: "Leaf-2",  role: "leaf",  asn: 65012, ip: "10.0.0.12", x: 400, y: 280 },
    { id: "leaf3",  name: "Leaf-3",  role: "leaf",  asn: 65013, ip: "10.0.0.13", x: 640, y: 280 }
  ],
  links: [
    { id: "l1-s1", source: "leaf1", target: "spine1", subnet: "10.0.11.0/30", isUp: true },
    { id: "l1-s2", source: "leaf1", target: "spine2", subnet: "10.0.12.0/30", isUp: true },
    { id: "l2-s1", source: "leaf2", target: "spine1", subnet: "10.0.21.0/30", isUp: true },
    { id: "l2-s2", source: "leaf2", target: "spine2", subnet: "10.0.22.0/30", isUp: true },
    { id: "l3-s1", source: "leaf3", target: "spine1", subnet: "10.0.31.0/30", isUp: true },
    { id: "l3-s2", source: "leaf3", target: "spine2", subnet: "10.0.32.0/30", isUp: true }
  ]
};

// Initial Control Plane State
let state = {
  links: JSON.parse(JSON.stringify(TOPOLOGY.links)),
  tenantPrefixInjected: true,
  selectedNode: "leaf2"
};

// SVG Canvas Elements
const svgLinks = document.getElementById("svg-links");
const svgNodes = document.getElementById("svg-nodes");

function renderTopology() {
  svgLinks.innerHTML = "";
  svgNodes.innerHTML = "";

  // 1. Draw Links
  state.links.forEach(link => {
    const srcNode = TOPOLOGY.nodes.find(n => n.id === link.source);
    const tgtNode = TOPOLOGY.nodes.find(n => n.id === link.target);

    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", srcNode.x);
    line.setAttribute("y1", srcNode.y);
    line.setAttribute("x2", tgtNode.x);
    line.setAttribute("y2", tgtNode.y);
    line.setAttribute("stroke", link.isUp ? "#3fb950" : "#f85149");
    line.setAttribute("stroke-width", link.isUp ? "3" : "2");
    if (!link.isUp) {
      line.setAttribute("stroke-dasharray", "6,4");
    }
    line.style.cursor = "pointer";
    line.onclick = () => toggleLink(link.id);

    // Link label
    const midX = (srcNode.x + tgtNode.x) / 2;
    const midY = (srcNode.y + tgtNode.y) / 2;
    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("x", midX);
    text.setAttribute("y", midY - 6);
    text.setAttribute("fill", link.isUp ? "#8b949e" : "#f85149");
    text.setAttribute("font-size", "10px");
    text.setAttribute("font-family", "monospace");
    text.setAttribute("text-anchor", "middle");
    text.textContent = link.id;

    svgLinks.appendChild(line);
    svgLinks.appendChild(text);
  });

  // 2. Draw Nodes
  TOPOLOGY.nodes.forEach(node => {
    const isSpine = node.role === "spine";
    const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
    g.style.cursor = "pointer";
    g.onclick = () => selectNode(node.id);

    // Outer glow for selected node
    if (state.selectedNode === node.id) {
      const ring = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      ring.setAttribute("cx", node.x);
      ring.setAttribute("cy", node.y);
      ring.setAttribute("r", isSpine ? "28" : "24");
      ring.setAttribute("fill", "none");
      ring.setAttribute("stroke", "#58a6ff");
      ring.setAttribute("stroke-width", "2");
      ring.setAttribute("stroke-dasharray", "4,2");
      g.appendChild(ring);
    }

    // Node body circle
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", node.x);
    circle.setAttribute("cy", node.y);
    circle.setAttribute("r", isSpine ? "22" : "18");
    circle.setAttribute("fill", isSpine ? "#bc8cff" : "#58a6ff");
    circle.setAttribute("stroke", "#ffffff");
    circle.setAttribute("stroke-width", "1.5");
    g.appendChild(circle);

    // Label: Node Name
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", node.x);
    label.setAttribute("y", node.y + (isSpine ? 34 : 30));
    label.setAttribute("fill", "#f0f6fc");
    label.setAttribute("font-size", "11px");
    label.setAttribute("font-weight", "600");
    label.setAttribute("text-anchor", "middle");
    label.textContent = `${node.name} (AS${node.asn})`;
    g.appendChild(label);

    svgNodes.appendChild(g);
  });
}

function selectNode(nid) {
  state.selectedNode = nid;
  renderTopology();
  renderTables();
}

function toggleLink(linkId) {
  const link = state.links.find(l => l.id === linkId);
  if (link) {
    link.isUp = !link.isUp;
    renderTopology();
    renderTables();
    updateTelemetry();
  }
}

function renderTables() {
  const l2s1Up = state.links.find(l => l.id === "l2-s1").isUp;
  const l2s2Up = state.links.find(l => l.id === "l2-s2").isUp;

  // Render Peers Table
  const peerTbody = document.querySelector("#peer-table tbody");
  peerTbody.innerHTML = `
    <tr>
      <td>10.0.21.1</td>
      <td>AS65100 (Spine-1)</td>
      <td><span class="badge ${l2s1Up ? 'badge-success' : 'badge-warning'}">${l2s1Up ? 'ESTABLISHED' : 'ACTIVE'}</span></td>
      <td>90s</td>
      <td>${l2s1Up ? 1 : 0}</td>
    </tr>
    <tr>
      <td>10.0.22.1</td>
      <td>AS65100 (Spine-2)</td>
      <td><span class="badge ${l2s2Up ? 'badge-success' : 'badge-warning'}">${l2s2Up ? 'ESTABLISHED' : 'ACTIVE'}</span></td>
      <td>90s</td>
      <td>${l2s2Up ? 1 : 0}</td>
    </tr>
  `;

  // Render RIB Table
  const ribTbody = document.querySelector("#rib-table tbody");
  let ribRows = "";

  if (state.tenantPrefixInjected) {
    if (l2s1Up) {
      ribRows += `
        <tr>
          <td><span class="status-best">*&gt;</span></td>
          <td>10.101.0.0/16</td>
          <td>10.0.21.1</td>
          <td>65100 65011</td>
          <td>0</td>
          <td>100</td>
          <td>IGP</td>
        </tr>
      `;
    }
    if (l2s2Up) {
      const bestMark = (!l2s1Up) ? "*&gt;" : "*";
      ribRows += `
        <tr>
          <td><span class="status-valid">${bestMark}</span></td>
          <td>10.101.0.0/16</td>
          <td>10.0.22.1</td>
          <td>65100 65011</td>
          <td>0</td>
          <td>100</td>
          <td>IGP</td>
        </tr>
      `;
    }
  }

  ribRows += `
    <tr>
      <td><span class="status-best">*&gt;</span></td>
      <td>10.0.21.0/30</td>
      <td>DIRECT</td>
      <td></td>
      <td>0</td>
      <td>100</td>
      <td>Connected</td>
    </tr>
    <tr>
      <td><span class="status-best">*&gt;</span></td>
      <td>10.0.22.0/30</td>
      <td>DIRECT</td>
      <td></td>
      <td>0</td>
      <td>100</td>
      <td>Connected</td>
    </tr>
  `;
  ribTbody.innerHTML = ribRows;

  // Render FIB Table
  const fibTbody = document.querySelector("#fib-table tbody");
  let fibRows = "";

  if (state.tenantPrefixInjected && (l2s1Up || l2s2Up)) {
    if (l2s1Up && l2s2Up) {
      fibRows += `
        <tr>
          <td><strong>10.101.0.0/16</strong></td>
          <td>10.0.21.1<br>10.0.22.1</td>
          <td>swp1<br>swp2</td>
          <td><span class="badge badge-info">ECMP (2-Path)</span></td>
        </tr>
      `;
    } else if (l2s1Up) {
      fibRows += `
        <tr>
          <td><strong>10.101.0.0/16</strong></td>
          <td>10.0.21.1</td>
          <td>swp1</td>
          <td><span class="badge badge-success">BGP</span></td>
        </tr>
      `;
    } else {
      fibRows += `
        <tr>
          <td><strong>10.101.0.0/16</strong></td>
          <td>10.0.22.1</td>
          <td>swp2</td>
          <td><span class="badge badge-warning">Failover Spine-2</span></td>
        </tr>
      `;
    }
  }

  fibRows += `
    <tr>
      <td>10.0.21.0/30</td>
      <td>CONNECTED</td>
      <td>swp1</td>
      <td>DIRECT</td>
    </tr>
    <tr>
      <td>10.0.22.0/30</td>
      <td>CONNECTED</td>
      <td>swp2</td>
      <td>DIRECT</td>
    </tr>
  `;
  fibTbody.innerHTML = fibRows;
}

function updateTelemetry() {
  const upCount = state.links.filter(l => l.isUp).length;
  document.getElementById("val-peers").textContent = `${upCount} / 6`;

  const l2s1Up = state.links.find(l => l.id === "l2-s1").isUp;
  const l2s2Up = state.links.find(l => l.id === "l2-s2").isUp;

  if (l2s1Up && l2s2Up) {
    document.getElementById("val-fib-ecmp").textContent = "3 (Dual-Path)";
  } else {
    document.getElementById("val-fib-ecmp").textContent = "Failover (Single-Path)";
  }
}

// Event Listeners for Operator Buttons
document.getElementById("btn-toggle-l2s1").onclick = () => {
  toggleLink("l2-s1");
  const link = state.links.find(l => l.id === "l2-s1");
  document.getElementById("btn-toggle-l2s1").textContent = link.isUp ? "Cut Link L2-S1" : "Restore Link L2-S1";
};

document.getElementById("btn-inject-prefix").onclick = () => {
  state.tenantPrefixInjected = !state.tenantPrefixInjected;
  document.getElementById("btn-inject-prefix").textContent = state.tenantPrefixInjected ? "Withdraw 10.101.0.0/16" : "Inject 10.101.0.0/16";
  renderTables();
};

document.getElementById("btn-reset").onclick = () => {
  state.links = JSON.parse(JSON.stringify(TOPOLOGY.links));
  state.tenantPrefixInjected = true;
  document.getElementById("btn-toggle-l2s1").textContent = "Cut Link L2-S1";
  document.getElementById("btn-inject-prefix").textContent = "Inject 10.101.0.0/16";
  renderTopology();
  renderTables();
  updateTelemetry();
};

// Initial Render
renderTopology();
renderTables();
updateTelemetry();
