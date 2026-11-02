/**
 * =============================================================================
 *  ATTACKGRAPH-AI — CLIENT APPLICATION CONTROLLER
 *  Graph Theory Visualization, Choke Point Simulator & Threat Intelligence
 *  Auteur : Tohon Fourier (CalderaFourier-code)
 * =============================================================================
 */

let currentScanData = null;
let selectedNodeId = null;
let patchedNodeId = null;

document.addEventListener("DOMContentLoaded", () => {
    // Initialiser l'analyse sur le scénario par défaut
    triggerAttackGraphGeneration();

    document.getElementById("generateBtn").addEventListener("click", () => {
        triggerAttackGraphGeneration();
    });

    // Redessiner les arêtes SVG lors du redimensionnement de la fenêtre
    window.addEventListener("resize", () => {
        if (currentScanData) drawGraphEdges(currentScanData.graph);
    });
});

async function triggerAttackGraphGeneration() {
    const targetUrl = document.getElementById("targetUrl").value.trim() || "https://entreprise.com";
    const scenario = document.getElementById("scenarioSelect").value;
    const generateBtn = document.getElementById("generateBtn");

    generateBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> CALCUL DES CHEMINS...';
    generateBtn.disabled = true;

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: targetUrl, scenario: scenario })
        });

        if (!response.ok) throw new Error("Erreur de calcul du graphe");

        const data = await response.json();
        currentScanData = data;
        patchedNodeId = null;
        document.getElementById("remediationBanner").classList.add("hidden");

        renderDashboard(data);
    } catch (err) {
        alert("Erreur lors de la génération du graphe d'attaque : " + err.message);
    } finally {
        generateBtn.innerHTML = '<i class="fas fa-wand-magic-sparkles"></i> CONSTRUIRE LE GRAPHE D\'ATTAQUE';
        generateBtn.disabled = false;
    }
}

function renderDashboard(data) {
    const graph = data.graph;
    const narrative = data.narrative;

    // 1. Narration Exécutive
    document.getElementById("executiveSummary").textContent = narrative.executive_summary;

    // 2. Point d'étranglement (Choke Point)
    const chokeBox = document.getElementById("chokePointContent");
    if (graph.choke_points && graph.choke_points.length > 0) {
        const best = graph.choke_points[0];
        chokeBox.innerHTML = `
            <div><strong>Nœud Critique :</strong> ${best.node.label} (${best.node.mitre_id || "Vuln"})</div>
            <div class="choke-action-box">
                <i class="fas fa-shield-virus"></i> <strong>Patch Prioritaire :</strong> ${best.remediation}
            </div>
            <button class="simulate-fix-btn" style="margin-top: 10px; width: 100%; justify-content: center;" onclick="applyQuickChokeFix('${best.node.id}')">
                <i class="fas fa-wrench"></i> SIMULER LE CORRECTIF SUR CE POINT
            </button>
        `;
    } else {
        chokeBox.innerHTML = `<p style="color:#94a3b8;">Aucun nœud d'étranglement unique identifié.</p>`;
    }

    // 3. Métriques Business
    const bImpact = narrative.business_impact;
    document.getElementById("cvssMax").textContent = bImpact.cvss_max;
    document.getElementById("financialRisk").textContent = bImpact.financial_risk;
    document.getElementById("complianceRisk").textContent = bImpact.compliance_risk;

    // 4. Chronologie / Walkthrough
    const wtList = document.getElementById("walkthroughList");
    wtList.innerHTML = "";
    narrative.steps.forEach(st => {
        const div = document.createElement("div");
        div.className = "walkthrough-item";
        div.innerHTML = st.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
        wtList.appendChild(div);
    });

    // 5. Rendu Visuel du Graphe (DAG)
    renderNodes(graph);
    setTimeout(() => drawGraphEdges(graph), 50);
}

function renderNodes(graph) {
    const wrapper = document.getElementById("nodesWrapper");
    wrapper.innerHTML = "";

    graph.nodes.forEach(node => {
        const card = document.createElement("div");
        card.id = `node_${node.id}`;
        card.className = `attack-node ${node.category}`;
        card.onclick = () => openNodeModal(node.id);

        let icon = "fa-server";
        if (node.category === "entrypoint") icon = "fa-globe";
        else if (node.category === "crown_jewel") icon = "fa-database";
        else if (node.asset_type === "Auth") icon = "fa-key";
        else if (node.asset_type === "API") icon = "fa-network-wired";
        else if (node.asset_type === "Storage") icon = "fa-file-upload";

        card.innerHTML = `
            <div class="node-header">
                <div class="node-title"><i class="fas ${icon}"></i> ${node.label}</div>
                <div class="node-pills">
                    ${node.cvss > 0 ? `<span class="pill-cvss">CVSS ${node.cvss}</span>` : ""}
                    ${node.mitre_id ? `<span class="pill-mitre">${node.mitre_id}</span>` : ""}
                </div>
            </div>
            <div class="node-desc">${node.description || "Nœud de transition du chemin d'attaque."}</div>
        `;

        wrapper.appendChild(card);
    });
}

function drawGraphEdges(graph) {
    const svg = document.getElementById("svgEdges");
    const container = document.getElementById("graphContainer");
    svg.innerHTML = "";

    // Dimensions SVG basées sur le conteneur défilant
    svg.setAttribute("width", container.scrollWidth);
    svg.setAttribute("height", container.scrollHeight);

    // Définir la flèche marqueur
    const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
    defs.innerHTML = `
        <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#00e5ff"/>
        </marker>
        <marker id="arrow-disabled" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#475569"/>
        </marker>
    `;
    svg.appendChild(defs);

    const cRect = container.getBoundingClientRect();

    graph.edges.forEach(edge => {
        const srcEl = document.getElementById(`node_${edge.source}`);
        const tgtEl = document.getElementById(`node_${edge.target}`);

        if (!srcEl || !tgtEl) return;

        const sRect = srcEl.getBoundingClientRect();
        const tRect = tgtEl.getBoundingClientRect();

        // Calcul des coordonnées relatives au conteneur scrollable
        const x1 = sRect.left + sRect.width / 2 - cRect.left + container.scrollLeft;
        const y1 = sRect.bottom - cRect.top + container.scrollTop;
        const x2 = tRect.left + tRect.width / 2 - cRect.left + container.scrollLeft;
        const y2 = tRect.top - cRect.top + container.scrollTop;

        const isCut = srcEl.classList.contains("neutralized") || srcEl.classList.contains("patched-shield");

        // Ligne connectrice avec flèche
        const line = document.createElementNS("http://www.w3.org/2000/svg", "path");
        const dy = (y2 - y1) / 2;
        const d = `M ${x1} ${y1} C ${x1} ${y1 + dy}, ${x2} ${y2 - dy}, ${x2} ${y2}`;

        line.setAttribute("d", d);
        line.setAttribute("fill", "none");
        line.setAttribute("stroke", isCut ? "#475569" : "#00e5ff");
        line.setAttribute("stroke-width", isCut ? "2" : "3");
        line.setAttribute("stroke-dasharray", isCut ? "4" : "none");
        line.setAttribute("marker-end", isCut ? "url(#arrow-disabled)" : "url(#arrow)");
        svg.appendChild(line);

        // Étiquette d'exploit sur l'arête
        if (!isCut && edge.exploit_name) {
            const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
            text.setAttribute("x", (x1 + x2) / 2 + 10);
            text.setAttribute("y", (y1 + y2) / 2);
            text.setAttribute("fill", "#f59e0b");
            text.setAttribute("font-size", "11px");
            text.setAttribute("font-family", "Share Tech Mono, monospace");
            text.textContent = `⚡ ${edge.exploit_name}`;
            svg.appendChild(text);
        }
    });
}

function openNodeModal(nodeId) {
    if (!currentScanData) return;
    const node = currentScanData.graph.nodes.find(n => n.id === nodeId);
    if (!node) return;

    selectedNodeId = nodeId;
    document.getElementById("modalTitle").textContent = node.label;
    document.getElementById("modalCategory").textContent = node.category.toUpperCase();
    document.getElementById("modalAsset").textContent = node.asset_type;
    document.getElementById("modalCvss").textContent = node.cvss > 0 ? `CVSS ${node.cvss}` : "N/A";
    document.getElementById("modalMitre").textContent = node.mitre_id || "Non répertorié";
    document.getElementById("modalDesc").textContent = node.description;
    document.getElementById("modalRemediation").textContent = node.remediation;

    document.getElementById("nodeModal").classList.remove("hidden");
}

function closeModal() {
    document.getElementById("nodeModal").classList.add("hidden");
}

function simulateFixOnSelectedNode() {
    if (!selectedNodeId) return;
    applyQuickChokeFix(selectedNodeId);
    closeModal();
}

function applyQuickChokeFix(nodeId) {
    if (!currentScanData) return;
    patchedNodeId = nodeId;

    const graph = currentScanData.graph;
    const nodes = graph.nodes;

    // Trouver l'index du nœud patché dans le chemin critique
    const critPath = graph.critical_path;
    const patchIdx = critPath.indexOf(nodeId);

    // Mettre à jour l'apparence des nœuds
    nodes.forEach(n => {
        const el = document.getElementById(`node_${n.id}`);
        if (!el) return;

        el.classList.remove("patched-shield", "neutralized");

        if (n.id === nodeId) {
            el.classList.add("patched-shield");
        } else if (patchIdx !== -1) {
            const nIdx = critPath.indexOf(n.id);
            if (nIdx > patchIdx) {
                // Tout ce qui est en aval du correctif est neutralisé
                el.classList.add("neutralized");
            }
        }
    });

    const patchedNode = nodes.find(n => n.id === nodeId);
    const banner = document.getElementById("remediationBanner");
    const msg = document.getElementById("remediationMsg");

    msg.textContent = `Correctif simulé sur "${patchedNode.label}" ! 100% des chemins d'attaque en aval vers le Joyau de la Couronne sont neutralisés.`;
    banner.classList.remove("hidden");

    // Redessiner les connecteurs
    drawGraphEdges(graph);
}

function resetRemediation() {
    patchedNodeId = null;
    document.getElementById("remediationBanner").classList.add("hidden");

    if (currentScanData) {
        currentScanData.graph.nodes.forEach(n => {
            const el = document.getElementById(`node_${n.id}`);
            if (el) el.classList.remove("patched-shield", "neutralized");
        });
        drawGraphEdges(currentScanData.graph);
    }
}

// Export JSON
function exportJSON() {
    if (!currentScanData) return;
    const blob = new Blob([JSON.stringify(currentScanData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `attackgraph_${Date.now()}.json`;
    a.click();
}

// Export Diagramme Mermaid.js pour rapports de pentest
function exportMermaid() {
    if (!currentScanData) return;
    const graph = currentScanData.graph;
    let mm = "```mermaid\ngraph TD\n";

    graph.nodes.forEach(n => {
        const safeLabel = n.label.replace(/"/g, "'");
        if (n.category === "crown_jewel") {
            mm += `    ${n.id}["👑 ${safeLabel} (CROWN JEWEL)"]:::jewel\n`;
        } else if (n.category === "entrypoint") {
            mm += `    ${n.id}["🌐 ${safeLabel}"]:::entry\n`;
        } else {
            mm += `    ${n.id}["⚡ ${safeLabel} [${n.mitre_id || 'Vuln'}]"]\n`;
        }
    });

    graph.edges.forEach(e => {
        mm += `    ${e.source} -->|"${e.exploit_name}"| ${e.target}\n`;
    });

    mm += "    classDef jewel fill:#ef4444,stroke:#fff,stroke-width:2px,color:#fff;\n";
    mm += "    classDef entry fill:#00e5ff,stroke:#0077b6,stroke-width:2px,color:#000;\n";
    mm += "```";

    navigator.clipboard.writeText(mm).then(() => {
        alert("Syntaxe Mermaid.js copiée dans le presse-papier ! Vous pouvez la coller dans GitHub, Notion ou vos rapports Markdown.");
    });
}
