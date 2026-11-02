# -*- coding: utf-8 -*-
"""
=============================================================================
  ATTACKGRAPH-AI — CORE GRAPH THEORY & PATHFINDING ENGINE
  Architecture : Directed Acyclic Graph (DAG) for Attack Path Management
  Auteur       : Tohon Fourier (CalderaFourier-code)
=============================================================================
"""

from collections import deque
import json


class AttackNode:
    """Représente une entité ou étape dans la chaîne d'attaque."""
    def __init__(self, node_id, label, category, asset_type, cvss=0.0, mitre_id=None, description="", remediation=""):
        self.node_id = node_id
        self.label = label
        self.category = category  # 'entrypoint', 'vulnerability', 'pivot', 'asset', 'crown_jewel'
        self.asset_type = asset_type  # 'Web', 'API', 'Storage', 'Database', 'Cloud', 'OS'
        self.cvss = float(cvss)
        self.mitre_id = mitre_id
        self.description = description
        self.remediation = remediation

    def to_dict(self):
        return {
            "id": self.node_id,
            "label": self.label,
            "category": self.category,
            "asset_type": self.asset_type,
            "cvss": self.cvss,
            "mitre_id": self.mitre_id,
            "description": self.description,
            "remediation": self.remediation
        }


class AttackEdge:
    """Représente une relation ou transition d'exploit entre deux nœuds."""
    def __init__(self, source_id, target_id, exploit_name, difficulty="Medium", probability=0.8):
        self.source_id = source_id
        self.target_id = target_id
        self.exploit_name = exploit_name
        self.difficulty = difficulty  # 'Low', 'Medium', 'High'
        self.probability = float(probability)

    def to_dict(self):
        return {
            "source": self.source_id,
            "target": self.target_id,
            "exploit_name": self.exploit_name,
            "difficulty": self.difficulty,
            "probability": self.probability
        }


class AttackGraph:
    """Moteur de graphe orienté calculant les chemins d'attaque et les points d'étranglement."""
    def __init__(self):
        self.nodes = {}  # node_id -> AttackNode
        self.edges = []  # List of AttackEdge
        self.adj = {}    # node_id -> [target_id]
        self.rev_adj = {}  # node_id -> [source_id]

    def add_node(self, node):
        self.nodes[node.node_id] = node
        if node.node_id not in self.adj:
            self.adj[node.node_id] = []
        if node.node_id not in self.rev_adj:
            self.rev_adj[node.node_id] = []

    def add_edge(self, edge):
        self.edges.append(edge)
        self.adj[edge.source_id].append(edge.target_id)
        self.rev_adj[edge.target_id].append(edge.source_id)

    def find_all_paths(self, start_id, target_id, visited=None):
        """Recherche récursivement tous les chemins acycliques entre start et target."""
        if visited is None:
            visited = set()
        visited.add(start_id)

        if start_id == target_id:
            return [[start_id]]

        paths = []
        for nxt in self.adj.get(start_id, []):
            if nxt not in visited:
                sub_paths = self.find_all_paths(nxt, target_id, visited.copy())
                for sp in sub_paths:
                    paths.append([start_id] + sp)
        return paths

    def calculate_critical_path(self):
        """Identifie le chemin d'attaque le plus court et le plus critique vers le Joyau."""
        entrypoints = [nid for nid, n in self.nodes.items() if n.category == "entrypoint"]
        crown_jewels = [nid for nid, n in self.nodes.items() if n.category == "crown_jewel"]

        if not entrypoints:
            entrypoints = [nid for nid in self.nodes.keys() if len(self.rev_adj.get(nid, [])) == 0]
        if not crown_jewels:
            crown_jewels = [nid for nid in self.nodes.keys() if len(self.adj.get(nid, [])) == 0]

        all_candidate_paths = []
        for ep in entrypoints:
            for cj in crown_jewels:
                paths = self.find_all_paths(ep, cj)
                for p in paths:
                    # Score de criticité du chemin = Somme des CVSS pondérés par la longueur
                    score = sum(self.nodes[nid].cvss for nid in p)
                    all_candidate_paths.append({"path": p, "score": score, "hops": len(p)})

        if not all_candidate_paths:
            return []

        # Trier par criticité décroissante puis par nombre de sauts
        all_candidate_paths.sort(key=lambda x: (x["score"], -x["hops"]), reverse=True)
        return all_candidate_paths[0]["path"]

    def analyze_choke_points(self):
        """
        Analyse de Théorie des Graphes : Identifie les Nœuds d'Étranglement (Choke Points).
        Ce sont les nœuds intermédiaires qui, s'ils sont patchés, coupent le maximum de chemins d'attaque.
        """
        critical_path = self.calculate_critical_path()
        crown_jewels = [nid for nid, n in self.nodes.items() if n.category == "crown_jewel"]

        choke_scores = {}
        # Ignorer l'entrée publique et le joyau final (on ne supprime pas la BDD ou Internet)
        intermediate_nodes = [nid for nid in self.nodes if self.nodes[nid].category in ["vulnerability", "pivot", "asset"]]

        for nid in intermediate_nodes:
            # Compte combien de chemins vers les crown jewels passent par ce nœud
            covered_routes = 0
            for cj in crown_jewels:
                for ep in [n for n, node in self.nodes.items() if node.category == "entrypoint"]:
                    paths = self.find_all_paths(ep, cj)
                    for p in paths:
                        if nid in p:
                            covered_routes += 1

            if covered_routes > 0:
                choke_scores[nid] = {
                    "node": self.nodes[nid].to_dict(),
                    "impact_score": covered_routes,
                    "is_in_critical_path": nid in critical_path,
                    "remediation": self.nodes[nid].remediation
                }

        # Tri par impact de réduction de risque
        ranked = sorted(choke_scores.values(), key=lambda x: (x["impact_score"], x["is_in_critical_path"]), reverse=True)
        return ranked

    def to_dict(self):
        critical_path = self.calculate_critical_path()
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "critical_path": critical_path,
            "choke_points": self.analyze_choke_points()
        }
