# -*- coding: utf-8 -*-
"""
=============================================================================
  ATTACKGRAPH-AI — AI NARRATIVE & THREAT STORYTELLING ENGINE
  Transformation de la Théorie des Graphes en Histoire d'Infiltration Compréhensible
  Auteur : Tohon Fourier (CalderaFourier-code)
=============================================================================
"""

class AIStoryteller:
    """Génère la narration offensive, l'impact business et la stratégie de mitigation."""

    @staticmethod
    def generate_narrative(graph_data, target_url):
        nodes_dict = {n["id"]: n for n in graph_data["nodes"]}
        critical_path = graph_data.get("critical_path", [])
        choke_points = graph_data.get("choke_points", [])

        if not critical_path:
            return {
                "story": "Aucun chemin d'attaque critique n'a été détecté vers un joyau de la couronne.",
                "business_impact": "Risque résiduel faible.",
                "choke_point_summary": "Poursuivre la surveillance continue."
            }

        path_nodes = [nodes_dict[nid] for nid in critical_path if nid in nodes_dict]
        entry = path_nodes[0]
        jewel = path_nodes[-1]
        intermediates = path_nodes[1:-1]

        # 1. Construction de la narration pas-à-pas
        story_steps = []
        for idx, n in enumerate(path_nodes, 1):
            if n["category"] == "entrypoint":
                story_steps.append(f"1. **Reconnaissance Initiale** : L'attaquant cible le périmètre externe de `{target_url}`.")
            elif n["category"] == "crown_jewel":
                story_steps.append(f"{idx}. **Impact Critique Final** : Les permissions acquises permettent d'accéder directement à **{n['label']}**, entraînant l'exfiltration intégrale des actifs les plus sensibles de l'organisation.")
            else:
                story_steps.append(f"{idx}. **Échelon d'Attaque (Pivot)** : Exploitation de **{n['label']}** ({n.get('mitre_id', 'TTP')}) — {n['description']}")

        full_story = "\n\n".join(story_steps)

        # 2. Synthèse exécutive CISO (Le Pitch)
        if len(intermediates) >= 2:
            first_exploit = intermediates[0]["label"]
            pivot = intermediates[1]["label"]
            executive_summary = (
                f"L'analyse par graphe d'attaque démontre qu'un cybercriminel débutant depuis Internet peut compromettre **{jewel['label']}** "
                f"en seulement **{len(critical_path)-1} étapes d'infiltration**. En exploitant une vulnérabilité sur **{first_exploit}**, "
                f"l'adversaire pivote vers **{pivot}**, contournant les défenses périmétriques pour s'emparer des données confidentielles."
            )
        else:
            executive_summary = f"Chemin direct identifié menant à la compromission de {jewel['label']}."

        # 3. Évaluation de l'impact Business
        max_cvss = max(n["cvss"] for n in path_nodes)
        business_impact = {
            "cvss_max": max_cvss,
            "financial_risk": "Critique (> 500 000 €)",
            "compliance_risk": "Infraction RGPD / Fuite de données personnelles & bancaires",
            "operational_impact": "Arrêt d'activité, dégradation d'image publique et perte de confiance des clients."
        }

        # 4. Recommandation Choke Point
        if choke_points:
            best_choke = choke_points[0]
            choke_summary = (
                f"🎯 **Point d'Étranglement Prioritaire identifié :**\n"
                f"Plutôt que de corriger séparément toutes les vulnérabilités du rapport, **concentrez vos efforts de remédiation sur le nœud `{best_choke['node']['label']}`**.\n"
                f"↳ **Action Corrective :** {best_choke['remediation']}\n"
                f"↳ **Résultat :** Ce correctif brise immédiatement le chemin critique et neutralise 100 % des routes menant au joyau."
            )
        else:
            choke_summary = "Appliquer les correctifs de sécurité standard sur les nœuds identifiés."

        return {
            "executive_summary": executive_summary,
            "full_story": full_story,
            "business_impact": business_impact,
            "choke_point_summary": choke_summary,
            "steps": story_steps
        }
