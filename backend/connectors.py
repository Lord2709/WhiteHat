import re
from typing import Any, Dict, List, Set

from schemas import DependencyEdge, InternalDoc, VendorAdvisory


def norm_token(value: str) -> str:
    return re.sub(r"[^a-z0-9._\-/@]+", "", (value or "").strip().lower())


def package_base_name(package_value: str) -> str:
    raw = (package_value or "").strip().lower()
    if "@" in raw and not raw.startswith("@"):
        return raw.split("@", 1)[0]
    return raw


def dependency_reach(start: str, edges: List[Dict[str, Any]], max_nodes: int = 25) -> List[str]:
    index: Dict[str, Set[str]] = {}
    for e in edges:
        src = norm_token(str(e.get("source", "")))
        tgt = norm_token(str(e.get("target", "")))
        if not src or not tgt:
            continue
        index.setdefault(src, set()).add(tgt)
    seen: Set[str] = set()
    queue: List[str] = [norm_token(start)]
    while queue and len(seen) < max_nodes:
        cur = queue.pop(0)
        for nxt in sorted(index.get(cur, set())):
            if nxt in seen:
                continue
            seen.add(nxt)
            queue.append(nxt)
            if len(seen) >= max_nodes:
                break
    return list(seen)


def apply_connector_signals(
    vuln: Dict[str, Any],
    advisories: List[VendorAdvisory],
    internal_docs: List[InternalDoc],
    dependency_graph: List[DependencyEdge],
) -> Dict[str, Any]:
    cve_id = norm_token(str(vuln.get("cve_id", "")))
    pkg = package_base_name(str(vuln.get("package", "")))

    advisory_hits: List[str] = []
    for adv in advisories:
        cves = {norm_token(c) for c in (adv.cve_ids or [])}
        adv_pkgs = {package_base_name(p) for p in (adv.affected_packages or [])}
        text_blob = " ".join([adv.title or "", adv.summary or "", adv.advisory_id or ""]).lower()
        if cve_id and cve_id in cves:
            advisory_hits.append(adv.advisory_id or adv.title or "vendor-advisory")
        elif pkg and (pkg in adv_pkgs or pkg in text_blob):
            advisory_hits.append(adv.advisory_id or adv.title or "vendor-advisory")

    doc_hits: List[str] = []
    doc_systems: Set[str] = set()
    for doc in internal_docs:
        blob = " ".join([
            doc.title or "",
            doc.content or "",
            " ".join(doc.tags or []),
            " ".join(doc.systems or []),
        ]).lower()
        if (cve_id and cve_id in blob) or (pkg and pkg in blob):
            doc_hits.append(doc.doc_id or doc.title or "internal-doc")
            for s in (doc.systems or []):
                if s:
                    doc_systems.add(str(s))

    dep_reach = dependency_reach(pkg, [e.model_dump() for e in dependency_graph]) if pkg else []

    connector_signals = {
        "vendor_advisory_hits": len(advisory_hits),
        "internal_doc_hits": len(doc_hits),
        "dependency_reach": len(dep_reach),
        "matched_advisories": advisory_hits[:5],
        "matched_docs": doc_hits[:5],
        "dependency_downstream": dep_reach[:8],
    }

    affected = list(vuln.get("affected_systems", []) or [])
    for item in list(doc_systems) + dep_reach:
        if item not in affected:
            affected.append(item)
    vuln["affected_systems"] = affected[:10]
    vuln["connector_signals"] = connector_signals
    return connector_signals
