#!/usr/bin/env python3
"""Build a CWE Weakness ID -> Root Pillar database from cwec_v4.20.xml and generate a Python module."""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
import xml.etree.ElementTree as ET

RESEARCH_CONCEPTS_VIEW_ID = "1000"
PRIMARY_ORDINAL = "Primary"
EXPECTED_ROOT_PILLAR_COUNT = 10


@dataclass(frozen=True)
class RelatedParent:
    """A parent relationship from <Related_Weakness Nature="ChildOf">."""

    cwe_id: int
    view_id: str | None
    ordinal: str | None


@dataclass(frozen=True)
class WeaknessInfo:
    """Metadata and ChildOf parent links extracted from a <Weakness> element."""

    cwe_id: int
    name: str
    abstraction: str
    status: str
    parents: tuple[RelatedParent, ...]


def _extract_namespace(tag: str) -> str:
    """Extract the XML namespace URI from an ElementTree tag like '{uri}LocalName'."""
    if tag.startswith("{") and "}" in tag:
        return tag[1 : tag.index("}")]
    return ""


def load_cwe_catalog(xml_path: Path) -> tuple[dict[int, WeaknessInfo], set[int]]:
    """Parse the CWE XML catalog and return all Weaknesses and the 10 Root Pillar IDs."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns_uri = _extract_namespace(root.tag)
    ns = {"cwe": ns_uri} if ns_uri else {}
    prefix = "cwe:" if ns_uri else ""

    weaknesses: dict[int, WeaknessInfo] = {}
    pillar_abstraction_ids: set[int] = set()

    for elem in root.findall(f"{prefix}Weaknesses/{prefix}Weakness", ns):
        cwe_id = int(elem.attrib["ID"])
        name = " ".join(elem.attrib.get("Name", "").split())
        abstraction = elem.attrib.get("Abstraction", "")
        status = elem.attrib.get("Status", "")

        parents: list[RelatedParent] = []
        for rel in elem.findall(
            f"{prefix}Related_Weaknesses/{prefix}Related_Weakness", ns
        ):
            if rel.attrib.get("Nature") == "ChildOf":
                parents.append(
                    RelatedParent(
                        cwe_id=int(rel.attrib["CWE_ID"]),
                        view_id=rel.attrib.get("View_ID"),
                        ordinal=rel.attrib.get("Ordinal"),
                    )
                )

        weaknesses[cwe_id] = WeaknessInfo(
            cwe_id=cwe_id,
            name=name,
            abstraction=abstraction,
            status=status,
            parents=tuple(parents),
        )

        if abstraction == "Pillar" and status != "Deprecated":
            pillar_abstraction_ids.add(cwe_id)

    view_1000_pillars: set[int] = set()
    for view in root.findall(f"{prefix}Views/{prefix}View", ns):
        if view.attrib.get("ID") == RESEARCH_CONCEPTS_VIEW_ID:
            for member in view.findall(f"{prefix}Members/{prefix}Has_Member", ns):
                view_1000_pillars.add(int(member.attrib["CWE_ID"]))
            break

    root_pillars = pillar_abstraction_ids or view_1000_pillars
    if view_1000_pillars and pillar_abstraction_ids != view_1000_pillars:
        raise ValueError(
            f"Mismatch between Abstraction='Pillar' IDs ({sorted(pillar_abstraction_ids)}) "
            f"and View {RESEARCH_CONCEPTS_VIEW_ID} members ({sorted(view_1000_pillars)})."
        )
    if len(root_pillars) != EXPECTED_ROOT_PILLAR_COUNT:
        raise ValueError(
            f"Expected {EXPECTED_ROOT_PILLAR_COUNT} Root Pillars, found {len(root_pillars)}: "
            f"{sorted(root_pillars)}"
        )

    return weaknesses, root_pillars


def _select_disambiguated_parent(parents: tuple[RelatedParent, ...]) -> RelatedParent:
    """Select the canonical ChildOf parent when multiple parents lead to different pillars."""
    for candidate_filter in (
        lambda p: p.view_id == RESEARCH_CONCEPTS_VIEW_ID
        and p.ordinal == PRIMARY_ORDINAL,
        lambda p: p.view_id == RESEARCH_CONCEPTS_VIEW_ID,
        lambda p: p.ordinal == PRIMARY_ORDINAL,
    ):
        matches = [p for p in parents if candidate_filter(p)]
        if len(matches) == 1:
            return matches[0]
        if matches:
            return matches[0]
    return parents[0]


def build_root_pillar_database(
    weaknesses: dict[int, WeaknessInfo],
    root_pillars: set[int],
) -> dict[int, int]:
    """Map each active Weakness ID to its corresponding Root Pillar ID."""
    resolved: dict[int, int] = {}
    visiting: set[int] = set()

    def resolve(cwe_id: int) -> int:
        if cwe_id in resolved:
            return resolved[cwe_id]
        if cwe_id in root_pillars:
            resolved[cwe_id] = cwe_id
            return cwe_id
        if cwe_id in visiting:
            raise ValueError(f"Cycle detected in ChildOf hierarchy involving CWE-{cwe_id}.")

        info = weaknesses.get(cwe_id)
        if info is None:
            raise KeyError(f"Referenced parent CWE-{cwe_id} was not found in Weaknesses.")
        if not info.parents:
            raise ValueError(
                f"CWE-{cwe_id} ({info.name}) is not a Root Pillar and has no ChildOf parents."
            )

        visiting.add(cwe_id)
        try:
            # First check only View 1000 Primary if multiple parents disagree across views/ordinals,
            # or inspect all ChildOf parents and disambiguate if more than one pillar is reachable.
            candidate_pillars = {resolve(parent.cwe_id) for parent in info.parents}
            if len(candidate_pillars) == 1:
                pillar_id = next(iter(candidate_pillars))
            else:
                chosen_parent = _select_disambiguated_parent(info.parents)
                pillar_id = resolve(chosen_parent.cwe_id)
        finally:
            visiting.remove(cwe_id)

        resolved[cwe_id] = pillar_id
        return pillar_id

    for cwe_id, info in sorted(weaknesses.items()):
        if info.status == "Deprecated":
            continue
        resolve(cwe_id)

    return resolved


def generate_python_module(
    weakness_to_pillar: dict[int, int],
    weaknesses: dict[int, WeaknessInfo],
    root_pillars: set[int],
    source_xml_name: str,
    output_path: Path,
) -> None:
    """Programmatically generate a Python file exposing the ID -> Root Pillar map."""
    grouped_by_pillar: dict[int, list[int]] = defaultdict(list)
    for cwe_id, pillar_id in weakness_to_pillar.items():
        grouped_by_pillar[pillar_id].append(cwe_id)

    lines: list[str] = [
        f'"""Auto-generated mapping from CWE Weakness ID to its corresponding Root Pillar ID.',
        "",
        f"Source: {source_xml_name}",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "WEAKNESS_TO_ROOT_PILLAR: dict[int, int] = {",
    ]

    sorted_pillars = sorted(root_pillars)
    for idx, pillar_id in enumerate(sorted_pillars):
        pillar_name = weaknesses[pillar_id].name
        ordered_ids = sorted(grouped_by_pillar.get(pillar_id, []))

        if idx > 0:
            lines.append("")
        lines.append(
            f"    # --- Root Pillar CWE-{pillar_id}: {pillar_name} "
            f"({len(ordered_ids)} weaknesses) ---"
        )
        for cwe_id in ordered_ids:
            w_name = weaknesses[cwe_id].name
            suffix = " (Root Pillar)" if cwe_id == pillar_id else ""
            lines.append(f"    {cwe_id}: {pillar_id},  # {w_name}{suffix}")

    lines.extend(
        [
            "}",
            "",
            '__all__ = ["WEAKNESS_TO_ROOT_PILLAR"]',
            "",
        ]
    )

    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    default_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description=(
            "Load CWE XML definitions, map each Weakness ID to its Root Pillar, "
            "and generate a Python module exposing the grouped mapping."
        )
    )
    parser.add_argument(
        "--xml",
        type=Path,
        default=default_dir / "cwec_v4.20.xml",
        help="Path to cwec_v4.20.xml (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=default_dir / "cwe_root_pillars.py",
        help="Path to the generated Python file (default: %(default)s)",
    )
    args = parser.parse_args()

    weaknesses, root_pillars = load_cwe_catalog(args.xml)
    weakness_to_pillar = build_root_pillar_database(weaknesses, root_pillars)
    generate_python_module(
        weakness_to_pillar=weakness_to_pillar,
        weaknesses=weaknesses,
        root_pillars=root_pillars,
        source_xml_name=args.xml.name,
        output_path=args.output,
    )

    deprecated_count = sum(1 for w in weaknesses.values() if w.status == "Deprecated")
    print(
        f"Mapped {len(weakness_to_pillar)} Weaknesses across {len(root_pillars)} Root Pillars "
        f"(skipped {deprecated_count} deprecated Weaknesses) -> {args.output}"
    )


if __name__ == "__main__":
    main()

