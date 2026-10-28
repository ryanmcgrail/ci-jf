#!/usr/bin/env python3
"""Parse cwec_v4.20.xml into an in-memory relational CWE database and query parent relationships."""

from __future__ import annotations

from collections.abc import Mapping
import argparse
from collections import deque
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from typing import Any
import xml.etree.ElementTree as ET

DEFAULT_XML_PATH = Path(__file__).resolve().parent / "cwec_v4.20.xml"

# Relationships where the declaring Weakness (A) is the parent of the target CWE_ID (B).
PARENT_TO_CHILD_NATURES = frozenset({"ParentOf", "CanPrecede"})

# Relationships where the declaring Weakness (A) is the child of the target CWE_ID (B).
CHILD_TO_PARENT_NATURES = frozenset({"ChildOf", "CanFollow", "CanAlsoBe", "StartsWith"})

SUPPORTED_NATURES = PARENT_TO_CHILD_NATURES | CHILD_TO_PARENT_NATURES


def _extract_namespace(tag: str) -> str:
    """Extract the XML namespace URI from an ElementTree tag like '{uri}LocalName'."""
    if tag.startswith("{") and "}" in tag:
        return tag[1 : tag.index("}")]
    return ""


def parse_cwe_id(value: int | str | Mapping[str, Any]) -> int | None:
    """Normalize an int, string (e.g. 79, '79', 'CWE-79'), or finding dict into an integer CWE ID."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, Mapping):
        combined = " ".join(
            str(value.get(k) or "")
            for k in (
                "vuln_id",
                "VulnID",
                "vuln_type",
                "VulnType",
                "title",
                "Title",
                "description",
            )
        )
        match = re.search(r"CWE-(\d+)", combined, re.IGNORECASE)
        return int(match.group(1)) if match else None
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
        match = re.search(r"CWE-(\d+)", text, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


@dataclass
class Weakness:
    """A CWE Weakness record and its relationships across all supported Natures."""

    cwe_id: int
    name: str
    abstraction: str = ""
    status: str = ""
    child_of: set[int] = field(default_factory=set)
    parent_of: set[int] = field(default_factory=set)
    can_precede: set[int] = field(default_factory=set)
    can_follow: set[int] = field(default_factory=set)
    can_also_be: set[int] = field(default_factory=set)
    starts_with: set[int] = field(default_factory=set)
    parents: set[int] = field(default_factory=set)
    children: set[int] = field(default_factory=set)


class CWEDatabase:
    """In-memory relational database of CWE Weaknesses and their directed relationships."""

    def __init__(self, weaknesses: dict[int, Weakness]) -> None:
        self.weaknesses: dict[int, Weakness] = weaknesses
        # Directed edges from (parent_id, child_id) -> set of relationship labels
        self._edge_natures: dict[tuple[int, int], set[str]] = {}
        for w in self.weaknesses.values():
            for p_id in w.child_of:
                self._add_edge_label(p_id, w.cwe_id, "ChildOf")
            for c_id in w.parent_of:
                self._add_edge_label(w.cwe_id, c_id, "ParentOf")
            for c_id in w.can_precede:
                self._add_edge_label(w.cwe_id, c_id, "CanPrecede")
            for p_id in w.can_follow:
                self._add_edge_label(p_id, w.cwe_id, "CanFollow")
            for p_id in w.can_also_be:
                self._add_edge_label(p_id, w.cwe_id, "CanAlsoBe")
            for p_id in w.starts_with:
                self._add_edge_label(p_id, w.cwe_id, "StartsWith")

    def _add_edge_label(self, parent_id: int, child_id: int, nature: str) -> None:
        self._edge_natures.setdefault((parent_id, child_id), set()).add(nature)

    @classmethod
    def from_xml(cls, xml_path: str | Path = DEFAULT_XML_PATH) -> CWEDatabase:
        """Load all Weaknesses and their supported relationships from CWE XML."""
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ns_uri = _extract_namespace(root.tag)
        ns = {"cwe": ns_uri} if ns_uri else {}
        prefix = "cwe:" if ns_uri else ""

        weaknesses: dict[int, Weakness] = {}
        raw_relations: list[tuple[int, str, int]] = []

        for elem in root.findall(f"{prefix}Weaknesses/{prefix}Weakness", ns):
            cwe_id = int(elem.attrib["ID"])
            name = " ".join(elem.attrib.get("Name", "").split())
            abstraction = elem.attrib.get("Abstraction", "")
            status = elem.attrib.get("Status", "")

            weaknesses[cwe_id] = Weakness(
                cwe_id=cwe_id,
                name=name,
                abstraction=abstraction,
                status=status,
            )

            for rel in elem.findall(
                f"{prefix}Related_Weaknesses/{prefix}Related_Weakness", ns
            ):
                nature = rel.attrib.get("Nature", "")
                if nature in SUPPORTED_NATURES:
                    target_id = int(rel.attrib["CWE_ID"])
                    raw_relations.append((cwe_id, nature, target_id))

        for source_id, nature, target_id in raw_relations:
            source = weaknesses.get(source_id)
            target = weaknesses.get(target_id)
            if source is None or target is None:
                continue

            if nature == "ChildOf":
                # source is ChildOf target -> target is parent of source
                source.child_of.add(target_id)
                target.parent_of.add(source_id)
                source.parents.add(target_id)
                target.children.add(source_id)
            elif nature == "ParentOf":
                # source is ParentOf target -> source is parent of target
                source.parent_of.add(target_id)
                target.child_of.add(source_id)
                source.children.add(target_id)
                target.parents.add(source_id)
            elif nature == "CanPrecede":
                # source CanPrecede target -> source is parent of target
                source.can_precede.add(target_id)
                target.can_follow.add(source_id)
                source.children.add(target_id)
                target.parents.add(source_id)
            elif nature == "CanFollow":
                # source CanFollow target -> target is parent of source
                source.can_follow.add(target_id)
                target.can_precede.add(source_id)
                source.parents.add(target_id)
                target.children.add(source_id)
            elif nature == "CanAlsoBe":
                # source CanAlsoBe target -> target is parent of source
                source.can_also_be.add(target_id)
                source.parents.add(target_id)
                target.children.add(source_id)
            elif nature == "StartsWith":
                # source StartsWith target -> target is parent of source
                source.starts_with.add(target_id)
                source.parents.add(target_id)
                target.children.add(source_id)

        return cls(weaknesses)

    def get_weakness(self, cwe_id: int | str) -> Weakness | None:
        """Return the Weakness record for cwe_id, or None if not found."""
        parsed = parse_cwe_id(cwe_id)
        if parsed is None:
            return None
        return self.weaknesses.get(parsed)

    def _shortest_distance(
        self,
        parent_id: int,
        child_id: int,
        strict_hierarchy_only: bool = False,
    ) -> int | None:
        """Return the minimum number of parent -> child steps from parent_id to child_id."""
        if parent_id == child_id:
            return 0

        queue: deque[tuple[int, int]] = deque([(parent_id, 0)])
        visited: set[int] = {parent_id}

        while queue:
            curr_id, dist = queue.popleft()
            curr = self.weaknesses.get(curr_id)
            if curr is None:
                continue
            next_ids = curr.parent_of if strict_hierarchy_only else curr.children
            for next_id in next_ids:
                if next_id == child_id:
                    return dist + 1
                if next_id not in visited:
                    visited.add(next_id)
                    queue.append((next_id, dist + 1))

        return None

    def find_parent(
        self, cwe_a: int | str | Mapping[str, Any], cwe_b: int | str | Mapping[str, Any]
    ) -> int | None:
        """Determine if cwe_a and cwe_b are related and return whichever is the parent.

        A Weakness P is considered the parent of C if there is a directed chain of one or
        more steps from P to C where each step is a ParentOf/CanPrecede relationship from
        parent to child, or a ChildOf/CanFollow/StartsWith/CanAlsoBe relationship from
        child to parent.

        Returns the parent CWE ID as an int, or None if the Weaknesses are unrelated.
        """
        id_a = parse_cwe_id(cwe_a)
        id_b = parse_cwe_id(cwe_b)
        if id_a is None or id_b is None:
            return None
        if id_a not in self.weaknesses or id_b not in self.weaknesses:
            return None
        if id_a == id_b:
            return id_a

        dist_a_to_b = self._shortest_distance(id_a, id_b)
        dist_b_to_a = self._shortest_distance(id_b, id_a)

        if dist_a_to_b is not None and dist_b_to_a is None:
            return id_a
        if dist_b_to_a is not None and dist_a_to_b is None:
            return id_b
        if dist_a_to_b is None and dist_b_to_a is None:
            return None

        # Both directions are reachable (e.g. a CanPrecede cycle with ChildOf):
        # prefer the shorter path, then pure ChildOf/ParentOf hierarchy, then lower ID.
        assert dist_a_to_b is not None and dist_b_to_a is not None
        if dist_a_to_b < dist_b_to_a:
            return id_a
        if dist_b_to_a < dist_a_to_b:
            return id_b

        strict_a_to_b = self._shortest_distance(id_a, id_b, strict_hierarchy_only=True)
        strict_b_to_a = self._shortest_distance(id_b, id_a, strict_hierarchy_only=True)
        if strict_a_to_b is not None and strict_b_to_a is None:
            return id_a
        if strict_b_to_a is not None and strict_a_to_b is None:
            return id_b

        return min(id_a, id_b)

    get_related_parent = find_parent

    def find_relationship_path(
        self, cwe_a: int | str, cwe_b: int | str
    ) -> list[tuple[int, str, int]] | None:
        """Return the shortest chain of (parent_id, nature, child_id) steps between cwe_a and cwe_b."""
        parent_id = self.find_parent(cwe_a, cwe_b)
        if parent_id is None:
            return None
        id_a = parse_cwe_id(cwe_a)
        id_b = parse_cwe_id(cwe_b)
        assert id_a is not None and id_b is not None
        if id_a == id_b:
            return []

        child_id = id_b if parent_id == id_a else id_a
        queue: deque[tuple[int, list[tuple[int, str, int]]]] = deque([(parent_id, [])])
        visited: set[int] = {parent_id}

        while queue:
            curr_id, path = queue.popleft()
            curr = self.weaknesses[curr_id]
            for next_id in sorted(curr.children):
                natures = sorted(self._edge_natures.get((curr_id, next_id), {"ParentOf"}))
                step = (curr_id, "/".join(natures), next_id)
                if next_id == child_id:
                    return path + [step]
                if next_id not in visited:
                    visited.add(next_id)
                    queue.append((next_id, path + [step]))

        return None


def load_cwe_database(xml_path: str | Path = DEFAULT_XML_PATH) -> CWEDatabase:
    """Convenience loader returning a CWEDatabase parsed from xml_path."""
    return CWEDatabase.from_xml(xml_path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Query the CWE relational database to determine if two Weaknesses are related "
            "and return whichever is the parent (or null if unrelated)."
        )
    )
    parser.add_argument("cwe_a", help="First CWE ID (e.g. 707 or CWE-707)")
    parser.add_argument("cwe_b", help="Second CWE ID (e.g. 79 or CWE-79)")
    parser.add_argument(
        "--xml",
        type=Path,
        default=DEFAULT_XML_PATH,
        help="Path to cwec_v4.20.xml (default: %(default)s)",
    )
    parser.add_argument(
        "--path",
        action="store_true",
        help="Also display the multi-step relationship chain from parent to child",
    )
    args = parser.parse_args()

    db = load_cwe_database(args.xml)
    parent = db.find_parent(args.cwe_a, args.cwe_b)
    print(json.dumps(parent))

    if args.path and parent is not None:
        steps = db.find_relationship_path(args.cwe_a, args.cwe_b) or []
        for p_id, nature, c_id in steps:
            p_name = db.weaknesses[p_id].name
            c_name = db.weaknesses[c_id].name
            print(f"  CWE-{p_id} ({p_name}) --[{nature}]--> CWE-{c_id} ({c_name})")


if __name__ == "__main__":
    main()

