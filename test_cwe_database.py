#!/usr/bin/env python3
"""Unit tests for cwe_database.py using parameterized test cases."""

from __future__ import annotations

from collections.abc import Callable, Iterable
import functools
from pathlib import Path
import tempfile
from typing import Any
import unittest

from cwe_database import CWEDatabase, load_cwe_database


def parameterized(cases: Iterable[tuple[Any, ...]]) -> Callable[[Callable[..., None]], Callable[..., None]]:
    """Run a unittest test method across a list of parameter tuples using subTest."""
    case_list = list(cases)

    def decorator(func: Callable[..., None]) -> Callable[..., None]:
        @functools.wraps(func)
        def wrapper(self: unittest.TestCase) -> None:
            for params in case_list:
                with self.subTest(params=params):
                    func(self, *params)

        return wrapper

    return decorator


def _build_xml_for_nature(nature: str, source_id: int = 10, target_id: int = 20) -> str:
    """Create a minimal CWE XML catalog with a single Related_Weakness of the given Nature."""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Name="CWE" Version="4.20">
  <Weaknesses>
    <Weakness ID="{source_id}" Name="Source Weakness" Abstraction="Base" Status="Stable">
      <Related_Weaknesses>
        <Related_Weakness Nature="{nature}" CWE_ID="{target_id}" View_ID="1000"/>
      </Related_Weaknesses>
    </Weakness>
    <Weakness ID="{target_id}" Name="Target Weakness" Abstraction="Base" Status="Stable"/>
  </Weaknesses>
</Weakness_Catalog>
"""


class TestCWEDatabase(unittest.TestCase):
    """Parameterized tests for CWEDatabase relationship handling and parent resolution."""

    db: CWEDatabase

    @classmethod
    def setUpClass(cls) -> None:
        cls.db = load_cwe_database()

    @parameterized(
        [
            # When source (10) declares ParentOf/CanPrecede target (20), source (10) is the parent.
            ("ParentOf", 10, 20, 10),
            ("ParentOf", 20, 10, 10),
            ("CanPrecede", 10, 20, 10),
            ("CanPrecede", 20, 10, 10),
            # When source (10) declares ChildOf/CanFollow/CanAlsoBe/StartsWith target (20), target (20) is the parent.
            ("ChildOf", 10, 20, 20),
            ("ChildOf", 20, 10, 20),
            ("CanFollow", 10, 20, 20),
            ("CanFollow", 20, 10, 20),
            ("CanAlsoBe", 10, 20, 20),
            ("CanAlsoBe", 20, 10, 20),
            ("StartsWith", 10, 20, 20),
            ("StartsWith", 20, 10, 20),
        ]
    )
    def test_each_relationship_nature_returns_correct_parent(
        self,
        nature: str,
        cwe_a: int,
        cwe_b: int,
        expected_parent: int,
    ) -> None:
        """Verify all 6 relationship Natures (ChildOf, ParentOf, CanPrecede, CanFollow, CanAlsoBe, StartsWith)."""
        xml_content = _build_xml_for_nature(nature, source_id=10, target_id=20)
        with tempfile.TemporaryDirectory() as tmp_dir:
            xml_path = Path(tmp_dir) / "test_cwe.xml"
            xml_path.write_text(xml_content, encoding="utf-8")
            db = CWEDatabase.from_xml(xml_path)

        self.assertEqual(db.find_parent(cwe_a, cwe_b), expected_parent)

    @parameterized(
        [
            # Direct ChildOf / ParentOf (1004 is ChildOf 732)
            ("ChildOf/ParentOf direct (child, parent)", 1004, 732, 732),
            ("ChildOf/ParentOf direct (parent, child)", 732, 1004, 732),
            # Multi-step ChildOf / ParentOf (707 -> 74 -> 79 -> 80)
            ("ChildOf/ParentOf multi-step (ancestor, descendant)", 707, 80, 707),
            ("ChildOf/ParentOf multi-step (descendant, ancestor)", 80, 707, 707),
            # Direct CanPrecede / CanFollow (113 CanPrecede 79)
            ("CanPrecede/CanFollow direct (preceding, following)", 113, 79, 113),
            ("CanPrecede/CanFollow direct (following, preceding)", 79, 113, 113),
            # Direct CanAlsoBe (144 CanAlsoBe 93 -> 93 is parent of 144)
            ("CanAlsoBe direct (child, parent)", 144, 93, 93),
            ("CanAlsoBe direct (parent, child)", 93, 144, 93),
            # Multi-step ChildOf + CanAlsoBe (74 -> 93 -> 144)
            ("ChildOf + CanAlsoBe multi-step", 74, 144, 74),
            # Direct StartsWith (680 StartsWith 190 -> 190 is parent of 680)
            ("StartsWith direct (child, parent)", 680, 190, 190),
            ("StartsWith direct (parent, child)", 190, 680, 190),
            # Multi-step ChildOf + StartsWith (682 -> 190 -> 680)
            ("ChildOf + StartsWith multi-step", 682, 680, 682),
        ]
    )
    def test_catalog_relationships_return_correct_parent(
        self,
        _description: str,
        cwe_a: int,
        cwe_b: int,
        expected_parent: int,
    ) -> None:
        """Verify direct and multi-step relationships in cwec_v4.20.xml return the expected parent."""
        self.assertEqual(self.db.find_parent(cwe_a, cwe_b), expected_parent)

    @parameterized(
        [
            (125, 129, 129),
            (129, 125, 129),
            (276, 732, 732),
            (732, 276, 732),
        ]
    )
    def test_ford_cases(
        self,
        cwe_a: int | str,
        cwe_b: int | str,
        expected_parent: int,
    ) -> None:
        """Verify Ford CWE pairs (125/129 -> 129, 276/732 -> 732) return the expected parent."""
        self.assertEqual(self.db.find_parent(cwe_a, cwe_b), expected_parent)

    @parameterized(
        [
            (79, 79, 79),
            ("CWE-125", 125, 125),
            (284, 707, None),
            (80, 83, None),
            (999999, 125, None),
        ]
    )
    def test_same_id_and_unrelated_weaknesses(
        self,
        cwe_a: int | str,
        cwe_b: int | str,
        expected_parent: int | None,
    ) -> None:
        """Verify identical CWEs return themselves and unrelated/unknown CWEs return None."""
        self.assertEqual(self.db.find_parent(cwe_a, cwe_b), expected_parent)

    @parameterized(
        [
            # Both under Pillar CWE-284 (Improper Access Control), but in separate branches
            (256, 291),
            (291, 256),
            # Both under Pillar CWE-707 (Improper Neutralization), but in separate branches
            (79, 89),
            (89, 79),
        ]
    )
    def test_unrelated_weaknesses_in_same_pillar_return_none(
        self,
        cwe_a: int | str,
        cwe_b: int | str,
    ) -> None:
        """Verify unrelated Weaknesses that share a Root Pillar are not treated as parent/child."""
        self.assertIsNone(self.db.find_parent(cwe_a, cwe_b))

    def test_all_cwe_pairs_do_not_lock_up_or_error(self) -> None:
        """Exhaustively test every pair of Weaknesses in the catalog for termination and validity."""
        all_ids = sorted(self.db.weaknesses.keys())
        for cwe_a in all_ids:
            for cwe_b in all_ids:
                result = self.db.find_parent(cwe_a, cwe_b)
                if result is not None:
                    self.assertIn(result, (cwe_a, cwe_b))


if __name__ == "__main__":
    unittest.main()
