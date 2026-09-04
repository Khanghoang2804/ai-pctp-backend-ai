from __future__ import annotations

import sys
import types
import unittest

query_module = types.ModuleType("app.service.queryNodeAndRel")
query_module.db_node_graph = lambda *args, **kwargs: {}
query_module.db_resolve_file_node_id = lambda *args, **kwargs: None
sys.modules.setdefault("app.service.queryNodeAndRel", query_module)

from app.service.ScanLayer3 import ScanLayer3


class TestScanLayer3Filtering(unittest.TestCase):
    def test_repository_grouping_filters_noise_paths_and_quality_rules(self) -> None:
        layer3 = ScanLayer3(repo_name="test-repo")

        grouped = layer3.group_findings_by_file([
            {
                "file_path": "File:src/app.py",
                "findings": [
                    {
                        "line": 10,
                        "rules": [
                            {
                                "rule_id": "SEC008",
                                "category": "hardcoded_secret",
                                "severity": "critical",
                            }
                        ],
                    },
                    {
                        "line": 20,
                        "rules": [
                            {
                                "rule_id": "py/commented-out-code",
                                "category": "quality",
                                "severity": "recommendation",
                            }
                        ],
                    },
                ],
            },
            {
                "file_path": "File:node_modules/pkg/index.js",
                "findings": [
                    {
                        "line": 1,
                        "rules": [
                            {
                                "rule_id": "SEC001",
                                "category": "security",
                                "severity": "critical",
                            }
                        ],
                    }
                ],
            },
            {
                "file_path": "File:test/fixtures/sample.py",
                "findings": [
                    {
                        "line": 1,
                        "rules": [
                            {
                                "rule_id": "SEC001",
                                "category": "security",
                                "severity": "critical",
                            }
                        ],
                    }
                ],
            },
        ])

        self.assertEqual(list(grouped.keys()), ["src/app.py"])
        self.assertEqual(len(grouped["src/app.py"]["layer1_findings"]), 1)
        self.assertEqual(grouped["src/app.py"]["layer1_findings"][0]["rules"][0]["rule_id"], "SEC008")
        self.assertEqual(layer3._last_repository_filter_stats["ignored_path_items"], 2)
        self.assertEqual(layer3._last_repository_filter_stats["layer1_findings_kept"], 1)

    def test_repository_grouping_ranks_files_by_security_severity(self) -> None:
        layer3 = ScanLayer3(repo_name="test-repo")

        grouped = layer3.group_findings_by_file([
            {
                "file_path": "File:src/warning.py",
                "findings": [
                    {
                        "line": 3,
                        "rules": [
                            {
                                "rule_id": "PATH001",
                                "category": "path_injection",
                                "severity": "warning",
                            }
                        ],
                    }
                ],
            },
            {
                "file_path": "File:src/critical.py",
                "findings": [
                    {
                        "line": 8,
                        "rules": [
                            {
                                "rule_id": "SEC008",
                                "category": "hardcoded_secret",
                                "severity": "critical",
                            }
                        ],
                    }
                ],
            },
        ])

        self.assertEqual(list(grouped.keys()), ["src/critical.py", "src/warning.py"])

    def test_build_graph_impact_context_extracts_internal_and_cross_file_edges(self) -> None:
        layer3 = ScanLayer3(repo_name="test-repo")

        context = layer3.build_graph_impact_context({
            "root": {"id": "File:src/a.py", "label": "File", "file_path": "src/a.py"},
            "nodes": [
                {"id": "File:src/a.py", "label": "File", "file_path": "src/a.py"},
                {"id": "Function:src/a.py:main", "label": "Function", "name": "main", "file_path": "src/a.py"},
                {"id": "Function:src/a.py:danger", "label": "Function", "name": "danger", "file_path": "src/a.py"},
                {"id": "Function:src/b.py:handler", "label": "Function", "name": "handler", "file_path": "src/b.py"},
            ],
            "edges": [
                {"from_id": "File:src/a.py", "to_id": "Function:src/a.py:main", "relation_type": "CALLS"},
                {"from_id": "Function:src/a.py:main", "to_id": "Function:src/a.py:danger", "relation_type": "CALLS"},
                {"from_id": "Function:src/b.py:handler", "to_id": "Function:src/a.py:danger", "relation_type": "CALLS"},
            ],
        })

        self.assertEqual(context["entrypoints"], ["Function:src/a.py:main"])
        self.assertEqual(context["related_files"], ["src/b.py"])
        self.assertEqual(context["internal_call_chain"][0]["caller"], "Function:src/a.py:main")
        self.assertEqual(context["upstream_callers"][0]["source_file"], "src/b.py")


if __name__ == "__main__":
    unittest.main()
