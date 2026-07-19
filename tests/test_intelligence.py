from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from logiclab.intelligence import (
    AnalysisStatus,
    DiagnosticSeverity,
    EvidenceSpan,
    InventoryEntryKind,
    InventoryLimits,
    IRNodeKind,
    RuntimeLevel,
    UnderstandingLevel,
    analyze_repository,
    safe_inventory,
)


def test_evidence_span_and_capability_contracts_are_strict() -> None:
    span = EvidenceSpan(path="src/app.py", start_line=2, end_line=4, start_column=1)
    assert span.path == "src/app.py"
    assert UnderstandingLevel.U0 < UnderstandingLevel.U2
    assert RuntimeLevel.R0 < RuntimeLevel.R1

    with pytest.raises(ValidationError):
        EvidenceSpan(path="/absolute.py", start_line=1, end_line=1)
    with pytest.raises(ValidationError):
        EvidenceSpan(path="src/app.py", start_line=4, end_line=2)
    with pytest.raises(ValidationError):
        InventoryLimits(max_files=0)


def test_safe_inventory_never_dereferences_symlinks(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "main.py").write_text("print('safe')\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("SECRET = 'must-not-be-read'\n", encoding="utf-8")
    link = repository / "linked"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlinks are unavailable: {error}")

    inventory = safe_inventory(repository)

    assert [entry.path for entry in inventory.entries] == ["linked", "main.py"]
    assert inventory.entries[0].kind is InventoryEntryKind.SYMLINK
    assert all("secret.py" not in entry.path for entry in inventory.entries)
    assert inventory.truncated is False


def test_inventory_limits_return_a_partial_report_instead_of_failing(tmp_path: Path) -> None:
    for index in range(5):
        (tmp_path / f"file_{index}.py").write_text(f"VALUE = {index}\n", encoding="utf-8")

    report = analyze_repository(tmp_path, limits=InventoryLimits(max_files=2))

    assert report.status is AnalysisStatus.PARTIAL
    assert len(report.inventory.entries) == 2
    assert report.inventory.truncated is True
    assert any(diagnostic.code == "inventory.max_files" for diagnostic in report.diagnostics)


def test_vcs_and_dependency_directories_are_explicit_exclusions_not_failures(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text("def healthy():\n    return True\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "library.js").write_text(
        "throw new Error('dependency');\n", encoding="utf-8"
    )

    report = analyze_repository(tmp_path)

    assert report.status is AnalysisStatus.COMPLETE
    assert report.inventory.excluded_paths == [".git", "node_modules"]
    assert not report.unsupported_zones


def test_detects_components_and_build_systems_across_ecosystems(tmp_path: Path) -> None:
    manifests = {
        "jvm/pom.xml": "<project />",
        "web/package.json": '{"name": "web"}',
        "python/pyproject.toml": "[project]\nname='service'\n",
        "go/go.mod": "module example.test/service\n",
        "rust/Cargo.toml": "[package]\nname='core'\nversion='0.1.0'\n",
        "dotnet/App.csproj": "<Project />",
        "ruby/Gemfile": "source 'https://rubygems.org'\n",
        "php/composer.json": "{}",
        "elixir/mix.exs": "defmodule Demo.MixProject do\nend\n",
        "dart/pubspec.yaml": "name: demo\n",
        "bazel/MODULE.bazel": "module(name = 'demo')\n",
        "cmake/CMakeLists.txt": "project(demo)\n",
        "make/Makefile": "all:\n\t@true\n",
        "nix/flake.nix": "{ outputs = _: {}; }\n",
    }
    for relative, content in manifests.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    report = analyze_repository(tmp_path)
    by_root = {component.root_path: component for component in report.components}

    assert by_root["jvm"].ecosystems == ["jvm"]
    assert by_root["jvm"].build_systems == ["maven"]
    assert by_root["web"].build_systems == ["npm"]
    assert by_root["python"].build_systems == ["python-packaging"]
    assert by_root["go"].build_systems == ["go"]
    assert by_root["rust"].build_systems == ["cargo"]
    assert by_root["dotnet"].build_systems == ["dotnet"]
    assert by_root["ruby"].build_systems == ["bundler"]
    assert by_root["php"].build_systems == ["composer"]
    assert by_root["elixir"].build_systems == ["mix"]
    assert by_root["dart"].build_systems == ["pub"]
    assert by_root["bazel"].build_systems == ["bazel"]
    assert by_root["cmake"].build_systems == ["cmake"]
    assert by_root["make"].build_systems == ["make"]
    assert by_root["nix"].build_systems == ["nix"]
    assert all(component.runtime_level is RuntimeLevel.R1 for component in report.components)


def test_python_analysis_builds_normalized_symbols_imports_and_endpoint_ir(tmp_path: Path) -> None:
    source = tmp_path / "service.py"
    source.write_text(
        "from fastapi import FastAPI\n"
        "import json\n"
        "app = FastAPI()\n"
        "class Greeter:\n"
        "    def hello(self):\n"
        "        return 'hi'\n"
        "@app.get('/health')\n"
        "async def health():\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )

    first = analyze_repository(tmp_path)
    second = analyze_repository(tmp_path)

    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.status is AnalysisStatus.COMPLETE
    assert first.understanding_level is UnderstandingLevel.U2
    assert first.runtime_level is RuntimeLevel.R0
    assert {node.kind for node in first.nodes} >= {
        IRNodeKind.MODULE,
        IRNodeKind.CLASS,
        IRNodeKind.FUNCTION,
        IRNodeKind.ENDPOINT,
        IRNodeKind.EXTERNAL_MODULE,
    }
    endpoint = next(node for node in first.nodes if node.kind is IRNodeKind.ENDPOINT)
    assert endpoint.name == "GET /health"
    assert endpoint.evidence[0].path == "service.py"
    assert any(edge.kind == "imports" for edge in first.edges)
    assert first.coverage.analyzed_source_files == 1
    assert first.coverage.analysis_percent == 100.0


def test_generic_javascript_and_go_analysis_is_deterministic(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        "import express from 'express';\n"
        "export function boot() { return true; }\n"
        "app.post('/events', handler);\n",
        encoding="utf-8",
    )
    (tmp_path / "main.go").write_text(
        'package main\nimport "net/http"\nfunc main() {}\n'
        "func Health(w http.ResponseWriter, r *http.Request) {}\n",
        encoding="utf-8",
    )

    report = analyze_repository(tmp_path)

    assert {"Go", "TypeScript"}.issubset(report.languages)
    assert any(node.name == "boot" for node in report.nodes)
    assert any(node.name == "Health" for node in report.nodes)
    assert any(
        node.kind is IRNodeKind.ENDPOINT and node.name == "POST /events" for node in report.nodes
    )
    assert report.coverage.analyzed_source_files == 2


def test_generic_analyzers_cover_go_import_blocks_and_jvm_dotnet_methods(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        'package main\nimport (\n  "fmt"\n  "net/http"\n)\nfunc main() {}\n',
        encoding="utf-8",
    )
    (tmp_path / "Controller.java").write_text(
        "import java.util.List;\n"
        "class Controller {\n"
        '  @GetMapping("/items")\n'
        '  public String listItems() { return "ok"; }\n'
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "Health.cs").write_text(
        "using System.Net;\n"
        "public class Health {\n"
        '  [HttpGet("/health")]\n'
        '  public string Check() { return "ok"; }\n'
        "}\n",
        encoding="utf-8",
    )

    report = analyze_repository(tmp_path)

    imported = {node.name for node in report.nodes if node.kind is IRNodeKind.EXTERNAL_MODULE}
    symbols = {node.name for node in report.nodes}
    assert {"fmt", "net/http", "java.util.List", "System.Net"}.issubset(imported)
    assert {"Controller", "listItems", "Health", "Check"}.issubset(symbols)
    assert {node.name for node in report.nodes if node.kind is IRNodeKind.ENDPOINT} >= {
        "GET /items",
        "GET /health",
    }


def test_parse_failures_binary_and_unknown_source_are_unsupported_zones(tmp_path: Path) -> None:
    (tmp_path / "good.go").write_text("package good\nfunc Healthy() {}\n", encoding="utf-8")
    (tmp_path / "broken.py").write_text("def nope(:\n", encoding="utf-8")
    (tmp_path / "firmware.bin").write_bytes(b"\x00\x01\x02")
    (tmp_path / "custom.xyz").write_text("proprietary source\n", encoding="utf-8")

    report = analyze_repository(tmp_path)

    assert report.status is AnalysisStatus.PARTIAL
    assert report.coverage.source_files == 2
    assert report.coverage.analyzed_source_files == 1
    assert {zone.path for zone in report.unsupported_zones} >= {
        "broken.py",
        "custom.xyz",
        "firmware.bin",
    }
    assert any(diagnostic.code == "source.syntax_error" for diagnostic in report.diagnostics)
    assert any(
        claim.predicate == "declares" and claim.object == "Healthy" for claim in report.claims
    )


def test_oversized_files_are_not_read_or_analyzed(tmp_path: Path) -> None:
    (tmp_path / "huge.py").write_text("x = 1\n" * 100, encoding="utf-8")
    report = analyze_repository(tmp_path, limits=InventoryLimits(max_file_bytes=20))

    assert report.status is AnalysisStatus.PARTIAL
    assert report.coverage.analyzed_source_files == 0
    assert report.unsupported_zones[0].reason == "file exceeds max_file_bytes"
    assert report.diagnostics[0].severity is DiagnosticSeverity.WARNING


def test_source_and_ir_budgets_fail_closed_as_partial_coverage(tmp_path: Path) -> None:
    (tmp_path / "many_lines.py").write_text("x = 1\n" * 12, encoding="utf-8")
    (tmp_path / "many_symbols.py").write_text(
        "def first():\n    pass\n\ndef second():\n    pass\n",
        encoding="utf-8",
    )

    report = analyze_repository(
        tmp_path,
        limits=InventoryLimits(max_source_lines_per_file=10, max_ir_nodes=1),
    )

    assert report.status is AnalysisStatus.PARTIAL
    assert report.coverage.analyzed_source_files == 0
    assert {item.code for item in report.diagnostics} >= {
        "source.line_limit",
        "analysis.ir_limit",
    }
