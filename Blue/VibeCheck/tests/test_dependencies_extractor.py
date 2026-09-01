from __future__ import annotations

from pathlib import Path

from vibecheck.dependencies.extractor import extract_declared_dependencies


def test_parses_requirements_txt(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text(
        "flask==3.0.0\n"
        "# a comment\n"
        "requests>=2.0  # trailing comment\n"
        "\n"
        "-e .\n"
        "flask-cors[extra]~=1.0\n"
        "git+https://example.com/foo.git\n"
    )
    deps = extract_declared_dependencies(tmp_path)
    names = {d.name for d in deps}
    assert names == {"flask", "requests", "flask-cors"}
    assert all(d.ecosystem == "pypi" for d in deps)


def test_parses_pep621_pyproject_dependencies(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "demo"\n'
        'dependencies = [\n'
        '    "requests>=2.0",\n'
        '    "totally-fake-package==1.0",\n'
        ']\n'
    )
    deps = extract_declared_dependencies(tmp_path)
    names = {d.name for d in deps}
    assert names == {"requests", "totally-fake-package"}


def test_parses_package_json_dependencies(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"express": "^4.18.0", "local-lib": "file:../local-lib"}, '
        '"devDependencies": {"jest": "^29.0.0"}}'
    )
    deps = extract_declared_dependencies(tmp_path)
    names = {d.name for d in deps}
    assert names == {"express", "jest"}
    assert all(d.ecosystem == "npm" for d in deps)


def test_skips_node_modules_and_venv(tmp_path: Path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text('{"dependencies": {"should-not-appear": "1.0.0"}}')
    (tmp_path / "package.json").write_text('{"dependencies": {"real-dep": "1.0.0"}}')
    deps = extract_declared_dependencies(tmp_path)
    names = {d.name for d in deps}
    assert names == {"real-dep"}
