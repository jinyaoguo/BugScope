#!/usr/bin/env python3
"""Download and verify BugScope reproduction projects from the release manifest."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime
from urllib.request import urlopen
import zipfile


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_MANIFEST = SCRIPT_DIR / "reproduce-manifest.json"
DEFAULT_DESTINATION = SCRIPT_DIR / "Reproduce" / "Cpp"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download or verify BugScope reproduction projects."
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    parser.add_argument(
        "--category",
        action="append",
        choices=["OOB", "DBZ", "MLK"],
        help="Only process projects in this category; may be repeated.",
    )
    parser.add_argument(
        "--bug-type",
        action="append",
        choices=["OSO", "NOF", "ASO", "DBZ", "MLK"],
        help="Only process projects containing this bug type; may be repeated.",
    )
    parser.add_argument(
        "--subtype",
        action="append",
        choices=["IZC", "LZD", "UEC", "MSC"],
        help="Only process projects containing this dataset subtype; may be repeated.",
    )
    parser.add_argument(
        "--project",
        action="append",
        help="Only process this manifest project ID, such as OOB/zstd; may be repeated.",
    )
    parser.add_argument("--list", action="store_true", help="List selected projects and exit.")
    parser.add_argument("--verify-only", action="store_true", help="Verify local projects without downloading.")
    parser.add_argument("--dry-run", action="store_true", help="Print planned actions without changing files.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing invalid project after moving it to a timestamped backup.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if a selected snapshot does not yet have a release archive URL.",
    )
    return parser.parse_args()


def load_manifest(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as manifest_file:
        manifest = json.load(manifest_file)
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("projects"), list):
        raise ValueError(f"Unsupported or malformed manifest: {path}")
    return manifest


def select_projects(projects: list, args: argparse.Namespace) -> list:
    selected = []
    requested_projects = set(args.project or [])
    known_projects = {project["id"] for project in projects}
    unknown = requested_projects - known_projects
    if unknown:
        raise ValueError("Unknown project ID(s): " + ", ".join(sorted(unknown)))

    for project in projects:
        project_id = project["id"]
        category = project_id.split("/", 1)[0]
        case_types = {case["bug_type"] for case in project.get("cases", [])}
        case_subtypes = {
            case["subtype"] for case in project.get("cases", []) if case.get("subtype")
        }
        if args.category and category not in args.category:
            continue
        if args.bug_type and not case_types.intersection(args.bug_type):
            continue
        if args.subtype and not case_subtypes.intersection(args.subtype):
            continue
        if requested_projects and project_id not in requested_projects:
            continue
        selected.append(project)
    return selected


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source_file:
        for chunk in iter(lambda: source_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list, cwd: Path = None) -> str:
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout.strip()


def verify_project(project: dict, destination: Path) -> list:
    errors = []
    source = project["source"]
    if not destination.is_dir():
        return [f"directory is missing: {destination}"]

    if source["type"] == "git":
        source_subdirectory = source.get("subdirectory")
        if source_subdirectory:
            provenance_path = destination / ".bugscope-source.json"
            if not provenance_path.is_file():
                errors.append("Git subdirectory provenance is missing")
            else:
                try:
                    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
                    expected = {
                        "url": source["url"],
                        "commit": source["commit"],
                        "subdirectory": source_subdirectory,
                    }
                    if provenance != expected:
                        errors.append("Git subdirectory provenance does not match manifest")
                except (OSError, json.JSONDecodeError) as error:
                    errors.append(f"cannot read Git subdirectory provenance: {error}")
        elif not (destination / ".git").exists():
            errors.append("Git metadata is missing")
        else:
            try:
                actual_commit = run(["git", "rev-parse", "HEAD"], cwd=destination)
                if actual_commit != source["commit"]:
                    errors.append(
                        f"commit mismatch: expected {source['commit']}, got {actual_commit}"
                    )
            except (subprocess.CalledProcessError, FileNotFoundError) as error:
                errors.append(f"cannot inspect Git checkout: {error}")

    for case in project.get("cases", []):
        target = destination / case["path"]
        if not target.is_file():
            errors.append(f"case target is missing: {case['path']}")
            continue
        expected_hash = case.get("sha256")
        if expected_hash:
            actual_hash = sha256_file(target)
            if actual_hash != expected_hash:
                errors.append(
                    f"SHA-256 mismatch for {case['path']}: expected {expected_hash}, got {actual_hash}"
                )
    return errors


def download(url: str, destination: Path) -> None:
    with urlopen(url) as response, destination.open("wb") as output_file:
        shutil.copyfileobj(response, output_file)


def safe_extract_tar(archive: Path, destination: Path) -> None:
    destination_root = destination.resolve()
    with tarfile.open(archive) as tar_file:
        for member in tar_file.getmembers():
            member_path = (destination / member.name).resolve()
            if member_path != destination_root and destination_root not in member_path.parents:
                raise ValueError(f"Unsafe archive member: {member.name}")
        tar_file.extractall(destination)


def safe_extract_zip(archive: Path, destination: Path) -> None:
    destination_root = destination.resolve()
    with zipfile.ZipFile(archive) as zip_file:
        for member in zip_file.infolist():
            member_path = (destination / member.filename).resolve()
            if member_path != destination_root and destination_root not in member_path.parents:
                raise ValueError(f"Unsafe archive member: {member.filename}")
        zip_file.extractall(destination)


def install_git(project: dict, checkout: Path, manifest_path: Path) -> None:
    source = project["source"]
    source_subdirectory = source.get("subdirectory")
    run(
        [
            "git",
            "clone",
            "--filter=blob:none",
            "--no-checkout",
            source["url"],
            str(checkout),
        ]
    )
    if source_subdirectory:
        run(["git", "sparse-checkout", "init", "--cone"], cwd=checkout)
        run(["git", "sparse-checkout", "set", source_subdirectory], cwd=checkout)
    try:
        run(["git", "checkout", "--detach", source["commit"]], cwd=checkout)
    except subprocess.CalledProcessError:
        run(["git", "fetch", "--depth", "1", "origin", source["commit"]], cwd=checkout)
        run(["git", "checkout", "--detach", "FETCH_HEAD"], cwd=checkout)

    patch_name = source.get("patch")
    if patch_name:
        patch_path = (REPO_ROOT / patch_name).resolve()
        if not patch_path.is_file():
            raise FileNotFoundError(f"Patch listed by manifest is missing: {patch_path}")
        run(["git", "apply", str(patch_path)], cwd=checkout)

    if source_subdirectory:
        subtree = checkout / source_subdirectory
        if not subtree.is_dir():
            raise FileNotFoundError(
                f"Subdirectory listed by manifest is missing: {source_subdirectory}"
            )
        exported = checkout.parent / "exported-subdirectory"
        shutil.copytree(subtree, exported, symlinks=True)
        provenance = {
            "url": source["url"],
            "commit": source["commit"],
            "subdirectory": source_subdirectory,
        }
        (exported / ".bugscope-source.json").write_text(
            json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
        )
        shutil.rmtree(checkout)
        exported.rename(checkout)


def install_snapshot(project: dict, checkout: Path, download_dir: Path) -> None:
    source = project["source"]
    archive_url = source.get("archive_url")
    expected_hash = source.get("archive_sha256")
    if not archive_url or not expected_hash:
        raise ValueError("snapshot does not yet have archive_url and archive_sha256")

    download_dir.mkdir(parents=True, exist_ok=True)
    archive_name = hashlib.sha256(archive_url.encode("utf-8")).hexdigest()[:16]
    archive = download_dir / archive_name
    if not archive.exists():
        download(archive_url, archive)
    actual_hash = sha256_file(archive)
    if actual_hash != expected_hash:
        raise ValueError(
            f"archive SHA-256 mismatch: expected {expected_hash}, got {actual_hash}"
        )

    extracted = checkout.parent / f"{checkout.name}-extracted"
    extracted.mkdir()
    if zipfile.is_zipfile(archive):
        safe_extract_zip(archive, extracted)
    elif tarfile.is_tarfile(archive):
        safe_extract_tar(archive, extracted)
    else:
        raise ValueError(f"Unsupported snapshot archive: {archive_url}")

    archive_root = source.get("archive_root")
    if archive_root:
        content_root = extracted / archive_root
    else:
        children = list(extracted.iterdir())
        content_root = children[0] if len(children) == 1 and children[0].is_dir() else extracted
    if not content_root.is_dir():
        raise ValueError(f"Archive root is missing: {content_root}")
    shutil.move(str(content_root), str(checkout))


def install_project(
    project: dict,
    destination: Path,
    manifest_path: Path,
    args: argparse.Namespace,
) -> str:
    project_id = project["id"]
    source = project["source"]
    errors = verify_project(project, destination)
    if not errors:
        return "already verified"

    if (
        source["type"] == "snapshot"
        and not source.get("archive_url")
        and not destination.exists()
    ):
        raise RuntimeError("snapshot release asset is not available yet")
    if args.verify_only:
        raise ValueError("; ".join(errors))
    if destination.exists() and not args.force:
        raise ValueError("; ".join(errors) + "; use --force to replace it")

    if source["type"] == "snapshot" and not source.get("archive_url"):
        raise RuntimeError("snapshot release asset is not available yet")
    if args.dry_run:
        return f"would install from {source['type']} source"

    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_parent = Path(tempfile.mkdtemp(prefix=".bugscope-download-", dir=str(destination.parent)))
    checkout = temp_parent / "checkout"
    try:
        if source["type"] == "git":
            install_git(project, checkout, manifest_path)
        elif source["type"] == "snapshot":
            install_snapshot(project, checkout, SCRIPT_DIR / ".cache" / "downloads")
        else:
            raise ValueError(f"Unsupported source type: {source['type']}")

        installed_errors = verify_project(project, checkout)
        if installed_errors:
            raise ValueError("downloaded project failed verification: " + "; ".join(installed_errors))

        if destination.exists():
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup = destination.with_name(f"{destination.name}.backup-{timestamp}")
            destination.rename(backup)
            print(f"  existing directory moved to {backup}")
        checkout.rename(destination)
    finally:
        shutil.rmtree(temp_parent, ignore_errors=True)
    return "installed and verified"


def list_projects(projects: list) -> None:
    print(f"{'PROJECT':32} {'SOURCE':10} {'AVAILABLE':10} {'BUG TYPES':12} SUBTYPES")
    for project in projects:
        source = project["source"]
        available = source["type"] == "git" or bool(source.get("archive_url"))
        bug_types = sorted({case["bug_type"] for case in project.get("cases", [])})
        subtypes = sorted(
            {case["subtype"] for case in project.get("cases", []) if case.get("subtype")}
        )
        print(
            f"{project['id']:32} {source['type']:10} "
            f"{('yes' if available else 'no'):10} {(','.join(bug_types) or '-'):12} "
            f"{','.join(subtypes) or '-'}"
        )


def main() -> int:
    args = parse_args()
    manifest_path = args.manifest.resolve()
    destination_root = args.destination.resolve()
    try:
        manifest = load_manifest(manifest_path)
        projects = select_projects(manifest["projects"], args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    if args.list:
        list_projects(projects)
        return 0
    if not projects:
        print("No projects matched the requested filters.", file=sys.stderr)
        return 2

    failures = 0
    skipped = 0
    for project in projects:
        project_id = project["id"]
        destination = destination_root / project_id
        try:
            result = install_project(project, destination, manifest_path, args)
            print(f"[OK]   {project_id}: {result}")
        except RuntimeError as error:
            skipped += 1
            print(f"[SKIP] {project_id}: {error}")
            if args.strict:
                failures += 1
        except (OSError, ValueError, subprocess.CalledProcessError) as error:
            failures += 1
            print(f"[FAIL] {project_id}: {error}", file=sys.stderr)

    print(
        f"Summary: selected={len(projects)} failed={failures} "
        f"skipped_unavailable={skipped}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
