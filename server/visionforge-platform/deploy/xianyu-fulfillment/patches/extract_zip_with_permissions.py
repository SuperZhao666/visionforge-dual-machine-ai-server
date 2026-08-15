#!/usr/bin/env python3
"""Safely extract ZIP archives while preserving their Unix permission bits."""

from __future__ import annotations

import argparse
import os
import zipfile
from pathlib import Path


def extract_archive(archive_path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    destination_root = destination.resolve()
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            target = (destination / member.filename).resolve()
            if target != destination_root and destination_root not in target.parents:
                raise ValueError(f"archive member escapes destination: {member.filename}")
            archive.extract(member, destination)
            unix_mode = (member.external_attr >> 16) & 0o777
            if unix_mode and target.exists():
                os.chmod(target, unix_mode)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    extract_archive(arguments.archive, arguments.destination)


if __name__ == "__main__":
    main()
