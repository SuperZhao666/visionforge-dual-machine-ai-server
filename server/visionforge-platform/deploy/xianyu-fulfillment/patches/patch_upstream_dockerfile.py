#!/usr/bin/env python3
"""Create the pinned upstream Dockerfile with deterministic China-local downloads."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


DEBIAN_SOURCE = "https://deb.debian.org"
DEBIAN_MIRROR = "https://mirrors.cloud.tencent.com"
PLAYWRIGHT_INSTALL_BLOCK = """RUN playwright install chromium && \\
    playwright install-deps chromium && \\
"""
PINNED_BROWSER_INSTALL_BLOCK = """ARG VF_CHROMIUM_URL=https://cdn.npmmirror.com/binaries/chrome-for-testing/147.0.7727.15/linux64/chrome-linux64.zip
ARG VF_CHROMIUM_SHA256=04883e331b31448d6255fa058f0e1c7e8657c004da1f8a1c04eb28855a37ec6c
ARG VF_CHROMIUM_HEADLESS_URL=https://cdn.npmmirror.com/binaries/chrome-for-testing/147.0.7727.15/linux64/chrome-headless-shell-linux64.zip
ARG VF_CHROMIUM_HEADLESS_SHA256=cf779cd5486f3fc5a18bea4ac606026a1667ae16efaee15af51bd3ad3ae01092
ARG VF_FFMPEG_URL=https://cdn.npmmirror.com/binaries/playwright/builds/ffmpeg/1011/ffmpeg-linux.zip
ARG VF_FFMPEG_SHA256=ebc74fc5b94830176a3c2914ae96bd8bc7f6a91f4f33890230f84a172ee61ccc
RUN curl --fail --location --retry 5 --output /tmp/chromium.zip \"${VF_CHROMIUM_URL}\" && \\
    echo \"${VF_CHROMIUM_SHA256}  /tmp/chromium.zip\" | sha256sum --check --strict && \\
    curl --fail --location --retry 5 --output /tmp/chromium-headless.zip \"${VF_CHROMIUM_HEADLESS_URL}\" && \\
    echo \"${VF_CHROMIUM_HEADLESS_SHA256}  /tmp/chromium-headless.zip\" | sha256sum --check --strict && \\
    curl --fail --location --retry 5 --output /tmp/playwright-ffmpeg.zip \"${VF_FFMPEG_URL}\" && \\
    echo \"${VF_FFMPEG_SHA256}  /tmp/playwright-ffmpeg.zip\" | sha256sum --check --strict && \\
    mkdir -p /ms-playwright/chromium-1217 /ms-playwright/chromium_headless_shell-1217 /ms-playwright/ffmpeg-1011 && \\
    python /app/.visionforge/extract_zip_with_permissions.py /tmp/chromium.zip /ms-playwright/chromium-1217 && \\
    python /app/.visionforge/extract_zip_with_permissions.py /tmp/chromium-headless.zip /ms-playwright/chromium_headless_shell-1217 && \\
    python /app/.visionforge/extract_zip_with_permissions.py /tmp/playwright-ffmpeg.zip /ms-playwright/ffmpeg-1011 && \\
    rm -rf /app/.visionforge && \\
    touch /ms-playwright/chromium-1217/INSTALLATION_COMPLETE /ms-playwright/chromium_headless_shell-1217/INSTALLATION_COMPLETE /ms-playwright/ffmpeg-1011/INSTALLATION_COMPLETE && \\
    rm -f /tmp/chromium.zip /tmp/chromium-headless.zip /tmp/playwright-ffmpeg.zip && \\
    playwright install-deps chromium && \\
"""


def patch_content(content: str) -> str:
    if content.count(DEBIAN_SOURCE) != 1:
        raise RuntimeError("unexpected Debian source occurrence count in pinned Dockerfile")
    if content.count(PLAYWRIGHT_INSTALL_BLOCK) != 1:
        raise RuntimeError("unexpected Playwright install block in pinned Dockerfile")
    patched = content.replace(DEBIAN_SOURCE, DEBIAN_MIRROR)
    return patched.replace(PLAYWRIGHT_INSTALL_BLOCK, PINNED_BROWSER_INSTALL_BLOCK)


def read_pinned_dockerfile(repository: Path, commit: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), "show", f"{commit}:Dockerfile"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    arguments = parser.parse_args()
    content = read_pinned_dockerfile(arguments.repository, arguments.commit)
    (arguments.repository / "Dockerfile").write_text(patch_content(content), encoding="utf-8")


if __name__ == "__main__":
    main()
