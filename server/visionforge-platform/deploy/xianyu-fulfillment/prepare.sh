#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPSTREAM_DIR="${ROOT_DIR}/upstream"
PATCH_FILE="${ROOT_DIR}/patches/visionforge-fulfillment.patch"
UPSTREAM_REPOSITORY="https://github.com/GuDong2003/xianyu-auto-reply-fix.git"
UPSTREAM_COMMIT="837497d576b1b864a7294b8565348531a6ce7039"
BASE_IMAGE="visionforge/xianyu-auto-reply:${UPSTREAM_COMMIT:0:12}-upstream"
HARDENED_IMAGE="visionforge/xianyu-auto-reply:${UPSTREAM_COMMIT:0:12}-hardened"
BUILD_ROOT=""
BUILD_DIR=""

cleanup() {
  if [[ -n "${BUILD_DIR}" && -e "${BUILD_DIR}" ]]; then
    git -C "${UPSTREAM_DIR}" worktree remove --force "${BUILD_DIR}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${BUILD_ROOT}" && -d "${BUILD_ROOT}" ]]; then
    rmdir -- "${BUILD_ROOT}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ -e "${UPSTREAM_DIR}" && ! -d "${UPSTREAM_DIR}/.git" ]]; then
  echo "Refusing to reuse non-git path: ${UPSTREAM_DIR}" >&2
  exit 1
fi
if [[ ! -d "${UPSTREAM_DIR}/.git" ]]; then
  git clone --filter=blob:none --no-checkout "${UPSTREAM_REPOSITORY}" "${UPSTREAM_DIR}"
fi
if ! git -C "${UPSTREAM_DIR}" cat-file -e "${UPSTREAM_COMMIT}^{commit}" 2>/dev/null; then
  git -C "${UPSTREAM_DIR}" fetch --depth=1 origin "${UPSTREAM_COMMIT}"
fi
if [[ ! -s "${PATCH_FILE}" ]]; then
  echo "Missing VisionForge upstream patch: ${PATCH_FILE}" >&2
  exit 1
fi

# Build from an isolated worktree so local review edits in upstream/ are never
# overwritten by a deployment run. The patch must apply cleanly to the exact pin.
BUILD_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/visionforge-xianyu-build.XXXXXX")"
BUILD_DIR="${BUILD_ROOT}/upstream"
git -C "${UPSTREAM_DIR}" worktree add --detach "${BUILD_DIR}" "${UPSTREAM_COMMIT}" >/dev/null
test "$(git -C "${BUILD_DIR}" rev-parse HEAD)" = "${UPSTREAM_COMMIT}"
git -C "${BUILD_DIR}" apply --check "${PATCH_FILE}"
git -C "${BUILD_DIR}" apply "${PATCH_FILE}"
git -C "${BUILD_DIR}" diff --check

# The patch is fail-closed against the pinned source and verifies browser archives by SHA-256.
python3 "${ROOT_DIR}/patches/patch_upstream_dockerfile.py" \
  --repository "${BUILD_DIR}" \
  --commit "${UPSTREAM_COMMIT}"
install -D --mode=0644 \
  "${ROOT_DIR}/patches/extract_zip_with_permissions.py" \
  "${BUILD_DIR}/.visionforge/extract_zip_with_permissions.py"

docker build --pull --tag "${BASE_IMAGE}" "${BUILD_DIR}"
docker build \
  --build-arg "UPSTREAM_IMAGE=${BASE_IMAGE}" \
  --file "${ROOT_DIR}/Dockerfile.hardened" \
  --tag "${HARDENED_IMAGE}" \
  "${ROOT_DIR}"

sudo install -d --owner=10001 --group=10001 --mode=700 \
  "${ROOT_DIR}/runtime" \
  "${ROOT_DIR}/runtime/data" \
  "${ROOT_DIR}/runtime/logs" \
  "${ROOT_DIR}/runtime/backups" \
  "${ROOT_DIR}/runtime/uploads" \
  "${ROOT_DIR}/runtime/trajectory_history" \
  "${ROOT_DIR}/runtime/home"

echo "Built ${HARDENED_IMAGE}"
docker image inspect --format 'local_image_id={{.Id}}' "${HARDENED_IMAGE}"
echo "Set XIANYU_IMAGE to the printed immutable local_image_id in .env, then run the documented checks."
