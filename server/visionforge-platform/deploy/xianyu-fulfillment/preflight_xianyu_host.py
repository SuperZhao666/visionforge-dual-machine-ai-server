#!/usr/bin/env python3
"""Validate host prerequisites before changing the Xianyu runtime."""
from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


EXPECTED_NETWORK_NAME = "fulfillment_internal"
EXPECTED_SUBNET = ipaddress.ip_network("172.29.47.0/28")
EXPECTED_CONTAINER_ADDRESSES = {
    "visionforge-fulfillment-bridge": ipaddress.ip_address("172.29.47.2"),
    "visionforge-xianyu-fulfillment": ipaddress.ip_address("172.29.47.3"),
}
EXPECTED_PLATFORM_PATH = "/api/integrations/code-issuances/issue"
EXPECTED_MANAGED_BRIDGE_URL = "http://fulfillment-bridge:8080/issue"
EXPECTED_PRODUCT_KEYS = {
    "1小时": "1h",
    "5小时": "5h",
    "10小时": "10h",
    "50小时": "50h",
    "100小时": "100h",
}
MINIMUM_FREE_BYTES = 1024 * 1024 * 1024


def _docker(*arguments: str, allow_missing: bool = False) -> str:
    result = subprocess.run(
        ["docker", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode and not allow_missing:
        raise RuntimeError("Docker prerequisite inspection failed")
    return result.stdout.strip()


def validate_networks() -> None:
    network_ids = _docker("network", "ls", "--format", "{{.ID}}").splitlines()
    if not network_ids:
        raise RuntimeError("Docker has no available networks")
    networks = json.loads(_docker("network", "inspect", *network_ids))
    expected_network = None
    for network in networks:
        name = str(network.get("Name") or "")
        ipv4_subnets = _ipv4_subnets(network)
        if name == EXPECTED_NETWORK_NAME:
            expected_network = network
            if ipv4_subnets != {EXPECTED_SUBNET}:
                raise RuntimeError("fulfillment_internal uses an unexpected subnet")
            if bool(network.get("Internal")):
                raise RuntimeError("fulfillment_internal cannot reach the Platform host")
            continue
        if any(subnet.overlaps(EXPECTED_SUBNET) for subnet in ipv4_subnets):
            raise RuntimeError("another Docker network overlaps fulfillment_internal")

    if expected_network is not None:
        _validate_expected_addresses(expected_network)


def _ipv4_subnets(network: dict) -> set[ipaddress.IPv4Network]:
    configurations = (network.get("IPAM") or {}).get("Config") or []
    subnets: set[ipaddress.IPv4Network] = set()
    for configuration in configurations:
        raw_subnet = str(configuration.get("Subnet") or "").strip()
        if not raw_subnet:
            continue
        parsed = ipaddress.ip_network(raw_subnet, strict=False)
        if isinstance(parsed, ipaddress.IPv4Network):
            subnets.add(parsed)
    return subnets


def _validate_expected_addresses(network: dict) -> None:
    for container in (network.get("Containers") or {}).values():
        name = str(container.get("Name") or "")
        if name not in EXPECTED_CONTAINER_ADDRESSES:
            raise RuntimeError("an unexpected container is attached to fulfillment_internal")
        raw_address = str(container.get("IPv4Address") or "").split("/", 1)[0]
        if not raw_address:
            continue
        address = ipaddress.ip_address(raw_address)
        expected_address = EXPECTED_CONTAINER_ADDRESSES.get(name)
        if address in EXPECTED_CONTAINER_ADDRESSES.values() and address != expected_address:
            raise RuntimeError("a reserved fulfillment address is already in use")
        if expected_address is not None and address != expected_address:
            raise RuntimeError("a fulfillment container uses an unexpected address")


def validate_admin_port(admin_port: int) -> None:
    if not 1024 <= admin_port <= 65535:
        raise RuntimeError("Xianyu admin port is outside the allowed range")
    running = _docker(
        "inspect",
        "--format",
        "{{.State.Running}}",
        "visionforge-xianyu-fulfillment",
        allow_missing=True,
    )
    if running == "true":
        bindings = _docker(
            "port",
            "visionforge-xianyu-fulfillment",
            "8090/tcp",
        ).splitlines()
        if bindings != [f"127.0.0.1:{admin_port}"]:
            raise RuntimeError("running Xianyu admin binding is not the expected loopback port")
        return
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", admin_port))


def validate_platform_endpoint(platform_url: str, platform_hostname: str) -> None:
    parsed = urlsplit(platform_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != platform_hostname
        or parsed.path != EXPECTED_PLATFORM_PATH
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("Platform issuance URL does not match the private contract")
    socket.getaddrinfo(platform_hostname, 443, type=socket.SOCK_STREAM)


def validate_managed_catalog(managed_bridge_url: str, product_keys_json: str) -> None:
    if managed_bridge_url != EXPECTED_MANAGED_BRIDGE_URL:
        raise RuntimeError("managed bridge URL is not the private bridge endpoint")
    try:
        product_keys = json.loads(product_keys_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError("managed package product keys are not valid JSON") from exc
    if product_keys != EXPECTED_PRODUCT_KEYS:
        raise RuntimeError("managed package product keys are incomplete or unexpected")


def validate_storage(deploy_directory: Path) -> None:
    resolved_deploy_directory = deploy_directory.resolve(strict=True)
    raw_runtime_directory = resolved_deploy_directory / "runtime"
    if raw_runtime_directory.is_symlink():
        raise RuntimeError("runtime directory cannot be a symlink")
    runtime_directory = raw_runtime_directory.resolve(strict=True)
    try:
        runtime_directory.relative_to(resolved_deploy_directory)
    except ValueError as exc:
        raise RuntimeError("runtime directory escapes the deployment root") from exc
    for name in ("data", "backups"):
        raw_path = runtime_directory / name
        if raw_path.is_symlink():
            raise RuntimeError(f"runtime/{name} cannot be a symlink")
        path = raw_path.resolve(strict=True)
        try:
            path.relative_to(runtime_directory)
        except ValueError as exc:
            raise RuntimeError(f"runtime/{name} escapes the runtime root") from exc
        if not path.is_dir():
            raise RuntimeError(f"runtime/{name} is not a directory")
    if shutil.disk_usage(runtime_directory).free < MINIMUM_FREE_BYTES:
        raise RuntimeError("less than 1 GiB is free for safe activation and rollback")


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deploy-directory", required=True, type=Path)
    parser.add_argument("--admin-port", required=True, type=int)
    parser.add_argument("--platform-url", required=True)
    parser.add_argument("--platform-hostname", required=True)
    parser.add_argument("--managed-bridge-url", required=True)
    parser.add_argument("--product-keys-json", required=True)
    return parser.parse_args()


def main() -> None:
    arguments = _parse_arguments()
    validate_storage(arguments.deploy_directory)
    validate_networks()
    validate_admin_port(arguments.admin_port)
    validate_platform_endpoint(arguments.platform_url, arguments.platform_hostname)
    validate_managed_catalog(arguments.managed_bridge_url, arguments.product_keys_json)
    print("deployment_preflight=ok")


if __name__ == "__main__":
    main()
