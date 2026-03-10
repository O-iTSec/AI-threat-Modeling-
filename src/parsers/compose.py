"""Parser for Docker Compose files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

SENSITIVE_KEY_PATTERNS = re.compile(
    r"(SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL|API_KEY|PRIVATE|AUTH)", re.IGNORECASE
)

DATASTORE_IMAGES = (
    "postgres",
    "mysql",
    "mariadb",
    "mongo",
    "redis",
    "memcached",
    "elasticsearch",
    "cassandra",
    "dynamodb",
    "couchdb",
    "neo4j",
    "influxdb",
    "clickhouse",
    "cockroach",
    "timescaledb",
    "sqlite",
)


class ComposeParser:
    """Extract services, networks, volumes, and relationships from Compose files."""

    SUPPORTED_VERSIONS = ("3", "3.1", "3.8", "3.9")

    def parse(self, path: Path) -> dict[str, Any]:
        """Parse a docker-compose YAML file into a normalised asset dict."""
        with open(path) as fh:
            raw = yaml.safe_load(fh)

        version = str(raw.get("version", "3"))
        services = self._extract_services(raw.get("services", {}))
        networks = self._extract_networks(raw.get("networks", {}))
        volumes = self._extract_volumes(raw.get("volumes", {}))

        return {
            "source": "compose",
            "version": version,
            "services": services,
            "networks": networks,
            "volumes": volumes,
        }

    def _extract_services(self, raw: dict) -> list[dict[str, Any]]:
        services = []
        for name, cfg in raw.items():
            image = cfg.get("image")
            env_raw = cfg.get("environment", {})
            services.append(
                {
                    "name": name,
                    "image": image,
                    "asset_type": self._classify_service(image),
                    "ports": self._parse_ports(cfg.get("ports", [])),
                    "environment": self._classify_env_vars(env_raw),
                    "depends_on": self._normalise_depends_on(cfg.get("depends_on", [])),
                    "networks": cfg.get("networks", []),
                    "volumes": self._parse_volume_mounts(cfg.get("volumes", [])),
                }
            )
        return services

    def _extract_networks(self, raw: dict) -> list[dict[str, Any]]:
        return [
            {"name": name, "driver": cfg.get("driver", "bridge") if cfg else "bridge"}
            for name, cfg in raw.items()
        ]

    def _extract_volumes(self, raw: dict) -> list[dict[str, Any]]:
        return [
            {"name": name, "driver": cfg.get("driver", "local") if cfg else "local"}
            for name, cfg in raw.items()
        ]

    @staticmethod
    def _classify_service(image: str | None) -> str:
        if not image:
            return "service"
        image_lower = image.lower()
        for ds in DATASTORE_IMAGES:
            if image_lower.startswith(ds) or f"/{ds}" in image_lower:
                return "datastore"
        return "service"

    @staticmethod
    def _parse_ports(raw_ports: list) -> list[dict[str, Any]]:
        parsed = []
        for entry in raw_ports:
            entry_str = str(entry)
            protocol = "tcp"
            if "/" in entry_str:
                entry_str, protocol = entry_str.rsplit("/", 1)

            parts = entry_str.split(":")
            if len(parts) == 2:
                parsed.append(
                    {
                        "host": int(parts[0]),
                        "container": int(parts[1]),
                        "protocol": protocol,
                    }
                )
            elif len(parts) == 3:
                parsed.append(
                    {
                        "host": int(parts[1]),
                        "container": int(parts[2]),
                        "protocol": protocol,
                        "ip": parts[0],
                    }
                )
            elif len(parts) == 1:
                parsed.append(
                    {
                        "host": None,
                        "container": int(parts[0]),
                        "protocol": protocol,
                    }
                )
        return parsed

    @staticmethod
    def _classify_env_vars(env_raw: dict | list) -> list[dict[str, Any]]:
        result = []
        items: list[tuple[str, str]] = []

        if isinstance(env_raw, dict):
            items = list(env_raw.items())
        elif isinstance(env_raw, list):
            for entry in env_raw:
                if "=" in str(entry):
                    k, v = str(entry).split("=", 1)
                    items.append((k, v))

        for key, value in items:
            result.append(
                {
                    "key": key,
                    "value": value,
                    "sensitive": bool(SENSITIVE_KEY_PATTERNS.search(key)),
                }
            )
        return result

    @staticmethod
    def _normalise_depends_on(raw: list | dict) -> list[str]:
        """Handle both list and dict (extended) forms of depends_on."""
        if isinstance(raw, dict):
            return list(raw.keys())
        return list(raw)

    @staticmethod
    def _parse_volume_mounts(raw_volumes: list) -> list[dict[str, Any]]:
        parsed = []
        for entry in raw_volumes:
            entry_str = str(entry)
            parts = entry_str.split(":")
            if len(parts) >= 2:
                mode = parts[2] if len(parts) > 2 else "rw"
                parsed.append(
                    {
                        "volume": parts[0],
                        "mount_path": parts[1],
                        "mode": mode,
                    }
                )
            else:
                parsed.append(
                    {
                        "volume": None,
                        "mount_path": parts[0],
                        "mode": "rw",
                    }
                )
        return parsed
