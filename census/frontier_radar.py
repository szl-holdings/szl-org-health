#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only open-source frontier release and estate-capability radar.

The radar does not install dependencies or call product effectors. It resolves
an explicit allowlist of official upstream repositories, dereferences release
tags to exact commits, records license and maintenance evidence, compares those
capabilities with the deep estate inventory, and emits reviewable adoption
candidates. Missing or ambiguous evidence remains UNKNOWN/REVIEW_REQUIRED.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

SCHEMA = "szl.open-source-frontier-radar/v1"
API_VERSION = "2022-11-28"
USER_AGENT = "SZL-Open-Source-Frontier-Radar/1.0"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PERMISSIVE_LICENSES = frozenset(
    {
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "MIT",
        "MPL-2.0",
    }
)
REVIEW_LICENSES = frozenset(
    {
        "AGPL-3.0",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "GPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "LGPL-2.1",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
    }
)
CATEGORY_PRIORITY = {
    "supply-chain": 10,
    "policy-identity": 20,
    "observability": 30,
    "evaluation": 40,
    "serving": 50,
    "orchestration": 60,
    "training": 70,
    "retrieval-data": 80,
    "agents-protocols": 90,
}


@dataclasses.dataclass(frozen=True)
class Upstream:
    repository: str
    category: str
    capability: str
    role: str
    deployment_boundary: str


UPSTREAMS: tuple[Upstream, ...] = (
    Upstream("sigstore/cosign", "supply-chain", "security.sigstore", "artifact signing and verification", "release-plane"),
    Upstream("in-toto/in-toto", "supply-chain", "security.in_toto", "software-supply-chain attestations", "release-plane"),
    Upstream("slsa-framework/slsa-verifier", "supply-chain", "security.slsa", "SLSA provenance verification", "release-plane"),
    Upstream("anchore/syft", "supply-chain", "security.sbom", "SBOM generation", "build-plane"),
    Upstream("anchore/grype", "supply-chain", "security.vulnerability_scan", "SBOM vulnerability analysis", "build-plane"),
    Upstream("aquasecurity/trivy", "supply-chain", "security.trivy", "container and source vulnerability analysis", "build-plane"),
    Upstream("gitleaks/gitleaks", "supply-chain", "security.gitleaks", "credential scanning", "build-plane"),
    Upstream("open-policy-agent/opa", "policy-identity", "policy.opa", "policy decision point", "governance-plane"),
    Upstream("kyverno/kyverno", "policy-identity", "policy.kyverno", "Kubernetes policy enforcement", "cluster-plane"),
    Upstream("spiffe/spire", "policy-identity", "identity.spiffe", "workload identity", "identity-plane"),
    Upstream("open-telemetry/opentelemetry-collector", "observability", "observability.opentelemetry", "vendor-neutral telemetry pipeline", "telemetry-plane"),
    Upstream("open-telemetry/opentelemetry-python", "observability", "observability.opentelemetry", "Python traces metrics and logs", "application-plane"),
    Upstream("Arize-ai/phoenix", "observability", "observability.phoenix", "LLM tracing and evaluation", "evaluation-plane"),
    Upstream("langfuse/langfuse", "observability", "observability.langfuse", "LLM observability and prompt lineage", "telemetry-plane"),
    Upstream("prometheus/prometheus", "observability", "observability.prometheus", "metrics and alerting", "telemetry-plane"),
    Upstream("grafana/tempo", "observability", "observability.tempo", "distributed trace storage", "telemetry-plane"),
    Upstream("grafana/loki", "observability", "observability.loki", "log aggregation", "telemetry-plane"),
    Upstream("EleutherAI/lm-evaluation-harness", "evaluation", "evaluation.lm_eval", "reproducible language-model evaluation", "evaluation-plane"),
    Upstream("stanford-crfm/helm", "evaluation", "evaluation.helm", "holistic model evaluation", "evaluation-plane"),
    Upstream("explodinggradients/ragas", "evaluation", "evaluation.ragas", "retrieval-augmented generation evaluation", "evaluation-plane"),
    Upstream("promptfoo/promptfoo", "evaluation", "evaluation.promptfoo", "red-team and prompt regression gates", "evaluation-plane"),
    Upstream("vllm-project/vllm", "serving", "inference.vllm", "high-throughput OpenAI-compatible inference", "inference-plane"),
    Upstream("sgl-project/sglang", "serving", "inference.sglang", "structured generation and inference runtime", "inference-plane"),
    Upstream("ggml-org/llama.cpp", "serving", "inference.llama_cpp", "portable local and edge inference", "edge-plane"),
    Upstream("kserve/kserve", "serving", "inference.kserve", "Kubernetes model serving control plane", "cluster-plane"),
    Upstream("llm-d/llm-d", "serving", "inference.llm_d", "Kubernetes-native distributed LLM serving", "cluster-plane"),
    Upstream("ai-dynamo/dynamo", "serving", "inference.dynamo", "distributed inference data plane", "inference-plane"),
    Upstream("ray-project/ray", "orchestration", "orchestration.ray", "distributed execution and model serving", "compute-plane"),
    Upstream("temporalio/sdk-python", "orchestration", "orchestration.temporal", "durable Python workflows", "workflow-plane"),
    Upstream("dagster-io/dagster", "orchestration", "orchestration.dagster", "data and ML asset orchestration", "data-plane"),
    Upstream("OpenLineage/OpenLineage", "orchestration", "data.openlineage", "cross-system data lineage", "data-plane"),
    Upstream("huggingface/transformers", "training", "training.transformers", "model architecture and training foundation", "training-plane"),
    Upstream("huggingface/trl", "training", "training.trl", "post-training and preference optimization", "training-plane"),
    Upstream("huggingface/peft", "training", "training.peft", "parameter-efficient fine-tuning", "training-plane"),
    Upstream("huggingface/accelerate", "training", "training.accelerate", "portable distributed training", "training-plane"),
    Upstream("microsoft/DeepSpeed", "training", "training.deepspeed", "large-model distributed training", "training-plane"),
    Upstream("axolotl-ai-cloud/axolotl", "training", "training.axolotl", "declarative post-training pipelines", "training-plane"),
    Upstream("qdrant/qdrant", "retrieval-data", "retrieval.qdrant", "vector retrieval service", "retrieval-plane"),
    Upstream("pgvector/pgvector", "retrieval-data", "retrieval.pgvector", "PostgreSQL vector search", "data-plane"),
    Upstream("lancedb/lancedb", "retrieval-data", "data.lance", "multimodal embedded retrieval", "data-plane"),
    Upstream("duckdb/duckdb", "retrieval-data", "data.duckdb", "embedded analytical query engine", "data-plane"),
    Upstream("modelcontextprotocol/python-sdk", "agents-protocols", "protocol.mcp", "Model Context Protocol implementation", "tool-plane"),
    Upstream("langchain-ai/langgraph", "agents-protocols", "agents.langgraph", "stateful agent graph runtime", "agent-plane"),
    Upstream("microsoft/autogen", "agents-protocols", "agents.autogen", "multi-agent application framework", "agent-plane"),
    Upstream("openai/openai-agents-python", "agents-protocols", "agents.openai_sdk", "provider-neutral agent primitives and tracing", "agent-plane"),
)


class RadarError(RuntimeError):
    """Fail-closed radar error."""


class Client(Protocol):
    def get(self, path: str, *, allow_404: bool = False) -> Any: ...


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def redact(text: str, token: str | None = None) -> str:
    value = text.replace(token, "[REDACTED]") if token else text
    value = re.sub(r"(?i)(authorization:\s*(?:bearer|token)\s+)[^\s]+", r"\1[REDACTED]", value)
    return value[:2000]


class GitHubClient:
    def __init__(self, token: str | None, *, timeout: float = 30.0, retries: int = 3) -> None:
        self.token = token or ""
        self.timeout = timeout
        self.retries = retries

    def get(self, path: str, *, allow_404: bool = False) -> Any:
        if not path.startswith("/"):
            raise RadarError("GitHub API path must be absolute")
        url = "https://api.github.com" + path
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": API_VERSION,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            request = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read(16 * 1024 * 1024 + 1)
                    if len(raw) > 16 * 1024 * 1024:
                        raise RadarError("GitHub response exceeded the 16 MiB evidence ceiling")
                    return json.loads(raw.decode("utf-8")) if raw else None
            except urllib.error.HTTPError as exc:
                detail = exc.read(65536).decode("utf-8", "replace")
                if allow_404 and exc.code == 404:
                    return None
                last = RadarError(
                    f"GitHub HTTP {exc.code} for {path}: {redact(detail, self.token)}"
                )
                retryable = exc.code in {429, 500, 502, 503, 504}
                if not retryable or attempt >= self.retries:
                    raise last
            except (OSError, TimeoutError, json.JSONDecodeError) as exc:
                last = exc
                if attempt >= self.retries:
                    raise RadarError(
                        f"GitHub request failed for {path}: {redact(str(exc), self.token)}"
                    ) from exc
            time.sleep(min(20.0, 2.0**attempt))
        raise RadarError(str(last or "GitHub request failed"))


def _encoded_repository(repository: str) -> str:
    owner, name = repository.split("/", 1)
    return "/".join(
        (urllib.parse.quote(owner, safe=""), urllib.parse.quote(name, safe=""))
    )


def _deref_tag(client: Client, repository: str, tag: str) -> tuple[str | None, str | None]:
    encoded = _encoded_repository(repository)
    encoded_tag = urllib.parse.quote(tag, safe="")
    ref = client.get(f"/repos/{encoded}/git/ref/tags/{encoded_tag}", allow_404=True)
    if not isinstance(ref, dict):
        return None, "release tag ref unavailable"
    obj = ref.get("object") if isinstance(ref.get("object"), dict) else {}
    object_type = obj.get("type")
    sha = obj.get("sha")
    if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
        return None, "release tag ref has no exact object SHA"
    seen: set[str] = set()
    while object_type == "tag":
        if sha in seen:
            return None, "annotated tag cycle observed"
        seen.add(sha)
        tag_object = client.get(f"/repos/{encoded}/git/tags/{sha}")
        if not isinstance(tag_object, dict):
            return None, "annotated tag object malformed"
        obj = tag_object.get("object") if isinstance(tag_object.get("object"), dict) else {}
        object_type = obj.get("type")
        sha = obj.get("sha")
        if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
            return None, "annotated tag has no exact target SHA"
        if len(seen) > 8:
            return None, "annotated tag depth exceeded"
    if object_type != "commit":
        return None, f"release tag resolves to {object_type or 'unknown'}, not commit"
    return sha, None


def _license_state(spdx: Any) -> str:
    if not isinstance(spdx, str) or spdx in {"", "NOASSERTION", "OTHER"}:
        return "UNKNOWN"
    if spdx in PERMISSIVE_LICENSES:
        return "PERMISSIVE_REVIEWABLE"
    if spdx in REVIEW_LICENSES:
        return "LEGAL_REVIEW_REQUIRED"
    return "LEGAL_REVIEW_REQUIRED"


def _age_days(value: Any, now: dt.datetime) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return max(0, (now - parsed.astimezone(dt.timezone.utc)).days)


def resolve_upstream(client: Client, upstream: Upstream, now: dt.datetime) -> dict[str, Any]:
    encoded = _encoded_repository(upstream.repository)
    metadata = client.get(f"/repos/{encoded}")
    if not isinstance(metadata, dict):
        raise RadarError(f"{upstream.repository}: repository metadata malformed")
    release = client.get(f"/repos/{encoded}/releases/latest", allow_404=True)
    release_kind = "github-release"
    tag: str | None = None
    release_url: str | None = None
    published_at: str | None = None
    prerelease: bool | None = None
    draft: bool | None = None
    if isinstance(release, dict):
        tag = release.get("tag_name") if isinstance(release.get("tag_name"), str) else None
        release_url = release.get("html_url") if isinstance(release.get("html_url"), str) else None
        published_at = release.get("published_at") if isinstance(release.get("published_at"), str) else None
        prerelease = release.get("prerelease") if isinstance(release.get("prerelease"), bool) else None
        draft = release.get("draft") if isinstance(release.get("draft"), bool) else None
    else:
        tags = client.get(f"/repos/{encoded}/tags?per_page=1")
        first = tags[0] if isinstance(tags, list) and tags and isinstance(tags[0], dict) else None
        tag = first.get("name") if isinstance(first, dict) and isinstance(first.get("name"), str) else None
        release_kind = "latest-tag" if tag else "unversioned"

    commit_sha: str | None = None
    ref_error: str | None = None
    if tag:
        commit_sha, ref_error = _deref_tag(client, upstream.repository, tag)

    license_info = metadata.get("license") if isinstance(metadata.get("license"), dict) else {}
    spdx = license_info.get("spdx_id") if isinstance(license_info.get("spdx_id"), str) else None
    archived = metadata.get("archived") is True
    disabled = metadata.get("disabled") is True
    age = _age_days(published_at or metadata.get("pushed_at"), now)
    maintenance = (
        "ARCHIVED"
        if archived or disabled
        else "STALE_REVIEW"
        if age is not None and age > 550
        else "ACTIVE_OBSERVED"
    )
    license_state = _license_state(spdx)
    evidence_complete = bool(
        tag
        and commit_sha
        and maintenance != "ARCHIVED"
        and license_state != "UNKNOWN"
        and (draft is not True)
        and (prerelease is not True)
    )
    state = "ADOPT_CANDIDATE" if evidence_complete else "REVIEW_REQUIRED"
    blockers: list[str] = []
    if archived or disabled:
        blockers.append("upstream archived or disabled")
    if not tag:
        blockers.append("no release or tag observed")
    if not commit_sha:
        blockers.append(ref_error or "release commit unresolved")
    if license_state == "UNKNOWN":
        blockers.append("license evidence unavailable")
    elif license_state == "LEGAL_REVIEW_REQUIRED":
        blockers.append(f"license {spdx} requires use-specific review")
    if draft is True or prerelease is True:
        blockers.append("latest release is draft or prerelease")
    if maintenance == "STALE_REVIEW":
        blockers.append("release or push age exceeds review threshold")

    return {
        "repository": upstream.repository,
        "category": upstream.category,
        "capability": upstream.capability,
        "role": upstream.role,
        "deployment_boundary": upstream.deployment_boundary,
        "state": state,
        "release": {
            "kind": release_kind,
            "tag": tag,
            "commit_sha": commit_sha,
            "published_at": published_at,
            "url": release_url,
            "draft": draft,
            "prerelease": prerelease,
        },
        "repository_evidence": {
            "default_branch": metadata.get("default_branch"),
            "pushed_at": metadata.get("pushed_at"),
            "archived": archived,
            "disabled": disabled,
            "fork": metadata.get("fork"),
            "stars_snapshot": metadata.get("stargazers_count"),
        },
        "license": {"spdx": spdx, "state": license_state},
        "maintenance": {"state": maintenance, "age_days": age},
        "blockers": blockers,
    }


def load_technology_index(path: Path | None) -> dict[str, list[str]]:
    if path is None:
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadarError(f"technology index unreadable: {exc}") from exc
    technologies = payload.get("technologies") if isinstance(payload, dict) else None
    if not isinstance(technologies, dict):
        raise RadarError("technology index has no technologies object")
    normalized: dict[str, list[str]] = {}
    for key, repos in technologies.items():
        if not isinstance(key, str) or not isinstance(repos, list) or any(
            not isinstance(repo, str) for repo in repos
        ):
            raise RadarError("technology index contains malformed capability rows")
        normalized[key] = sorted(set(repos))
    return normalized


def apply_estate_presence(
    rows: list[dict[str, Any]], technologies: Mapping[str, list[str]]
) -> None:
    for row in rows:
        repos = list(technologies.get(str(row["capability"]), []))
        row["estate_presence"] = {
            "state": "OBSERVED" if repos else "NOT_OBSERVED",
            "repositories": repos,
        }
        missing = not repos
        row["priority"] = CATEGORY_PRIORITY.get(str(row["category"]), 999) + (
            0 if missing else 500
        )


def render_markdown(payload: Mapping[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Open-source frontier radar",
        "",
        f"- State: **{payload['state']}**",
        f"- Upstreams resolved: **{summary['resolved']} / {summary['total']}**",
        f"- Exact adoption candidates: **{summary['adopt_candidates']}**",
        f"- Review required: **{summary['review_required']}**",
        f"- Capabilities not observed in the estate: **{summary['not_observed']}**",
        "",
        "This is a read-only adoption radar. Candidate does not mean installed, "
        "deployed, secure for every use, or approved for production.",
        "",
        "## Prioritized candidates",
        "",
        "| Priority | Capability | Upstream | Release | License | Estate | State |",
        "|---:|---|---|---|---|---|---|",
    ]
    rows = sorted(
        payload["upstreams"],
        key=lambda row: (int(row.get("priority") or 9999), str(row["repository"])),
    )
    for row in rows:
        release = row["release"]
        estate = row["estate_presence"]
        tag = release.get("tag") or "UNAVAILABLE"
        sha = release.get("commit_sha")
        release_label = f"{tag} @ {sha[:12]}" if isinstance(sha, str) else tag
        lines.append(
            "| {priority} | `{capability}` | `{repository}` | `{release}` | "
            "`{license}` | `{estate}` | `{state}` |".format(
                priority=row.get("priority"),
                capability=row["capability"],
                repository=row["repository"],
                release=release_label,
                license=row["license"].get("spdx") or "UNKNOWN",
                estate=estate["state"],
                state=row["state"],
            )
        )
    lines.extend(
        [
            "",
            "## Adoption gate",
            "",
            "Before any dependency lands: pin the exact release commit or package "
            "digest, verify license and provenance, add an SBOM, run vulnerability "
            "and secret scans, prove rollback, add OpenTelemetry signals, and merge "
            "through the owning repository's protected checks. The radar never "
            "performs that mutation itself.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def run(args: argparse.Namespace) -> int:
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    technologies = load_technology_index(
        Path(args.technology_index) if args.technology_index else None
    )
    client = GitHubClient(
        args.token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"),
        timeout=args.timeout,
        retries=args.retries,
    )
    now = dt.datetime.now(dt.timezone.utc)
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for upstream in UPSTREAMS:
        try:
            rows.append(resolve_upstream(client, upstream, now))
        except Exception as exc:
            errors.append(
                {
                    "repository": upstream.repository,
                    "error": redact(str(exc), client.token),
                }
            )
            rows.append(
                {
                    "repository": upstream.repository,
                    "category": upstream.category,
                    "capability": upstream.capability,
                    "role": upstream.role,
                    "deployment_boundary": upstream.deployment_boundary,
                    "state": "UNKNOWN",
                    "release": {
                        "kind": "unavailable",
                        "tag": None,
                        "commit_sha": None,
                        "published_at": None,
                        "url": None,
                        "draft": None,
                        "prerelease": None,
                    },
                    "repository_evidence": {},
                    "license": {"spdx": None, "state": "UNKNOWN"},
                    "maintenance": {"state": "UNKNOWN", "age_days": None},
                    "blockers": ["upstream evidence unavailable"],
                }
            )
    apply_estate_presence(rows, technologies)
    state_counts = Counter(str(row["state"]) for row in rows)
    state = "INCOMPLETE" if errors else "REVIEW_READY"
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "state": state,
        "summary": {
            "total": len(rows),
            "resolved": len(rows) - len(errors),
            "adopt_candidates": state_counts["ADOPT_CANDIDATE"],
            "review_required": state_counts["REVIEW_REQUIRED"] + state_counts["UNKNOWN"],
            "not_observed": sum(
                1
                for row in rows
                if row["estate_presence"]["state"] == "NOT_OBSERVED"
            ),
        },
        "upstreams": sorted(rows, key=lambda row: str(row["repository"]).lower()),
        "errors": errors,
        "authority": {
            "read_only": True,
            "dependency_mutation": False,
            "provider_mutation": False,
            "production_authorization": False,
            "secrets_emitted": False,
        },
    }
    json_path = output / "frontier-radar.json"
    json_path.write_bytes(canonical_json_bytes(payload) + b"\n")
    markdown_path = output / "FRONTIER_RADAR.md"
    markdown_path.write_text(render_markdown(payload), encoding="utf-8")
    receipt = {
        "schema": SCHEMA,
        "generated_at": payload["generated_at"],
        "state": state,
        "frontier_radar_sha256": sha256_bytes(json_path.read_bytes()),
        "markdown_sha256": sha256_bytes(markdown_path.read_bytes()),
        "summary": payload["summary"],
        "source": {
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "workflow_sha": os.environ.get("GITHUB_SHA"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        },
        "authority": payload["authority"],
    }
    (output / "receipt.json").write_bytes(canonical_json_bytes(receipt) + b"\n")
    print(json.dumps(receipt, sort_keys=True))
    return 2 if errors else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--technology-index")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--token")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--retries", type=int, default=3)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(build_parser().parse_args(argv))
    except RadarError as exc:
        print(json.dumps({"state": "INCOMPLETE", "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
