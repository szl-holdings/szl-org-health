"""Fail-closed cybersecurity and data-governance evaluation.

The policy is a target profile. Results are observations over one census report;
they are not certifications and never upgrade unavailable evidence to PASS.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

DEFAULT_POLICY = Path(__file__).resolve().parents[1] / "governance" / "policy.json"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
VALID_STATUSES = {"PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"}
MAX_EXAMPLES = 20


class PolicyError(ValueError):
    """The versioned target policy is missing or structurally invalid."""


def _load_policy(path: str | Path | None) -> dict[str, Any]:
    policy_path = Path(path) if path is not None else DEFAULT_POLICY
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyError(f"policy unavailable: {exc}") from exc
    if policy.get("schema") != "szl.estate-governance-policy/v1":
        raise PolicyError("unsupported policy schema")
    operating = policy.get("operating_model")
    if not isinstance(operating, dict) or operating.get("type") != "solo-maintainer":
        raise PolicyError("solo-maintainer operating model is required")
    if operating.get("dco_required") is not False:
        raise PolicyError("DCO must not be a required solo-maintainer control")
    if operating.get("independent_review_claim_allowed_without_external_actor") is not False:
        raise PolicyError("independent review may not be self-asserted")
    controls = policy.get("controls")
    if not isinstance(controls, list) or not controls:
        raise PolicyError("policy controls are required")
    ids = [control.get("id") for control in controls if isinstance(control, dict)]
    if len(ids) != len(controls) or len(set(ids)) != len(ids) or not all(ids):
        raise PolicyError("policy control IDs must be unique non-empty strings")
    return policy


def _source(report: dict[str, Any], name: str) -> tuple[bool, dict[str, Any]]:
    raw = (report.get("sources") or {}).get(name)
    if not isinstance(raw, dict):
        return False, {}
    data = raw.get("data")
    return raw.get("ok") is True and isinstance(data, dict), data if isinstance(data, dict) else {}


def _bounded(values: list[str]) -> dict[str, Any]:
    ordered = sorted(set(values))
    return {"count": len(ordered), "examples": ordered[:MAX_EXAMPLES]}


def _control(control_id: str, status: str, summary: str, evidence: Any) -> dict[str, Any]:
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid control status: {status}")
    return {"id": control_id, "status": status, "summary": summary, "evidence": evidence}


def _github_inventory(report: dict[str, Any], _policy: dict[str, Any]) -> dict[str, Any]:
    ok, data = _source(report, "github")
    discovery = data.get("discovery") if isinstance(data.get("discovery"), dict) else {}
    total = ((data.get("summary") or {}).get("total") if isinstance(data.get("summary"), dict) else None)
    if not ok or discovery.get("complete") is not True:
        return _control("GH-INVENTORY", "UNKNOWN", "Complete GitHub estate discovery was not observed.", {"source_ok": ok, "discovery": discovery, "observed_total": total})
    return _control("GH-INVENTORY", "PASS", "GitHub estate discovery completed for this census.", {"observed_total": total, "scope": discovery.get("scope")})


def _github_ci(report: dict[str, Any], _policy: dict[str, Any]) -> dict[str, Any]:
    ok, data = _source(report, "github")
    repos = data.get("repos") if isinstance(data.get("repos"), dict) else {}
    active = {name: value for name, value in repos.items() if isinstance(value, dict) and not value.get("archived")}
    failed = [name for name, value in active.items() if value.get("ci") == "failure"]
    uncertain = [name for name, value in active.items() if value.get("ci") in {None, "unknown", "pending"}]
    if failed:
        return _control("GH-ACTIVE-CI", "FAIL", "At least one active repository has a failing latest-per-workflow result.", {"failed": _bounded(failed), "uncertain": _bounded(uncertain)})
    if not ok or not active or uncertain:
        return _control("GH-ACTIVE-CI", "UNKNOWN", "Active-repository CI is not fully observable and green.", {"source_ok": ok, "active_count": len(active), "uncertain": _bounded(uncertain)})
    return _control("GH-ACTIVE-CI", "PASS", "Every observed active repository has terminal green latest-per-workflow evidence.", {"active_count": len(active)})


def _github_protection(report: dict[str, Any], _policy: dict[str, Any]) -> dict[str, Any]:
    ok, data = _source(report, "github")
    repos = data.get("repos") if isinstance(data.get("repos"), dict) else {}
    active = {name: value for name, value in repos.items() if isinstance(value, dict) and not value.get("archived")}
    unprotected = [name for name, value in active.items() if value.get("protected") is False]
    unknown = [name for name, value in active.items() if value.get("protected") is not True and value.get("protected") is not False]
    if unprotected:
        return _control("GH-BRANCH-PROTECTION", "FAIL", "At least one active default branch is observed unprotected.", {"unprotected": _bounded(unprotected), "unknown": _bounded(unknown)})
    if not ok or not active or unknown:
        return _control("GH-BRANCH-PROTECTION", "UNKNOWN", "Default-branch protection is not readable for the complete active estate.", {"source_ok": ok, "active_count": len(active), "unknown": _bounded(unknown)})
    return _control("GH-BRANCH-PROTECTION", "PASS", "Every observed active default branch is protected.", {"active_count": len(active)})


def _github_alert(report: dict[str, Any], control_id: str, field: str, label: str) -> dict[str, Any]:
    ok, data = _source(report, "github")
    alerts = data.get("alerts") if isinstance(data.get("alerts"), dict) else {}
    count = alerts.get(field)
    complete = alerts.get("complete") is True
    if isinstance(count, int) and count > 0:
        return _control(control_id, "FAIL", f"Open {label} were observed.", {"open": count, "alert_read_complete": complete})
    if ok and complete and count == 0:
        return _control(control_id, "PASS", f"No open {label} were observed in the complete alert read.", {"open": 0})
    return _control(control_id, "UNKNOWN", f"The complete {label} state is unavailable.", {"source_ok": ok, "open": count, "alert_read_complete": complete, "errors": alerts.get("errors")})


def _github_classification(report: dict[str, Any], _policy: dict[str, Any]) -> dict[str, Any]:
    ok, data = _source(report, "github")
    repos = data.get("repos") if isinstance(data.get("repos"), dict) else {}
    unclassified = [name for name, value in repos.items() if isinstance(value, dict) and not value.get("archived") and value.get("classification") == "unclassified"]
    if unclassified:
        return _control("GH-REPOSITORY-CLASSIFICATION", "FAIL", "Active repositories without a governed role classification were observed.", {"unclassified": _bounded(unclassified)})
    discovery = data.get("discovery") if isinstance(data.get("discovery"), dict) else {}
    if not ok or discovery.get("complete") is not True:
        return _control("GH-REPOSITORY-CLASSIFICATION", "UNKNOWN", "Complete repository classification coverage is unavailable.", {"source_ok": ok, "discovery": discovery})
    return _control("GH-REPOSITORY-CLASSIFICATION", "PASS", "Every observed active repository has a governed role classification.", {"active_total": sum(1 for value in repos.values() if isinstance(value, dict) and not value.get("archived"))})


def _hf_assets(report: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    ok, data = _source(report, "huggingface")
    assets = data.get("assets") if isinstance(data.get("assets"), dict) else {}
    return ok, assets


def _hf_inventory(report: dict[str, Any], _policy: dict[str, Any]) -> dict[str, Any]:
    ok, assets = _hf_assets(report)
    required = ("models", "datasets", "spaces", "kernels", "collections", "buckets")
    unavailable = [name for name in required if not isinstance(assets.get(name), dict) or assets[name].get("ok") is not True]
    counts = {name: (assets.get(name) or {}).get("count") if isinstance(assets.get(name), dict) else None for name in required}
    if not ok or unavailable:
        return _control("HF-INVENTORY", "UNKNOWN", "The authenticated/public Hugging Face asset census is incomplete.", {"source_ok": ok, "unavailable": unavailable, "counts": counts})
    return _control("HF-INVENTORY", "PASS", "All configured Hugging Face asset classes were enumerated for this census scope.", {"counts": counts, "scope_warning": "Counts reflect the credential and API scope used by this census."})


def _hf_items(assets: dict[str, Any], kinds: tuple[str, ...]) -> tuple[list[dict[str, Any]], list[str]]:
    items: list[dict[str, Any]] = []
    unavailable: list[str] = []
    for kind in kinds:
        asset = assets.get(kind)
        if not isinstance(asset, dict) or asset.get("ok") is not True or not isinstance(asset.get("items"), list):
            unavailable.append(kind)
            continue
        items.extend(value for value in asset["items"] if isinstance(value, dict))
    return items, unavailable


def _hf_cards(report: dict[str, Any], _policy: dict[str, Any]) -> dict[str, Any]:
    ok, assets = _hf_assets(report)
    items, unavailable = _hf_items(assets, ("models", "datasets", "spaces"))
    incomplete = [str(value.get("id") or "unknown") for value in items if value.get("card_state") == "INCOMPLETE" or value.get("card_present") is False]
    unknown = [str(value.get("id") or "unknown") for value in items if value.get("card_state") == "UNKNOWN" or value.get("card_present") is None]
    if incomplete:
        return _control("HF-CARDS", "FAIL", "Hugging Face assets with incomplete cards were observed.", {"incomplete": _bounded(incomplete), "unknown": _bounded(unknown)})
    if not ok or unavailable or unknown:
        return _control("HF-CARDS", "UNKNOWN", "Complete Hugging Face card coverage is unavailable.", {"unavailable": unavailable, "unknown": _bounded(unknown)})
    return _control("HF-CARDS", "PASS", "Every observed model, dataset, and Space has a complete basic card.", {"asset_count": len(items)})


def _hf_licenses(report: dict[str, Any], _policy: dict[str, Any]) -> dict[str, Any]:
    ok, assets = _hf_assets(report)
    items, unavailable = _hf_items(assets, ("models", "datasets", "spaces"))
    missing = [str(value.get("id") or "unknown") for value in items if value.get("license_declared") is False]
    unknown = [str(value.get("id") or "unknown") for value in items if value.get("license_declared") is None]
    if missing:
        return _control("HF-LICENSES", "FAIL", "Hugging Face assets without declared license metadata were observed.", {"missing": _bounded(missing), "unknown": _bounded(unknown)})
    if not ok or unavailable or unknown:
        return _control("HF-LICENSES", "UNKNOWN", "Complete Hugging Face license coverage is unavailable.", {"unavailable": unavailable, "unknown": _bounded(unknown)})
    return _control("HF-LICENSES", "PASS", "Every observed model, dataset, and Space declares a license.", {"asset_count": len(items)})


def _hf_safe_formats(report: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    ok, assets = _hf_assets(report)
    models, unavailable = _hf_items(assets, ("models",))
    suffixes = tuple(str(value).lower() for value in policy.get("unsafe_model_suffixes") or [])
    exceptions = {str(value) for value in policy.get("unsafe_serialization_exceptions") or []}
    unsafe: list[str] = []
    for model in models:
        model_id = str(model.get("id") or "unknown")
        if model_id in exceptions:
            continue
        paths = list(model.get("model_artifact_files_observed") or [])
        paths.extend(model.get("weight_files_observed") or [])
        paths.extend(model.get("estimator_files_observed") or [])
        bad = sorted({str(path) for path in paths if str(path).lower().endswith(suffixes)})
        unsafe.extend(f"{model_id}:{path}" for path in bad)
    if unsafe:
        return _control("HF-SAFE-MODEL-FORMATS", "FAIL", "Executable or unsafe serialized model artifacts were observed without a policy exception.", {"unsafe_artifacts": _bounded(unsafe), "exceptions": sorted(exceptions)})
    if not ok or unavailable:
        return _control("HF-SAFE-MODEL-FORMATS", "UNKNOWN", "Model-format coverage is unavailable.", {"unavailable": unavailable})
    return _control("HF-SAFE-MODEL-FORMATS", "PASS", "No policy-banned serialized model artifacts were observed.", {"model_count": len(models), "exceptions": sorted(exceptions)})


def _hf_revisions(report: dict[str, Any], _policy: dict[str, Any]) -> dict[str, Any]:
    ok, assets = _hf_assets(report)
    items, unavailable = _hf_items(assets, ("models", "datasets", "spaces"))
    invalid = [str(value.get("id") or "unknown") for value in items if not SHA40.fullmatch(str(value.get("sha") or "").lower())]
    if invalid:
        return _control("HF-IMMUTABLE-REVISIONS", "FAIL", "Assets without an observed immutable 40-hex revision were found.", {"invalid": _bounded(invalid)})
    if not ok or unavailable or not items:
        return _control("HF-IMMUTABLE-REVISIONS", "UNKNOWN", "Complete immutable-revision coverage is unavailable.", {"unavailable": unavailable, "asset_count": len(items)})
    return _control("HF-IMMUTABLE-REVISIONS", "PASS", "Every observed model, dataset, and Space has an immutable revision.", {"asset_count": len(items)})


def _hf_space_binding(report: dict[str, Any], _policy: dict[str, Any]) -> dict[str, Any]:
    ok, assets = _hf_assets(report)
    spaces, unavailable = _hf_items(assets, ("spaces",))
    dynamic = [value for value in spaces if value.get("sdk") != "static"]
    failed = [str(value.get("id") or "unknown") for value in dynamic if value.get("stage") == "RUNNING" and value.get("source_binding_state") != "OBSERVED"]
    unknown = [str(value.get("id") or "unknown") for value in dynamic if value.get("stage") != "RUNNING" and value.get("source_binding_state") != "OBSERVED"]
    if failed:
        return _control("HF-DYNAMIC-SPACE-SOURCE-BINDING", "FAIL", "Running dynamic Spaces without an observed immutable source binding were found.", {"failed": _bounded(failed), "non_running_unavailable": _bounded(unknown)})
    if not ok or unavailable or unknown:
        return _control("HF-DYNAMIC-SPACE-SOURCE-BINDING", "UNKNOWN", "Every dynamic Space cannot be bound to a running immutable source revision.", {"unavailable": unavailable, "non_running_unavailable": _bounded(unknown), "dynamic_count": len(dynamic)})
    return _control("HF-DYNAMIC-SPACE-SOURCE-BINDING", "PASS", "Every observed dynamic Space is running with an immutable source binding.", {"dynamic_count": len(dynamic)})


def _dns(report: dict[str, Any], policy: dict[str, Any], field: str, control_id: str, label: str) -> dict[str, Any]:
    ok, data = _source(report, "dns")
    domains = [str(value) for value in policy.get("authoritative_domains") or []]
    failed: list[str] = []
    unknown: list[str] = []
    for domain in domains:
        entry = data.get(domain)
        if not isinstance(entry, dict) or entry.get(field) is None:
            unknown.append(domain)
        elif entry.get(field) is not True:
            failed.append(domain)
    if failed:
        return _control(control_id, "FAIL", f"Domains without {label} were observed.", {"failed": _bounded(failed), "unknown": _bounded(unknown)})
    if not ok or not domains or unknown:
        return _control(control_id, "UNKNOWN", f"Complete {label} evidence is unavailable.", {"source_ok": ok, "unknown": _bounded(unknown), "domain_count": len(domains)})
    return _control(control_id, "PASS", f"Every authoritative domain has {label}.", {"domain_count": len(domains)})


CONTROL_EVALUATORS: dict[str, Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]] = {
    "GH-INVENTORY": _github_inventory,
    "GH-ACTIVE-CI": _github_ci,
    "GH-BRANCH-PROTECTION": _github_protection,
    "GH-HIGH-CODE-ALERTS": lambda report, policy: _github_alert(report, "GH-HIGH-CODE-ALERTS", "code_scanning_high", "high-severity code-scanning alerts"),
    "GH-SECRET-ALERTS": lambda report, policy: _github_alert(report, "GH-SECRET-ALERTS", "secret_scanning_open", "secret-scanning alerts"),
    "GH-DEPENDABOT-ALERTS": lambda report, policy: _github_alert(report, "GH-DEPENDABOT-ALERTS", "dependabot_open", "Dependabot alerts"),
    "GH-REPOSITORY-CLASSIFICATION": _github_classification,
    "HF-INVENTORY": _hf_inventory,
    "HF-CARDS": _hf_cards,
    "HF-LICENSES": _hf_licenses,
    "HF-SAFE-MODEL-FORMATS": _hf_safe_formats,
    "HF-IMMUTABLE-REVISIONS": _hf_revisions,
    "HF-DYNAMIC-SPACE-SOURCE-BINDING": _hf_space_binding,
    "DNS-SPF": lambda report, policy: _dns(report, policy, "spf", "DNS-SPF", "SPF"),
    "DNS-DMARC-REJECT": lambda report, policy: _dns(report, policy, "dmarc_reject", "DNS-DMARC-REJECT", "DMARC reject enforcement"),
}


def evaluate_report(report: dict[str, Any], policy_path: str | Path | None = None) -> dict[str, Any]:
    """Evaluate one census without fabricating unavailable or partial state."""
    try:
        policy = _load_policy(policy_path)
    except PolicyError as exc:
        return {
            "schema": "szl.estate-governance-evaluation/v1",
            "policy_status": "UNAVAILABLE",
            "overall_status": "UNKNOWN",
            "certification": "NOT_A_CERTIFICATION",
            "generated_at_from_census": report.get("generated_at"),
            "summary": {"PASS": 0, "FAIL": 0, "UNKNOWN": 1, "NOT_APPLICABLE": 0},
            "controls": [_control("POLICY-LOAD", "UNKNOWN", "The target policy could not be loaded.", {"error": str(exc)[:200]})],
        }

    controls: list[dict[str, Any]] = []
    policy_controls = policy["controls"]
    for specification in policy_controls:
        control_id = specification["id"]
        evaluator = CONTROL_EVALUATORS.get(control_id)
        if evaluator is None:
            result = _control(control_id, "UNKNOWN", "No evaluator is registered for this policy control.", {})
        else:
            try:
                result = evaluator(report, policy)
            except Exception as exc:  # fail closed at the individual control boundary
                result = _control(control_id, "UNKNOWN", "Control evaluation failed closed.", {"error": str(exc)[:200]})
        result["severity"] = specification.get("severity")
        result["frameworks"] = list(specification.get("frameworks") or [])
        controls.append(result)

    summary = {status: sum(1 for result in controls if result["status"] == status) for status in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE")}
    overall = "FAIL" if summary["FAIL"] else "UNKNOWN" if summary["UNKNOWN"] else "PASS"
    return {
        "schema": "szl.estate-governance-evaluation/v1",
        "policy_status": policy.get("status"),
        "policy_version": policy.get("version"),
        "operating_model": policy.get("operating_model"),
        "overall_status": overall,
        "certification": "NOT_A_CERTIFICATION",
        "generated_at_from_census": report.get("generated_at"),
        "summary": summary,
        "controls": controls,
    }
