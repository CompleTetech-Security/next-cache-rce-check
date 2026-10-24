# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Vendoring-friendly checker contract, validation and offline reports. Python 3.10+."""
from __future__ import annotations

import csv
import base64
import hashlib
import html
import io
import json
import math
import os
import re
import stat
import tempfile
from copy import deepcopy
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

CONTRACT_VERSION = "1.0"
COMMON_VERSION = "0.1.0"
MAX_JSON_BYTES = 4 * 1024 * 1024
STATUSES = (
    "potentially_affected", "precondition_present", "likely_exposed",
    "mitigated_configuration", "fixed_version_reported", "unsupported_runtime", "unknown",
)
VERSION_STATES = ("affected", "fixed_reported", "not_affected", "unsupported", "unknown")
EVIDENCE_STATES = ("present", "absent", "unknown", "conflicting", "candidate")
CONDITION_STATES = ("present", "absent", "unknown", "conflicting")
FINDING_STATUSES = frozenset({"potentially_affected", "precondition_present", "likely_exposed", "unsupported_runtime"})


class ContractError(ValueError):
    """Invalid, ambiguous or inconsistent canonical data. Messages omit values."""


def _text(max_length=2048, *, min_length=0):
    return {"type": "string", "minLength": min_length, "maxLength": max_length,
            "pattern": r"^[^\x00-\x1f\x7f-\x9f]*(?![\s\S])"}


def _enum(values):
    return {"type": "string", "enum": list(values)}


def _object(properties, required=None):
    return {"type": "object", "properties": properties,
            "required": list(properties if required is None else required), "additionalProperties": False}


def _array(items, maximum=1000, minimum=0):
    return {"type": "array", "items": items, "minItems": minimum, "maxItems": maximum}


ID_SCHEMA = {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])", "maxLength": 128}
DATE_SCHEMA = {"type": "string", "format": "date"}
URL_SCHEMA = {"type": "string", "format": "uri", "maxLength": 2048}
NULLABLE_DATE = {"anyOf": [DATE_SCHEMA, {"type": "null"}]}
NULLABLE_URL = {"anyOf": [URL_SCHEMA, {"type": "null"}]}
VERSION_SCHEMA = {"anyOf": [_text(128, min_length=1), {"type": "null"}]}
EVIDENCE_SCHEMA = _object({
    "id": ID_SCHEMA,
    "kind": _enum(("version", "configuration", "source", "reachability", "mitigation", "inventory")),
    "state": _enum(EVIDENCE_STATES), "detail": _text(2048),
    "path": {"type": "string", "format": "relative-path", "maxLength": 512},
    "line": {"type": "integer", "minimum": 1, "maximum": 100000000},
}, required=("id", "kind", "state", "detail"))
CONDITION_SCHEMA = _object({"id": ID_SCHEMA, "state": _enum(CONDITION_STATES),
                            "evidence_ids": _array(ID_SCHEMA, 100)})
MITIGATION_SCHEMA = _object({"state": _enum(("observed", "not_observed", "unknown", "conflicting")),
                             "evidence_ids": _array(ID_SCHEMA, 100)})
REACHABILITY_SCHEMA = _object({
    "state": _enum(("not_tested", "metadata_observed", "unknown")),
    "evidence_ids": _array(ID_SCHEMA, 100), "authorized": {"type": "boolean"},
    "asset_id": ID_SCHEMA, "component": _text(128, min_length=1),
})


def _threat_schema(states):
    return _object({"state": _enum(states), "as_of": NULLABLE_DATE, "source": NULLABLE_URL})


THREAT_SCHEMA = _object({
    "kev": _threat_schema(("listed", "not_listed", "unknown")),
    "vendor_exploitation": _threat_schema(("reported", "not_reported", "unknown")),
})
RESULT_SCHEMA = _object({
    "asset_id": ID_SCHEMA,
    "component": _object({"name": _text(128, min_length=1), "version": VERSION_SCHEMA,
                          "build_source": _enum(("upstream", "vendor", "custom", "unknown"))}),
    "rule_id": ID_SCHEMA, "status": _enum(STATUSES),
    "version_assessment": _enum(VERSION_STATES),
    "confidence": _enum(("low", "medium", "high", "unknown")),
    "evidence": _array(EVIDENCE_SCHEMA, 1000), "preconditions": _array(CONDITION_SCHEMA, 100),
    "mitigation": MITIGATION_SCHEMA, "reachability": REACHABILITY_SCHEMA,
    "threat": THREAT_SCHEMA, "exploitability": {"const": "not_tested"},
    "reasons": _array(_text(2048), 100), "recommendation": _text(4096),
    "sources": _array(URL_SCHEMA, 100),
})
REPORT_SCHEMA = _object({
    "schema_version": {"const": CONTRACT_VERSION},
    "tool": _object({"name": ID_SCHEMA, "version": _text(64, min_length=1)}),
    "rules": _object({
        "snapshot_id": ID_SCHEMA, "verified_at": DATE_SCHEMA,
        "sha256": {"anyOf": [{"type": "string", "pattern": r"^[a-f0-9]{64}(?![\s\S])"}, {"type": "null"}]},
    }),
    "complete": {"type": "boolean"},
    "limitations": _array(_text(2048), 1000), "results": _array(RESULT_SCHEMA, 10000),
})
SOURCE_SCHEMA = _object({"id": ID_SCHEMA, "url": URL_SCHEMA, "publisher": _text(128, min_length=1),
                         "verified_at": DATE_SCHEMA})
CLAIM_SCHEMA = _object({"id": ID_SCHEMA, "description": _text(4096, min_length=1),
                        "source_ids": _array(ID_SCHEMA, 100, 1)})
BRANCH_SCHEMA = _object({
    "branch": _text(64, min_length=1), "introduced": VERSION_SCHEMA,
    "fixed": VERSION_SCHEMA, "last_affected": VERSION_SCHEMA,
    "source_ids": _array(ID_SCHEMA, 100, 1),
})
RULE_SCHEMA = _object({
    "id": ID_SCHEMA, "revision": {"type": "integer", "minimum": 1},
    "title": _text(256, min_length=1), "component": _text(128, min_length=1),
    "advisories": _array(ID_SCHEMA, 100), "enabled": {"type": "boolean"},
    "verification_status": _enum(("verified", "unverified", "disputed")),
    "verified_at": NULLABLE_DATE, "version_scheme": _enum(("semver", "vendor")),
    "affected": _array(BRANCH_SCHEMA, 100), "preconditions": _array(CLAIM_SCHEMA, 100),
    "mitigations": _array(CLAIM_SCHEMA, 100), "sources": _array(SOURCE_SCHEMA, 100),
    "notes": _array(_text(4096), 100),
})
SNAPSHOT_SCHEMA = _object({
    "schema_version": {"const": CONTRACT_VERSION}, "snapshot_id": ID_SCHEMA,
    "created_at": DATE_SCHEMA, "rules": _array(RULE_SCHEMA, 1000),
})
INVENTORY_SCHEMA = _object({
    "schema_version": {"const": CONTRACT_VERSION},
    "records": _array(_object({
        "asset_id": ID_SCHEMA, "component": _text(128, min_length=1), "version": VERSION_SCHEMA,
        "build_source": _enum(("upstream", "vendor", "custom", "unknown")),
        "evidence": _array(EVIDENCE_SCHEMA, 1000),
    }), 10000, 1),
})


def _check_format(value, fmt, path):
    if fmt == "date":
        try:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                raise ValueError
            date.fromisoformat(value)
        except ValueError:
            raise ContractError(f"{path}: invalid ISO date") from None
    elif fmt == "uri":
        try:
            parsed = urlsplit(value)
            valid = (parsed.scheme == "https" and parsed.hostname and parsed.username is None
                     and parsed.password is None and not parsed.query and not parsed.fragment
                     and not any(ord(c) <= 32 or ord(c) >= 127 for c in value) and "\\" not in value)
            _ = parsed.port
        except ValueError:
            valid = False
        if not valid:
            raise ContractError(f"{path}: expected credential-free HTTPS source URL without query or fragment")
    elif fmt == "relative-path":
        pieces = value.split("/")
        if (not value or value.startswith("/") or "\\" in value or ":" in value
                or any(part in {"", ".", ".."} for part in pieces)
                or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)):
            raise ContractError(f"{path}: expected normalized relative path")


def validate_schema(value, schema, path="$", depth=0):
    """Validate this repository's bounded schema vocabulary; never resolve references."""
    if depth > 40:
        raise ContractError(f"{path}: nesting limit exceeded")
    if "anyOf" in schema:
        for alternative in schema["anyOf"]:
            try:
                validate_schema(value, alternative, path, depth + 1)
                return
            except ContractError:
                pass
        raise ContractError(f"{path}: no permitted type or value matched")
    if "const" in schema and (type(value) is not type(schema["const"]) or value != schema["const"]):
        raise ContractError(f"{path}: invalid constant")
    typ = schema.get("type")
    types = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool, "null": type(None)}
    if typ and type(value) is not types[typ]:
        raise ContractError(f"{path}: expected {typ}")
    if "enum" in schema and value not in schema["enum"]:
        raise ContractError(f"{path}: unsupported value")
    if typ == "object":
        properties = schema["properties"]
        if set(value) - set(properties):
            raise ContractError(f"{path}: unexpected field")
        if set(schema["required"]) - set(value):
            raise ContractError(f"{path}: missing required field")
        for key, item in value.items():
            validate_schema(item, properties[key], f"{path}.{key}", depth + 1)
    elif typ == "array":
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", 10000):
            raise ContractError(f"{path}: item count outside bounds")
        for index, item in enumerate(value):
            validate_schema(item, schema["items"], f"{path}[{index}]", depth + 1)
    elif typ == "string":
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 4096):
            raise ContractError(f"{path}: string length outside bounds")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise ContractError(f"{path}: invalid string")
        if "format" in schema:
            _check_format(value, schema["format"], path)
    elif typ == "integer":
        if not schema.get("minimum", -2**63) <= value <= schema.get("maximum", 2**63-1):
            raise ContractError(f"{path}: integer outside bounds")


def _evidence_map(evidence):
    by_id = {item["id"]: item for item in evidence}
    if len(by_id) != len(evidence):
        raise ContractError("duplicate evidence identifier")
    for item in evidence:
        if "line" in item and "path" not in item:
            raise ContractError("source line requires a relative path")
    return by_id


def _references(ids, evidence):
    if len(set(ids)) != len(ids) or any(key not in evidence for key in ids):
        raise ContractError("unknown or duplicate evidence reference")
    return [evidence[key] for key in ids]


def validate_result(result):
    validate_schema(result, RESULT_SCHEMA)
    evidence = _evidence_map(result["evidence"])
    conditions = result["preconditions"]
    if len({item["id"] for item in conditions}) != len(conditions):
        raise ContractError("duplicate precondition identifier")
    for condition in conditions:
        refs = _references(condition["evidence_ids"], evidence)
        if condition["state"] in {"present", "absent"}:
            if not refs or not all(item["state"] == condition["state"] for item in refs):
                raise ContractError("established precondition requires matching observed evidence")
    mitigation = result["mitigation"]
    mrefs = _references(mitigation["evidence_ids"], evidence)
    if mitigation["state"] == "observed" and (not mrefs or not all(item["state"] == "present" for item in mrefs)):
        raise ContractError("observed mitigation requires observed evidence")
    reachability = result["reachability"]
    rrefs = _references(reachability["evidence_ids"], evidence)
    if reachability["asset_id"] != result["asset_id"] or reachability["component"] != result["component"]["name"]:
        raise ContractError("reachability belongs to a different asset or component")
    if reachability["state"] == "metadata_observed":
        if not reachability["authorized"] or not rrefs or not all(item["kind"] == "reachability" and item["state"] == "present" for item in rrefs):
            raise ContractError("reachability requires explicit authorization and matching metadata evidence")
    for threat in result["threat"].values():
        if threat["state"] != "unknown" and (threat["as_of"] is None or threat["source"] is None):
            raise ContractError("external threat assertion requires dated source")
    status = result["status"]
    version_state = result["version_assessment"]
    version_evidence = [item for item in evidence.values() if item["kind"] == "version"]
    if version_state in {"affected", "fixed_reported", "not_affected", "unsupported"}:
        if (result["component"]["version"] is None or not version_evidence
                or not all(item["state"] == "present" for item in version_evidence)):
            raise ContractError("version assessment requires exact, consistent version evidence")
    if status != "unknown" and not result["sources"]:
        raise ContractError("assessment requires primary source references")
    expected = {"fixed_version_reported": "fixed_reported", "unsupported_runtime": "unsupported",
                "potentially_affected": "affected", "precondition_present": "affected",
                "likely_exposed": "affected", "mitigated_configuration": "affected"}
    if status in expected and version_state != expected[status]:
        raise ContractError("status contradicts version assessment")
    if status == "fixed_version_reported" and result["component"]["build_source"] in {"vendor", "custom"}:
        raise ContractError("vendor or custom build cannot be cleared by upstream version")
    if status in {"precondition_present", "likely_exposed"}:
        if not conditions or not all(item["state"] == "present" for item in conditions):
            raise ContractError("status requires all declared preconditions to be established")
    if status == "likely_exposed" and reachability["state"] != "metadata_observed":
        raise ContractError("likely_exposed requires authorized same-component reachability evidence")
    if status == "mitigated_configuration" and mitigation["state"] != "observed":
        raise ContractError("mitigated_configuration requires an observed mitigation")
    return result


def validate_report(report):
    validate_schema(report, REPORT_SCHEMA)
    for result in report["results"]:
        validate_result(result)
    return report


def make_result(asset_id, component, rule_id, status="unknown", *, version=None,
                build_source="unknown", version_assessment="unknown", evidence=None,
                preconditions=None, mitigation=None, reachability=None, threat=None,
                reasons=None, recommendation="", sources=None, confidence="unknown"):
    result = {
        "asset_id": asset_id, "component": {"name": component, "version": version, "build_source": build_source},
        "rule_id": rule_id, "status": status, "version_assessment": version_assessment, "confidence": confidence,
        "evidence": deepcopy(evidence or []), "preconditions": deepcopy(preconditions or []),
        "mitigation": deepcopy(mitigation or {"state": "unknown", "evidence_ids": []}),
        "reachability": deepcopy(reachability or {"state": "not_tested", "evidence_ids": [],
                                                 "authorized": False, "asset_id": asset_id, "component": component}),
        "threat": deepcopy(threat or {
            "kev": {"state": "unknown", "as_of": None, "source": None},
            "vendor_exploitation": {"state": "unknown", "as_of": None, "source": None},
        }),
        "exploitability": "not_tested", "reasons": deepcopy(reasons or []),
        "recommendation": recommendation, "sources": deepcopy(sources or []),
    }
    return validate_result(result)


def make_report(tool, tool_version, snapshot_id, rules_as_of, results, *, complete=True,
                limitations=None, snapshot_digest=None):
    report = {"schema_version": CONTRACT_VERSION, "tool": {"name": tool, "version": tool_version},
              "rules": {"snapshot_id": snapshot_id, "verified_at": rules_as_of, "sha256": snapshot_digest},
              "complete": complete, "limitations": deepcopy(limitations or []), "results": deepcopy(results)}
    return validate_report(report)


def validate_rule(rule):
    validate_schema(rule, RULE_SCHEMA)
    source_ids = {source["id"] for source in rule["sources"]}
    if len(source_ids) != len(rule["sources"]):
        raise ContractError("duplicate rule source identifier")
    for entry in rule["affected"] + rule["preconditions"] + rule["mitigations"]:
        if len(set(entry["source_ids"])) != len(entry["source_ids"]) or not set(entry["source_ids"]) <= source_ids:
            raise ContractError("rule contains unresolved source reference")
    if rule["enabled"]:
        if rule["verification_status"] != "verified" or not rule["verified_at"] or not source_ids or not rule["affected"]:
            raise ContractError("enabled rules require verified primary-source version boundaries")
        if any(branch["introduced"] is None and branch["fixed"] is None and branch["last_affected"] is None for branch in rule["affected"]):
            raise ContractError("enabled rule branch has no version boundary")
        if any(source["verified_at"] > rule["verified_at"] for source in rule["sources"]):
            raise ContractError("rule verification predates source verification")
    return rule


def validate_snapshot(snapshot):
    validate_schema(snapshot, SNAPSHOT_SCHEMA)
    if len({rule["id"] for rule in snapshot["rules"]}) != len(snapshot["rules"]):
        raise ContractError("duplicate rule identifier")
    for rule in snapshot["rules"]:
        validate_rule(rule)
        if rule["verified_at"] and rule["verified_at"] > snapshot["created_at"]:
            raise ContractError("snapshot predates rule verification")
    return snapshot


def validate_inventory(inventory):
    validate_schema(inventory, INVENTORY_SCHEMA)
    for record in inventory["records"]:
        _evidence_map(record["evidence"])
    return inventory


def _json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def snapshot_digest(snapshot):
    """Integrity identifier for canonical snapshot bytes; not a signature."""
    validate_snapshot(snapshot)
    return hashlib.sha256(_json_bytes(snapshot)).hexdigest()


def canonical_json(report):
    validate_report(report)
    return _json_bytes(report).decode("utf-8")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate JSON object key")
        result[key] = value
    return result


def _read_regular_file(path, max_bytes):
    """Read one bounded regular file without following symlinks or blocking on FIFOs."""
    if type(max_bytes) is not int or not 0 < max_bytes <= 64 * 1024 * 1024:
        raise ContractError("invalid byte bound")
    fd = None
    try:
        before = Path(path).lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ContractError("input must be a regular file, not a link or special file")
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ContractError("input identity changed while opening")
        if opened.st_size > max_bytes:
            raise ContractError("input byte limit exceeded")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(max_bytes + 1)
    except OSError:
        raise ContractError("input could not be read") from None
    finally:
        if fd is not None:
            os.close(fd)
    if len(raw) > max_bytes:
        raise ContractError("input byte limit exceeded")
    return raw


def load_json(path, max_bytes=MAX_JSON_BYTES):
    """Read bounded JSON; error messages deliberately omit paths and raw input."""
    raw = _read_regular_file(path, max_bytes)
    try:
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ContractError("non-finite JSON number")))
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError("invalid JSON encoding, syntax or nesting") from None
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > 200000 or depth > 40:
            raise ContractError("JSON structure limit exceeded")
        if isinstance(item, float) and not math.isfinite(item):
            raise ContractError("non-finite JSON number")
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
    return value


def _csv_safe(value):
    value = str(value)
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value


def render_csv(report):
    validate_report(report)
    output = io.StringIO(newline="")
    fields = ("record_type", "asset_id", "component", "version", "rule_id", "status", "version_assessment", "confidence",
              "exploitability", "complete", "rules_as_of", "evidence", "preconditions", "mitigation",
              "reachability", "threat", "reasons", "recommendation", "sources", "limitations")
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for result in report["results"]:
        row = {key: result[key] for key in fields if key in result}
        row.update(record_type="result", component=result["component"]["name"], version=result["component"]["version"] or "",
                   complete=report["complete"], rules_as_of=report["rules"]["verified_at"], limitations=report["limitations"])
        writer.writerow({key: _csv_safe(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                                       if isinstance(value, (dict, list)) else value) for key, value in row.items()})
    if not report["results"]:
        writer.writerow({"record_type": "summary", "complete": report["complete"],
                         "rules_as_of": report["rules"]["verified_at"], "exploitability": "not_tested",
                         "limitations": json.dumps(report["limitations"], ensure_ascii=False, sort_keys=True, separators=(",", ":"))})
    return output.getvalue()


def _logo_uri(path):
    if path is None:
        return ""
    data = _read_regular_file(path, 1024 * 1024)
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        mime = "image/png"
    elif data.startswith(b"\xff\xd8\xff"):
        mime = "image/jpeg"
    elif data.startswith((b"GIF87a", b"GIF89a")):
        mime = "image/gif"
    elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        mime = "image/webp"
    else:
        raise ContractError("logo must be a bounded PNG, JPEG, GIF or WebP raster file")
    return "data:" + mime + ";base64," + base64.b64encode(data).decode("ascii")


def render_html(report, brand="CompleteTech LLC", logo=None):
    validate_report(report)
    esc = lambda value: html.escape(str(value), quote=True)
    logo_data = _logo_uri(logo)
    logo_html = '<img class="logo" src="' + logo_data + '" alt="' + esc(brand) + ' logo">' if logo_data else ""
    rows = []
    for result in report["results"]:
        evidence = "".join("<li>" + esc(item["kind"] + ": " + item["state"] + " — " + item["detail"])
                           + (" <code>" + esc(item["path"]) + (":" + str(item["line"]) if "line" in item else "") + "</code>" if "path" in item else "")
                           + "</li>" for item in result["evidence"])
        reasons = "".join("<li>" + esc(reason) + "</li>" for reason in result["reasons"])
        sources = " ".join('<a href="' + esc(url) + '">Source</a>' for url in result["sources"])
        dimensions = {key: result[key] for key in ("version_assessment", "confidence", "preconditions", "mitigation", "reachability", "threat")}
        rows.append("<article><h2>" + esc(result["asset_id"]) + " · " + esc(result["component"]["name"])
                    + "</h2><p class='status'>" + esc(result["status"]) + "</p><p>Reported version: <code>"
                    + esc(result["component"]["version"] or "unknown") + "</code> · Rule: <code>" + esc(result["rule_id"])
                    + "</code> · Exploitability: <code>not_tested</code></p><p>" + esc(result["recommendation"])
                    + "</p><ul>" + reasons + "</ul><details><summary>Evidence and assessment dimensions</summary><ul>"
                    + evidence + "</ul><pre>" + esc(json.dumps(dimensions, ensure_ascii=False, indent=2, sort_keys=True))
                    + "</pre></details><p>" + sources + "</p></article>")
    limitations = "".join("<li>" + esc(item) + "</li>" for item in report["limitations"])
    counts = " · ".join(esc(status) + ": " + str(sum(r["status"] == status for r in report["results"]))
                        for status in STATUSES if any(r["status"] == status for r in report["results"]))
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Security evidence report</title><style>
:root{color-scheme:light dark;--bg:#f8fafc;--surface:#fff;--ink:#172033;--muted:#526077;--accent:#1e3a8a;--line:#d8dee9}
@media(prefers-color-scheme:dark){:root{--bg:#0f172a;--surface:#1e293b;--ink:#f1f5f9;--muted:#a8bad2;--accent:#93c5fd;--line:#3c4b61}}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,sans-serif}main{max-width:1000px;margin:auto;padding:32px 20px}
header{border-bottom:4px solid var(--accent);padding-bottom:20px}.logo{height:64px;max-width:240px;object-fit:contain;float:right;background:#f8fafc;padding:6px;border-radius:8px}h1{margin:.2em 0}h2{font-size:1.2rem}.eyebrow,.status{color:var(--accent);font-weight:700}
article,.callout{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:18px 22px;margin:20px 0}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.85rem}p,li,code{overflow-wrap:anywhere}a{color:var(--accent)}summary{cursor:pointer}
footer{font-size:.85rem;color:var(--muted)}@media print{body{background:white;color:black}article{break-inside:avoid}details>summary{display:none}details>ul,details>pre{display:block}}
</style></head><body><main><header>""" + logo_html + "<div class='eyebrow'>" + esc(brand) + "</div><h1>Security evidence report</h1><p>" + esc(report["tool"]["name"]) \
        + " " + esc(report["tool"]["version"]) + " · rules verified " + esc(report["rules"]["verified_at"]) \
        + "</p></header><div class='callout'><strong>" + ("Completed assessment" if report["complete"] else "Incomplete assessment") \
        + "</strong><p>Local exploitability is not tested. Version, configuration, candidate source patterns and external exploitation reports are separate evidence.</p><p>" \
        + counts + "</p><ul>" + limitations + "</ul></div>" + "".join(rows) \
        + "<footer>Schema " + CONTRACT_VERSION + " · Snapshot " + esc(report["rules"]["snapshot_id"]) \
        + " · SHA-256 " + esc(report["rules"]["sha256"] or "not supplied") + "</footer></main></body></html>\n"


def save_report(path, text, force=False, protected_paths=()):
    """Atomic publication; never overwrite an input or follow an output symlink."""
    target = Path(path)
    if target.is_symlink():
        raise ContractError("output symlink is not permitted")
    for item in protected_paths:
        source = Path(item)
        if target.resolve() == source.resolve():
            raise ContractError("output must differ from every protected input")
        if target.exists() and source.exists() and os.path.samefile(target, source):
            raise ContractError("output aliases a protected input")
    if not target.parent.is_dir():
        raise ContractError("output directory must exist")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="", dir=target.parent,
                                         prefix=".checker-report-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        if force:
            os.replace(temporary, target)
        else:
            os.link(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
