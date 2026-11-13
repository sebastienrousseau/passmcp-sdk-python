# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Offline verifier for in-toto passmcp MCP evaluation attestations."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://satellion.com/attestation/mcp-evaluation/v1"
SUBJECT_KIND_DESCRIPTOR = "mcp-target-descriptor"
VALID_TRANSPORTS = frozenset({"http", "stdio"})
VALID_STATUSES = frozenset({"pass", "warn", "fail", "skip", "info"})


class AttestationError(ValueError):
    """Raised when an attestation statement fails structural or digest validation."""


class NoSuchCheckError(LookupError):
    """Raised when a statement carries no verdict for the requested check ID."""


@dataclass(frozen=True)
class Subject:
    """in-toto statement subject entry."""

    name: str
    digest: Mapping[str, str]


@dataclass(frozen=True)
class ServerIdentity:
    """Optional server identity recorded during evaluation."""

    name: str = ""
    version: str = ""
    protocol_version: str = ""


@dataclass(frozen=True)
class Target:
    """Evaluated MCP server target descriptor."""

    transport: str
    endpoint: str
    server: ServerIdentity | None = None


@dataclass(frozen=True)
class Basis:
    """Evaluation specification, rubric, and check inventory basis."""

    spec_revision: str = ""
    rubric: str = ""
    check_inventory: str = ""


@dataclass(frozen=True)
class Instrument:
    """Producer tool metadata."""

    name: str
    version: str
    report_schema_version: int = 0


@dataclass(frozen=True)
class Verdict:
    """Single check verdict in an evaluation statement."""

    id: str
    phase: str
    status: str
    severity: str = ""
    evidence: tuple[str, ...] = ()
    doc: str = ""


@dataclass(frozen=True)
class Counts:
    """Tallied verdict counts by status."""

    passed: int = 0
    warn: int = 0
    fail: int = 0
    skip: int = 0
    info: int = 0

    def to_status_map(self) -> dict[str, int]:
        return {
            "pass": self.passed,
            "warn": self.warn,
            "fail": self.fail,
            "skip": self.skip,
            "info": self.info,
        }


@dataclass(frozen=True)
class Score:
    """Rubric-backed numeric score and letter grade."""

    total: float
    grade: str
    categories_assessed: int = 0
    categories_total: int = 0


@dataclass(frozen=True)
class Evaluation:
    """Decoded mcp-evaluation/v1 predicate."""

    subject_kind: str
    target: Target
    judged_against: Basis
    instrument: Instrument
    ran_at: str
    took: str
    verdicts: tuple[Verdict, ...]
    counts: Counts
    score: Score | None = None
    blocked: str = ""
    trace_id: str = ""


@dataclass(frozen=True)
class Statement:
    """Verified in-toto Statement/v1 carrying an mcp-evaluation/v1 predicate."""

    type: str
    subject: tuple[Subject, ...]
    predicate_type: str
    predicate: Evaluation

    @property
    def score_total(self) -> float | None:
        return self.predicate.score.total if self.predicate.score is not None else None

    @property
    def score_grade(self) -> str | None:
        return self.predicate.score.grade if self.predicate.score is not None else None

    def covers(self, transport: str, endpoint: str) -> bool:
        """Report whether the subject digest covers the given transport and endpoint."""
        if len(self.subject) != 1:
            return False
        descriptor = target_descriptor(transport, endpoint)
        found, mismatch = _check_digest_set(self.subject[0].digest, descriptor)
        return found and mismatch == ""

    def verdict_for(self, check_id: str) -> Verdict:
        """Return the first verdict recorded for check_id or raise NoSuchCheckError."""
        for verdict in self.predicate.verdicts:
            if verdict.id == check_id:
                return verdict
        raise NoSuchCheckError(
            f"attestation: the statement carries no verdict for that check: {check_id}"
        )


def target_descriptor(transport: str, endpoint: str) -> bytes:
    """Compute the canonical UTF-8 target descriptor bytes."""
    return f"{transport}\n{endpoint.strip()}".encode()


def subject_for(transport: str, endpoint: str) -> Subject:
    """Construct a canonical SHA-256 subject entry for (transport, endpoint)."""
    digest = hashlib.sha256(target_descriptor(transport, endpoint)).hexdigest()
    return Subject(name=endpoint, digest={"sha256": digest})


def _check_digest_set(digest_map: Mapping[str, str], descriptor: bytes) -> tuple[bool, str]:
    found = False
    mismatch = ""
    known = (
        ("sha256", hashlib.sha256(descriptor).hexdigest()),
        ("sha512", hashlib.sha512(descriptor).hexdigest()),
    )
    for alg, expected in known:
        if alg not in digest_map:
            continue
        found = True
        if digest_map[alg] != expected and not mismatch:
            mismatch = alg
    return found, mismatch


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AttestationError(f"attestation: {label} must be an object")
    return value


def _str_field(obj: Mapping[str, Any], key: str) -> str:
    val = obj.get(key, "")
    if val is None:
        return ""
    if not isinstance(val, str):
        raise AttestationError(f"attestation: {key} must be a string")
    return val


def _int_field(obj: Mapping[str, Any], key: str) -> int:
    val = obj.get(key, 0)
    if isinstance(val, bool) or not isinstance(val, int):
        raise AttestationError(f"attestation: {key} must be an integer")
    return val


def _is_valid_timestamp(ran_at: str) -> bool:
    trimmed = ran_at.strip()
    if not trimmed:
        return False
    try:
        parsed = datetime.fromisoformat(trimmed)
    except ValueError:
        return False
    return parsed.year > 1


def _parse_subjects(raw_subjects: Any) -> tuple[Subject, ...]:
    if raw_subjects is None:
        return ()
    if not isinstance(raw_subjects, list):
        raise AttestationError("attestation: subject must be an array")
    subjects: list[Subject] = []
    for item in raw_subjects:
        sub = _require_mapping(item, "subject entry")
        name = _str_field(sub, "name")
        raw_digest = sub.get("digest")
        if raw_digest is None:
            digest_map: dict[str, str] = {}
        else:
            mapped = _require_mapping(raw_digest, "subject.digest")
            digest_map = {}
            for k, v in mapped.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    raise AttestationError("attestation: subject.digest entries must be strings")
                digest_map[k] = v
        subjects.append(Subject(name=name, digest=digest_map))
    return tuple(subjects)


def _parse_target(raw_target: Any) -> Target:
    obj = _require_mapping(raw_target if raw_target is not None else {}, "predicate.target")
    raw_srv = obj.get("server")
    server: ServerIdentity | None = None
    if raw_srv is not None:
        srv_map = _require_mapping(raw_srv, "predicate.target.server")
        server = ServerIdentity(
            name=_str_field(srv_map, "name"),
            version=_str_field(srv_map, "version"),
            protocol_version=_str_field(srv_map, "protocolVersion"),
        )
    return Target(
        transport=_str_field(obj, "transport"),
        endpoint=_str_field(obj, "endpoint"),
        server=server,
    )


def _parse_verdicts(raw_verdicts: Any) -> tuple[Verdict, ...]:
    if raw_verdicts is None:
        return ()
    if not isinstance(raw_verdicts, list):
        raise AttestationError("attestation: predicate.verdicts must be an array")
    out: list[Verdict] = []
    for entry in raw_verdicts:
        item = _require_mapping(entry, "verdict")
        raw_ev = item.get("evidence")
        evidence: tuple[str, ...] = ()
        if raw_ev is not None:
            if not isinstance(raw_ev, list) or not all(isinstance(x, str) for x in raw_ev):
                raise AttestationError("attestation: verdict.evidence must be a string array")
            evidence = tuple(raw_ev)
        out.append(
            Verdict(
                id=_str_field(item, "id"),
                phase=_str_field(item, "phase"),
                status=_str_field(item, "status"),
                severity=_str_field(item, "severity"),
                evidence=evidence,
                doc=_str_field(item, "doc"),
            )
        )
    return tuple(out)


def _parse_score(raw_score: Any) -> Score | None:
    if raw_score is None:
        return None
    obj = _require_mapping(raw_score, "predicate.score")
    total = obj.get("total", 0)
    if isinstance(total, bool) or not isinstance(total, (int, float)):
        raise AttestationError("attestation: score.total must be numeric")
    return Score(
        total=float(total),
        grade=_str_field(obj, "grade"),
        categories_assessed=_int_field(obj, "categoriesAssessed"),
        categories_total=_int_field(obj, "categoriesTotal"),
    )


def _parse_evaluation(raw_pred: Any) -> Evaluation:
    pred = _require_mapping(raw_pred if raw_pred is not None else {}, "predicate")
    basis_map = _require_mapping(pred.get("judgedAgainst") or {}, "predicate.judgedAgainst")
    inst_map = _require_mapping(pred.get("instrument") or {}, "predicate.instrument")
    counts_map = _require_mapping(pred.get("counts") or {}, "predicate.counts")
    return Evaluation(
        subject_kind=_str_field(pred, "subjectKind"),
        target=_parse_target(pred.get("target")),
        judged_against=Basis(
            spec_revision=_str_field(basis_map, "specRevision"),
            rubric=_str_field(basis_map, "rubric"),
            check_inventory=_str_field(basis_map, "checkInventory"),
        ),
        instrument=Instrument(
            name=_str_field(inst_map, "name"),
            version=_str_field(inst_map, "version"),
            report_schema_version=_int_field(inst_map, "reportSchemaVersion"),
        ),
        ran_at=_str_field(pred, "ranAt"),
        took=_str_field(pred, "took"),
        verdicts=_parse_verdicts(pred.get("verdicts")),
        counts=Counts(
            passed=_int_field(counts_map, "pass"),
            warn=_int_field(counts_map, "warn"),
            fail=_int_field(counts_map, "fail"),
            skip=_int_field(counts_map, "skip"),
            info=_int_field(counts_map, "info"),
        ),
        score=_parse_score(pred.get("score")),
        blocked=_str_field(pred, "blocked"),
        trace_id=_str_field(pred, "traceId"),
    )


def _validate_subject(subjects: tuple[Subject, ...], target: Target, problems: list[str]) -> None:
    if len(subjects) == 0:
        problems.append("no subject: the statement is about nothing")
        return
    if len(subjects) > 1:
        problems.append(f"{len(subjects)} subjects: a passmcp evaluation is about one server")
        return
    sub = subjects[0]
    want = target.endpoint.strip()
    if not sub.name.strip():
        problems.append("the subject has no name")
    elif sub.name.strip() != want:
        problems.append(f'the subject is named "{sub.name}" but the predicate is about "{want}"')
    found, mismatch = _check_digest_set(
        sub.digest, target_descriptor(target.transport, target.endpoint)
    )
    if not found:
        problems.append("the subject has no sha256 or sha512 digest")
    elif mismatch:
        problems.append(f"the subject {mismatch} digest does not cover the target it names")


def _validate_predicate_fields(pred: Evaluation, problems: list[str]) -> None:
    if pred.subject_kind != SUBJECT_KIND_DESCRIPTOR:
        problems.append(
            f'subjectKind is "{pred.subject_kind}", want "{SUBJECT_KIND_DESCRIPTOR}"'
        )
    if not pred.target.endpoint.strip():
        problems.append("the target has no endpoint")
    if pred.target.transport == "":
        problems.append("the target has no transport")
    elif pred.target.transport not in VALID_TRANSPORTS:
        problems.append(f'unknown transport "{pred.target.transport}"')
    if not pred.instrument.name.strip() or not pred.instrument.version.strip():
        problems.append("the instrument is not identified")
    if not _is_valid_timestamp(pred.ran_at):
        problems.append("no run time: a verdict about a live service is a verdict about a moment")
    if len(pred.verdicts) == 0:
        problems.append("no verdicts")
    if not pred.judged_against.check_inventory.strip():
        problems.append("judgedAgainst.checkInventory is empty")
    if pred.score is not None and not pred.judged_against.rubric.strip():
        problems.append("a score with no rubric version")


def _validate_verdicts(pred: Evaluation, problems: list[str]) -> None:
    tallied = {"pass": 0, "warn": 0, "fail": 0, "skip": 0, "info": 0}
    for idx, verdict in enumerate(pred.verdicts):
        if not verdict.id.strip():
            problems.append(f"verdict {idx} has no id")
            continue
        if verdict.status not in VALID_STATUSES:
            problems.append(f'verdict {verdict.id} has status "{verdict.status}"')
        else:
            tallied[verdict.status] += 1
    if pred.verdicts and tallied != pred.counts.to_status_map():
        problems.append("the counts disagree with the verdicts")


def parse_statement(raw: bytes | str) -> Statement:
    """Parse and strictly validate an in-toto passmcp evaluation statement offline."""
    try:
        text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
    except UnicodeDecodeError as exc:
        raise AttestationError(f"attestation: not a statement: {exc}") from exc
    if not isinstance(text, str):
        raise AttestationError("attestation: input must be bytes or str")
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AttestationError(f"attestation: not a statement: {exc}") from exc
    root = _require_mapping(decoded, "not a statement: root")
    stmt = Statement(
        type=_str_field(root, "_type"),
        subject=_parse_subjects(root.get("subject")),
        predicate_type=_str_field(root, "predicateType"),
        predicate=_parse_evaluation(root.get("predicate")),
    )
    problems: list[str] = []
    if stmt.type != STATEMENT_TYPE:
        problems.append(f'_type is "{stmt.type}", want "{STATEMENT_TYPE}"')
    if stmt.predicate_type != PREDICATE_TYPE:
        problems.append(f'predicateType is "{stmt.predicate_type}", want "{PREDICATE_TYPE}"')
    _validate_subject(stmt.subject, stmt.predicate.target, problems)
    _validate_predicate_fields(stmt.predicate, problems)
    _validate_verdicts(stmt.predicate, problems)
    if problems:
        raise AttestationError("attestation: " + "; ".join(problems))
    return stmt
