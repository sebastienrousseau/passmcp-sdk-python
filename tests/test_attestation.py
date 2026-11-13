# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Tests for offline passmcp in-toto attestation statement verification."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from passmcp_sdk import (
    AttestationError,
    NoSuchCheckError,
    parse_statement,
    subject_for,
    target_descriptor,
)

FIXTURE_PATH = Path(__file__).resolve().parent.parent / "testdata" / "statement.json"


def _load_fixture_dict() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_parse_statement_fixture_succeeds() -> None:
    st = parse_statement(FIXTURE_PATH.read_bytes())
    assert st.score_total == 88.0
    assert st.score_grade == "B"
    assert st.covers("http", "https://mcp.example.com/mcp")
    assert st.covers("http", "  https://mcp.example.com/mcp  ")
    assert not st.covers("stdio", "https://mcp.example.com/mcp")
    assert not st.covers("http", "https://other.example.com/mcp")

    verdict = st.verdict_for("protocol.origin")
    assert verdict.status == "fail"
    assert verdict.severity == "major"
    assert verdict.evidence == ("req#12",)

    with pytest.raises(NoSuchCheckError):
        st.verdict_for("never.measured")


@pytest.mark.parametrize(
    ("expected_fragment", "mutate"),
    [
        ("_type is", lambda d: d.__setitem__("_type", "x")),
        ("predicateType is", lambda d: d.__setitem__("predicateType", "x")),
        ("no subject", lambda d: d.__setitem__("subject", [])),
        ("2 subjects", lambda d: d["subject"].append(copy.deepcopy(d["subject"][0]))),
        ("subject has no name", lambda d: d["subject"][0].__setitem__("name", "  ")),
        (
            "subject is named",
            lambda d: d["subject"][0].__setitem__("name", "https://trusted.example.com/mcp"),
        ),
        ("no sha256 or sha512 digest", lambda d: d["subject"][0].__setitem__("digest", {})),
        (
            "sha256 digest does not cover",
            lambda d: d["subject"][0]["digest"].__setitem__("sha256", "0" * 64),
        ),
        (
            "subjectKind is",
            lambda d: d["predicate"].__setitem__("subjectKind", "artifact"),
        ),
        ("no endpoint", lambda d: d["predicate"]["target"].__setitem__("endpoint", " ")),
        ("no transport", lambda d: d["predicate"]["target"].__setitem__("transport", "")),
        (
            "unknown transport",
            lambda d: d["predicate"]["target"].__setitem__("transport", "pigeon"),
        ),
        (
            "not identified",
            lambda d: d["predicate"]["instrument"].__setitem__("version", ""),
        ),
        ("no run time", lambda d: d["predicate"].__setitem__("ranAt", "")),
        (
            "no run time",
            lambda d: d["predicate"].__setitem__("ranAt", "0001-01-01T00:00:00Z"),
        ),
        (
            "no verdicts",
            lambda d: (
                d["predicate"].__setitem__("verdicts", []),
                d["predicate"].__setitem__(
                    "counts", {"pass": 0, "warn": 0, "fail": 0, "skip": 0, "info": 0}
                ),
            ),
        ),
        (
            "checkInventory is empty",
            lambda d: d["predicate"]["judgedAgainst"].__setitem__("checkInventory", ""),
        ),
        (
            "no rubric version",
            lambda d: d["predicate"]["judgedAgainst"].__setitem__("rubric", ""),
        ),
        ("has no id", lambda d: d["predicate"]["verdicts"][0].__setitem__("id", "")),
        (
            "has status",
            lambda d: d["predicate"]["verdicts"][0].__setitem__("status", "maybe"),
        ),
        ("counts disagree", lambda d: d["predicate"]["counts"].__setitem__("pass", 7)),
    ],
)
def test_tampered_statement_rejected(
    expected_fragment: str, mutate: Callable[[dict[str, Any]], Any]
) -> None:
    doc = _load_fixture_dict()
    mutate(doc)
    with pytest.raises(AttestationError, match=expected_fragment):
        parse_statement(json.dumps(doc))


def test_sha512_and_multi_digest_verification() -> None:
    doc = _load_fixture_dict()
    desc = target_descriptor("http", "https://mcp.example.com/mcp")
    good256 = hashlib.sha256(desc).hexdigest()
    good512 = hashlib.sha512(desc).hexdigest()

    # SHA-512 alone succeeds.
    doc["subject"][0]["digest"] = {"sha512": good512}
    st = parse_statement(json.dumps(doc))
    assert st.covers("http", "https://mcp.example.com/mcp")

    # Both SHA-256 and SHA-512 plus unknown md5 succeed.
    doc["subject"][0]["digest"] = {"sha256": good256, "sha512": good512, "md5": "ignored"}
    st_both = parse_statement(json.dumps(doc))
    assert st_both.covers("http", "https://mcp.example.com/mcp")

    # Good SHA-256 beside wrong SHA-512 is refused.
    doc["subject"][0]["digest"] = {"sha256": good256, "sha512": "0" * 128}
    with pytest.raises(AttestationError, match="sha512 digest does not cover"):
        parse_statement(json.dumps(doc))

    # Uppercase hex digest is refused.
    doc["subject"][0]["digest"] = {"sha256": good256.upper()}
    with pytest.raises(AttestationError, match="sha256 digest does not cover"):
        parse_statement(json.dumps(doc))

    # Unknown digest algorithm alone is refused.
    doc["subject"][0]["digest"] = {"md5": "d41d8cd98f00b204e9800998ecf8427e"}
    with pytest.raises(AttestationError, match="no sha256 or sha512 digest"):
        parse_statement(json.dumps(doc))


def test_scoreless_statement_and_all_verdict_buckets() -> None:
    doc = _load_fixture_dict()
    doc["predicate"].pop("score", None)
    doc["predicate"]["judgedAgainst"]["rubric"] = ""
    doc["predicate"]["verdicts"] = [
        {"id": "c1", "phase": "p", "status": "pass"},
        {"id": "c2", "phase": "p", "status": "warn"},
        {"id": "c3", "phase": "p", "status": "fail"},
        {"id": "c4", "phase": "p", "status": "skip"},
        {"id": "c5", "phase": "p", "status": "info"},
    ]
    doc["predicate"]["counts"] = {"pass": 1, "warn": 1, "fail": 1, "skip": 1, "info": 1}
    st = parse_statement(json.dumps(doc))
    assert st.score_total is None
    assert st.score_grade is None


def test_malformed_json_and_subject_for() -> None:
    with pytest.raises(AttestationError, match="not a statement"):
        parse_statement(b"{not valid json")
    with pytest.raises(AttestationError, match="not a statement"):
        parse_statement(b"\xff\xfe")
    sub = subject_for("http", "https://mcp.example.com/mcp")
    assert sub.digest["sha256"] == (
        "a386a033799c95c21f3d01b2f0efcf71b95b1ef2a420908ce34e3c1eb41a2325"
    )
