"""Summarises the raw rows of M1, M2 and M3. Predeclared; nothing here is tuned
after seeing a result.

Methods, written down so no reader has to guess them:

* Proportions: Wilson score interval, 95 %, z = 1.959963984540054, no
  continuity correction. Defined for zero and for all-failure counts.
* M1 and M3 arm comparison: Fisher's exact test on the 2x2 table
  (arm x pass/fail), two-sided, p = the sum of the probabilities of every table
  with the same margins whose hypergeometric probability is no greater than the
  observed one (relative tolerance 1e-7, as R's fisher.test). Computed with exact
  integers. Zero cells need no adjustment in this test and none is made: no 0.5
  is added anywhere.
* Rate ratio (treatment / baseline) with a 95 % Katz log interval, only when
  both arms have at least one failure. With a zero cell the ratio is reported as
  "not estimable" and no interval is given; the Wilson intervals and the Fisher
  p-value are the result in that case.
* M1 and M3 are secondary to the deterministic controls: a zero baseline is
  reported as INCONCLUSIVE, never as "no defect".
* M2: median and p95 (nearest rank: the ceil(0.95 n)-th smallest) and the ECDF
  are over uncensored completions only, and the censored count is reported
  beside them; with any censored row those statistics are conditional on
  completion and biased low. Duration > 10 s counts censored rows as > 10 s.
  No p99 or sub-1 % claim is made from 100 trials.
* Load conditions are reported separately and never pooled.

usage: report.py ARTIFACT_DIR OUT_DIR
"""

import csv
import glob
import json
import math
import sys
from fractions import Fraction
from pathlib import Path

Z = 1.959963984540054

# The predeclared design. A cell with any other row count fails the report.
M1 = {"arms": ("C0-baseline", "C1-rewrite"), "conditions": ("idle", "stressed"), "n": 600}
M3 = {"arms": ("C0-baseline", "C2-fix"), "conditions": ("stressed",), "n": 1000}
M2 = {
    "cells": [("vault", "default"), ("vault", "ed25519"), ("openbao", "default"), ("openbao", "ed25519")],
    "n": 100,
    "shards": 4,
    "budget_s": 10.0,
}


def wilson(k: int, n: int) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    denom = 1 + Z * Z / n
    centre = (p + Z * Z / (2 * n)) / denom
    half = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def fisher_two_sided(a: int, b: int, c: int, d: int) -> float:
    """Table [[a, b], [c, d]]: rows are arms, columns fail / pass."""
    row1, col1, n = a + b, a + c, a + b + c + d
    lo, hi = max(0, col1 - (n - row1)), min(row1, col1)

    def weight(x: int) -> int:
        return math.comb(row1, x) * math.comb(n - row1, col1 - x)

    total = math.comb(n, col1)
    observed = weight(a)
    limit = Fraction(observed) * (1 + Fraction(1, 10**7))
    tail = sum(w for w in (weight(x) for x in range(lo, hi + 1)) if w <= limit)
    return float(Fraction(tail, total))


def rate_ratio(k_base: int, n_base: int, k_treat: int, n_treat: int) -> str:
    if k_base == 0 or k_treat == 0:
        return "not estimable (zero cell; no continuity correction applied)"
    rr = (k_treat / n_treat) / (k_base / n_base)
    se = math.sqrt(1 / k_treat - 1 / n_treat + 1 / k_base - 1 / n_base)
    return f"{rr:.3g} (95% Katz log CI {rr * math.exp(-Z * se):.3g} to {rr * math.exp(Z * se):.3g})"


def pct(x: float) -> str:
    return f"{100 * x:.2f}%"


def read_rows(pattern: str) -> list[dict]:
    rows = []
    for path in sorted(glob.glob(pattern, recursive=True)):
        with open(path, newline="") as f:
            rows.extend(csv.DictReader(f))
    return rows


def arm_section(name: str, spec: dict, rows: list[dict], problems: list[str], out: list[str], data: dict):
    out.append(f"## {name}\n")
    out.append(
        "Trials are independent invocations of each arm's test binary (one process per trial); "
        "rates are per-invocation rates.\n"
    )
    base, treat = spec["arms"]
    for condition in spec["conditions"]:
        out.append(f"### {name} — {condition}\n")
        out.append("| arm | source | binary sha256 | n | failures | rate | Wilson 95% | failure classes |")
        out.append("|---|---|---|---|---|---|---|---|")
        counts = {}
        for arm in (base, treat):
            sel = [r for r in rows if r["condition"] == condition and r["arm"] == arm]
            n = len(sel)
            k = sum(r["outcome"] == "fail" for r in sel)
            if n != spec["n"]:
                problems.append(f"{name}/{condition}/{arm}: {n} rows, predeclared {spec['n']}")
            shas = sorted({r["source_sha"] for r in sel}) or ["-"]
            bins = sorted({r["binary_sha256"] for r in sel}) or ["-"]
            if len(shas) > 1 or len(bins) > 1:
                problems.append(f"{name}/{condition}/{arm}: more than one source or binary in one arm")
            classes = {}
            for r in sel:
                if r["outcome"] == "fail":
                    classes[r["class"]] = classes.get(r["class"], 0) + 1
            lo, hi = wilson(k, n)
            out.append(
                f"| {arm} | `{shas[0][:12]}` | `{bins[0][:16]}` | {n} | {k} | "
                f"{pct(k / n) if n else '-'} | {pct(lo)} to {pct(hi)} | {classes or '-'} |"
            )
            counts[arm] = (k, n)
            data.setdefault(name, {}).setdefault(condition, {})[arm] = {
                "n": n, "failures": k, "wilson95": [lo, hi], "classes": classes,
                "source_sha": shas, "binary_sha256": bins,
            }
        (kb, nb), (kt, nt) = counts[base], counts[treat]
        if nb and nt:
            p = fisher_two_sided(kb, nb - kb, kt, nt - kt)
            rr = rate_ratio(kb, nb, kt, nt)
            out.append("")
            out.append(f"Fisher's exact test, two-sided: p = {p:.4g}. Rate ratio {treat}/{base}: {rr}.")
            if kb == 0:
                out.append(
                    f"\n**INCONCLUSIVE** for the comparison: the baseline did not fail in {nb} trials "
                    f"(Wilson upper bound {pct(wilson(0, nb)[1])}). This does not show the defect is absent."
                )
            data[name][condition]["fisher_p"] = p
            data[name][condition]["rate_ratio"] = rr
        out.append("")


def quantile_nearest_rank(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(q * len(ordered)) - 1)]


def m2_section(rows: list[dict], problems: list[str], out: list[str], data: dict, out_dir: Path):
    out.append("## M2 — config/ca duration on fresh servers (no stress)\n")
    out.append(
        f"Ceiling {rows[0]['ceiling_s'] if rows else '120'} s; a ceiling hit is right-censored. "
        "Statistics marked *uncensored* are over completed calls only.\n"
    )
    out.append(
        "| cell | image | server version | n | ok | censored | error | CA key (type bits: count) "
        "| median* | p95* | max* | > 10 s | Wilson 95% (> 10 s) | health-ready median / p95 / max | health censored |"
    )
    out.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    ecdf_rows = []
    for engine, key_cell in M2["cells"]:
        sel = [r for r in rows if r["engine"] == engine and r["key_cell"] == key_cell]
        n = len(sel)
        if n != M2["n"]:
            problems.append(f"M2/{engine}/{key_cell}: {n} rows, predeclared {M2['n']}")
        for shard in range(M2["shards"]):
            per = sum(1 for r in sel if r["shard"] == str(shard))
            if per != M2["n"] // M2["shards"]:
                problems.append(f"M2/{engine}/{key_cell}/shard {shard}: {per} rows, predeclared {M2['n'] // M2['shards']}")
        ok = [float(r["config_ca_s"]) for r in sel if r["config_ca_status"] == "ok"]
        censored = sum(r["config_ca_status"] == "censored" for r in sel)
        errors = sum(r["config_ca_status"] not in ("ok", "censored") for r in sel)
        over = sum(v > M2["budget_s"] for v in ok) + censored
        valid = len(ok) + censored
        lo, hi = wilson(over, valid)
        keys = {}
        for r in sel:
            if r["config_ca_status"] == "ok":
                label = f"{r['ca_key_type']} {r['ca_key_bits']}"
                keys[label] = keys.get(label, 0) + 1
        health = [float(r["health_ready_s"]) for r in sel if r["health_censored"] == "False" and r["health_ready_s"]]
        health_censored = sum(r["health_censored"] == "True" for r in sel)
        images = sorted({r["image_ref"] for r in sel}) or ["-"]
        versions = sorted({r["server_version"] for r in sel if r["server_version"]}) or ["-"]
        if len(images) > 1:
            problems.append(f"M2/{engine}/{key_cell}: more than one image in one cell: {images}")

        def stats(values):
            if not values:
                return "-", "-", "-"
            return (
                f"{quantile_nearest_rank(values, 0.5):.2f}",
                f"{quantile_nearest_rank(values, 0.95):.2f}",
                f"{max(values):.2f}",
            )

        med, p95, mx = stats(ok)
        hmed, hp95, hmx = stats(health)
        out.append(
            f"| {engine}/{key_cell} | `{images[0]}` | {', '.join(versions)} | {n} | {len(ok)} | {censored} | {errors} "
            f"| {keys or '-'} | {med} | {p95} | {mx} | {over}/{valid} | {pct(lo)} to {pct(hi)} "
            f"| {hmed} / {hp95} / {hmx} | {health_censored} |"
        )
        for i, v in enumerate(sorted(ok), start=1):
            ecdf_rows.append({"engine": engine, "key_cell": key_cell, "config_ca_s": v, "ecdf": i / len(ok)})
        data.setdefault("M2", {})[f"{engine}/{key_cell}"] = {
            "n": n, "ok": len(ok), "censored": censored, "errors": errors,
            "over_budget": over, "valid": valid, "wilson95_over_budget": [lo, hi],
            "median_uncensored": med, "p95_uncensored": p95, "max_uncensored": mx,
            "ca_keys": keys, "images": images, "server_versions": versions,
            "health_median": hmed, "health_p95": hp95, "health_max": hmx,
            "health_censored": health_censored,
        }
    with open(out_dir / "m2-ecdf.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["engine", "key_cell", "config_ca_s", "ecdf"])
        writer.writeheader()
        writer.writerows(ecdf_rows)
    out.append("\n\\* over uncensored completions only; see the censored column. Full ECDF: `m2-ecdf.csv`.\n")


def main() -> int:
    artifacts, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []
    out = ["# Harness-flake measurement report\n", "Methods: see the docstring of `report.py`.\n"]
    data: dict = {}

    m1 = read_rows(str(artifacts / "**" / "rows-M1-*.csv"))
    m3 = read_rows(str(artifacts / "**" / "rows-M3-*.csv"))
    m2 = read_rows(str(artifacts / "**" / "m2-rows-shard-*.csv"))

    arm_section("M1 (D3, hold-drain test)", M1, m1, problems, out, data)
    arm_section("M3 (D2, oversized-body test)", M3, m3, problems, out, data)
    m2_section(m2, problems, out, data, out_dir)

    out.append("## Row-count and provenance checks\n")
    out.extend(f"- FAIL: {p}" for p in problems) if problems else out.append("- every cell has its predeclared row count")
    data["problems"] = problems

    (out_dir / "report.md").write_text("\n".join(out) + "\n")
    (out_dir / "report.json").write_text(json.dumps(data, indent=2, default=str) + "\n")
    print("\n".join(out))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
