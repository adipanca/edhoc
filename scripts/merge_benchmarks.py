#!/usr/bin/env python3
"""Merge per-mode benchmark CSVs into combined files.

Run after all three benchmark modes (Non-EAP, EAP standalone, EAP+AAA)
have completed, e.g.:

    python3 scripts/merge_benchmarks.py            # uses ./output and ./output

Reads from output/ and writes the merged files back into output/ with
names like:

    benchmark_fullhandshake_processing_p2p_.csv
    benchmark_fullhandshake_overhead_p2p_.csv
    benchmark_fullhandshake_operation_p2p_.csv
    benchmark_fullhandshake_fragmentation_p2p_.csv
    benchmark_crypto_.csv
    benchmark_eap_keymat_.csv
    internal_test_vectors_sections_.csv

Each merged file uses ';' as the column separator and adds a
``status EAP`` column with one of ``Non-EAP``, ``Standalone`` or ``AAA``
to identify the mode the row came from.
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
from typing import Iterable, Optional

# (mode_label, file_suffix) - ordered so the merged file stays grouped
MODES = [
    ("AAA",        "_eap_aaa"),
    ("Standalone", "_eap"),
    ("Non-EAP",    ""),
]


def read_csv(path: str) -> tuple[list[str], list[list[str]]]:
    with open(path, newline="") as f:
        reader = csv.reader(f)
        rows = list(reader)
    if not rows:
        return [], []
    return rows[0], rows[1:]


def write_merged(path: str, header: list[str], rows: Iterable[list[str]]) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(header)
        for r in rows:
            writer.writerow(r)


def merge_role_pair(out_dir: str,
                    base: str,
                    out_name: str,
                    type_col_label: str,
                    status_col_label: str,
                    role_col_label: str,
                    fragmentation: bool = False) -> Optional[str]:
    """Merge files of the form ``{base}{suffix}_{role}.csv``.

    Layout assumption: every source CSV has either ``type,role,...`` (most
    benchmarks) or ``section,...`` (fragmentation/keymat). The merged
    output prepends ``status EAP`` (and ``role`` for fragmentation which
    has no role column).
    """
    merged_rows: list[list[str]] = []
    final_header: list[str] = []

    for mode_label, suffix in MODES:
        for role in ("initiator", "responder"):
            src = os.path.join(out_dir, f"{base}{suffix}_{role}.csv")
            if not os.path.isfile(src):
                continue
            header, rows = read_csv(src)
            if not header:
                continue
            # Drop blank rows that csv.reader returns from trailing newlines.
            rows = [r for r in rows if r and any(c.strip() for c in r)]
            if not rows:
                continue

            role_label = role.capitalize()
            if fragmentation:
                # fragmentation CSVs have 'section,mtu,...' (no role column).
                # Build merged header: type;status EAP;role;<rest after section>
                if not final_header:
                    final_header = [type_col_label, status_col_label,
                                    role_col_label] + header[1:]
                for r in rows:
                    merged_rows.append([r[0], mode_label, role_label] + r[1:])
            else:
                # 'type,role,...' source: replace 'type','role' with our
                # canonical labels and inject status EAP between them.
                if not final_header:
                    rest = header[2:]
                    final_header = [type_col_label, status_col_label,
                                    role_col_label] + rest
                for r in rows:
                    merged_rows.append([r[0], mode_label, role_label] + r[2:])

    if not merged_rows:
        return None
    out_path = os.path.join(out_dir, out_name)
    write_merged(out_path, final_header, merged_rows)
    return out_path


def merge_aaa_only(out_dir: str) -> Optional[str]:
    src = os.path.join(out_dir,
                       "benchmark_aaa_auth_p2p_eap_aaa_responder.csv")
    if not os.path.isfile(src):
        return None
    header, rows = read_csv(src)
    if not header:
        return None
    out = os.path.join(out_dir, "benchmark_aaa_auth_p2p_.csv")
    merged_header = [header[0], "status EAP", "role"] + header[1:]
    merged_rows = [[r[0], "AAA", "Responder"] + r[1:] for r in rows]
    write_merged(out, merged_header, merged_rows)
    return out


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", "-o", default="output",
                        help="Directory containing the per-mode CSVs and where "
                             "the merged files are written (default: output)")
    args = parser.parse_args(argv)

    out_dir = args.output_dir
    if not os.path.isdir(out_dir):
        print(f"error: output directory not found: {out_dir}", file=sys.stderr)
        return 2

    plan = [
        # base prefix, merged filename, type_label, status_label, role_label, frag?
        ("benchmark_fullhandshake_processing_p2p",
         "benchmark_fullhandshake_processing_p2p_.csv",
         "type", "status EAP", "role", False),
        ("benchmark_fullhandshake_overhead_p2p",
         "benchmark_fullhandshake_overhead_p2p_.csv",
         "type", "status EAP", "role", False),
        ("benchmark_fullhandshake_operation_p2p",
         "benchmark_fullhandshake_operation_p2p_.csv",
         "type", "status EAP", "role", False),
        ("benchmark_crypto",
         "benchmark_crypto_.csv",
         "type", "status EAP", "role", False),
    ]

    written: list[str] = []
    for base, out_name, t, s, r, frag in plan:
        p = merge_role_pair(out_dir, base, out_name, t, s, r, fragmentation=frag)
        if p:
            written.append(p)

    # Fragmentation only exists for EAP modes (no Non-EAP fragmentation file).
    p = merge_role_pair(out_dir, "benchmark_fragmentation",
                        "benchmark_fullhandshake_fragmentation_p2p_.csv",
                        "section", "status EAP", "role", fragmentation=True)
    if p:
        written.append(p)

    # EAP keymat (initiator/responder per mode); has 'section,...' columns.
    p = merge_role_pair(out_dir, "benchmark_eap_keymat",
                        "benchmark_eap_keymat_.csv",
                        "section", "status EAP", "role", fragmentation=True)
    if p:
        written.append(p)

    # internal_test_vectors_sections is global (no role); merge across modes.
    iv_rows: list[list[str]] = []
    iv_header: list[str] = []
    for mode_label, suffix in MODES:
        src = os.path.join(out_dir, f"internal_test_vectors_sections{suffix}.csv")
        if not os.path.isfile(src):
            continue
        h, rows = read_csv(src)
        if not h:
            continue
        if not iv_header:
            iv_header = ["status EAP"] + h
        for r in rows:
            iv_rows.append([mode_label] + r)
    if iv_rows:
        out = os.path.join(out_dir, "internal_test_vectors_sections_.csv")
        write_merged(out, iv_header, iv_rows)
        written.append(out)

    p = merge_aaa_only(out_dir)
    if p:
        written.append(p)

    if not written:
        print("warning: no source CSVs were found to merge.", file=sys.stderr)
        return 1
    print("Merged files:")
    for p in written:
        print(f"  {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
