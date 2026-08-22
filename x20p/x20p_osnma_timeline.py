#!/usr/bin/env python3
"""
x20p_osnma_timeline.py

Read-only terminal timeline viewer for the SQLite database produced by
x20p_osnma_sqlite.py.

No third-party Python packages are required.

Examples:

  ./x20p_osnma_timeline.py \
      --db /var/log/x20p-osnma/status.sqlite3 \
      --hours 1

  ./x20p_osnma_timeline.py --db status.sqlite3 --hours 24

  watch -n 5 './x20p_osnma_timeline.py --db status.sqlite3 --hours 2'

Tracks:
  FIX       valid GNSS fix
  NMA       strict VERIFIED FIX+TIME
  TIME      authenticated/trusted time
  GAL-AUTH  authenticated+used Galileo SV count
  AGE       seconds since the most recent VERIFIED FIX+TIME

The tool never writes to the database.
"""

import argparse
import datetime as dt
import math
import os
import shutil
import sqlite3
import statistics
import sys


RESET = "\033[0m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
DIM = "\033[2m"
BOLD = "\033[1m"

BLOCK_TRUE = "█"
BLOCK_FALSE = "░"
BLOCK_NO_DATA = " "
SPARK = "▁▂▃▄▅▆▇█"


def color(text, ansi, enabled=True):
    return f"{ansi}{text}{RESET}" if enabled else text


def parse_utc(s):
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return dt.datetime.fromisoformat(s).astimezone(dt.timezone.utc)
    except ValueError:
        return None


def fmt_hms(seconds):
    if seconds is None:
        return "n/a"
    seconds = max(0, int(round(seconds)))
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {sec:02d}s"
    hours, minute = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minute:02d}m"
    days, hour = divmod(hours, 24)
    return f"{days}d {hour:02d}h"


def fmt_pct(v):
    return "n/a" if v is None else f"{v * 100.0:.1f}%"


def floor_dt(value, seconds):
    epoch = int(value.timestamp())
    return dt.datetime.fromtimestamp(
        epoch - (epoch % seconds), tz=dt.timezone.utc
    )


def get_db_time_bounds(conn):
    row = conn.execute(
        """
        SELECT MIN(receiver_utc), MAX(receiver_utc)
        FROM epochs
        WHERE receiver_utc IS NOT NULL
        """
    ).fetchone()
    if not row or not row[1]:
        return None, None
    return parse_utc(row[0]), parse_utc(row[1])


def fetch_rows(conn, start, end):
    return conn.execute(
        """
        SELECT
            receiver_utc,
            fix_ok,
            nma_fix_verified,
            auth_time,
            verified_fix_time,
            trusted_valid,
            gal_used_auth_sv_count,
            gal_auth_sv_count,
            gal_used_sv_count,
            h_acc_m
        FROM epochs
        WHERE receiver_utc >= ?
          AND receiver_utc <= ?
        ORDER BY receiver_utc
        """,
        (
            start.isoformat().replace("+00:00", "Z"),
            end.isoformat().replace("+00:00", "Z"),
        ),
    ).fetchall()


def bucketize(rows, start, end, width):
    span = max((end - start).total_seconds(), 1.0)
    buckets = [[] for _ in range(width)]

    for row in rows:
        ts = parse_utc(row[0])
        if ts is None:
            continue
        pos = (ts - start).total_seconds() / span
        idx = min(width - 1, max(0, int(pos * width)))
        buckets[idx].append(row)

    return buckets


def state_bar(buckets, column, no_color=False):
    """
    Column is zero-based into SELECT rows.
    A bucket is true if any sample is true. False if samples exist and none true.
    """
    out = []
    for b in buckets:
        if not b:
            out.append(color(BLOCK_NO_DATA, DIM, not no_color))
            continue
        true = any(bool(r[column]) for r in b)
        if true:
            out.append(color(BLOCK_TRUE, GREEN, not no_color))
        else:
            out.append(color(BLOCK_FALSE, RED, not no_color))
    return "".join(out)


def avg_bar(buckets, column, no_color=False):
    """
    Fractional state bar: true fraction per bucket rendered with Unicode levels.
    Useful for long windows where a single bucket contains many epochs.
    """
    shades = " ░▒▓█"
    out = []
    for b in buckets:
        if not b:
            out.append(" ")
            continue
        vals = [1 if r[column] else 0 for r in b]
        frac = sum(vals) / len(vals)
        idx = min(len(shades) - 1, int(round(frac * (len(shades) - 1))))
        ch = shades[idx]
        ansi = GREEN if frac >= 0.75 else YELLOW if frac > 0 else RED
        out.append(color(ch, ansi, not no_color))
    return "".join(out)


def sparkline(values, no_color=False, good_high=False):
    finite = [v for v in values if v is not None]
    if not finite:
        return " " * len(values), None, None

    lo = min(finite)
    hi = max(finite)

    out = []
    for v in values:
        if v is None:
            out.append(" ")
            continue
        if hi == lo:
            idx = 0 if hi == 0 else len(SPARK) - 1
        else:
            idx = int(round((v - lo) / (hi - lo) * (len(SPARK) - 1)))
        idx = min(len(SPARK) - 1, max(0, idx))
        ch = SPARK[idx]

        if good_high:
            ansi = GREEN if v >= hi * 0.66 else YELLOW if v > 0 else RED
        else:
            ansi = GREEN if v == 0 else YELLOW if v <= max(5, hi * 0.33) else RED
        out.append(color(ch, ansi, not no_color))

    return "".join(out), lo, hi


def bucket_numeric(buckets, column, reducer="max"):
    result = []
    for b in buckets:
        vals = [r[column] for r in b if r[column] is not None]
        if not vals:
            result.append(None)
        elif reducer == "avg":
            result.append(sum(vals) / len(vals))
        elif reducer == "min":
            result.append(min(vals))
        else:
            result.append(max(vals))
    return result


def derive_verification_age(rows, buckets, start, end, prior_verified=None):
    """
    Compute age from raw verified epochs.

    We first walk all rows in time order and associate each sample with the
    most recent verified_fix_time=1 timestamp. Then each bucket gets the age
    of its last sample. This keeps age derived rather than stored.
    """
    last_verified = prior_verified
    row_age = {}

    for row in rows:
        ts = parse_utc(row[0])
        if ts is None:
            continue
        if row[4]:
            last_verified = ts
            age = 0.0
        elif last_verified is not None:
            age = max(0.0, (ts - last_verified).total_seconds())
        else:
            age = None
        row_age[id(row)] = age

    ages = []
    for b in buckets:
        if not b:
            ages.append(None)
        else:
            ages.append(row_age.get(id(b[-1])))
    return ages


def availability(rows, column):
    if not rows:
        return None
    vals = [1 if r[column] else 0 for r in rows]
    return sum(vals) / len(vals)


def longest_unverified_gap(rows):
    start = None
    longest = 0.0
    current = 0.0
    prev_ts = None

    for row in rows:
        ts = parse_utc(row[0])
        if ts is None:
            continue

        if row[4]:
            if start is not None:
                longest = max(longest, (ts - start).total_seconds())
                start = None
        else:
            if start is None:
                start = ts

        prev_ts = ts

    if start is not None and prev_ts is not None:
        longest = max(longest, (prev_ts - start).total_seconds())

    return longest


def latest_verified_row(conn, end):
    return conn.execute(
        """
        SELECT receiver_utc, h_acc_m
        FROM epochs
        WHERE verified_fix_time = 1
          AND receiver_utc <= ?
        ORDER BY receiver_utc DESC
        LIMIT 1
        """,
        (end.isoformat().replace("+00:00", "Z"),),
    ).fetchone()


def axis_line(start, end, width):
    """
    Create a compact three-label UTC x-axis.
    """
    if width < 20:
        return start.strftime("%H:%M")[:width]

    left = start.strftime("%H:%M")
    mid_dt = start + (end - start) / 2
    mid = mid_dt.strftime("%H:%M")
    right = end.strftime("%H:%M")

    chars = [" "] * width
    for label, pos in (
        (left, 0),
        (mid, max(0, width // 2 - len(mid) // 2)),
        (right, max(0, width - len(right))),
    ):
        for i, ch in enumerate(label):
            if 0 <= pos + i < width:
                chars[pos + i] = ch

    return "".join(chars)


def main():
    ap = argparse.ArgumentParser(
        description="Terminal timeline for X20P OSNMA SQLite history"
    )
    ap.add_argument("--db", required=True, help="SQLite status database")
    ap.add_argument(
        "--hours",
        type=float,
        default=1.0,
        help="Time window ending at latest DB sample (default: 1 hour)",
    )
    ap.add_argument(
        "--width",
        type=int,
        help="Plot width in characters (default: fit terminal)",
    )
    ap.add_argument(
        "--fractional",
        action="store_true",
        help="For FIX/NMA/TIME, shade each bucket by fraction true instead of any-true",
    )
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = ap.parse_args()

    if args.hours <= 0:
        ap.error("--hours must be > 0")

    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)

    db_start, db_end = get_db_time_bounds(conn)
    if db_end is None:
        print("No receiver epochs in database.")
        return 1

    end = db_end
    start = max(
        db_start,
        end - dt.timedelta(hours=args.hours),
    )

    terminal_width = shutil.get_terminal_size((120, 24)).columns
    label_width = 10
    width = args.width or max(30, terminal_width - label_width - 2)
    width = max(20, min(width, 240))

    rows = fetch_rows(conn, start, end)
    if not rows:
        print("No rows in selected time window.")
        return 1

    buckets = bucketize(rows, start, end, width)

    bar_fn = avg_bar if args.fractional else state_bar

    fix_bar = bar_fn(buckets, 1, args.no_color)
    nma_bar = bar_fn(buckets, 4, args.no_color)
    time_bar = bar_fn(buckets, 2 if False else 3, args.no_color)

    gal_vals = bucket_numeric(buckets, 6, reducer="max")
    gal_spark, gal_lo, gal_hi = sparkline(
        gal_vals, no_color=args.no_color, good_high=True
    )

    prior_row = conn.execute(
        """
        SELECT receiver_utc
        FROM epochs
        WHERE verified_fix_time = 1
          AND receiver_utc < ?
        ORDER BY receiver_utc DESC
        LIMIT 1
        """,
        (start.isoformat().replace("+00:00", "Z"),),
    ).fetchone()
    prior_verified = parse_utc(prior_row[0]) if prior_row else None

    age_vals = derive_verification_age(
        rows, buckets, start, end, prior_verified=prior_verified
    )
    age_spark, age_lo, age_hi = sparkline(
        age_vals, no_color=args.no_color, good_high=False
    )

    fix_avail = availability(rows, 1)
    nma_avail = availability(rows, 4)
    time_avail = availability(rows, 3)
    longest_gap = longest_unverified_gap(rows)

    latest = rows[-1]
    latest_ts = parse_utc(latest[0])
    latest_verified = latest_verified_row(conn, end)

    if latest_verified:
        lv_ts = parse_utc(latest_verified[0])
        current_age = (
            max(0.0, (latest_ts - lv_ts).total_seconds())
            if latest_ts and lv_ts else None
        )
    else:
        current_age = None

    title = f"X20P OSNMA timeline — {args.hours:g}h ending {end.strftime('%Y-%m-%d %H:%M:%SZ')}"
    print(color(title, BOLD, not args.no_color))
    print()

    print(f"{'FIX':<9}┃{fix_bar}┃  {fmt_pct(fix_avail)} valid")
    print(f"{'NMA':<9}┃{nma_bar}┃  {fmt_pct(nma_avail)} verified")
    print(f"{'TIME':<9}┃{time_bar}┃  {fmt_pct(time_avail)} authenticated")

    gal_range = (
        "n/a"
        if gal_lo is None
        else f"{int(gal_lo)}–{int(gal_hi)} SV"
    )
    print(f"{'GAL-AUTH':<9}┃{gal_spark}┃  {gal_range}")

    age_range = (
        "no verified fix"
        if age_hi is None
        else f"max {fmt_hms(age_hi)}"
    )
    print(f"{'AGE':<9}┃{age_spark}┃  {age_range}")

    print(f"{'':<9}┗{'━' * width}┛")
    print(f"{'UTC':<9} {axis_line(start, end, width)}")
    print()

    current_state = "VERIFIED" if latest[4] else "NOT VERIFIED"
    current_state_col = GREEN if latest[4] else RED
    print(
        "Current: "
        + color(current_state, current_state_col, not args.no_color)
        + f"  verification age: {fmt_hms(current_age)}"
    )

    if latest_verified:
        print(
            "Last verified: "
            f"{latest_verified[0]}  hAcc={latest_verified[1]:.3f} m"
        )
    else:
        print("Last verified: none in database")

    print(
        f"Window: {len(rows)} epochs  "
        f"NMA availability={fmt_pct(nma_avail)}  "
        f"longest unverified gap={fmt_hms(longest_gap)}"
    )

    if gal_hi is not None:
        latest_gal = latest[6]
        print(
            f"Galileo auth+used: current={latest_gal if latest_gal is not None else 'n/a'}  "
            f"window range={int(gal_lo)}–{int(gal_hi)}"
        )

    conn.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
