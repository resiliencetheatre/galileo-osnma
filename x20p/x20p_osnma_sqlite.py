#!/usr/bin/env python3
"""
x20p_osnma.py - Linux-only u-blox X20P OSNMA provisioning and status monitor.

Dependencies:
    python3-serial
    python3-cryptography

Provisioning example:
    ./x20p_osnma.py \
        --device /dev/ttyACM0 \
        --baud 38400 \
        --pubkey-cert OSNMA_PublicKey_20251210100000_newPKID_2.crt \
        --pkid 2 \
        --merkle-root [ROOT] \
        --trust-system-time

Monitor-only example:
    ./x20p_osnma.py --device /dev/ttyACM0 --baud 38400 \\
        --monitor-only --trust-system-time --anonymity \\
        --db /var/log/x20p-osnma/status.sqlite3

The script:
  1. sends the Galileo OSNMA public key to the receiver,
  2. sends the current Merkle-tree root,
  3. enables OSNMA and OSNMA time synchronization,
  4. optionally supplies Linux CLOCK_REALTIME as trusted UTC assistance,
  5. polls UBX-SEC-OSNMA, UBX-NAV-TIMETRUSTED and UBX-NAV-PVT,
  6. prints red/green navigation and OSNMA authentication status,
  7. remembers and prints the most recent NMA-verified position/time,
  8. optionally records raw PVT/OSNMA/trusted-time/NAV-SIG observations to SQLite.

IMPORTANT:
  --trust-system-time is a security assertion. Use it only when the Linux
  system clock is supplied by a time source you consider independent and
  trustworthy for spoofing/replay detection.
"""

import argparse
import datetime as dt
import struct
import sys
import time
import sqlite3
from pathlib import Path

import serial
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


SYNC = b"\xb5\x62"

UBX_ACK = 0x05
UBX_ACK_NAK = 0x00
UBX_ACK_ACK = 0x01

UBX_CFG = 0x06
UBX_CFG_VALSET = 0x8A

UBX_MGA = 0x13
UBX_MGA_GAL = 0x02
UBX_MGA_INI = 0x40

UBX_NAV = 0x01
UBX_NAV_PVT = 0x07
UBX_NAV_SIG = 0x43
UBX_NAV_TIMETRUSTED = 0x64

UBX_SEC = 0x27
UBX_SEC_OSNMA = 0x0A

CFG_GAL_USE_OSNMA = 0x10350005
CFG_GAL_OSNMA_TIMESYNC = 0x10350009


NMA_STATUS = {
    0: "not-authenticated-yet",
    1: "test",
    2: "operational",
    3: "invalid",
}

CPKS_STATUS = {
    0: "n/a",
    1: "nominal",
    2: "end-of-chain",
    3: "chain-revoked",
    4: "new-public-key",
    5: "public-key-revocation",
    6: "new-merkle-tree",
    7: "alert-message",
}

TIMESYNC_STATUS = {
    0: "not-performed",
    1: "no-trusted-time",
    2: "trusted-time-not-accurate-enough",
    3: "passed",
    4: "FAILED-replay-attack",
}

DSM_STATUS = {
    0: "not-performed",
    1: "DSM-KROOT-authenticated",
    2: "DSM-PKR-authenticated",
    3: "ALERT-crypto-dropped",
    4: "DSM-KROOT-auth-failed",
    5: "DSM-PKR-auth-failed",
    6: "unknown-public-key",
    7: "public-key-decompression-failed",
    8: "authenticated-but-unsupported-config",
    9: "missing-future-merkle-root",
}

TESLA_STATUS = {
    0: "not-performed",
    1: "authenticated",
    2: "FAILED",
    3: "authentication-ongoing",
    4: "key-in-past/replay-or-simulation",
    5: "root-key-too-old",
}

TIMING_AUTH = {
    0: "not-authenticated",
    1: "authenticated",
    2: "FAILED",
}

SOURCE = {
    0: "factory-default",
    1: "satellites",
    2: "aided-message",
    3: "NVS",
}

FIX_TYPE = {
    0: "no-fix",
    1: "dead-reckoning",
    2: "2D",
    3: "3D",
    4: "GNSS+DR",
    5: "time-only",
}


GALILEO_SIGNAL = {
    0: "E1C",
    1: "E1B",
    3: "E5aI",
    4: "E5aQ",
    5: "E5bI",
    6: "E5bQ",
    8: "E6B",
    9: "E6C",
    10: "E6A",
}

QUALITY = {
    0: "none",
    1: "search",
    2: "acquired",
    3: "unusable",
    4: "code-lock",
    5: "code+carrier",
    6: "code+carrier",
    7: "code+carrier",
}


ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"
ANSI_RESET = "\033[0m"


def colorize(text: str, color: str, enabled: bool = True) -> str:
    if not enabled:
        return text
    return f"{color}{text}{ANSI_RESET}"


def anonymize_coord(value: float, enabled: bool = False) -> str:
    """
    Format coordinate with the leading digits masked when --anonymity is used.

    Example:
        123.123123 -> XXXX.123123
         1.123123 -> XXXX.123123

    The fractional part is preserved so movement/noise remains visible while
    the coarse geographic location is hidden.
    """
    if not enabled:
        return f"{value:.8f}"

    s = f"{abs(value):.8f}"
    frac = s.split(".", 1)[1] if "." in s else ""
    sign = "-" if value < 0 else ""
    return f"{sign}XXXX.{frac}"


def ubx_checksum(body: bytes) -> bytes:
    a = 0
    b = 0
    for v in body:
        a = (a + v) & 0xFF
        b = (b + a) & 0xFF
    return bytes((a, b))


def ubx_message(msg_class: int, msg_id: int, payload: bytes = b"") -> bytes:
    body = bytes((msg_class, msg_id)) + struct.pack("<H", len(payload)) + payload
    return SYNC + body + ubx_checksum(body)


class UbxReader:
    def __init__(self, ser):
        self.ser = ser

    def read_message(self, deadline):
        """Return (class, id, payload), or None when deadline expires."""
        state = 0
        while time.monotonic() < deadline:
            b = self.ser.read(1)
            if not b:
                continue

            if state == 0:
                if b == b"\xb5":
                    state = 1
                continue

            if state == 1:
                if b == b"\x62":
                    break
                state = 1 if b == b"\xb5" else 0

        else:
            return None

        header = self._read_exact(4, deadline)
        if header is None:
            return None

        msg_class, msg_id, length = struct.unpack("<BBH", header)
        rest = self._read_exact(length + 2, deadline)
        if rest is None:
            return None

        payload = rest[:-2]
        received_ck = rest[-2:]
        body = header + payload
        if ubx_checksum(body) != received_ck:
            return None

        return msg_class, msg_id, payload

    def _read_exact(self, n, deadline):
        out = bytearray()
        while len(out) < n and time.monotonic() < deadline:
            chunk = self.ser.read(n - len(out))
            if chunk:
                out.extend(chunk)
        return bytes(out) if len(out) == n else None


def send(ser, msg_class, msg_id, payload=b""):
    ser.write(ubx_message(msg_class, msg_id, payload))
    ser.flush()


def wait_cfg_ack(reader, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        msg = reader.read_message(deadline)
        if msg is None:
            break
        cls, mid, payload = msg
        if cls != UBX_ACK or len(payload) < 2:
            continue
        if payload[0] == UBX_CFG and payload[1] == UBX_CFG_VALSET:
            if mid == UBX_ACK_ACK:
                return True
            if mid == UBX_ACK_NAK:
                return False
    return None


def load_osnma_public_key(cert_path: str, pkid: int):
    data = Path(cert_path).read_bytes()
    try:
        cert = x509.load_pem_x509_certificate(data)
    except ValueError:
        cert = x509.load_der_x509_certificate(data)

    key = cert.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("OSNMA certificate does not contain an EC public key")

    if isinstance(key.curve, ec.SECP256R1):
        pubkey_type = 1
    elif isinstance(key.curve, ec.SECP521R1):
        pubkey_type = 3
    else:
        raise ValueError(f"Unsupported EC curve: {key.curve.name}")

    point = key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

    if len(point) > 67:
        raise ValueError("Compressed public-key point is longer than X20 field")

    # UBX-MGA-GAL-OSNMA_PUBKEY has a fixed U1[67] point field.
    # P-256 uses 33 significant bytes; the unused tail is zero-filled.
    point_field = point.ljust(67, b"\x00")

    bitfield0 = ((pubkey_type & 0x0F) << 4) | (pkid & 0x0F)
    payload = (
        bytes((0x07, 0x00, bitfield0, 0x00))
        + point_field
        + b"\x00"
    )

    if len(payload) != 72:
        raise AssertionError("Internal error constructing public-key payload")

    return payload, pubkey_type, point


def parse_merkle_root(s: str) -> bytes:
    compact = "".join(s.split())
    try:
        root = bytes.fromhex(compact)
    except ValueError as e:
        raise ValueError("Merkle root must be hexadecimal") from e
    if len(root) != 32:
        raise ValueError("Merkle root must be exactly 32 bytes / 64 hex characters")
    return root


def make_merkle_payload(root: bytes, future=False) -> bytes:
    payload = bytes((0x08, 0x00, 1 if future else 0, 0x00)) + root
    if len(payload) != 36:
        raise AssertionError("Internal error constructing Merkle payload")
    return payload


def make_cfg_valset(enable_osnma=True, enable_timesync=True):
    # UBX-CFG-VALSET v0. Layers 0x03 = RAM + BBR.
    # Both configuration keys are type L, encoded in one byte.
    payload = bytearray((0x00, 0x03, 0x00, 0x00))
    payload += struct.pack("<I", CFG_GAL_USE_OSNMA)
    payload += bytes((1 if enable_osnma else 0,))
    payload += struct.pack("<I", CFG_GAL_OSNMA_TIMESYNC)
    payload += bytes((1 if enable_timesync else 0,))
    return bytes(payload)


def make_trusted_utc_payload(accuracy_ms: int):
    now_ns = time.time_ns()
    sec = now_ns // 1_000_000_000
    ns = now_ns % 1_000_000_000
    now = dt.datetime.fromtimestamp(sec, dt.timezone.utc)

    t_acc_s, rem_ms = divmod(accuracy_ms, 1000)
    t_acc_ns = rem_ms * 1_000_000

    if t_acc_s > 0xFFFF:
        raise ValueError("Time accuracy is too large")

    # type=0x10, version=0, ref source=0 (on receipt)
    # leapSecs=-128 means unknown
    # bitfield0 bit0=1 asserts trustedSource
    return struct.pack(
        "<BBBbHBBBBBBIH2sI",
        0x10,
        0x00,
        0x00,
        -128,
        now.year,
        now.month,
        now.day,
        now.hour,
        now.minute,
        now.second,
        0x01,
        ns,
        t_acc_s,
        b"\x00\x00",
        t_acc_ns,
    )


def parse_pvt(payload):
    if len(payload) < 92:
        return None

    year = struct.unpack_from("<H", payload, 4)[0]
    month, day, hour, minute, second = payload[6:11]
    valid = payload[11]
    fix_type = payload[20]
    flags = payload[21]
    num_sv = payload[23]

    lon = struct.unpack_from("<i", payload, 24)[0] * 1e-7
    lat = struct.unpack_from("<i", payload, 28)[0] * 1e-7
    height = struct.unpack_from("<i", payload, 32)[0] / 1000.0
    h_msl = struct.unpack_from("<i", payload, 36)[0] / 1000.0
    h_acc = struct.unpack_from("<I", payload, 40)[0] / 1000.0

    flags3 = struct.unpack_from("<H", payload, 78)[0]

    nano = struct.unpack_from("<i", payload, 16)[0]
    t_acc_ns = struct.unpack_from("<I", payload, 12)[0]

    return {
        "itow_ms": struct.unpack_from("<I", payload, 0)[0],
        "utc": f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}Z",
        "date_valid": bool(valid & 0x01),
        "time_valid": bool(valid & 0x02),
        "fully_resolved": bool(valid & 0x04),
        "nano": nano,
        "t_acc_ns": t_acc_ns,
        "fix_type": fix_type,
        "fix_ok": bool(flags & 0x01),
        "num_sv": num_sv,
        "lon": lon,
        "lat": lat,
        "height": height,
        "h_msl": h_msl,
        "h_acc": h_acc,
        "auth_time": bool(flags3 & (1 << 13)),
        "nma_fix_verified": bool(flags3 & (1 << 14)),
    }


def parse_nav_sig(payload):
    """
    Parse UBX-NAV-SIG and return Galileo signal records only.

    X20 HPG 2.10:
      header = 8 bytes
      repeated signal block = 16 bytes
      gnssId 2 = Galileo
      sigFlags bit 3 = pseudorange used
      sigFlags bit 4 = carrier range used
      sigFlags bit 5 = Doppler/range-rate used
      sigFlags bit 9 = authenticated navigation data used to compute this SV position
    """
    if len(payload) < 8:
        return None

    itow_ms = struct.unpack_from("<I", payload, 0)[0]
    version = payload[4]
    num_sigs = payload[5]

    expected = 8 + num_sigs * 16
    if len(payload) < expected:
        return None

    galileo = []
    for n in range(num_sigs):
        off = 8 + n * 16
        gnss_id = payload[off + 0]
        if gnss_id != 2:
            continue

        sv_id = payload[off + 1]
        sig_id = payload[off + 2]
        pr_res = struct.unpack_from("<h", payload, off + 4)[0] * 0.1
        cno = payload[off + 6]
        quality = payload[off + 7]
        sig_flags = struct.unpack_from("<H", payload, off + 10)[0]

        galileo.append({
            "sv_id": sv_id,
            "sig_id": sig_id,
            "signal": GALILEO_SIGNAL.get(sig_id, f"sig{sig_id}"),
            "pr_res_m": pr_res,
            "cno": cno,
            "quality": quality,
            "health": sig_flags & 0x03,
            "pr_used": bool(sig_flags & (1 << 3)),
            "cr_used": bool(sig_flags & (1 << 4)),
            "do_used": bool(sig_flags & (1 << 5)),
            "auth": bool(sig_flags & (1 << 9)),
        })

    return {
        "itow_ms": itow_ms,
        "version": version,
        "num_sigs": num_sigs,
        "galileo": galileo,
    }


def parse_trusted_time(payload):
    if len(payload) < 40:
        return None

    version = payload[0]
    ref_sys = payload[1]
    valid = payload[2]

    ini_wno = struct.unpack_from("<H", payload, 8)[0]
    prop_wno = struct.unpack_from("<H", payload, 10)[0]
    ini_tow = struct.unpack_from("<I", payload, 12)[0]
    prop_tow = struct.unpack_from("<I", payload, 16)[0]
    ini_tacc = struct.unpack_from("<I", payload, 20)[0]
    prop_tacc = struct.unpack_from("<I", payload, 24)[0]
    delta_s = struct.unpack_from("<i", payload, 28)[0]
    delta_ms = struct.unpack_from("<i", payload, 32)[0]

    return {
        "version": version,
        "ref_sys": ref_sys,
        "trusted_valid": bool(valid & 0x01),
        "delta_valid": bool(valid & 0x02),
        "ini_wno": ini_wno,
        "prop_wno": prop_wno,
        "ini_tow_ms": ini_tow,
        "prop_tow_ms": prop_tow,
        "ini_tacc_ms": ini_tacc,
        "prop_tacc_ms": prop_tacc,
        "delta_s": delta_s,
        "delta_ms": delta_ms,
    }


def parse_osnma(payload):
    if len(payload) < 28:
        return None

    version = payload[0]
    nma_header = payload[1]
    monitoring = struct.unpack_from("<H", payload, 2)[0]
    time_sync = payload[4]
    time_sync_diff_ms = struct.unpack_from("<i", payload, 8)[0]
    dsm = struct.unpack_from("<I", payload, 16)[0]
    tesla = struct.unpack_from("<I", payload, 20)[0]
    general = struct.unpack_from("<I", payload, 24)[0]

    return {
        "version": version,
        "header_authenticated": bool(nma_header & 0x01),
        "nma_status": (nma_header >> 1) & 0x03,
        "chain_in_force": (nma_header >> 3) & 0x03,
        "cpks": (nma_header >> 5) & 0x07,

        "enabled": bool(monitoring & 0x01),
        "number_svs_collecting": (monitoring >> 1) & 0x1F,
        "header_update": (monitoring >> 6) & 0x03,
        "no_data": bool(monitoring & (1 << 8)),
        "wrong_data": bool(monitoring & (1 << 9)),
        "wrong_flx_mac": bool(monitoring & (1 << 10)),
        "wrong_maclt": bool(monitoring & (1 << 11)),

        "timesync_enabled": bool(time_sync & 0x01),
        "timesync_status": (time_sync >> 1) & 0x07,
        "timesync_diff_ms": time_sync_diff_ms,

        "dsm_status": dsm & 0x3F,
        "pubkey_id": (dsm >> 10) & 0x0F,

        "tesla_status": tesla & 0x07,

        "auth_svs": general & 0x3F,
        "auth_num_timing": (general >> 6) & 0x3F,
        "timing_auth": (general >> 12) & 0x03,
        "slow_mac": bool(general & (1 << 14)),
        "pubkey_source": (general >> 15) & 0x03,
        "merkle_source": (general >> 17) & 0x03,
        "merkle_valid": bool(general & (1 << 19)),
    }


def pvt_fix_and_time_verified(pvt):
    """
    Conservative application-level acceptance condition.

    A stored VERIFIED_FIX is updated only when all evidence comes from the
    same UBX-NAV-PVT navigation epoch and all of the following are true:

      - gnssFixOK = 1
      - nmaFixStatus = 1
      - authTime = 1
      - validDate = 1
      - validTime = 1
      - fullyResolved = 1

    nmaFixStatus authenticates/verifies the PVT solution against NMA data.
    authTime independently says output time was validated against external
    trusted time. Requiring both makes "verified fix + time" unambiguous.
    """
    return bool(
        pvt
        and pvt["fix_ok"]
        and pvt["nma_fix_verified"]
        and pvt["auth_time"]
        and pvt["date_valid"]
        and pvt["time_valid"]
        and pvt["fully_resolved"]
    )


def print_status(pvt, osnma, trusted, trusted_age, navsig, last_authenticated, color_enabled=True, anonymity=False):
    print("=" * 78)

    current_nma_verified = bool(
        pvt
        and pvt["fix_ok"]
        and pvt["nma_fix_verified"]
    )
    current_verified = pvt_fix_and_time_verified(pvt)
    current_color = ANSI_GREEN if current_verified else ANSI_RED

    def state_print(line):
        print(colorize(line, current_color, color_enabled))

    # --- Current PVT -------------------------------------------------------
    if pvt:
        fix = FIX_TYPE.get(pvt["fix_type"], str(pvt["fix_type"]))
        state_print(
            f"PVT      {pvt['utc']}  iTOW={pvt['itow_ms']} ms  "
            f"fix={fix}  fixOK={int(pvt['fix_ok'])}  SV={pvt['num_sv']}"
        )
        if pvt["fix_ok"]:
            state_print(
                f"POS      lat={anonymize_coord(pvt['lat'], anonymity)}  lon={anonymize_coord(pvt['lon'], anonymity)}  "
                f"hMSL={pvt['h_msl']:.3f} m  hAcc={pvt['h_acc']:.3f} m"
            )
    else:
        state_print("PVT      no UBX-NAV-PVT response")

    # --- High-level state -------------------------------------------------
    pvt_state = "NMA-VERIFIED" if current_nma_verified else "NOT-NMA-VERIFIED"
    time_state = (
        "AUTHENTICATED"
        if pvt and pvt["auth_time"]
        else "NOT-AUTHENTICATED"
    )
    verified_fix_state = "YES" if current_verified else "NO"

    if osnma:
        osnma_state = NMA_STATUS.get(osnma["nma_status"], str(osnma["nma_status"]))
        cpks_state = CPKS_STATUS.get(osnma["cpks"], str(osnma["cpks"]))
        merkle_state = "VALID" if osnma["merkle_valid"] else "INVALID"
        header_state = "AUTHENTICATED" if osnma["header_authenticated"] else "NOT-AUTHENTICATED"

        state_print(
            "STATE    "
            f"PVT={pvt_state}  "
            f"TIME={time_state}  "
            f"OSNMA={osnma_state.upper()}  "
            f"CPKS={cpks_state.upper()}"
        )
        print(colorize(
            "VERIFY   "
            f"FIX+TIME={verified_fix_state}  "
            f"NMA_FIX={pvt_state}  "
            f"TIME={time_state}  "
            f"UTC_VALID={int(bool(pvt and pvt['date_valid'] and pvt['time_valid']))}  "
            f"UTC_RESOLVED={int(bool(pvt and pvt['fully_resolved']))}",
            ANSI_GREEN if current_verified else ANSI_RED,
            color_enabled,
        ))
        state_print(
            "TRUST    "
            f"HEADER={header_state}  "
            f"PKID={osnma['pubkey_id']}  "
            f"PK={SOURCE.get(osnma['pubkey_source'], osnma['pubkey_source'])}  "
            f"MERKLE={merkle_state}  "
            f"MERKLE_SRC={SOURCE.get(osnma['merkle_source'], osnma['merkle_source'])}"
        )
    else:
        state_print(
            "STATE    "
            f"PVT={pvt_state}  TIME={time_state}  "
            "OSNMA=no-status"
        )
        print(colorize(
            "VERIFY   "
            f"FIX+TIME={verified_fix_state}  "
            f"NMA_FIX={pvt_state}  TIME={time_state}",
            ANSI_GREEN if current_verified else ANSI_RED,
            color_enabled,
        ))

    # --- Current OSNMA processing activity -------------------------------
    if osnma:
        dsm_activity = DSM_STATUS.get(osnma["dsm_status"], str(osnma["dsm_status"]))
        tesla_activity = TESLA_STATUS.get(osnma["tesla_status"], str(osnma["tesla_status"]))
        timing_activity = TIMING_AUTH.get(osnma["timing_auth"], str(osnma["timing_auth"]))
        sync_activity = TIMESYNC_STATUS.get(
            osnma["timesync_status"], str(osnma["timesync_status"])
        )

        print(
            "ACTIVITY "
            f"DSM={dsm_activity}  "
            f"TESLA={tesla_activity}  "
            f"newAuthSVs={osnma['auth_svs']}  "
            f"timingAuth={timing_activity}  "
            f"sync={sync_activity}"
        )

        if osnma["timesync_status"] != 0:
            print(
                "ACTIVITY "
                f"syncDiff={osnma['timesync_diff_ms']} ms  "
                f"MAC={'slow' if osnma['slow_mac'] else 'fast'}"
            )

        problems = [
            name for name, value in (
                ("noData", osnma["no_data"]),
                ("wrongData", osnma["wrong_data"]),
                ("wrongFlxMac", osnma["wrong_flx_mac"]),
                ("wrongMaclt", osnma["wrong_maclt"]),
            )
            if value
        ]
        if problems:
            print(colorize(
                "ALERT    OSNMA monitor flags: " + ", ".join(problems),
                ANSI_RED,
                color_enabled,
            ))
    else:
        print("ACTIVITY no UBX-SEC-OSNMA response")

    # --- Per-satellite Galileo authentication ---------------------------
    if navsig is not None:
        gal = navsig["galileo"]

        # Group all tracked Galileo signals by SV.
        by_sv = {}
        for sig in gal:
            by_sv.setdefault(sig["sv_id"], []).append(sig)

        authenticated_svs = set()
        used_svs = set()
        used_and_authenticated_svs = set()

        for sv_id, signals in sorted(by_sv.items()):
            sv_authenticated = any(s["auth"] for s in signals)
            sv_used = any(
                s["pr_used"] or s["cr_used"] or s["do_used"]
                for s in signals
            )

            if sv_authenticated:
                authenticated_svs.add(sv_id)
            if sv_used:
                used_svs.add(sv_id)
            if sv_authenticated and sv_used:
                used_and_authenticated_svs.add(sv_id)

        print(
            "GAL      "
            f"SVs={len(by_sv)}  "
            f"usedSVs={len(used_svs)}  "
            f"authSVsCurrentEpoch={len(authenticated_svs)}  "
            f"usedAndAuthSVs={len(used_and_authenticated_svs)}"
        )

        for sv_id, signals in sorted(by_sv.items()):
            pieces = []

            sv_authenticated = any(s["auth"] for s in signals)
            sv_used = any(
                s["pr_used"] or s["cr_used"] or s["do_used"]
                for s in signals
            )

            for sig in sorted(signals, key=lambda x: x["sig_id"]):
                used = sig["pr_used"] or sig["cr_used"] or sig["do_used"]

                auth_txt = "AUTH" if sig["auth"] else "UNKNOWN"
                used_txt = "USED" if used else "not-used"
                quality_txt = QUALITY.get(sig["quality"], str(sig["quality"]))

                pieces.append(
                    f"{sig['signal']}:{auth_txt},{used_txt},"
                    f"C/N0={sig['cno']},q={quality_txt}"
                )

            sv_state = (
                "AUTH+USED"
                if sv_authenticated and sv_used
                else "AUTH"
                if sv_authenticated
                else "USED/UNKNOWN"
                if sv_used
                else "UNKNOWN"
            )

            sat_line = (
                f"GALSV    E{sv_id:02d}  "
                f"SV={sv_state}  "
                + " | ".join(pieces)
            )

            # SV-level semantics:
            # - green: this SV has authenticated nav data somewhere and is used
            # - green: authenticated but not currently used
            # - neutral: used but authStatus is unknown, not failed
            # - neutral: tracked but neither authenticated nor used
            if sv_authenticated:
                print(colorize(sat_line, ANSI_GREEN, color_enabled))
            else:
                print(sat_line)
    else:
        print("GAL      no UBX-NAV-SIG response")

    # --- Trusted-time state ----------------------------------------------
    if trusted:
        delta = (
            f"{trusted['delta_s']} s + {trusted['delta_ms']} ms"
            if trusted["delta_valid"]
            else "unavailable"
        )
        age_text = (
            f"{trusted_age:.1f} s ago"
            if trusted_age is not None
            else "current"
        )
        trusted_line = (
            "TIME     "
            f"trustedValid={int(trusted['trusted_valid'])}  "
            f"deltaValid={int(trusted['delta_valid'])}  "
            f"propAccuracy={trusted['prop_tacc_ms']} ms  "
            f"delta={delta}  "
            f"lastUpdate={age_text}"
        )
        time_color = ANSI_GREEN if trusted["trusted_valid"] else ANSI_RED
        print(colorize(trusted_line, time_color, color_enabled))
    else:
        print(colorize(
            "TIME     no trusted-time status received yet",
            ANSI_RED,
            color_enabled,
        ))

    # --- Authoritative current verified-fix result ------------------------
    if current_verified:
        print(colorize(
            "RESULT   VERIFIED FIX+TIME  "
            f"utc={pvt['utc']}  iTOW={pvt['itow_ms']} ms  "
            f"lat={anonymize_coord(pvt['lat'], anonymity)}  lon={anonymize_coord(pvt['lon'], anonymity)}  "
            f"hMSL={pvt['h_msl']:.3f} m  hAcc={pvt['h_acc']:.3f} m",
            ANSI_GREEN,
            color_enabled,
        ))
    elif pvt and pvt["fix_ok"]:
        print(colorize(
            "RESULT   CURRENT FIX NOT FULLY VERIFIED  "
            f"NMA={int(pvt['nma_fix_verified'])}  "
            f"authTime={int(pvt['auth_time'])}  "
            f"utcValid={int(pvt['date_valid'] and pvt['time_valid'])}  "
            f"utcResolved={int(pvt['fully_resolved'])}",
            ANSI_RED,
            color_enabled,
        ))
    else:
        print(colorize(
            "RESULT   NO VALID NAVIGATION FIX",
            ANSI_RED,
            color_enabled,
        ))

    # --- Historical last authenticated fix -------------------------------
    if last_authenticated:
        last_line = (
            "LAST VERIFIED FIX+TIME  "
            f"utc={last_authenticated['utc']}  "
            f"iTOW={last_authenticated['itow_ms']} ms  "
            f"lat={anonymize_coord(last_authenticated['lat'], anonymity)}  "
            f"lon={anonymize_coord(last_authenticated['lon'], anonymity)}  "
            f"hMSL={last_authenticated['h_msl']:.3f} m  "
            f"hAcc={last_authenticated['h_acc']:.3f} m"
        )
        print(colorize(last_line, ANSI_GREEN, color_enabled))
    else:
        print(colorize(
            "LAST VERIFIED FIX+TIME  none observed in this process",
            ANSI_RED,
            color_enabled,
        ))


def provision(ser, reader, args):
    pub_payload, pub_type, point = load_osnma_public_key(args.pubkey_cert, args.pkid)
    merkle = parse_merkle_root(args.merkle_root)

    print(
        f"Public key: PKID={args.pkid}, "
        f"type={'P-256' if pub_type == 1 else 'P-521'}, "
        f"compressed={point.hex().upper()}"
    )
    print(f"Merkle root: {merkle.hex().upper()}")

    print("Sending UBX-MGA-GAL-OSNMA_PUBKEY...")
    send(ser, UBX_MGA, UBX_MGA_GAL, pub_payload)
    time.sleep(0.2)

    print("Sending UBX-MGA-GAL-OSNMA_MERKLE (current)...")
    send(ser, UBX_MGA, UBX_MGA_GAL, make_merkle_payload(merkle, future=False))
    time.sleep(0.2)

    print("Enabling OSNMA + OSNMA time synchronization (RAM + BBR)...")
    send(
        ser,
        UBX_CFG,
        UBX_CFG_VALSET,
        make_cfg_valset(enable_osnma=True, enable_timesync=True),
    )
    ack = wait_cfg_ack(reader)
    if ack is False:
        raise RuntimeError("Receiver NAKed CFG-GAL OSNMA configuration")
    if ack is None:
        print("WARNING: no CFG-VALSET ACK received; continuing to status check")
    else:
        print("Configuration ACK received")

    if args.trust_system_time:
        print(
            f"Sending trusted Linux UTC time "
            f"(declared accuracy {args.time_accuracy_ms} ms)..."
        )
        send(
            ser,
            UBX_MGA,
            UBX_MGA_INI,
            make_trusted_utc_payload(args.time_accuracy_ms),
        )
        time.sleep(0.2)
    else:
        print(
            "NOTE: trusted time was NOT supplied. OSNMA time synchronization "
            "is enabled, so the receiver may report 'no-trusted-time'."
        )



DB_SCHEMA_VERSION = 1


def bool_int(value):
    if value is None:
        return None
    return int(bool(value))


def open_status_db(path):
    """
    Open/create the optional SQLite trend database.

    The database stores raw receiver observations. Derived quantities such as
    "seconds since last VERIFIED FIX+TIME" are intentionally NOT stored; they
    should be calculated later from the verified_fix_time column.
    """
    db_path = Path(path)
    if db_path.parent and str(db_path.parent) not in ("", "."):
        db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS epochs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            host_recorded_utc TEXT NOT NULL,
            receiver_utc TEXT,
            itow_ms INTEGER,

            fix_type INTEGER,
            fix_ok INTEGER,
            num_sv INTEGER,
            lat REAL,
            lon REAL,
            h_msl_m REAL,
            h_acc_m REAL,
            t_acc_ns INTEGER,

            nma_fix_verified INTEGER,
            auth_time INTEGER,
            utc_date_valid INTEGER,
            utc_time_valid INTEGER,
            utc_fully_resolved INTEGER,
            verified_fix_time INTEGER NOT NULL,

            osnma_present INTEGER NOT NULL,
            osnma_enabled INTEGER,
            osnma_header_authenticated INTEGER,
            osnma_nma_status INTEGER,
            osnma_chain_in_force INTEGER,
            osnma_cpks INTEGER,
            osnma_dsm_status INTEGER,
            osnma_pubkey_id INTEGER,
            osnma_tesla_status INTEGER,
            osnma_new_auth_svs INTEGER,
            osnma_timing_auth INTEGER,
            osnma_timesync_enabled INTEGER,
            osnma_timesync_status INTEGER,
            osnma_timesync_diff_ms INTEGER,
            osnma_slow_mac INTEGER,
            osnma_pubkey_source INTEGER,
            osnma_merkle_source INTEGER,
            osnma_merkle_valid INTEGER,
            osnma_no_data INTEGER,
            osnma_wrong_data INTEGER,
            osnma_wrong_flx_mac INTEGER,
            osnma_wrong_maclt INTEGER,

            trusted_present INTEGER NOT NULL,
            trusted_valid INTEGER,
            trusted_delta_valid INTEGER,
            trusted_prop_tacc_ms INTEGER,
            trusted_delta_s INTEGER,
            trusted_delta_ms INTEGER,
            trusted_age_s REAL,

            navsig_present INTEGER NOT NULL,
            navsig_itow_ms INTEGER,
            navsig_epoch_match INTEGER,
            gal_sv_count INTEGER,
            gal_used_sv_count INTEGER,
            gal_auth_sv_count INTEGER,
            gal_used_auth_sv_count INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_epochs_receiver_utc
            ON epochs(receiver_utc);
        CREATE INDEX IF NOT EXISTS idx_epochs_itow
            ON epochs(itow_ms);
        CREATE INDEX IF NOT EXISTS idx_epochs_verified
            ON epochs(verified_fix_time);

        CREATE TABLE IF NOT EXISTS galileo_signals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            epoch_id INTEGER NOT NULL
                REFERENCES epochs(id) ON DELETE CASCADE,

            navsig_itow_ms INTEGER,
            sv_id INTEGER NOT NULL,
            sig_id INTEGER NOT NULL,
            signal TEXT NOT NULL,

            auth_status INTEGER NOT NULL,
            pr_used INTEGER NOT NULL,
            cr_used INTEGER NOT NULL,
            do_used INTEGER NOT NULL,

            cno_dbhz INTEGER,
            quality INTEGER,
            health INTEGER,
            pr_res_m REAL
        );

        CREATE INDEX IF NOT EXISTS idx_galileo_signals_epoch
            ON galileo_signals(epoch_id);
        CREATE INDEX IF NOT EXISTS idx_galileo_signals_sv
            ON galileo_signals(sv_id);
        """
    )
    conn.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
        ("schema_version", str(DB_SCHEMA_VERSION)),
    )
    conn.commit()
    return conn


def galileo_epoch_summary(navsig):
    if not navsig:
        return {
            "sv_count": None,
            "used_sv_count": None,
            "auth_sv_count": None,
            "used_auth_sv_count": None,
        }

    by_sv = {}
    for sig in navsig["galileo"]:
        by_sv.setdefault(sig["sv_id"], []).append(sig)

    used = set()
    auth = set()
    used_auth = set()

    for sv_id, signals in by_sv.items():
        sv_used = any(
            s["pr_used"] or s["cr_used"] or s["do_used"]
            for s in signals
        )
        sv_auth = any(s["auth"] for s in signals)

        if sv_used:
            used.add(sv_id)
        if sv_auth:
            auth.add(sv_id)
        if sv_used and sv_auth:
            used_auth.add(sv_id)

    return {
        "sv_count": len(by_sv),
        "used_sv_count": len(used),
        "auth_sv_count": len(auth),
        "used_auth_sv_count": len(used_auth),
    }


def insert_status_epoch(conn, pvt, osnma, trusted, trusted_age, navsig):
    """
    Insert one receiver observation.

    An epochs row is written only when UBX-NAV-PVT was received, because PVT
    iTOW is the canonical navigation-epoch key for later timeline analysis.

    The per-signal NAV-SIG observations received in the same polling cycle are
    attached to that row. navsig_epoch_match records whether NAV-SIG and PVT
    actually carry the same iTOW, so later analysis can choose to use only
    rigorously epoch-matched satellite data.
    """
    if pvt is None:
        return None

    host_recorded_utc = (
        dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )

    summary = galileo_epoch_summary(navsig)
    navsig_present = navsig is not None
    navsig_itow_ms = navsig["itow_ms"] if navsig else None
    navsig_epoch_match = (
        int(navsig_itow_ms == pvt["itow_ms"])
        if navsig_itow_ms is not None
        else None
    )

    values = (
        host_recorded_utc,
        pvt.get("utc"),
        pvt.get("itow_ms"),

        pvt.get("fix_type"),
        bool_int(pvt.get("fix_ok")),
        pvt.get("num_sv"),
        pvt.get("lat"),
        pvt.get("lon"),
        pvt.get("h_msl"),
        pvt.get("h_acc"),
        pvt.get("t_acc_ns"),

        bool_int(pvt.get("nma_fix_verified")),
        bool_int(pvt.get("auth_time")),
        bool_int(pvt.get("date_valid")),
        bool_int(pvt.get("time_valid")),
        bool_int(pvt.get("fully_resolved")),
        int(pvt_fix_and_time_verified(pvt)),

        int(osnma is not None),
        bool_int(osnma.get("enabled")) if osnma else None,
        bool_int(osnma.get("header_authenticated")) if osnma else None,
        osnma.get("nma_status") if osnma else None,
        osnma.get("chain_in_force") if osnma else None,
        osnma.get("cpks") if osnma else None,
        osnma.get("dsm_status") if osnma else None,
        osnma.get("pubkey_id") if osnma else None,
        osnma.get("tesla_status") if osnma else None,
        osnma.get("auth_svs") if osnma else None,
        osnma.get("timing_auth") if osnma else None,
        bool_int(osnma.get("timesync_enabled")) if osnma else None,
        osnma.get("timesync_status") if osnma else None,
        osnma.get("timesync_diff_ms") if osnma else None,
        bool_int(osnma.get("slow_mac")) if osnma else None,
        osnma.get("pubkey_source") if osnma else None,
        osnma.get("merkle_source") if osnma else None,
        bool_int(osnma.get("merkle_valid")) if osnma else None,
        bool_int(osnma.get("no_data")) if osnma else None,
        bool_int(osnma.get("wrong_data")) if osnma else None,
        bool_int(osnma.get("wrong_flx_mac")) if osnma else None,
        bool_int(osnma.get("wrong_maclt")) if osnma else None,

        int(trusted is not None),
        bool_int(trusted.get("trusted_valid")) if trusted else None,
        bool_int(trusted.get("delta_valid")) if trusted else None,
        trusted.get("prop_tacc_ms") if trusted else None,
        trusted.get("delta_s") if trusted else None,
        trusted.get("delta_ms") if trusted else None,
        trusted_age,

        int(navsig_present),
        navsig_itow_ms,
        navsig_epoch_match,
        summary["sv_count"],
        summary["used_sv_count"],
        summary["auth_sv_count"],
        summary["used_auth_sv_count"],
    )

    cur = conn.execute(
        """
        INSERT INTO epochs (
            host_recorded_utc, receiver_utc, itow_ms,
            fix_type, fix_ok, num_sv, lat, lon, h_msl_m, h_acc_m, t_acc_ns,
            nma_fix_verified, auth_time, utc_date_valid, utc_time_valid,
            utc_fully_resolved, verified_fix_time,
            osnma_present, osnma_enabled, osnma_header_authenticated,
            osnma_nma_status, osnma_chain_in_force, osnma_cpks,
            osnma_dsm_status, osnma_pubkey_id, osnma_tesla_status,
            osnma_new_auth_svs, osnma_timing_auth, osnma_timesync_enabled,
            osnma_timesync_status, osnma_timesync_diff_ms, osnma_slow_mac,
            osnma_pubkey_source, osnma_merkle_source, osnma_merkle_valid,
            osnma_no_data, osnma_wrong_data, osnma_wrong_flx_mac,
            osnma_wrong_maclt,
            trusted_present, trusted_valid, trusted_delta_valid,
            trusted_prop_tacc_ms, trusted_delta_s, trusted_delta_ms,
            trusted_age_s,
            navsig_present, navsig_itow_ms, navsig_epoch_match,
            gal_sv_count, gal_used_sv_count, gal_auth_sv_count,
            gal_used_auth_sv_count
        ) VALUES (
            ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?
        )
        """,
        values,
    )
    epoch_id = cur.lastrowid

    if navsig:
        signal_rows = []
        for sig in navsig["galileo"]:
            signal_rows.append(
                (
                    epoch_id,
                    navsig_itow_ms,
                    sig["sv_id"],
                    sig["sig_id"],
                    sig["signal"],
                    bool_int(sig["auth"]),
                    bool_int(sig["pr_used"]),
                    bool_int(sig["cr_used"]),
                    bool_int(sig["do_used"]),
                    sig["cno"],
                    sig["quality"],
                    sig["health"],
                    sig["pr_res_m"],
                )
            )

        conn.executemany(
            """
            INSERT INTO galileo_signals (
                epoch_id, navsig_itow_ms, sv_id, sig_id, signal,
                auth_status, pr_used, cr_used, do_used,
                cno_dbhz, quality, health, pr_res_m
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            signal_rows,
        )

    conn.commit()
    return epoch_id


def monitor(ser, reader, args, db_conn=None):
    last_time_aid = 0.0
    last_authenticated = None
    last_trusted = None
    last_trusted_monotonic = None

    while True:
        now = time.monotonic()
        if args.trust_system_time and (
            last_time_aid == 0.0 or now - last_time_aid >= args.time_refresh
        ):
            send(
                ser,
                UBX_MGA,
                UBX_MGA_INI,
                make_trusted_utc_payload(args.time_accuracy_ms),
            )
            last_time_aid = now

        send(ser, UBX_SEC, UBX_SEC_OSNMA)
        send(ser, UBX_NAV, UBX_NAV_TIMETRUSTED)
        send(ser, UBX_NAV, UBX_NAV_SIG)
        send(ser, UBX_NAV, UBX_NAV_PVT)

        pvt = None
        osnma = None
        trusted_this_poll = None
        navsig = None

        deadline = time.monotonic() + args.poll_window
        while time.monotonic() < deadline:
            msg = reader.read_message(deadline)
            if msg is None:
                break
            cls, mid, payload = msg
            if cls == UBX_NAV and mid == UBX_NAV_PVT:
                pvt = parse_pvt(payload)
            elif cls == UBX_NAV and mid == UBX_NAV_TIMETRUSTED:
                trusted_this_poll = parse_trusted_time(payload)
            elif cls == UBX_NAV and mid == UBX_NAV_SIG:
                navsig = parse_nav_sig(payload)
            elif cls == UBX_SEC and mid == UBX_SEC_OSNMA:
                osnma = parse_osnma(payload)

        if trusted_this_poll is not None:
            last_trusted = trusted_this_poll
            last_trusted_monotonic = time.monotonic()

        trusted_age = None
        if last_trusted_monotonic is not None:
            trusted_age = max(0.0, time.monotonic() - last_trusted_monotonic)

        # Store only a position AND time verified in the SAME UBX-NAV-PVT
        # navigation epoch. This deliberately does not depend on transient
        # UBX-SEC-OSNMA activity messages.
        if pvt_fix_and_time_verified(pvt):
            last_authenticated = {
                "utc": pvt["utc"],
                "itow_ms": pvt["itow_ms"],
                "lat": pvt["lat"],
                "lon": pvt["lon"],
                "h_msl": pvt["h_msl"],
                "h_acc": pvt["h_acc"],
                "t_acc_ns": pvt["t_acc_ns"],
            }

        if db_conn is not None:
            try:
                insert_status_epoch(
                    db_conn,
                    pvt,
                    osnma,
                    last_trusted,
                    trusted_age,
                    navsig,
                )
            except sqlite3.Error as exc:
                print(f"DB ERROR  {exc}", file=sys.stderr)

        print_status(
            pvt,
            osnma,
            last_trusted,
            trusted_age,
            navsig,
            last_authenticated,
            color_enabled=not args.no_color,
            anonymity=args.anonymity,
        )
        time.sleep(max(0.0, args.interval - args.poll_window))


def main():
    ap = argparse.ArgumentParser(
        description="Provision and monitor u-blox X20P Galileo OSNMA"
    )
    ap.add_argument("--device", required=True, help="Serial device, e.g. /dev/ttyACM0")
    ap.add_argument("--baud", type=int, default=38400, help="Serial baud rate (default: 38400)")
    ap.add_argument(
        "--pubkey-cert",
        help="GSC OSNMA public-key X.509 certificate (.crt/.pem); required unless --monitor-only",
    )
    ap.add_argument(
        "--pkid",
        type=int,
        choices=range(0, 16),
        metavar="0..15",
        help="Galileo OSNMA Public Key ID; required unless --monitor-only",
    )
    ap.add_argument(
        "--merkle-root",
        help="Current OSNMA Merkle-tree root, exactly 64 hex characters; required unless --monitor-only",
    )
    ap.add_argument(
        "--trust-system-time",
        action="store_true",
        help="Assert Linux CLOCK_REALTIME as an independent trusted UTC source",
    )
    ap.add_argument(
        "--time-accuracy-ms",
        type=int,
        default=1000,
        help="Accuracy claimed for host UTC assistance (default: 1000 ms)",
    )
    ap.add_argument(
        "--time-refresh",
        type=float,
        default=30.0,
        help="Refresh trusted UTC assistance every N seconds (default: 30)",
    )
    ap.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Status print interval in seconds (default: 2)",
    )
    ap.add_argument(
        "--poll-window",
        type=float,
        default=1.0,
        help="How long to collect replies after each poll (default: 1 s)",
    )
    ap.add_argument(
        "--monitor-only",
        action="store_true",
        help=(
            "Do not send Public Key, Merkle root, or OSNMA CFG writes. "
            "Only refresh trusted time if requested and poll receiver status."
        ),
    )
    ap.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI red/green terminal colors",
    )
    ap.add_argument(
        "--anonymity",
        action="store_true",
        help="Mask leading latitude/longitude digits as XXXX in all terminal output",
    )
    ap.add_argument(
        "--db",
        metavar="PATH",
        help=(
            "Optionally append each PVT epoch and Galileo signal status to "
            "a SQLite database at PATH"
        ),
    )
    args = ap.parse_args()

    if not args.monitor_only:
        missing = []
        if not args.pubkey_cert:
            missing.append("--pubkey-cert")
        if args.pkid is None:
            missing.append("--pkid")
        if not args.merkle_root:
            missing.append("--merkle-root")
        if missing:
            ap.error(
                "provisioning mode requires: " + ", ".join(missing) +
                " (or use --monitor-only)"
            )

    if args.time_accuracy_ms < 0:
        ap.error("--time-accuracy-ms must be >= 0")
    if args.time_refresh <= 0 or args.interval <= 0 or args.poll_window <= 0:
        ap.error("timing intervals must be > 0")

    try:
        ser = serial.Serial(
            args.device,
            args.baud,
            timeout=0.1,
            write_timeout=1.0,
        )
    except serial.SerialException as e:
        print(f"Cannot open {args.device}: {e}", file=sys.stderr)
        return 2

    reader = UbxReader(ser)

    try:
        # Remove stale bytes without relying on any u-blox host tooling.
        ser.reset_input_buffer()

        if args.monitor_only:
            print(
                "Mode: MONITOR-ONLY "
                "(no Public Key/Merkle provisioning, no OSNMA CFG writes)"
            )
        else:
            print("Mode: PROVISION + MONITOR")
            provision(ser, reader, args)

        if args.no_color:
            print("Monitoring. Ctrl-C to stop. Color output disabled.")
        else:
            print("Color legend: " + colorize("NMA VERIFIED", ANSI_GREEN, True) + " / " + colorize("NOT NMA VERIFIED", ANSI_RED, True))
            print("Monitoring. Ctrl-C to stop.")
        db_conn = None
        if args.db:
            db_conn = open_status_db(args.db)
            print(f"SQLite logging: {args.db}")

        try:
            monitor(ser, reader, args, db_conn=db_conn)
        finally:
            if db_conn is not None:
                db_conn.close()

    except KeyboardInterrupt:
        print("\nStopped.")
        return 0
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    finally:
        ser.close()


if __name__ == "__main__":
    raise SystemExit(main())
