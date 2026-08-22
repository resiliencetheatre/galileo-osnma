# AGENTS.md --- X20P Galileo OSNMA monitor project

## Purpose

This file is for developers and coding agents working on this project.
It records how the project reached its current design, which results are
treated as authoritative, what is derived locally, and which upstream
Galileo OSNMA tools remain part of the workflow.

The current project consists primarily of:

``` text
x20p_osnma_sqlite.py    current X20P monitor/logger
x20p_osnma_timeline.py  read-only SQLite terminal timeline viewer
README.md                user-facing operation and interpretation
```

The project is Linux-oriented. Do not introduce Windows-only u-blox
tooling into the documented workflow.

## How the project got here

The goal began as: use a serial-attached u-blox X20P on Linux, load
Galileo OSNMA cryptographic material, obtain normal navigation/time
output, and make a simple trustworthy statement about whether a
particular fix and time had been authenticated.

Development proceeded experimentally against real X20P output.

### 1. Understand OSNMA and prepare official material

Daniel Estévez's upstream project was used as an important technical
reference:

``` text
https://github.com/daniestevez/galileo-osnma.git
```

Upstream `galileo-osnma` is a Rust implementation of Galileo Open
Service Navigation Message Authentication. Its documentation explains
the practical OSNMA trust chain and how the ECDSA public key and
Merkle-tree root are used.

The upstream documentation also points to the official Galileo OSNMA
specifications and explains how official GSC cryptographic products are
prepared for use.

### 2. Reuse upstream `utils/` for material preparation

This project still relies on utilities from the upstream repository.
Most importantly:

``` text
galileo-osnma/utils/extract_merkle_tree_root.py
```

is used to extract the 256-bit Merkle-tree root from the official GSC
OSNMA Merkle-tree XML product.

The upstream repository also provides:

``` text
galileo-osnma/utils/extract_public_key.py
galileo-osnma/utils/extract_merkle_tree_key.py
galileo-osnma/utils/sec1_to_pem.py
```

These remain upstream tools. They are not maintained by this project.

Do not remove the upstream dependency from the documentation merely
because the live X20P logger does not import these scripts. They are
part of the cryptographic-material preparation workflow.

Do not vendor/copy these scripts into this repository without an
explicit decision to do so and without preserving their upstream
provenance and applicable licensing.

### 3. Move live authentication responsibility to the X20P

The project does not independently authenticate every Galileo navigation
message in Python.

Instead:

``` text
official OSNMA material
        |
        v
prepare/extract using GSC material + galileo-osnma utils
        |
        v
provision X20P through UBX
        |
        v
X20P firmware performs OSNMA processing
        |
        v
Python reads receiver authentication/PVT status
```

This distinction is fundamental.

`galileo-osnma` is a protocol reference and material-preparation
dependency. The X20P firmware is the live OSNMA engine whose PVT/status
output is being observed by this project.

### 4. Learn that authentication activity is not the same as verified PVT

Early output exposed fields such as:

``` text
DSM
TESLA
authSVs
timingAuth
sync
```

These fields often reported `not-performed`, `none`, or zero between
actual authentication events even while the receiver still reported an
NMA-verified PVT solution.

Therefore these activity fields must not be used as a home-grown
substitute for the receiver's PVT-level NMA decision.

Per-satellite authentication is diagnostic. A fixed rule such as "N
authenticated Galileo satellites means the fix is verified" must not be
invented.

### 5. Define a deliberately strict result

The project evolved toward a simple final indication:

``` text
RESULT VERIFIED FIX+TIME
```

The current logic combines the X20P's PVT-level NMA verification with
authenticated/trusted time and valid/resolved UTC requirements.

The exact implementation in `x20p_osnma_sqlite.py` is authoritative for
the current software behavior. Documentation should describe that
implementation, not replace it with an assumed Galileo-SV threshold.

### 6. Preserve the last verified epoch as historical knowledge

The receiver can transition:

``` text
VERIFIED
NOT VERIFIED
VERIFIED
```

while ordinary GNSS fixes remain valid.

`LAST VERIFIED FIX+TIME` means exactly what it says: it is the most
recent historical epoch at which the strict verification criteria
passed.

It must never be presented as proof that the **current** location
remains verified.

### 7. Prefer monitor-only continuous operation

Experiments showed that authentication can take time to accumulate and
that verification is intermittent.

The project therefore added monitor-only operation. Once the receiver
has been configured/provisioned, repeatedly restarting or reprovisioning
it is not the preferred observation method.

There is no project evidence that merely re-sending the same valid
Public Key and Merkle root necessarily resets the X20P's accumulated
authenticated state, but there is also no reason to reprovision
continuously during ordinary monitoring.

### 8. Add per-satellite diagnostics

Per-Galileo-SV output was added to understand which E1C signals were
authenticated and which satellites/signals were used.

Useful diagnostics include:

``` text
GAL
GALSV
authSVsCurrentEpoch
usedAndAuthSVs
```

Again, these explain the environment; they do not override the X20P
PVT-level NMA status.

### 9. Add SQLite history

`x20p_osnma_sqlite.py` optionally writes raw observations to SQLite
with:

``` text
--db PATH
```

The principal tables are:

``` text
epochs
galileo_signals
```

`epochs` stores PVT/authentication/trusted-time state per observed
epoch.

`galileo_signals` stores the associated per-signal Galileo diagnostics.

The database intentionally stores observations rather than trying to
make all future analysis decisions at collection time.

For example, **verification age** is derived later from the most recent
`verified_fix_time=1` epoch rather than being treated as an
authoritative receiver field.

When changing the schema:

-   preserve the distinction between receiver facts and derived metrics;
-   avoid silently changing the meaning of existing columns;
-   add a schema-version migration if an incompatible change becomes
    necessary;
-   keep the acquisition path simple and robust.

### 10. Add a read-only terminal timeline

`x20p_osnma_timeline.py` reads the SQLite database in read-only mode.

Its main tracks are:

``` text
FIX       normal GNSS fix validity
NMA       strict VERIFIED FIX+TIME state
TIME      authenticated/trusted time
GAL-AUTH  authenticated + used Galileo SV count
AGE       derived age of most recent VERIFIED FIX+TIME
```

The timeline exists to make a key observed behavior obvious:

``` text
FIX   may remain continuously valid
TIME  may remain continuously authenticated
NMA   may be intermittent
AGE   rises during gaps and resets on a newly verified epoch
```

For long windows, bucketed/fractional visualization is preferred over
plotting every two-second observation individually.

## OSNMA interpretation rules

### What OSNMA tells us

OSNMA authenticates Galileo **navigation-message data**.

For this project, the X20P uses authenticated Galileo information
internally and reports whether its PVT solution satisfies its NMA
verification logic.

A receiver-reported NMA-verified solution is therefore meaningful
evidence that the navigation solution agrees with authenticated Galileo
navigation data.

### What OSNMA does not authenticate

OSNMA does not cryptographically authenticate the physical ranging
waveform itself.

Authentic navigation data can in principle be carried by
delayed/rebroadcast signals. Therefore do not document OSNMA as making
GNSS immune to all spoofing, replay, or meaconing attacks.

### Trusted time

The X20P trusted-time mechanism provides a time constraint useful to
OSNMA and to replay/delay resistance.

In this project, authenticated time is part of the strict
`VERIFIED FIX+TIME` decision. Preserve the distinction between:

``` text
navigation message/PVT authentication
trusted/authenticated time
```

### Future SAS

Galileo Signal Authentication Service (SAS) addresses a different
assurance layer: signal/ranging authentication evidence.

Conceptually:

``` text
OSNMA
  -> authenticates navigation-message data

X20P trusted time
  -> constrains timing/replay and provides trusted epoch information

SAS
  -> adds signal/ranging authentication evidence
```

Do not claim that SAS is already provided by this project.

## Upstream `galileo-osnma` reference

Canonical upstream repository:

``` text
https://github.com/daniestevez/galileo-osnma.git
```

Important upstream facts used by this project:

-   It is a Rust Galileo OSNMA implementation.
-   It can verify OSNMA cryptographic data against an ECDSA public key
    and/or Merkle-tree root.
-   The current ECDSA public key validates TESLA root keys transmitted
    in the signal-in-space.
-   The Merkle-tree root validates ECDSA public keys broadcast in the
    signal-in-space.
-   Upstream documents extraction of the public key from the GSC
    certificate.
-   Upstream documents extraction of the Merkle root with
    `utils/extract_merkle_tree_root.py`.
-   Its `utils/` directory contains public-key/Merkle conversion helpers
    that remain useful to this project.

When protocol interpretation is uncertain, prefer:

1.  current official Galileo OSNMA SIS ICD / Receiver Guidelines;
2.  current u-blox X20 interface/integration documentation for
    X20P-specific semantics;
3.  current upstream `galileo-osnma` documentation/source as an
    implementation reference;
4.  observed receiver logs, clearly labelled as empirical behavior.

Do not turn an observed correlation into a protocol requirement.

## Cryptographic material workflow

The normal preparation flow is:

``` text
GSC OSNMA Public Key certificate
GSC OSNMA Merkle-tree XML
             |
             +--> galileo-osnma/utils/extract_merkle_tree_root.py
             |        -> 256-bit hexadecimal Merkle root
             |
             +--> Public Key certificate + PKID
                      |
                      v
                x20p_osnma_sqlite.py provisioning mode
                      |
                      v
                    X20P
```

The X20P script can extract the EC public key from the GSC X.509
certificate using Python `cryptography` and encode the compressed SEC1
point needed for the UBX aiding message.

The Merkle-root extraction still uses the upstream helper in the
documented workflow.

Keep cryptographic material current. Public-key/chain renewal and
revocation are part of OSNMA operation.

## Privacy

`--anonymity` masks leading latitude/longitude digits in terminal output
so logs can be shared more safely.

Do not assume this automatically anonymizes persistent SQLite data. The
database may contain actual numeric coordinates. Documentation and
analysis tools must make this distinction clear.

## Maintenance principles

When modifying this project:

-   Keep Linux as the primary documented environment.
-   Keep live acquisition separate from analysis/visualization.
-   Keep the SQLite timeline viewer read-only.
-   Treat X20P PVT-level NMA status as authoritative for the receiver's
    verification decision.
-   Treat GAL/GALSV authentication counts as diagnostics.
-   Preserve `LAST VERIFIED FIX+TIME` as historical, not current,
    knowledge.
-   Do not invent an authenticated-SV threshold.
-   Do not treat transient `DSM/TESLA/timingAuth=not-performed` as proof
    that a receiver-reported NMA-verified PVT is invalid.
-   Keep raw observations separate from derived metrics such as
    verification age and availability percentage.
-   Preserve upstream attribution for `galileo-osnma` and its utilities.
-   Check current upstream and official documentation before changing
    cryptographic or protocol assumptions.

## Files to read before making substantial changes

At minimum:

``` text
AGENTS.md
README.md
x20p_osnma_sqlite.py
x20p_osnma_timeline.py
```

For cryptographic-material or protocol work also inspect:

``` text
https://github.com/daniestevez/galileo-osnma.git
galileo-osnma/utils/
current Galileo OSNMA SIS ICD
current Galileo OSNMA Receiver Guidelines
current u-blox X20 interface/integration documentation
```
