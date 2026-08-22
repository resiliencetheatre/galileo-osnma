# X20P Galileo OSNMA Monitor


Note: This project currently contains AI-generated code and documentation; no complete human review or independent verification against the official Galileo OSNMA and u-blox X20P specifications has yet been performed.

Linux command-line utility for provisioning Galileo OSNMA cryptographic
material into a u-blox ZED-X20P, enabling the receiver's internal OSNMA
implementation, supplying trusted time, and monitoring the resulting
authenticated navigation solution.

The utility talks directly to the receiver using the UBX binary
protocol. No Windows-only u-blox tooling is required.

The current acquisition/logger script is:

``` text
x20p_osnma_sqlite.py
```

The companion read-only terminal visualization tool is:

``` text
x20p_osnma_timeline.py
```

## Current project tools

This README documents the current project state. The primary receiver
program is:

``` text
x20p_osnma_sqlite.py
```

It supports both initial provisioning and true `--monitor-only`
operation. With `--db PATH`, it also records each observed
PVT/authentication epoch and the associated Galileo signal state into
SQLite. Without `--db`, it behaves as a terminal monitor without
database logging.

The companion analysis program is:

``` text
x20p_osnma_timeline.py
```

It opens the SQLite database read-only and draws terminal timelines for
normal fix availability, strict NMA verified fix+time availability,
authenticated time, authenticated+used Galileo SV count, and age since
the latest verified fix+time epoch.

Recommended continuous-monitor command:

``` bash
./x20p_osnma_sqlite.py \
    --device /dev/ttyACM0 \
    --baud 38400 \
    --monitor-only \
    --trust-system-time \
    --anonymity \
    --db /var/log/x20p-osnma/status.sqlite3
```

Recommended terminal timeline command:

``` bash
./x20p_osnma_timeline.py \
    --db /var/log/x20p-osnma/status.sqlite3 \
    --hours 0.5
```

## What this project demonstrates

The ZED-X20P performs Galileo Open Service Navigation Message
Authentication (OSNMA) internally.

The Linux host supplies the receiver with the trust material and, when
desired, an independent trusted-time reference:

``` text
GSC cryptographic material
        |
        +-- Public Key / PKID
        +-- Merkle-tree root
        |
        v
     Linux host
        |
        | UBX-MGA-GAL-OSNMA_*
        v
   +-------------+
   |  ZED-X20P   |
   |             |
   | OSNMA       |
   | DSM-KROOT   |
   | TESLA       |
   | MAC checks  |
   | PVT checks  |
   +-------------+
        ^
        |
        | trusted UTC assistance
        |
     Linux host
```

The receiver then reports both low-level OSNMA processing state and the
high-level result relevant to an application: whether the current PVT
solution has been verified against NMA-authenticated data.

## Important security distinction

OSNMA is primarily **navigation-message authentication**.

It allows the receiver to establish that protected Galileo I/NAV
navigation data originated from Galileo and has not been modified
without detection.

GNSS positioning, however, also depends on physical signal timing and
ranging measurements. Navigation-message authentication alone does not
cryptographically prove that the RF signal travelled directly from the
satellite to the antenna without delay, relay, or rebroadcast.

Therefore:

``` text
OSNMA authentication PASS
        does not mean
all possible GNSS spoofing is impossible
```

A sophisticated attacker may, for example, relay or delay genuine
authenticated Galileo signals. The navigation data can remain
cryptographically authentic while the physical signal arrival time has
been manipulated. This class of attack is generally associated with
replay or meaconing.

OSNMA nevertheless substantially raises the difficulty of spoofing
because an attacker can no longer freely invent protected Galileo
navigation data and produce valid authentication for it.

## Why trusted time matters

OSNMA uses TESLA, a delayed-key-disclosure authentication scheme.

The receiver must know sufficiently trustworthy time so that it can
establish that navigation data and authentication tags were received
before the corresponding TESLA key was disclosed.

The X20P can receive independent time assistance from the host using:

``` text
UBX-MGA-INI-TIME_UTC
```

The script can mark this time as:

``` text
trustedSource = 1
```

This allows the X20P to compare its Galileo-derived time against
independently supplied trusted time.

This comparison is important for replay/delay detection. If an attacker
presents sufficiently old delayed Galileo material, the TESLA timing
relationship should no longer agree with the independent trusted-time
reference.

The X20P exposes the result through OSNMA time-synchronization and
trusted-time status.

This is why the combination:

``` text
authTime=1
trustedValid=1
SYNC status=passed
```

is meaningful.

It indicates that the receiver has a usable external trusted-time
reference and that the applicable time comparison has passed.

It does **not** transform OSNMA into complete physical ranging
authentication. It adds an important timing/replay consistency check to
navigation-message authentication.

The host must not blindly claim that its clock is trusted.
`--trust-system-time` is a security assertion made by this application.

For bench testing, a well-synchronized Linux clock may be suitable. For
a security-sensitive installation, document why the time source is
independent and trustworthy. Possible sources include authenticated
network time, a disciplined local clock, an RTC with an appropriate
trust model, PTP, or another independent timing system.

## X20P authentication and spoofing validity

Several different receiver outputs must be distinguished.

### `UBX-SEC-OSNMA`

This reports OSNMA protocol execution and current/recent authentication
activity.

The script displays information such as:

``` text
OSNMA  enabled=1
       headerAuth=1
       service=operational
       chain=1
       CPKS=nominal

AUTH   DSM=...
       PKID=2
       TESLA=...
       authSVs=...

TRUST  PK=aided-message
       Merkle=aided-message
       MerkleValid=1

SYNC   enabled=1
       status=...
```

Fields such as DSM authentication, TESLA authentication, `authSVs`, and
time synchronization are not necessarily persistent accumulated
counters.

For example, it is normal to observe:

``` text
DSM=not-performed
TESLA=not-performed
authSVs=0
SYNC status=not-performed
```

while the current PVT solution remains NMA-verified.

`not-performed` means that the corresponding authentication operation
was not performed for that particular report/processing event. It does
not mean that previously authenticated trust state has been lost.

### `UBX-NAV-PVT` and `nmaFixStatus`

For this project's high-level result, the most important field is:

``` text
nmaFixStatus
```

The script displays it as:

``` text
NMAFIX verified=1
```

and:

``` text
RESULT VALID FIX, NMA VERIFIED
```

When the X20P sets this status, the receiver is reporting that the
current PVT fix has been verified with NMA data.

This is stronger and more useful to an application than merely observing
that a TESLA key was successfully authenticated at some earlier instant.

However, it is still important to use precise terminology:

> `NMA VERIFIED` means that the X20P reports the current PVT solution as
> verified against NMA-authenticated navigation data. It does not mean
> that the physical ranges have received cryptographic range
> authentication or that every possible spoofing technique has been
> excluded.

The Galileo Signal Authentication Service (SAS) is intended to provide
complementary range-authentication capability.

### `authTime`

The script also displays:

``` text
authTime=1
```

This is separate from `nmaFixStatus`.

It indicates that output time has been validated against the external
trusted-time mechanism according to the X20P's applicable checks.

A particularly desirable operating state is therefore:

``` text
fixOK=1
NMAFIX verified=1
authTime=1
service=operational
CPKS=nominal
MerkleValid=1
```

This means:

1.  the receiver has a valid navigation fix;
2.  OSNMA is operational;
3.  the receiver reports the PVT fix as verified with NMA data;
4.  output time passes the trusted-time validation;
5.  the OSNMA chain/public-key state is nominal; and
6.  the stored/provisioned Merkle trust material is valid.

This is the main healthy state expected by this project.

## Per-satellite Galileo authentication with `UBX-NAV-SIG`

The latest script also polls:

``` text
UBX-NAV-SIG
```

This is especially useful when the high-level PVT state changes between:

``` text
PVT=NMA-VERIFIED
```

and:

``` text
PVT=NOT-NMA-VERIFIED
```

`UBX-NAV-SIG` reports individual GNSS signals for the current navigation
epoch. For Galileo (`gnssId=2`), the script decodes the signal type and
the `sigFlags.authStatus` bit.

The X20 documentation defines `authStatus` as indicating whether
authenticated navigation data was used to compute that satellite's
position in the current navigation epoch.

This gives a more useful diagnostic than the transient `UBX-SEC-OSNMA`
`authSVs` activity field.

The script prints a Galileo summary such as:

``` text
GAL      SVs=8  usedSVs=6  authSVsCurrentEpoch=4  usedAndAuthSVs=4
```

The fields mean:

``` text
SVs
    Number of Galileo SVs represented by the received UBX-NAV-SIG data.

usedSVs
    Galileo SVs for which at least one reported signal is being used for
    pseudorange, carrier-range, or Doppler/range-rate navigation.

authSVsCurrentEpoch
    Galileo SVs for which at least one signal reports authenticated
    navigation data for the current navigation epoch.

usedAndAuthSVs
    Galileo SVs that are both being used by navigation and report
    authenticated navigation data.
```

The script then prints each Galileo satellite and signal, for example:

``` text
GALSV    E04  E1B:AUTH,USED,C/N0=43,q=code+carrier
GALSV    E12  E1B:AUTH,USED,C/N0=39,q=code+carrier
GALSV    E16  E1B:unknown,USED,C/N0=37,q=code+carrier
GALSV    E31  E1B:AUTH,USED,C/N0=41,q=code+carrier
```

`AUTH` means the X20P reports authenticated navigation data for that
signal/SV in the current navigation epoch.

`unknown` means the `authStatus` bit is not asserted. It should **not**
automatically be interpreted as a cryptographic authentication failure
or proof of spoofing.

`USED` means that the signal contributes to navigation through at least
one of the pseudorange, carrier-range, or Doppler/range-rate usage flags
decoded by the script.

The script also reports signal C/N0 and quality information.

For Galileo E1 OSNMA monitoring, E1B is particularly relevant because
OSNMA is carried in the Galileo E1-B I/NAV message.

### Per-satellite colors

Per-satellite output uses the following display policy:

-   a Galileo SV with authenticated navigation data in the current epoch
    is shown in **green**;
-   a Galileo SV used by navigation but without the `authStatus`
    indication is shown in **red**;
-   a tracked Galileo SV that is neither authenticated nor currently
    used remains neutral.

Red in this diagnostic display means **authentication is not indicated
for that currently used SV**. It is an operator-attention state, not by
itself a declaration that spoofing has been detected.

### Diagnosing verified-to-unverified transitions

The purpose of adding `UBX-NAV-SIG` is to correlate the high-level PVT
result with the Galileo satellites available at that instant.

For example:

``` text
07:35:48
STATE    PVT=NMA-VERIFIED
GAL      ... authSVsCurrentEpoch=4  usedAndAuthSVs=4

07:35:57
STATE    PVT=NOT-NMA-VERIFIED
GAL      ... authSVsCurrentEpoch=1  usedAndAuthSVs=1

07:36:20
STATE    PVT=NMA-VERIFIED
GAL      ... authSVsCurrentEpoch=4  usedAndAuthSVs=4
```

The numbers above are illustrative only.

This correlation can help explain whether a temporary loss of PVT-level
NMA verification coincides with a reduction or change in the set of
Galileo satellites whose navigation data is authenticated.

Do not infer a fixed minimum number of authenticated Galileo SVs from
one observation. The X20P navigation engine determines whether the mixed
PVT solution can be verified, and the high-level `nmaFixStatus` remains
authoritative for the current PVT result.

## What `NMAFIX verified=0` means

Do not interpret every `verified=0` epoch as proof of spoofing.

The X20P can temporarily be unable to verify a particular PVT epoch
because sufficient authenticated navigation information is not currently
available.

During acquisition it is normal to see:

``` text
RESULT VALID FIX, CURRENT FIX NOT NMA VERIFIED
```

followed later by:

``` text
RESULT VALID FIX, NMA VERIFIED
```

The status may also move back to unverified if the receiver cannot
perform the NMA verification for the current solution.

For this reason the script preserves the most recent authenticated
position separately as `LASTAUTH`.

A persistent loss of NMA verification, failed OSNMA cryptographic
checks, failed trusted-time synchronization, non-nominal CPKS state, or
explicit spoofing/replay indicators deserves investigation. A single
unverified PVT epoch alone should not be labelled as a confirmed
spoofing attack.

## `LASTAUTH`

Whenever the current PVT fix has:

``` text
fixOK=1
nmaFixStatus=1
```

the script records that position as the most recent authenticated PVT
result.

Example:

``` text
LASTAUTH VERIFIED  time=2026-08-21T07:20:35Z \
lat=XX lon=XX \
hMSL=315.138 m hAcc=1.354 m
```

If the current PVT later becomes unverified, `LASTAUTH` remains
available.

This gives the operator both:

``` text
CURRENT POSITION / CURRENT NMA STATE
```

and:

``` text
MOST RECENT NMA-VERIFIED POSITION
```

Do not interpret `LASTAUTH` as authentication of a newer unverified
position. It is deliberately a historical last-known-authenticated
location.

## Terminal output, state, activity, and colors

The latest script deliberately separates **current navigation/trust
state** from **transient OSNMA processing activity**.

A healthy authenticated result looks conceptually like:

``` text
PVT      2026-08-21T07:30:45Z  fix=3D  fixOK=1  SV=20
POS      lat=XX  lon=XX  hMSL=316.597 m  hAcc=1.453 m
STATE    PVT=NMA-VERIFIED  TIME=AUTHENTICATED  OSNMA=OPERATIONAL  CPKS=NOMINAL
TRUST    HEADER=AUTHENTICATED  PKID=2  PK=aided-message  MERKLE=VALID  MERKLE_SRC=aided-message
ACTIVITY DSM=not-performed  TESLA=not-performed  newAuthSVs=0  timingAuth=not-authenticated  sync=not-performed
TIME     trustedValid=1  deltaValid=1  propAccuracy=1000 ms  delta=0 s + 3 ms  lastUpdate=0.0 s ago
RESULT   VALID FIX, NMA VERIFIED
LASTAUTH VERIFIED  time=2026-08-21T07:30:45Z  lat=XX  lon=XX  hMSL=316.597 m  hAcc=1.453 m
```

The separation is intentional.

`STATE` and `TRUST` describe the high-level condition relevant to the
current navigation solution and established OSNMA trust state.

`ACTIVITY` describes cryptographic or OSNMA operations represented by
the current status report. Values such as:

``` text
DSM=not-performed
TESLA=not-performed
newAuthSVs=0
timingAuth=not-authenticated
sync=not-performed
```

do **not** contradict:

``` text
PVT=NMA-VERIFIED
RESULT VALID FIX, NMA VERIFIED
```

For example, the receiver may already have authenticated the required
KROOT, TESLA keys, and navigation data. It does not need to perform a
new DSM or TESLA authentication operation on every PVT epoch.

For this reason the script treats `UBX-NAV-PVT.nmaFixStatus` as the
primary high-level indication that the **current PVT fix** has been
verified with NMA data. The transient `ACTIVITY` fields are displayed
separately and are not colored as failures merely because no new
authentication operation occurred.

The script uses ANSI terminal colors:

-   **Green** indicates a currently accepted/verified state, such as
    `PVT=NMA-VERIFIED`, valid trusted-time state,
    `RESULT VALID FIX, NMA VERIFIED`, and `LASTAUTH VERIFIED`.
-   **Red** indicates a current navigation state that is not
    NMA-verified, no valid navigation fix, invalid trusted-time state,
    or an explicit alert/error condition.
-   `ACTIVITY` is normally neutral because `not-performed` is not itself
    an authentication failure.

At startup the program prints:

``` text
Color legend: NMA VERIFIED / NOT NMA VERIFIED
```

The first label should appear green and the second red.

Use:

``` text
--no-color
```

when ANSI colors are undesirable, for example when producing plain-text
logs.

Copied terminal output may lose ANSI color formatting even though the
original terminal displayed it correctly.

## Provision once, then use monitor-only mode

For long-running OSNMA observation, the recommended workflow is to
provision the X20P with the required OSNMA cryptographic material once
and then leave that material untouched while monitoring.

Provisioning mode requires the Public Key certificate, PKID, and
Merkle-tree root. After the receiver has been provisioned, subsequent
script restarts should normally use:

``` bash
./x20p_osnma_sqlite.py \
    --device /dev/ttyACM0 \
    --baud 38400 \
    --monitor-only \
    --trust-system-time \
    --anonymity
```

In this mode the script prints:

``` text
Mode: MONITOR-ONLY (no Public Key/Merkle provisioning, no OSNMA CFG writes)
```

`--monitor-only` deliberately does **not** resend the OSNMA Public Key,
Merkle-tree root, or OSNMA configuration writes. It continues to refresh
trusted time when `--trust-system-time` is selected and continues
polling the receiver's OSNMA, PVT, per-satellite, and trusted-time
status.

This is useful when investigating acquisition and loss of
`nmaFixStatus`, because restarting the Python monitor does not introduce
unnecessary OSNMA provisioning/configuration operations.

### Note about re-sending cryptographic material

During development, no u-blox documentation was found stating that
simply re-sending the **same valid Public Key and Merkle-tree root**
explicitly resets the X20P's accumulated authenticated-navigation state.

Therefore this project does **not** claim that re-sending identical
valid cryptographic material necessarily resets OSNMA authentication.

Nevertheless, repeatedly provisioning the receiver while investigating
authentication acquisition is unnecessary and introduces another
variable into the experiment. The recommended operational pattern is
consequently:

``` text
1. Provision the correct OSNMA Public Key and Merkle root.
2. Leave the receiver powered and the provisioned material untouched.
3. Restart the Python program in --monitor-only mode when necessary.
4. Continue supplying trusted time with --trust-system-time.
5. Wait for the receiver itself to assert nmaFixStatus=1.
```

A Python process restart still clears the script's in-memory
`LAST VERIFIED FIX+TIME` history. It does **not** by itself mean that
the X20P has lost its OSNMA cryptographic state. A newly started monitor
therefore reports no historical verified fix until it observes a new
qualifying PVT epoch.

## Authoritative verified fix + time

For the project's simple high-confidence indication, a PVT epoch is
accepted as `VERIFIED FIX+TIME` only when the **same `UBX-NAV-PVT`
message** satisfies:

``` text
gnssFixOK       = 1
nmaFixStatus    = 1
authTime        = 1
validDate       = 1
validTime       = 1
fullyResolved   = 1
```

The script also records that PVT message's `iTOW`, so the accepted
position and UTC time remain tied to one exact receiver navigation
epoch.

A successful current result is printed as:

``` text
VERIFY   FIX+TIME=YES  NMA_FIX=NMA-VERIFIED  TIME=AUTHENTICATED
         UTC_VALID=1  UTC_RESOLVED=1

RESULT   VERIFIED FIX+TIME
         utc=2026-08-21TXX:XX:XXZ
         iTOW=XX ms
         lat=XX
         lon=XX
         hMSL=XX m
         hAcc=XX m
```

If a later PVT epoch is not NMA-verified, the current result is rejected
while the last accepted epoch remains historical knowledge:

``` text
RESULT   CURRENT FIX NOT FULLY VERIFIED
         NMA=0  authTime=1  utcValid=1  utcResolved=1

LAST VERIFIED FIX+TIME
         utc=2026-08-21TXX:XX:XXZ
         iTOW=XX ms
         lat=XX
         lon=XX
```

`LAST VERIFIED FIX+TIME` means **the most recent PVT epoch observed by
this running process for which both the fix-verification and
trusted-time criteria were satisfied**. It must not be interpreted as
saying that the receiver is still located at that historical position.

## Log anonymity

Use:

``` text
--anonymity
```

when collecting logs that may be copied or shared. Coordinate output is
masked while retaining the fractional component needed to observe
short-term movement and GNSS noise, for example:

``` text
lat=XXXX.XXXXXXXX
lon=XXXX.XXXXXXXX
```

This masking applies to current PVT output, `RESULT VERIFIED FIX+TIME`,
and `LAST VERIFIED FIX+TIME`.

## Observed verification behavior in monitor-only operation

A long-running monitor-only test confirmed the intended operating model:
the X20P can move naturally between NMA-unverified and NMA-verified PVT
epochs **without re-provisioning the Public Key or Merkle-tree root**.

For example, one observed sequence was:

``` text
08:31:22  RESULT VERIFIED FIX+TIME
08:31:24  RESULT CURRENT FIX NOT FULLY VERIFIED
08:31:26  RESULT CURRENT FIX NOT FULLY VERIFIED
08:31:28  RESULT VERIFIED FIX+TIME
```

During this sequence, trusted time remained valid and the receiver
continued reporting normal OSNMA operation. This is important
operational evidence that a temporary loss of `nmaFixStatus` does not by
itself mean that the OSNMA cryptographic material has been lost, that
the receiver must be re-provisioned, or that spoofing has been detected.

The receiver should therefore normally be left running and observed in
`--monitor-only` mode. Verification may appear, disappear, and later
return as the authenticated Galileo data available to the receiver,
satellite use, geometry, cross-authentication state, and the receiver's
internal mixed-solution verification conditions change.

### Do not infer a fixed authenticated-SV threshold

The same observation also showed an NMA-verified PVT while the
diagnostic summary reported:

``` text
authSVsCurrentEpoch=5
usedAndAuthSVs=4
```

Immediately preceding epochs with similar simple counts were not
NMA-verified.

Therefore `usedAndAuthSVs` and `authSVsCurrentEpoch` must remain
**diagnostic fields only**. This project must not implement a rule such
as:

``` text
usedAndAuthSVs >= 5  => verified
```

or any other locally chosen satellite-count threshold.

The authoritative indication for the current navigation solution is the
X20P's own `UBX-NAV-PVT.nmaFixStatus`. The receiver has information and
internal verification logic that cannot be reconstructed reliably from a
simple count printed by this script.

### Practical interpretation

For an application that needs authenticated location and time, wait for:

``` text
RESULT   VERIFIED FIX+TIME
```

That line means the same PVT epoch satisfied the script's conservative
acceptance criteria (`gnssFixOK`, `nmaFixStatus`, `authTime`, valid UTC
date/time, and fully resolved UTC).

If the following epoch becomes unverified, retain:

``` text
LAST VERIFIED FIX+TIME
```

only as **historical authenticated knowledge**: it identifies the last
position/time epoch that was verified when produced. It does not claim
that the receiver is still at that position.

A later `RESULT VERIFIED FIX+TIME` replaces it with the newly verified
PVT epoch.

This observed verified → unverified → verified sequence is also a useful
reason to prefer continuous monitoring over repeatedly provisioning the
receiver while waiting for authentication.

## Requirements

Linux with Python 3.

On Debian:

``` bash
sudo apt install python3-serial python3-cryptography
```

The serial user must have permission to access the X20P device.

Typical devices are:

``` text
/dev/ttyACM0
/dev/ttyUSB0
```

## Project provenance and upstream `galileo-osnma` dependency

This project did not start by implementing the Galileo OSNMA
cryptographic protocol itself. The initial investigation used Daniel
Estévez's `galileo-osnma` project as an important reference
implementation and as the source of practical Linux utilities for
handling official Galileo OSNMA cryptographic material:

``` text
https://github.com/daniestevez/galileo-osnma.git
```

Upstream describes `galileo-osnma` as a Rust implementation of Galileo
Open Service Navigation Message Authentication. It processes Galileo
navigation message and OSNMA cryptographic data and verifies the
cryptographic chain against an ECDSA public key and/or Merkle-tree root.

The upstream documentation was especially useful for understanding the
trust chain:

``` text
GSC Merkle-tree root
        |
        v
authenticate broadcast OSNMA public key
        |
        v
authenticate TESLA root/key chain
        |
        v
authenticate MACK tags
        |
        v
authenticate Galileo navigation-message data
```

That upstream implementation and the Galileo OSNMA specifications
provided the protocol-level background. This project then moved in a
different direction: instead of independently performing OSNMA
authentication in software, it uses the **u-blox X20P's built-in OSNMA
implementation** and reads the receiver's UBX status/PVT messages to
determine when the receiver considers navigation data and the resulting
PVT solution authenticated.

The development path was approximately:

``` text
1. Obtain official OSNMA Public Key / PKID / Merkle-tree material.
2. Use galileo-osnma utilities to inspect and extract that material.
3. Determine how X20P accepts OSNMA aiding material over UBX.
4. Provision the X20P from Linux over its serial interface.
5. Read X20P PVT, OSNMA, trusted-time and per-satellite status.
6. Distinguish instantaneous authentication activity from PVT verification.
7. Define the strict VERIFIED FIX+TIME indication.
8. Add monitor-only operation so receiver authentication state can accumulate.
9. Add per-Galileo-SV diagnostics.
10. Add optional SQLite history logging.
11. Add the read-only terminal timeline viewer for long-term analysis.
```

### Upstream utilities are still part of the workflow

The `galileo-osnma` repository is **not merely a historical reference**.
The current material-preparation workflow still relies on scripts in its
`utils/` directory, in particular:

``` text
galileo-osnma/utils/extract_merkle_tree_root.py
```

Other useful upstream conversion/extraction utilities include:

``` text
galileo-osnma/utils/extract_public_key.py
galileo-osnma/utils/extract_merkle_tree_key.py
galileo-osnma/utils/sec1_to_pem.py
```

These utilities should be treated as **upstream dependencies/tools**,
not as code maintained by this X20P monitor project. Do not silently
copy or rewrite them into this project unless there is a deliberate
decision to vendor them and preserve the applicable upstream licensing
and provenance.

The current X20P logger itself does **not** import or execute the Rust
`galileo-osnma` authentication engine while monitoring. Authentication
of the live navigation solution is performed by the X20P firmware. The
upstream repository is used for protocol understanding, cross-checking
the OSNMA trust model, and preparation/conversion of official
cryptographic material.

## Obtaining OSNMA cryptographic material

Current Galileo OSNMA cryptographic material is distributed through the
European GNSS Service Centre (GSC).

The receiver requires the applicable:

``` text
Public Key
Public Key ID (PKID)
Merkle-tree root
```

Keep this material current. OSNMA includes public-key and chain renewal
mechanisms, and a production implementation should monitor key/chain
status rather than assuming that one provisioned key remains valid
indefinitely.

## `galileo-osnma` helper repository

Daniel Estévez's Galileo OSNMA implementation is an upstream reference
and an active material-preparation dependency for this project:

``` text
https://github.com/daniestevez/galileo-osnma.git
```

Clone it with:

``` bash
git clone https://github.com/daniestevez/galileo-osnma.git
cd galileo-osnma
```

The repository contains utilities including:

``` text
utils/extract_merkle_tree_root.py
utils/extract_public_key.py
utils/extract_merkle_tree_key.py
utils/sec1_to_pem.py
```

`extract_merkle_tree_root.py`, used in this project to obtain the
256-bit Merkle root from the GSC XML product, originates from this
repository.

## Extracting the Merkle-tree root

Given a GSC file such as:

``` text
OSNMA_MerkleTree_20251210100000_newPKID_2.xml
```

run:

``` bash
./utils/extract_merkle_tree_root.py \
    OSNMA_MerkleTree_20251210100000_newPKID_2.xml
```

Example output:

``` text
[MERKLE-ROOT-STRING]
```

This is supplied to the X20P utility with:

``` text
--merkle-root
```

## Public Key certificate

The script accepts the GSC OSNMA X.509 Public Key certificate directly:

``` text
OSNMA_PublicKey_20251210100000_newPKID_2.crt
```

and the corresponding PKID:

``` text
--pkid 2
```

Python `cryptography` extracts the EC public key and encodes its
compressed SEC1 point for the X20P `UBX-MGA-GAL-OSNMA_PUBKEY` message.

There is therefore no need to manually convert the certificate to PEM
for this utility.

## Example preparation

Assume:

``` text
OSNMA_PublicKey_20251210100000_newPKID_2.crt
OSNMA_MerkleTree_20251210100000_newPKID_2.xml
```

Extract the root:

``` bash
git clone https://github.com/daniestevez/galileo-osnma.git

./galileo-osnma/utils/extract_merkle_tree_root.py \
    OSNMA_MerkleTree_20251210100000_newPKID_2.xml
```

Record the resulting 64-character hexadecimal root.

Confirm the Linux clock if it will be asserted as trusted:

``` bash
timedatectl
chronyc tracking
chronyc sources -v
```

## Running the utility

Example:

``` bash
./x20p_osnma_sqlite.py \
    --device /dev/ttyACM0 \
    --baud 38400 \
    --pubkey-cert OSNMA_PublicKey_20251210100000_newPKID_2.crt \
    --pkid 2 \
    --merkle-root [MERKLE-ROOT-STRING] \
    --trust-system-time
```

The program:

1.  opens the X20P serial interface;
2.  extracts the EC Public Key from the certificate;
3.  sends `UBX-MGA-GAL-OSNMA_PUBKEY`;
4.  sends `UBX-MGA-GAL-OSNMA_MERKLE`;
5.  enables OSNMA;
6.  enables OSNMA time synchronization;
7.  optionally supplies trusted Linux UTC;
8.  polls OSNMA status;
9.  polls trusted-time status;
10. polls PVT;
11. polls `UBX-NAV-SIG` for per-satellite Galileo authentication state;
12. displays current trust state separately from transient OSNMA
    activity;
13. displays per-Galileo-SV authentication/use state; and
14. retains the latest NMA-verified position.

## Monitor-only mode

After provisioning, the material is retained by the receiver according
to the X20P OSNMA/NVS behavior.

To monitor without reprovisioning, use:

``` bash
./x20p_osnma_sqlite.py \
    --device /dev/ttyACM0 \
    --baud 38400 \
    --pubkey-cert OSNMA_PublicKey_20251210100000_newPKID_2.crt \
    --pkid 2 \
    --merkle-root [MERKLE-ROOT-STRING] \
    --trust-system-time \
    --monitor-only
```

The current script still requires the material arguments because of its
command-line parser even in monitor-only mode. This can be relaxed in a
future version.

## Successful acquisition

Initial output may contain a valid navigation fix before the current PVT
solution has been NMA-verified:

``` text
PVT      ... fix=3D fixOK=1
POS      lat=XX lon=XX ...

STATE    PVT=NOT-NMA-VERIFIED  TIME=AUTHENTICATED
         OSNMA=OPERATIONAL  CPKS=NOMINAL

TRUST    HEADER=AUTHENTICATED  PKID=2
         PK=aided-message  MERKLE=VALID
         MERKLE_SRC=aided-message

ACTIVITY DSM=DSM-KROOT-authenticated
         TESLA=authenticated
         newAuthSVs=3
         ...

RESULT   VALID FIX, CURRENT FIX NOT NMA VERIFIED
LASTAUTH no NMA-verified position observed yet
```

This is not necessarily a failure. The receiver may still be
accumulating sufficient authenticated navigation information to verify
the current PVT solution.

A successful steady state looks like:

``` text
PVT      ... fix=3D fixOK=1
POS      lat=XX lon=XX ...

STATE    PVT=NMA-VERIFIED  TIME=AUTHENTICATED
         OSNMA=OPERATIONAL  CPKS=NOMINAL

TRUST    HEADER=AUTHENTICATED  PKID=2
         PK=aided-message  MERKLE=VALID
         MERKLE_SRC=aided-message

ACTIVITY DSM=not-performed
         TESLA=not-performed
         newAuthSVs=0
         timingAuth=not-authenticated
         sync=not-performed

GAL      SVs=XX  usedSVs=XX
         authSVsCurrentEpoch=XX  usedAndAuthSVs=XX

GALSV    EXX  E1B:AUTH,USED,C/N0=XX,q=code+carrier
GALSV    EXX  E1B:unknown,USED,C/N0=XX,q=code+carrier

RESULT   VALID FIX, NMA VERIFIED
LASTAUTH VERIFIED  time=... lat=XX lon=XX ...
```

This is the primary success result.

## Why `not-performed` activity can coexist with `NMA VERIFIED`

After successful authentication it is normal to observe:

``` text
STATE    PVT=NMA-VERIFIED
ACTIVITY DSM=not-performed  TESLA=not-performed  newAuthSVs=0
RESULT   VALID FIX, NMA VERIFIED
```

These fields have different scopes.

The `STATE` line includes the PVT-level NMA result. `PVT=NMA-VERIFIED`
means the X20P reports the current navigation solution as verified with
NMA data.

The `ACTIVITY` line reports OSNMA processing represented by the current
`UBX-SEC-OSNMA` status. `DSM=not-performed` or `TESLA=not-performed`
means no corresponding new authentication operation is reported for that
event. It does not mean that previously authenticated KROOT, TESLA, or
navigation data have been discarded.

Likewise:

``` text
newAuthSVs=0
```

should be read as an activity/result count for the current report, not
as a persistent statement that the receiver has no authenticated
navigation information.

This distinction was confirmed during testing: the X20P continued to
report:

``` text
PVT=NMA-VERIFIED
RESULT VALID FIX, NMA VERIFIED
```

across consecutive PVT epochs while the activity fields simultaneously
reported `not-performed` and `newAuthSVs=0`.

The utility therefore uses `UBX-NAV-PVT.nmaFixStatus` as its primary
high-level current-fix authentication indication.

## Trusted-time output

Typical output:

``` text
TIME   trustedValid=1
       deltaValid=1
       propAccuracy=1000 ms
       delta=0 s + 2 ms
       lastUpdate=0.0 s ago
```

The utility caches the most recent `UBX-NAV-TIMETRUSTED` result.

If one poll response is missed, the last known trusted-time state
remains visible with an increasing `lastUpdate` age rather than
immediately reporting a security failure.

A stale cached value should not be treated indefinitely as proof that
trusted time remains healthy. A future production version should apply
an explicit maximum acceptable age.

## Interpreting suspicious states

The following deserve attention:

``` text
service != operational
CPKS != nominal
MerkleValid=0
headerAuth=0 for an extended period
TESLA authentication failed
DSM authentication failed
time synchronization failed
trustedValid=0
authTime=0
persistent nmaFixStatus=0 after previously stable authentication
OSNMA monitor error flags
```

The strongest interpretation should come from the combination of fields
rather than one transient value.

For example:

``` text
fixOK=1
nmaFixStatus=0
```

alone means that a navigation fix exists but the current PVT solution is
not being reported as NMA-verified.

It does not by itself prove spoofing.

Conversely:

``` text
nmaFixStatus=1
authTime=1
```

is strong evidence that the X20P's OSNMA and trusted-time consistency
mechanisms accept the current solution, but it is still not equivalent
to cryptographic authentication of every physical pseudorange.

## What the X20P contributes to spoofing detection

The X20P's value is not merely that it exposes raw OSNMA bits.

It integrates OSNMA into the receiver and can:

-   validate OSNMA cryptographic material;
-   authenticate the NMA header;
-   authenticate DSM-KROOT/public-key chain information;
-   authenticate TESLA keys;
-   authenticate Galileo navigation data;
-   track authenticated navigation information per signal;
-   compare trusted external time against Galileo-derived time;
-   expose OSNMA timing/replay-related failures;
-   indicate whether output time passes trusted-time validation; and
-   indicate whether the current PVT fix has been verified with NMA
    data.

This gives an application a much more useful integrity picture than
simply running a standalone cryptographic check on captured navigation
messages.

Still, OSNMA should be viewed as one layer in a spoofing-resilient GNSS
design.

For stronger protection, combine it with relevant receiver capabilities
and independent checks such as:

``` text
trusted external time
receiver spoofing/jamming indicators
multi-band consistency
multi-constellation consistency
Doppler consistency
signal-level monitoring
inertial sensors
known-position/geofence constraints
external timing or position references
```

## Recommended application policy

For this project a practical interpretation is:

``` text
GREEN / ACCEPTED
    fixOK=1
    PVT=NMA-VERIFIED (`nmaFixStatus=1`)
    OSNMA service operational
    CPKS nominal
    Merkle valid
    trusted-time state acceptable for the deployment

RED / NOT CURRENTLY AUTHENTICATED
    no valid fix
    or PVT=NOT-NMA-VERIFIED (`nmaFixStatus=0`)

ALERT / INVESTIGATE
    cryptographic authentication failure
    trusted-time failure
    replay/spoofing indication
    non-nominal chain/key state
    persistent loss of verification
```

Do not silently convert a red/unverified current fix into green merely
because a previous fix was verified.

Instead, use the separately displayed green `LASTAUTH VERIFIED` value as
the historical last-known-authenticated position.

## SQLite history database

The current logger can optionally record the receiver state to SQLite
for long-term observation. This is intentionally separate from the
authentication decision itself: the database records what the receiver
reported at each epoch, while later analysis derives trends such as
verification availability and the age of the last verified fix.

On Debian, install the SQLite command-line client with:

``` bash
sudo apt install sqlite3
```

Run the current logger with a database path, for example:

``` bash
./x20p_osnma_sqlite.py \
    --device /dev/ttyACM0 \
    --baud 38400 \
    --monitor-only \
    --trust-system-time \
    --anonymity \
    --db /var/log/x20p-osnma/status.sqlite3
```

Without `--db`, database logging is disabled.

`--anonymity` anonymizes latitude and longitude in terminal output. The
database is intended as the analysis record and may contain the actual
numeric position values; protect or relocate the database accordingly if
location privacy is required.

### Database contents

### SQLite state captured

For each PVT epoch, the logger preserves the state needed for later
trend analysis: normal fix validity, `nmaFixStatus`, `authTime`, UTC
validity/resolution, strict `verified_fix_time`, OSNMA
header/CPKS/TESLA/DSM/time-sync status, trusted-time state, Galileo
authentication/use counts, horizontal accuracy, coordinates, PVT `iTOW`,
NAV-SIG `iTOW`, and whether the PVT/NAV-SIG epochs match. Individual
Galileo signal observations are stored separately.

The database contains two principal tables:

``` text
epochs
galileo_signals
```

`epochs` contains one row per observed PVT epoch. It records the normal
fix state, NMA verification state, authenticated-time state, UTC
validity, `verified_fix_time`, OSNMA/trusted-time information, Galileo
satellite counts, accuracy, position, and navigation epoch identifiers.

`galileo_signals` contains the individual Galileo signal observations
associated with an epoch, including satellite/signal identity,
authentication indication, usage flags, C/N0, signal quality, health,
and related diagnostic information.

The important distinction is:

``` text
epochs.verified_fix_time = 1
```

means that the logger's strict `VERIFIED FIX+TIME` criteria were
satisfied for that recorded epoch. Per-satellite authentication counts
are useful diagnostic evidence but are not a replacement for this
PVT-level result.

Values such as **verification age** are deliberately derived later
rather than stored as authoritative receiver facts. Verification age
means:

``` text
current epoch time - time of most recent VERIFIED FIX+TIME epoch
```

Thus a new verified epoch resets the age to zero. If valid navigation
continues while current NMA verification is absent, the age increases.

### Inspecting the database

Open it interactively:

``` bash
sqlite3 /var/log/x20p-osnma/status.sqlite3
```

Useful SQLite commands are:

``` sql
.tables
.schema epochs
.schema galileo_signals
.headers on
.mode column
```

Show recent epochs:

``` sql
SELECT
    receiver_utc,
    fix_ok,
    nma_fix_verified,
    auth_time,
    verified_fix_time,
    gal_auth_sv_count,
    gal_used_auth_sv_count
FROM epochs
ORDER BY id DESC
LIMIT 20;
```

Show only strict verified fix+time epochs:

``` sql
SELECT
    receiver_utc,
    itow_ms,
    lat,
    lon,
    h_acc_m
FROM epochs
WHERE verified_fix_time = 1
ORDER BY id DESC
LIMIT 20;
```

A one-shot shell query can also be used:

``` bash
sqlite3 -header -column /var/log/x20p-osnma/status.sqlite3 \
'SELECT receiver_utc,verified_fix_time,gal_used_auth_sv_count
 FROM epochs ORDER BY id DESC LIMIT 20;'
```

The logger and database should normally be left running continuously.
This preserves verified -\> unverified -\> verified transitions instead
of examining only isolated receiver snapshots.

## Terminal timeline visualization

`x20p_osnma_timeline.py` is a separate **read-only** analysis tool for
the SQLite history. It does not configure the X20P and does not modify
the database. It requires only Python 3 standard-library modules.

Example:

``` bash
./x20p_osnma_timeline.py \
    --db /var/log/x20p-osnma/status.sqlite3 \
    --hours 1
```

A shorter window can be selected with a fractional hour:

``` bash
./x20p_osnma_timeline.py \
    --db /var/log/x20p-osnma/status.sqlite3 \
    --hours 0.5
```

For a continuously refreshed terminal view:

``` bash
watch -n 5 './x20p_osnma_timeline.py \
    --db /var/log/x20p-osnma/status.sqlite3 \
    --hours 2'
```

The display is designed to make the difference between ordinary GNSS
availability and authenticated navigation immediately visible:

``` text
FIX      |████████████████████████████████|  100.0% valid
NMA      |░░██░░████░░░██░████░░░░███░░|   40.1% verified
TIME     |████████████████████████████████|  100.0% authenticated
GAL-AUTH |▅▅████▅▅████████▅█████████████|  4-6 SV
AGE      |▁▂▃▁▁▂▃▄▁▁▂▃▄▅▆▇▁▂▃▄▅▆▇█▁▁|  max 1m 30s
```

The rows mean:

-   **FIX** -- a normal valid GNSS position fix was available.
-   **NMA** -- Navigation Message Authentication at the final solution
    level: the current epoch satisfied the strict `VERIFIED FIX+TIME`
    criteria.
-   **TIME** -- the receiver reported authenticated/trusted time.
-   **GAL-AUTH** -- number of Galileo satellites that were both
    authenticated and used (`gal_used_auth_sv_count`). This is
    diagnostic and is not itself the final verification decision.
-   **AGE** -- elapsed time since the most recent `VERIFIED FIX+TIME`
    epoch. It resets to zero when another verified epoch appears and
    rises while the current fix is not fully verified.

The summary below the timeline reports the current verification state,
age of the last verified result, last verified UTC epoch, NMA
availability over the selected window, longest unverified gap, and
authenticated+used Galileo SV range.

For example:

``` text
Current: VERIFIED  verification age: 0s
Last verified: 2026-08-21T09:26:00Z  hAcc=1.441 m
Window: 509 epochs  NMA availability=40.1%  longest unverified gap=1m 30s
Galileo auth+used: current=6  window range=4-6
```

This should be interpreted as follows: normal GNSS may remain
continuously valid while strict NMA verification appears only
intermittently. `TIME` can also remain authenticated throughout those
gaps. The `NMA` row and verification-age row therefore provide the
clearest long-term view of when the receiver actually produced a
verified position+time epoch and how old the most recent such result has
become.

Do **not** infer a fixed NMA-verification threshold from `GAL-AUTH`.
Observed verification can change while the authenticated+used Galileo
count remains in the same range. The X20P's reported PVT-level NMA
result remains authoritative for this monitor.

For long windows, use:

``` bash
./x20p_osnma_timeline.py \
    --db /var/log/x20p-osnma/status.sqlite3 \
    --hours 24 \
    --fractional
```

`--fractional` shades each FIX/NMA/TIME time bucket according to the
fraction of samples satisfying that state. This is preferable when many
receiver epochs are compressed into each terminal character.

Other useful options are:

``` text
--width N       explicitly choose plot width
--no-color      disable ANSI colors
```

The viewer otherwise adapts to the current terminal width automatically.

### Recommended long-term interpretation

For continuous observation, the most useful measurements are:

``` text
normal fix availability
NMA verified-fix+time availability
current verification age
longest unverified interval
authenticated+used Galileo SV count
horizontal accuracy
```

A particularly useful pattern is:

``` text
FIX   continuously valid
TIME  continuously authenticated
NMA   intermittent
AGE   repeatedly rises and resets
```

This does not mean that ordinary positioning stopped working. It means
that the receiver continued to navigate, but only some PVT epochs met
the stricter authenticated fix+time condition. The SQLite history makes
those transitions persistent, while the terminal timeline makes their
frequency and duration easy to inspect.

## References

u-blox ZED-X20P Integration Manual:

``` text
https://content.u-blox.com/sites/default/files/documents/ZED-X20P_IntegrationManual_UBXDOC-963802114-12901.pdf
```

u-blox X20 HPG Interface Description:

``` text
https://content.u-blox.com/
```

Galileo OSNMA service:

``` text
https://www.gsc-europa.eu/galileo/services/galileo-open-service-navigation-message-authentication-osnma
```

Current Galileo OSNMA reference documents:

``` text
https://www.gsc-europa.eu/electronic-library/programme-reference-documents/galileo-in-force/osnma
```

`galileo-osnma` reference implementation and utilities:

``` text
https://github.com/daniestevez/galileo-osnma.git
```

## Current project status

The monitor/logger utilities, including `x20p_osnma_sqlite.py`, have
been tested with a serial-attached X20P and has observed the expected
transition from a valid but not-yet-NMA-verified PVT solution to:

``` text
RESULT VALID FIX, NMA VERIFIED
```

with:

``` text
authTime=1
service=operational
CPKS=nominal
MerkleValid=1
```

The receiver has also demonstrated that transient `DSM`, `TESLA`,
`authSVs`, and `SYNC` execution fields can return to `not-performed`
while `nmaFixStatus=1` remains asserted. This is why the utility treats
the PVT-level NMA verification result as its primary current-fix
authentication indicator.

## Summary clarification

### OSNMA, trusted time, and future SAS

In short:

-   **OSNMA authenticates Galileo navigation-message data.** On the
    X20P, authenticated Galileo information can also be used to
    cross-check the complete/mixed GNSS navigation solution. When the
    receiver reports `nmaFixStatus=1`, the current PVT solution has
    passed the X20P's NMA verification.
-   **OSNMA does not cryptographically authenticate the physical ranging
    signal itself.** Genuine Galileo signals and authentic navigation
    messages can potentially be rebroadcast or delayed
    (meaconing/replay), so OSNMA alone should not be described as making
    GNSS immune to every spoofing technique.
-   **X20P trusted time provides an independent time constraint for
    OSNMA.** It helps the receiver detect excessively delayed/replayed
    authentic OSNMA data. `authTime=1` indicates that the output time
    has been validated against the trusted-time source.
-   In this project, **`nmaFixStatus=1` together with `authTime=1`**
    (plus valid/resolved UTC and a valid GNSS fix) is used to produce
    `RESULT VERIFIED FIX+TIME`: a navigation result verified against
    authenticated Galileo data and tied to a trusted time epoch.
-   **Galileo SAS (Signal Authentication Service)** is relevant to the
    remaining signal-level problem. SAS is intended to add
    authentication evidence for the received ranging signal itself,
    strengthening detection of sophisticated spoofing,
    signal-generation, replay, and meaconing attacks.

Conceptually:

``` text
OSNMA
  -> authenticates navigation-message data
  -> X20P cross-checks the PVT solution against authenticated Galileo data
  -> nmaFixStatus=1

X20P trusted time
  -> independent time constraint for OSNMA
  -> helps constrain delayed/replayed authentic messages
  -> authTime=1

nmaFixStatus=1 + authTime=1
  -> verified navigation fix tied to trusted time
  -> RESULT VERIFIED FIX+TIME

Future SAS
  -> adds signal/ranging authentication evidence
  -> addresses an assurance gap that OSNMA alone does not cover

OSNMA + trusted time + SAS
  -> authenticated navigation data
  + trusted time/replay constraint
  + signal/ranging authentication evidence
  -> substantially stronger GNSS spoofing protection
```
