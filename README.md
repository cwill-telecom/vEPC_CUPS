# vEPC_cups_python — CUPS-vEPC + full LTE/EPC simulator

A high-fidelity, scriptable **Python simulation of a 4G LTE/Evolved Packet Core**, covering
both the 3GPP **CUPS** split-gateway architecture (Control/User Plane Separation, TS 23.214)
and the surrounding network (UE, eNB, MME, HSS, PCRF, PDN) so a complete **EPS attach** can be
driven end-to-end over real UDP sockets.

Everything is **stdlib-only** — no third-party packages. Nodes are ordinary OS processes (or
in-process objects) that talk to each other with real protocol messages over loopback UDP;
each protocol has a small, explicitly documented codec under `protocols/`.

The CUPS half follows the Affirmed vEPC CUPS design and the `cwill-telecom/vEPC_python` layout
(one module per functional entity, global config at the top of each component, threaded UDP
servers, protocol codecs under `protocols/`).

---

## Architecture

```
Full EPS / EPC
                                                      S6a (Diameter)
                              ┌──────────────────────────────────────────┐
                              │                                          ▼
   ┌────┐   Uu    ┌─────┐  S1-MME (S1AP)  ┌─────┐  S11 (GTPv2-C)  ┌───────┐  Sxa (PFCP)  ┌───────┐
   │ UE │────────▶│ eNB │────────────────▶│ MME │────────────────▶│ SGW-C │─────────────▶│ SGW-U │
   └────┘         └─────┘                 └─────┘                 └───────┘              └───────┘
                     │                                               S5-C (GTPv2-C)          ▲
                     │                                                  │                   │ S5-U
                     │ S1-U (GTP-U)                                     ▼                   │
                     └──────────────────────────────────────────────▶ SGW-U ──S5-U──▶ PGW-U ─┘
                                                                     PGW-C ──Sxb (PFCP)──▶ PGW-U
                                                                       │  Gx (Diameter)
                                                                       ▼
                                                                     PCRF          PGW-U ──SGi──▶ PDN
```

CUPS-only view (the split gateways):

```
   UE ──LTE── eNB ──S1-U────────────────────────────▶ SGW-U ──S5-U──▶ PGW-U ──SGi──▶ PDN
                 │ S1-C                                  ▲             ▲
                 ▼                                       │ Sxa         │ Sxb   (PFCP / UDP 8805)
                MME ──S11──▶ SGW-C ──S5-C──▶ PGW-C ──────┴─────────────┘
                                                                  (CPF: GTP-C, Diameter Gx/Gy/Gz)
```

**Two ways to run the CUPS split gateways**

* **CUPS-only mode** — `core/sgw_c.py` / `core/pgw_c.py` + `core/sgw_u.py` / `core/pgw_u.py`
  drive each other purely over PFCP (Sxa/Sxb) and are driven by `simulators/cups_simulator.py`
  or `run_stack.py`.
* **EPC mode** — `core/epc_sgw_c.py` / `core/epc_pgw_c.py` add the S11/S5-C/Gx legs and reuse
  the same PFCP `CPF` engine to talk to the UPFs, so the MME can drive real session setup.

---

## Repository layout

```
vEPC_cups_python/
├── core/
│   ├── cpf.py            Control Plane Function engine (Sx node/session procedures)
│   ├── upf.py            User Plane Function engine (PDR/FAR/QER/URR pipeline)
│   ├── sgw_c.py          SGW-C (CUPS-only)     ── Sxa
│   ├── pgw_c.py          PGW-C (CUPS-only)     ── Sxb
│   ├── sgw_u.py          SGW-U (UPF)           ── Sxa
│   ├── pgw_u.py          PGW-U (UPF, embedded TDF) ── Sxb
│   ├── epc_sgw_c.py      SGW-C for the EPC     ── S11 + S5-C + Sxa
│   ├── epc_pgw_c.py      PGW-C for the EPC     ── S5-C + Gx + Sxb
│   ├── hss.py            HSS                   ── S6a (AIR/AIA, ULR/ULA)
│   ├── pcrf.py           PCRF                  ── Gx (CCR/CCA)
│   ├── mme.py            MME                   ── S1-MME + S6a + S11
│   ├── enb.py            eNB                   ── S1-MME + S1-U + Uu
│   ├── ue.py             UE                    ── NAS/EMM+ESM over Uu
│   ├── pdn.py            External packet network ── SGi
│   └── gtpu.py           GTP-U relay (TEID forwarding) used by eNB/UPFs
├── protocols/
│   ├── pfcp.py           PFCP  (TS 29.244)      Sx / Sxa / Sxb
│   ├── gtp.py            GTP-U (TS 29.281)      S1-U / S5-U
│   ├── gtp_c.py          GTPv2-C (TS 29.274)    S11 / S5-C
│   ├── diameter.py       Diameter base + S6a + Gx
│   ├── nas.py            NAS (EMM/ESM, TS 24.301)  Uu
│   └── s1ap.py           S1AP (TS 36.413)          S1-MME
├── network/              udp_server.py, udp_client.py
├── sxcups/               rules.py (PDR/FAR/QER/URR/BAR), session.py, reporting.py
├── simulators/
│   ├── cups_simulator.py CUPS demo (in-process)
│   └── epc_simulator.py  Full EPC demo (in-process)
├── tests/                test_pfcp.py, test_epc.py
├── run_stack.py          Full CUPS stack as separate processes
├── run_epc.py            Full EPC as separate processes (--web dashboard)
├── capture_pfcp.py       In-process raw PFCP wiretap -> hexdump + pcap
├── core/webdash.py       Live web dashboard (stdlib http.server) over control sockets
└── utils/utils.py        logging, addresses, timers
```

---

## Requirements

* Python **3.8+** (developed on 3.11) — **standard library only**.
* No external services. All nodes bind distinct loopback addresses in `127.0.0.0/8`.
* Optional: Wireshark/`tshark` to open the generated `.pcap` capture.

---

## Quick start

### 1. CUPS demo (single process)

```bash
python3 simulators/cups_simulator.py
```
Runs: Sx Association Setup → Session Establishment → user-plane traffic → Session Report →
Modification → Deletion → PFD Management → Association Update/Release.

### 2. CUPS stack as separate processes

```bash
python3 run_stack.py            # up → demo → down
python3 run_stack.py --keep     # stay up (Ctrl-C to stop)
python3 run_stack.py --seconds 30
python3 run_stack.py --no-demo  # just bring the stack up
```

### 3. Full EPC (UE + eNB + MME + HSS + PCRF + gateways + PDN)

```bash
python3 run_epc.py              # 10 processes: up → attach → data → detach → down
python3 run_epc.py --keep
python3 run_epc.py --seconds 30
python3 simulators/epc_simulator.py   # same flow, single process
```

The EPC run performs a complete **EPS attach**, pushes uplink data `UE → eNB → SGW-U → PGW-U →
PDN`, receives the echoed downlink back at the UE, then detaches.

### 4. Capture raw PFCP

```bash
python3 capture_pfcp.py
# -> captures/pfcp_raw_<timestamp>.txt   (per-PDU hexdump + decoded IE tree)
# -> captures/pfcp_raw_<timestamp>.pcap  (open in Wireshark)
```

### 5. Live state dashboard (browser)

Every node exposes a text control socket (`STATUS` + extras); `core/webdash.py` polls them
and serves a live status page:

```bash
# with the EPC runner (dashboard on by default):
python3 run_epc.py --keep            # then open http://127.0.0.1:8080
python3 run_epc.py --web 9000        # custom port;  --web 0 disables

# or standalone (while a stack is running):
python3 core/webdash.py --port 8080 --host 127.0.0.1
```

Endpoints: `/` (HTML page, auto-refresh 2s), `/state.json` (machine-readable),
`/healthz`. The page shows each node's live `STATUS` plus `SESSIONS` / `GTPSTAT` / `UES`
where available. Control ports: SGW-C 8905, PGW-C 8906, SGW-U 8907, PGW-U 8908, UE 8909,
MME 8910, eNB 8911, HSS 8912, PCRF 8913, PDN 8914.

---

## Components

### CUPS engines

| Module | Role |
|---|---|
| `core/cpf.py` | Shared Control Plane Function: Sx association/session procedures, PFD management, reports, heartbeats. |
| `core/upf.py` | Shared User Plane Function: PDR/FAR/QER/URR rule pipeline, TDF, DL buffering, optional GTP-U relay. |

### Gateways

| Module | Mode | Interfaces |
|---|---|---|
| `core/sgw_c.py` | CUPS | (configured peer) Sxa |
| `core/pgw_c.py` | CUPS | (configured peer) Sxb |
| `core/sgw_u.py` | CUPS/EPC | Sxa, S1-U (GTP-U), control socket |
| `core/pgw_u.py` | CUPS/EPC | Sxb, S5-U + SGi (GTP-U/raw), control socket |
| `core/epc_sgw_c.py` | EPC | S11, S5-C, Sxa |
| `core/epc_pgw_c.py` | EPC | S5-C, Gx, Sxb |

### Access / core network (EPC)

| Module | Interfaces |
|---|---|
| `core/ue.py` | NAS (EMM+ESM) over Uu; attach state machine; control socket |
| `core/enb.py` | S1-MME (S1AP), S1-U (GTP-U), Uu bridge |
| `core/mme.py` | S1-MME, S6a, S11 — attach/detach orchestration |
| `core/hss.py` | S6a: AIR/AIA (auth vectors), ULR/ULA (subscription data) |
| `core/pcrf.py` | Gx: CCR/CCA (authorized QoS, charging) |
| `core/pdn.py` | SGi external packet network (echo) |

---

## Addressing & ports

All nodes use distinct loopback addresses; the same well-known 3GPP ports are reused where the
IP differs.

| Node | IP | Key ports |
|---|---|---|
| SGW-U | 127.0.0.2 | PFCP 8805, GTP-U 2152, ctl 8907 |
| PGW-U | 127.0.0.3 | PFCP 8805, GTP-U 2152, SGi 2153, ctl 8908 |
| SGW-C | 127.0.0.4 | PFCP 8805, S11 (GTP-C) 2123, ctl 8905 |
| PGW-C | 127.0.0.5 | PFCP 8805, S5-C (GTP-C) 2123, ctl 8906 |
| UE | 127.0.0.10 | Uu NAS 36422, Uu data 36423, ctl 8909 |
| eNB | 127.0.0.11 | S1-MME 36412, S1-U 2152, Uu 36422/36423 |
| MME | 127.0.0.12 | S1-MME 36412, S11 2123, S6a 3868 |
| HSS | 127.0.0.13 | S6a (Diameter) 3868 |
| PCRF | 127.0.0.14 | Gx (Diameter) 3868 |
| PDN | 127.0.0.15 | SGi 9999 |

Reference points: **S1-MME** (S1AP), **Uu** (NAS), **S1-U / S5-U** (GTP-U), **S11 / S5-C**
(GTPv2-C), **S6a / Gx** (Diameter), **Sxa / Sxb** (PFCP).

---

## Protocol codecs

Each codec is self-contained with a runnable `__main__` round-trip self-test
(`python3 protocols/<name>.py`).

| Codec | Spec | Scope |
|---|---|---|
| `pfcp.py` | TS 29.244 | TLV IEs (incl. grouped), node + session messages |
| `gtp.py` | TS 29.281 | GTP-U header + G-PDU |
| `gtp_c.py` | TS 29.274 | GTPv2-C header + Echo/Create/Modify/Delete Session TLVs |
| `diameter.py` | RFC 6733 / TS 29.272 / 29.212 | Header + AVPs; S6a (AIR/AIA, ULR/ULA); Gx (CCR/CCA) |
| `nas.py` | TS 24.301 | EMM/ESM messages for attach (flat TLV subset) |
| `s1ap.py` | TS 36.413 | S1 setup + NAS transport + context setup/release (flat TLV subset) |

> NAS and S1AP use a simplified flat TLV encoding (not octet-aligned/ASN.1 APER) so the
> signalling is explicit and readable on the wire. Diameter and GTPv2-C use the real header
> layout with a documented subset of AVPs/IEs.

---

## Attach call flow

```
UE            eNB            MME               HSS        SGW-C        PGW-C        PCRF       SGW-U   PGW-U   PDN
 │  Attach Req │              │                 │           │            │           │           │       │      │
 ├────────────▶│ InitialUE    │                 │           │            │           │           │       │      │
 │             ├─────────────▶│                 │           │            │           │           │       │      │
 │             │              ├── AIR ─────────▶│           │            │           │           │       │      │
 │             │              │◀─ AIA (vectors)─┤           │            │           │           │       │      │
 │             │◀─ DownlinkNAS(AuthReq)─────────┤           │            │           │           │       │      │
 │◀─ Auth Req ─┤              │                 │           │            │           │           │       │      │
 ├─ Auth Resp ▶├─ UplinkNAS ─▶│ (verify RES)    │           │            │           │           │       │      │
 │             │◀─ SecurityModeCommand ─────────┤           │            │           │           │       │      │
 ├─ SecMode ▶  ├─ UplinkNAS ─▶│                 │           │            │           │           │       │      │
 │             │              ├── Create Session Req ─────▶ │ Create Session Req ──▶│ CCR ──────▶│       │      │
 │             │              │                 │           │            │◀─ CCA ────┤           │       │      │
 │             │              │                 │           │            │── Sxb PFCP Session Est ──▶│       │
 │             │              │                 │           │            │◀─ Create Session Resp ────┤       │
 │             │              │                 │           │◀── S5-C Create Session Response ─────┤       │
 │             │              │                 │           │── Sxa PFCP Session Est ──▶│       │      │      │
 │             │              │◀── S11 Create Session Response ───────┤           │           │       │      │
 │             │◀─ InitialContextSetupRequest(Attach Accept) ─────────┤           │           │       │      │
 │◀─ Attach Accept ───────────┤                 │           │            │           │           │       │      │
 ├─ Attach Complete ─────────▶├─ UplinkNAS ────▶│           │            │           │           │       │      │
 │             ├─ InitialContextSetupResponse ─▶│           │            │           │           │       │      │
 │             │              ├── S11 Modify Bearer ──────▶ │  (installs DL route)      │           │       │      │
 │  UL data ──▶│─ GTP-U(S1-U) ─────────────────────────────────────────────────────────────────────▶│       │      │
 │             │              │                 │           │            │           │           │─ GTP-U ▶│─raw─▶│
 │◀─ DL data ──┤◀─────────────────────────────────────────────────────────────────────────────────┤◀─ GTP-U ──────┤
```

Detach reverses step 5: `S11 Delete Session` (SGW-C → PGW-C, PFCP deletion on both UPFs) plus
`S1 UE Context Release`, with a NAS `Detach Accept` back to the UE.

---

## User plane

Data packets are carried in real **GTP-U** between `eNB → SGW-U → PGW-U → PDN` and back. The
relay (`core/gtpu.py`) holds a small **TEID → next-hop** table per node; the F-TEIDs for the
table come from the PFCP sessions and the GTP-C signalling:

```
eNB  : route[SGW S1-U TEID] -> SGW-U                     (uplink)
       route[eNB DL TEID]   -> UE (raw)                  (downlink, egress)
SGW-U: route[SGW S1-U TEID] -> PGW-U  (PGW S5-U TEID)    (uplink)
       route[SGW S5-U TEID] -> eNB    (eNB DL TEID)      (downlink)
PGW-U: route[PGW S5-U TEID] -> PDN (raw, SGi egress)     (uplink)
       SGi downlink -> SGW-U (SGW S5-U TEID)             (downlink)
```

The UPF's GTP-U relay is enabled with `UPF.enable_gtpu()` and programmed over the control
socket (`ROUTE` / `SGI` commands).

---

## Control interfaces

Nodes optionally expose a small text control socket (separate socket/thread, so it never
deadlocks the PFCP receive loop) for drivers/tests:

* **CPF** (`CPF.enable_control`, env `CPF_CTL_PORT`): `STATUS`, `SESSIONS`, `ASSOC`,
  `ESTABLISH`, `MODIFY`, `DELETE`, `RELEASE`.
* **UPF** (`UPF.enable_control`, env `UPF_CTL_PORT`): `STATUS`, `SESSIONS`, `FORWARD`,
  `REPORT`, `ADMIN`, `ROUTE`, `SGI`, `GTPSTAT`.
* **UE** (`UE.enable_control`, env `UE_CTL_PORT`): `ATTACH`, `DETACH`, `UL <payload>`, `STATUS`.
* **MME** (`MME_CTL_PORT`): `STATUS`, `UES`. **eNB** (`ENB_CTL_PORT`): `STATUS`, `GTPSTAT`.
* **HSS** (`HSS_CTL_PORT`): `STATUS`, `SUBS`. **PCRF** (`PCRF_CTL_PORT`): `STATUS`, `POLICIES`.
* **PDN** (`PDN_CTL_PORT`): `STATUS`.

UPF GTP-U relay is enabled by env `UPF_GTPU_PORT` (+ `UPF_SGI_PORT` on the PGW-U).

---

## Tests

```bash
python3 -m unittest discover -s tests -v
```

* `tests/test_pfcp.py` — PFCP codec round-trips and PDR/FAR rule round-trips.
* `tests/test_epc.py` — NAS/S1AP/GTPv2-C/Diameter round-trips + an in-process end-to-end
  attach that asserts the UE gets `10.10.0.2` and receives downlink data.

---

## Design notes & simplifications

* **Teaching/simulation codebase.** Protocol codecs implement the subset needed to exercise
  the flows end-to-end; the implemented messages/IEs are listed in each module's header.
* **NAS / S1AP** use simplified flat TLV encodings, not ASN.1 APER. **Diameter / GTPv2-C**
  use the real header layouts with a documented AVP/IE subset.
* The user-plane GTP-U forwarding uses an explicit TEID route table rather than PFCP
  *Outer Header Creation* IEs. The **PDR/FAR/QER/URR** rule layer and usage reporting are
  still applied on the UPFs.
* Authentication vectors are derived deterministically from a simulated per-subscriber secret
  `K` (a stand-in for Milenage/AuC), so the UE, MME and HSS agree without a real AuC.
* Everything binds loopback `127.0.0.0/8`; no real radio stack, SCTP, or IPsec is used.

---

## Extending

* Add an IE: extend the relevant codec's tables/helpers (keep the `__main__` round-trip green).
* Add a procedure: implement the handler in the entity's `handle()` dispatch and add a control
  command if a driver needs to trigger it.
* New node: follow the pattern — global config at the top, a threaded `UDPServer`, a codec
  under `protocols/`, and wire it into `run_epc.py`.

---

License: MIT.
