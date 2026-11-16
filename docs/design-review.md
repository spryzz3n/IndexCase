# Design review: changes to the original build overview

Notes from reviewing the build overview against existing tools and against how
real intrusions look. Each item says what changes in the MVP.

## Where IndexCase sits

| Tool | What it does | Gap IndexCase fills |
|---|---|---|
| LogonTracer (JPCERT/CC) | Account/host logon graph, centrality ranking | No execution evidence, no malware profile, no origin |
| IRFlow Timeline (Lateral Movement Tracker) | GUI graph, multi-hop chains, Impacket/RMM detections, exec sessions | No origin ranking, no profile matching in the tracker |
| masstin | Many artifacts and OSes, statistical edge scoring, chain rebuild from a seed host | Needs a known-bad seed; no logon-to-execution tie |
| Epagneul, Sabonis, LogHound | EVTX to Neo4j / BloodHound graphs | Visualisation only |
| Defender XDR, CrowdStrike, Elastic | Live incident graphs | Need agents deployed beforehand; closed; not offline EVTX |
| Hopper (USENIX Security 2021) | Causal login-path inference | Research system, detection rather than origin |

The pitch is therefore not "a lateral movement graph" (crowded) but:
**execution-confirmed edges, each citing its events, plus a ranked origin that
can say "outside log coverage".**

## Problems in the original design and what changes

1. **Malware origin is not intrusion origin.**
   In human-operated attacks the binary is often pushed from one host (frequently
   a DC) long after the attacker got in. Restricting edges to infected-host pairs
   hides pivots.
   *Change:* the source of an edge can be any host. Nodes carry a kind:
   `infected`, `suspected`, `transit` (has logs, no profile match), `no_logs`,
   `unresolved_ip`.

2. **No node for a source without logs.**
   The Impacket tests run from a Linux VM that has no EVTX at all.
   *Change:* unresolved sources become `ip:<addr>` nodes, and the report states
   when the origin is outside log coverage instead of naming the first Windows
   host.

3. **Missing logs on an intermediate host split the tree.**
   *Change:* "inferred" edges into a `no_logs` node, built from source-side
   evidence only (4648, DC 4769, Sysmon 3). They are labelled as inferred and
   never called confirmed.

4. **The naive baseline wins T1 to T5.**
   In a clean lab the earliest infected host is patient zero, and T5 removes an
   intermediate host, which does not hurt the baseline.
   *Change:* add scenarios where the true origin's logs are rolled over, missing
   or skewed, and where the origin is unmanaged.

5. **Too few scenarios for the accuracy targets.**
   Top-1 accuracy over three held-out runs is not a measurement.
   *Change:* script randomised topologies (30+ runs) and perturb captured logs
   (drop a host, add skew, truncate) to multiply them. `tests/synth.py` is the
   start of this.

6. **The patient-zero score was mostly the baseline.**
   `earliness` carried 0.40.
   *Change:* earliness 0.30, coverage 0.35, initial access 0.20, completeness
   0.15, unexplained auth -0.10. Each host records its log coverage window, and a
   first-seen at the start of the log is flagged as truncation.

7. **`logon_id` does not survive the service boundary.**
   7045 has no logon ID and the payload runs as SYSTEM.
   *Change:* tie through 4697 / 4698 / 5145 `SubjectLogonId` when present, fall
   back to time proximity with a lower `exec` term. Needs checking against real
   lab logs in week 5.

8. **`match` double-counted.**
   Both ends are already profile matches.
   *Change:* weight lowered to 0.15; auth and exec raised to 0.35 each.

9. **`WorkstationName` is attacker-controlled.**
   Impacket sends arbitrary or empty names.
   *Change:* a source IP that resolves wins over the workstation name.

10. **The baseline penalty hit true edges.**
    Worms reuse the same helpdesk account that logs on everywhere every day.
    *Change:* the penalty applies only when time is all that ties the logon to
    the execution, is keyed on account + source + target, and is raised to 0.30
    so a routine, time-only link drops to a candidate.

## YARA

YARA scans files and memory, not logs, so it sits beside the log pipeline:

- `indexcase scan` runs the profile's rules over a triage folder, one
  sub-folder per host.
- Every matching file's SHA-256 is added to the profile as a hash indicator
  (labelled `yara:<rule>:<hash>`), which the hunt then finds in Sysmon events on
  all hosts. One sample is enough to find a repacked build everywhere.
- A match on a host's own file is a `yara-file:<rule>` indicator for that host.
- A host matched only by files has no first-seen. Copying a file keeps its
  modified time, so a file timestamp can predate the infection and would wreck
  the earliness ranking. Such a host can still be placed in the tree by edges
  that other hosts' logs prove.
- Running YARA-style string rules over command lines was rejected: the
  profile's regex indicators already do it, and Sigma is the better fit there.

Engine: `yara-x`, as an optional dependency.

## Scope changes

- Streamlit view dropped from the MVP; the static HTML report is enough.
- Later: accept Hayabusa / Velociraptor / KAPE output as input; import
  indicators from Sigma or STIX; compare against LogonTracer centrality and a
  seeded masstin chain as stronger baselines.

## Open questions, decided

- LabWorm in C# (PyInstaller's bootstrap process muddies process trees).
- Lab built with GOAD-light.
- Apache 2.0.
- Suspected hosts take part in edge building, capped at "probable".

## Still to verify

- Whether 4697 `SubjectLogonId` really equals the remote 4624 `TargetLogonId`
  for PsExec, psexec.py and smbexec.py on Server 2022 / Windows 11.
- How often Sysmon 3 `DestinationHostname` is populated with the default
  sysmon-modular config (used for IP to host resolution of hosts without logs).
- JPCERT's Black Hat Asia 2026 talk on graph-aware logon detection, for the gap
  analysis.
