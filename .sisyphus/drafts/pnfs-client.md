# Draft: pNFS client

## Requirements (confirmed)
- User request: implement a pNFS client (details TBD)
- Target layout for v1: pNFS flexfiles (user selected)
- V1 must-have: DS read-only + DS write/commit; callbacks deferred
- Interop target (priority): Linux knfsd
- On pNFS failure: fallback to MDS path (user selected)
- Tests: YES, TDD (user selected)

## Technical Decisions
- Recommended architecture (Oracle): keep `Nfs41Client` as per-server v4.1 RPC/session client; add a new `pnfs` orchestrator owning an MDS client + DS client pool + device cache.
- Negotiate pNFS roles via EXCHANGE_ID flags:
  - MDS-side: likely set `USE_PNFS_MDS` (and optionally `USE_NON_PNFS` to allow fallback).
  - DS-side: set `USE_PNFS_DS`.
- Policy recommendation: pNFS as opportunistic accelerator with robust fallback to MDS I/O when layouts/DS fail (especially since callbacks are deferred).

## Research Findings
- Repo already has an NFSv4.1 read-only MVP client and protocol plumbing:
  - `src/client41.rs` implements EXCHANGE_ID + CREATE_SESSION + SEQUENCE and READ via COMPOUND.
  - `src/nfs4.rs` contains v4.1 op encoding/decoding (currently a small subset).
  - `src/rpc.rs` + `src/xdr.rs` provide ONC RPC-over-TCP + XDR codec.
- Current v4.1 EXCHANGE_ID encoding sets `EXCHGID4_FLAG_USE_NON_PNFS`, which effectively disables pNFS; pNFS client work likely needs to change this.
- pNFS-related NFSv4.1 op numbers to implement (from OSS references):
  - `OP_GETDEVICEINFO` = 47
  - `OP_LAYOUTCOMMIT` = 49
  - `OP_LAYOUTGET` = 50
  - `OP_LAYOUTRETURN` = 51
- Primary specification for pNFS file layout is in RFC 5661:
  - pNFS overview/semantics: RFC 5661 Section 12
  - File layout type details: RFC 5661 Section 13
- Newer authoritative spec: RFC 8881 obsoletes RFC 5661 and includes pNFS + file layout sections and op definitions:
  - pNFS overview: RFC 8881 Section 12
  - File layout: RFC 8881 Section 13
  - Ops: GETDEVICEINFO (18.40), LAYOUTCOMMIT/GET/RETURN (18.42-18.44), callbacks CB_LAYOUTRECALL (20.3)
- Layout type registry: IANA pNFS layout types: `LAYOUT4_NFSV4_1_FILES` = 0x00000001
- OSS implementation references:
  - Linux kernel pNFS client: deviceid cache + layout drivers + callbacks (`fs/nfs/pnfs_dev.c`, `fs/nfs/filelayout/`, `fs/nfs/callback_proc.c`)
  - ms-nfs41-client (user-space): pNFS file layout + DS client caching + recall handling (see `daemon/pnfs_*.c`)
  - dCache/nfs4j basic-client: minimal pNFS file-layout flow (LAYOUTGET + GETDEVICEINFO + DS I/O), simple device cache
- Repo-specific risk for pNFS enablement:
  - Current client sends `EXCHGID4_FLAG_USE_NON_PNFS` in `src/nfs4.rs`, which must change for pNFS.
  - Current QEMU knfsd harness is a single-server export; pNFS file layout testing may require MDS+DS topology and/or different server stack.
- Critical interop finding: Linux knfsd (nfs-kernel-server) does NOT support classic pNFS file layout (`LAYOUT4_NFSV4_1_FILES`) as a server-side layout type.
  - Knfsd pNFS server-side layout ops cover flexfiles/block/SCSI only.
  - Therefore: if we keep “file layout” as requirement, we likely need a non-knfsd MDS for real integration testing (knfsd can still be used as a DS in some topologies).
- Flexfiles layout basics (RFC 8435 / nfstest XDR):
  - `LAYOUT4_FLEX_FILES` = 0x4.
  - Layout content: `ff_layout4 { stripe_unit, mirrors<ff_mirror4>, flags, stats_hint }`.
  - Each mirror: `ff_mirror4 { data_servers<ff_data_server4> }`.
  - Each data server entry: `ff_data_server4 { deviceid, efficiency, stateid, fh_list, user, group }`.
  - Device address: `ff_device_addr4 { netaddrs<>, versions<> }` from GETDEVICEINFO.
- Flexfiles client mapping (Linux kernel):
  - `dss_id = (offset / stripe_unit) % dss_count` (if `dss_count>1` and `stripe_unit>0`).
  - Reads choose a mirror by efficiency; writes iterate all mirrors.
- EXCHANGE_ID pNFS role flag values (Linux headers):
  - `EXCHGID4_FLAG_USE_NON_PNFS` = 0x00010000
  - `EXCHGID4_FLAG_USE_PNFS_MDS` = 0x00020000
  - `EXCHGID4_FLAG_USE_PNFS_DS` = 0x00040000
- Crate landscape (Rust):
  - Potential codegen for NFS-style XDR unions: `domodwyer/fastxdr` (active)
  - Generic ONC RPC envelope/auth: `domodwyer/onc-rpc` (active)
  - Existing Rust NFSv4 client reference with pNFS ops present: `bobbobbio/nfs4`
  - License caution: some serde-xdr implementations are GPL.

## Proposed V1 Flow (tentative)
- MDS: EXCHANGE_ID (pNFS MDS role) -> CREATE_SESSION -> per-call SEQUENCE
- Per file:
  - OPEN on MDS to obtain `open_stateid`
  - LAYOUTGET on MDS (flexfiles) -> `layout_stateid` + segments (ff_layout4)
  - GETDEVICEINFO per deviceid -> DS address(es) (ff_device_addr4)
  - DS: EXCHANGE_ID (pNFS DS role) -> CREATE_SESSION -> SEQUENCE
  - DS READ/WRITE using `layout_stateid` and DS filehandle from layout (ff_data_server4.fh_list)
  - Close/commit order (oracle suggestion): DS COMMIT -> MDS LAYOUTCOMMIT -> MDS LAYOUTRETURN -> MDS CLOSE

## Test Strategy (tentative)
- Unit tests: XDR encode/decode golden tests for pNFS ops + file layout parsing.
- Hermetic integration: optional tiny scripted fake MDS+DS to validate state machine without real pNFS.
- External integration: ignored tests gated by env vars pointing at a real pNFS setup.
- Test infrastructure exists:
  - Hermetic tests via `cargo test`.
  - Ignored integration tests for v4.1 in `tests/nfs41_vm.rs` using a QEMU harness (`scripts/vm/nfs41-up.sh`).

## Open Questions
- Target environment: user-space library/binary vs kernel module?
- Protocol scope: NFSv4.1 only (pNFS), or also v4.2 features?
- Security: AUTH_SYS only, or also RPCSEC_GSS (Kerberos)?
- Transport: TCP only, or also RDMA?
- Flexfiles specifics to decide:
  - Mirror handling: single mirror only vs multi-mirror writes (FF_FLAGS_WRITE_ONE_MIRROR).
  - Credentials: use ffds_user/group (AUTH_SYS) vs ignore and use client creds.
- Testing realism: must be testable locally (VM), or OK to rely on external pNFS env?
- Integration tests: required with real knfsd flexfiles env, or optional-only?

## Scope Boundaries
- INCLUDE: TBD
- EXCLUDE: TBD
