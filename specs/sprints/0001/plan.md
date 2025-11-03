# Sprint 0001 Implementation Plan

## 1. eBPF data-path components
1. Author XDP program (`xdp_dns_redirect.bpf.c`) that:
   - Parses Ethernet/IP/UDP/TCP headers.
   - Identifies DNS (UDP/TCP port 53) packets and redirects them into an `xskmap` entry keyed by RX queue.
   - Returns `XDP_PASS` for non-DNS traffic.
   - Includes CO-RE friendly structures and is built with libbpf.
2. Author tc ingress program (`tc_mirror.bpf.c`) that:
   - Uses `bpf_redirect_peer()` to mirror every ingress packet from the physical NIC into veth `kidos` peer.
   - Returns `TC_ACT_OK` to preserve original forwarding.
3. Provide libbpf bootstrap skeletons (BTF loading, maps definition, license) and build system (Makefile) to compile both programs.

## 2. User-space Go services
1. **DNS Inspector (`cmd/dns-inspector`):**
   - Initializes AF_XDP sockets (one per NIC queue) using `github.com/cilium/ebpf` + `github.com/asavie/xdp` or `github.com/dropbox/goebpf/xdp` (evaluate best fit).
   - Drains DNS frames, parses with `miekg/dns`, applies rule engine (in-memory + persisted config), and reinjects allowed packets via AF_XDP Tx ring.
   - Emits structured events to the monitoring backend and exposes gRPC/REST for rule updates.
2. **Monitor (`cmd/monitor`):**
   - Attaches to veth `kidos` interface (pcap or raw socket) to sample/log full traffic.
   - Publishes metrics (flow counts, top talkers) to the web backend.
3. Shared Go package (`pkg/`): config management, logging, rule store, event bus.

## 3. Web backend & API
1. Implement Go HTTP server (`cmd/web`) that:
   - Serves REST endpoints for rules, DNS events, telemetry.
   - Provides WebSocket stream for live DNS activity.
   - Persists configuration and recent events (SQLite or in-memory with JSON snapshot to disk).
2. Integrate with DNS inspector and monitor via internal pub/sub or gRPC for event ingestion.

## 4. React SPA
1. Scaffold React app under `web/ui` with Vite or Create React App.
2. Pages/components:
   - Dashboard (live DNS timeline, block counters).
   - Rules management (list/add/remove domain blocks).
3. API client for REST/WebSocket endpoints; handle optimistic updates and error reporting.
4. Build pipeline (npm scripts) and static asset output consumed by Go web server.

## 5. Bootstrap scripts & packaging
1. Create `scripts/setup.sh` to:
   - Create veth pair `kidos` ↔ `kidos-peer` and bring interfaces up.
   - Compile eBPF objects, attach XDP and tc programs.
   - Launch Go daemons (dns inspector, monitor, web server) via background processes or supervisor (e.g., `tmux`/`systemd` units template).
2. Create `scripts/teardown.sh` to detach programs, kill daemons, and remove veth pair.
3. Provide `Makefile` targets for `build`, `run`, `clean`, `lint`, `test`.
4. Document prerequisites (kernel version, Go, Node, clang/llvm, bpftool) in `README.md` and `AGENTS.md` starting instructions.

## 6. Validation & observability
1. Include smoke tests or scripts to verify:
   - DNS queries are intercepted and enforced (e.g., using `dig` against test domain).
   - Mirrored traffic appears on veth.
   - Web UI reflects live events and rule changes propagate.
2. Add metrics/logging hooks (Prometheus metrics, structured logs) to support ongoing monitoring.

## 7. Delivery checklist
- Ensure code compiles on fresh machine with documented prerequisites.
- Verify `setup.sh` followed by `teardown.sh` leaves system clean.
- Provide end-to-end demo instructions (launch, perform DNS block, observe UI).
