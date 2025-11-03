# Sprint 0001 User Stories

## Story 1: Parental control device bootstrap
- **As** a device operator
- **I want** a one-command script that prepares the system (creates the `kidos` veth pair, loads required eBPF programs, launches Go services and the web UI)
- **So that** I can bring a fresh machine to a working state quickly

### Acceptance Criteria
- Script supports start and stop flows, idempotent on re-run.
- Script reports clear success/failure status for each subsystem (eBPF, Go daemons, web server).
- Teardown cleans up veth interfaces, detach eBPF programs, and stops user-space processes.

## Story 2: DNS inspection and blocking pipeline
- **As** a parental-control admin
- **I want** DNS traffic to be routed through a Go AF_XDP inspector that can allow, modify, or block queries/responses
- **So that** I can enforce DNS-based policies in real time

### Acceptance Criteria
- XDP program redirects only DNS packets into AF_XDP sockets; other packets must remain on the fast path.
- Go DNS worker processes each frame, can drop requests/responses, and reinject allowed ones without breaking connectivity.
- Blocking decisions are visible in system logs and surfaced to the web backend API.

## Story 3: Network monitoring tap
- **As** a network analyst
- **I want** every packet mirrored into a `kidos` veth interface
- **So that** I can observe full traffic without disturbing forwarding

### Acceptance Criteria
- tc eBPF program mirrors ingress packets to the veth peer using `bpf_redirect_peer()`.
- Monitoring Go service listens on the veth interface and records packet metadata for the web UI.
- Mirror path must tolerate sustained traffic without dropping the primary flow.

## Story 4: Web control surface
- **As** a parent
- **I want** a single-page web app that shows live DNS activity and lets me define block rules
- **So that** I can manage household browsing policies easily

### Acceptance Criteria
- Web backend exposes REST/WebSocket endpoints for DNS events and rule updates.
- React front-end displays DNS query history, block decisions, and offers forms to add/remove rules.
- Rule changes apply immediately to the DNS inspector and persist across restarts.
