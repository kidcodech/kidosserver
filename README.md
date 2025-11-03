# Kidos Parental Control Prototype

This repository contains an experimental parental-control stack featuring:

- XDP eBPF program that redirects DNS packets into an AF_XDP user-space plane for inspection and enforcement.
- tc ingress eBPF program that mirrors all packets into a `kidos` veth interface for monitoring.
- Go services for DNS inspection, monitoring, and web/API handling.
- React single-page application for rule management and live DNS visibility.
- Setup/teardown scripts that provision the environment on a fresh system.

> **Note:** The code base is a bootstrap skeleton. The AF_XDP processing loop and monitoring capture are placeholders and must be completed before production use.

## Prerequisites

- Linux kernel with eBPF, XDP, and `bpf_redirect_peer` support.
- Root privileges when running the setup/teardown scripts.
- `clang`, `llvm-strip`, and `bpftool` for eBPF compilation.
- Go 1.22.
- Node.js 20+ (for the React build).

## Quick Start

```bash
sudo ./scripts/setup.sh PHYSICAL_IF=eth0
```

The script performs the following:

1. Creates the `kidos`/`kidos-peer` veth pair and brings both ends up.
2. Regenerates `bpf/include/vmlinux.h` for the current kernel.
3. Builds the eBPF object files and Go binaries.
4. Ensures no stale XDP program is attached and loads the tc mirror program onto the physical NIC.
5. Updates the mirror target map with the `kidos` ifindex.
6. Launches the DNS inspector (which attaches the XDP program and AF_XDP socket), monitoring service, and web server (logs under `data/logs`).

Tear down everything with:

```bash
sudo ./scripts/teardown.sh PHYSICAL_IF=eth0
```

## Repository Layout

```
├── bpf/                  # eBPF sources and headers
├── cmd/
│   ├── dns-inspector/    # AF_XDP DNS decision service
│   ├── monitor/          # Traffic monitor reading from mirrored veth
│   └── web/              # HTTP API and SPA asset server
├── pkg/                  # Shared Go packages (config, rules, events, logging)
├── scripts/              # setup/teardown helpers
├── web/ui/               # React SPA source code
├── public/               # Static fallback assets served by web backend
└── specs/                # Sprint specifications and planning artifacts
```

## Development Notes

- `bpf/include/vmlinux.h` must be regenerated for each target kernel using `bpftool btf dump file /sys/kernel/btf/vmlinux format c` before building the eBPF objects.
- The DNS inspector process attaches the XDP program, opens an AF_XDP socket, and reinjects or drops DNS frames according to the configured block list.
- The monitoring service consumes mirrored traffic from the `kidos` veth peer and periodically publishes flow statistics to the web UI.
- The web backend exposes `/api/rules`, `/ws/dns`, and serves the static React build from `/static`.
- React build artifacts should be copied or symlinked into `public/static` by the CI/build pipeline; adjust `cmd/web` if you prefer embedding assets via `go:embed`.
- DNS decisions and monitoring statistics are pushed into the web backend through `/api/events` and streamed to the SPA via WebSocket.

## Testing Ideas

- Use `dig` against known domains to validate DNS interception once the AF_XDP loop is implemented.
- Mirror verification: run `tcpdump -i kidos` to confirm packets arrive through the tc mirror program.
- UI verification: `npm install && npm run dev` inside `web/ui` for local development, pointing the proxy at the Go backend.
- Quick smoke test: with services running, execute `./scripts/validate.sh` to hit the REST APIs.

## Security & Safety

- Scripts remove `bpf/include/vmlinux.h` during teardown to avoid stale headers between kernel upgrades.
- Logs are stored in `data/logs`; rotate or forward them for production use.
- Always validate new eBPF changes with `verifier` logs before deploying to production kernels.
