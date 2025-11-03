import React, { useEffect, useMemo, useState } from "react";
import {
  fetchDnsEvents,
  fetchPairCounts,
  fetchBlocklist,
  updateBlocklist,
  PairCount,
  DnsEvent,
  subscribeToEvents,
} from "./api";

const MAX_DNS_EVENTS = 200;

type Tab = "traffic" | "dns";

type PairRow = {
  id: string;
  type: string;
  internal: string;
  external: string;
  packets: string;
};

type DnsRow = {
  id: string;
  time: string;
  domain: string;
  direction: string;
  flow: string;
  action: string;
  rawDomain?: string;
};

function App() {
  const [pairCounts, setPairCounts] = useState<PairCount[]>([]);
  const [dnsEvents, setDnsEvents] = useState<DnsEvent[]>([]);
  const [blockedDomains, setBlockedDomains] = useState<string[]>([]);
  const [pendingBlock, setPendingBlock] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const [activeTab, setActiveTab] = useState<Tab>("traffic");

  useEffect(() => {
    fetchPairCounts()
      .then((initial) => setPairCounts(sortCounts(initial)))
      .catch((err) => console.error("failed to load pair counts", err));

    fetchDnsEvents(MAX_DNS_EVENTS)
      .then((initial) => setDnsEvents(sortDns(initial)))
      .catch((err) => console.error("failed to load DNS events", err));

    fetchBlocklist()
      .then((list) => setBlockedDomains(list.map(normalizeDomain)))
      .catch((err) => console.error("failed to load blocklist", err));

    const unsubscribe = subscribeToEvents({
      onOpen: () => setConnected(true),
      onClose: () => setConnected(false),
      onPairSummary: (counts) => setPairCounts(sortCounts(counts)),
      onDnsBatch: (events) => setDnsEvents(sortDns(events).slice(0, MAX_DNS_EVENTS)),
      onDnsEvent: (event) =>
        setDnsEvents((prev) => sortDns([event, ...prev]).slice(0, MAX_DNS_EVENTS)),
    });

    return () => unsubscribe();
  }, []);

  const trafficRows = useMemo(() => pairCounts.map(toPairRow), [pairCounts]);
  const dnsRows = useMemo(() => dnsEvents.map(toDnsRow), [dnsEvents]);
  const blockedSet = useMemo(() => new Set(blockedDomains), [blockedDomains]);

  const handleBlockDomain = async (domain: string | undefined) => {
    if (!domain) {
      return;
    }
    const normalized = normalizeDomain(domain);
    if (blockedSet.has(normalized) || pendingBlock === normalized) {
      return;
    }
    setPendingBlock(normalized);
    try {
      const nextList = Array.from(new Set([...blockedDomains, normalized]));
      await updateBlocklist(nextList);
      setBlockedDomains(nextList);
    } catch (err) {
      console.error("failed to block domain", err);
    } finally {
      setPendingBlock(null);
    }
  };

  return (
    <main className="app">
      <header className="app__header">
        <div>
          <h1>Network Intelligence</h1>
          <div className="tabs">
            <button
              className={`tab ${activeTab === "traffic" ? "tab--active" : ""}`}
              onClick={() => setActiveTab("traffic")}
            >
              Traffic
            </button>
            <button
              className={`tab ${activeTab === "dns" ? "tab--active" : ""}`}
              onClick={() => setActiveTab("dns")}
            >
              DNS Activity
            </button>
          </div>
        </div>
        <span className={`status ${connected ? "status--up" : "status--down"}`}>
          {connected ? "live" : "offline"}
        </span>
      </header>

      <section className="app__body">
        {activeTab === "traffic" ? (
          <table key="traffic" className="packet-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Internal</th>
                <th>External</th>
                <th>Packets (in/out)</th>
              </tr>
            </thead>
            <tbody>
              {trafficRows.length === 0 ? (
                <tr>
                  <td colSpan={4} className="packet-table__empty">
                    Waiting for traffic...
                  </td>
                </tr>
              ) : (
                trafficRows.map((row) => (
                  <tr key={row.id}>
                    <td>{row.type}</td>
                    <td>{row.internal}</td>
                    <td>{row.external}</td>
                    <td>{row.packets}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        ) : (
          <table key="dns" className="packet-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Domain</th>
                <th>Direction</th>
                <th>Flow</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {dnsRows.length === 0 ? (
                <tr>
                  <td colSpan={5} className="packet-table__empty">
                    Waiting for DNS events...
                  </td>
                </tr>
              ) : (
                dnsRows.map((row) => {
                  const normalized = normalizeDomain(row.rawDomain ?? "");
                  const blocked = normalized !== "" && blockedSet.has(normalized);
                  const isPending = pendingBlock === normalized;

                  const hasDomain = row.rawDomain !== "" && row.rawDomain !== null && row.rawDomain !== undefined;
                  return (
                    <tr key={row.id}>
                      <td>{row.time}</td>
                      <td>
                        <span>{row.domain}</span>
                        {hasDomain && (
                          <button
                            className={`block-button ${blocked ? "block-button--blocked" : ""}`}
                            onClick={() => handleBlockDomain(row.rawDomain)}
                            disabled={blocked || isPending}
                          >
                            {blocked ? "Blocked" : isPending ? "Blocking..." : "Block"}
                          </button>
                        )}
                      </td>
                      <td>{row.direction}</td>
                      <td>{row.flow}</td>
                      <td>{row.action}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        )}
      </section>
    </main>
  );
}

function toPairRow(item: PairCount): PairRow {
  const total = `${item.incoming}/${item.outgoing}`;
  return {
    id: `${item.category}|${item.internal}->${item.external}`,
    type: labelCategory(item.category),
    internal: item.internal || "-",
    external: externalLabel(item.external, item.externalDomain),
    packets: total,
  };
}

function toDnsRow(event: DnsEvent): DnsRow {
  const raw = (event.domain ?? "").trim();
  const normalized = normalizeDomain(raw);
  const displayDomain = raw || normalized || "-";
  return {
    id: `${event.timestamp}-${displayDomain || event.sourceIp || ""}`,
    time: formatTimestamp(event.timestamp),
    domain: displayDomain,
    rawDomain: normalized,
    direction: capitalize(event.direction ?? ""),
    flow: `${event.sourceIp ?? "-"} → ${event.destinationIp ?? "-"} (${event.transport ?? ""})`,
    action: event.reason ? `${event.action ?? ""} (${event.reason})` : event.action ?? "allow",
  };
}

function sortCounts(counts: PairCount[]): PairCount[] {
  return [...counts].sort((a, b) => {
    const totalA = a.incoming + a.outgoing;
    const totalB = b.incoming + b.outgoing;
    if (totalA === totalB) {
      return `${a.internal}->${a.external}`.localeCompare(`${b.internal}->${b.external}`);
    }
    return totalB - totalA;
  });
}

function sortDns(events: DnsEvent[]): DnsEvent[] {
  return [...events].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
}

function labelCategory(category: string): string {
  switch (category) {
    case "internal":
      return "Internal";
    case "external":
      return "External";
    default:
      return category || "-";
  }
}

function externalLabel(ip: string, domain?: string): string {
  if (!ip) {
    return "-";
  }
  if (domain) {
    return `${ip} (${domain})`;
  }
  return ip;
}

function capitalize(value: string): string {
  if (!value) {
    return "-";
  }
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleTimeString([], { hour12: false });
}

function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase();
}

export default App;
