export type PairCount = {
  category: string;
  internal: string;
  external: string;
  externalDomain?: string;
  incoming: number;
  outgoing: number;
};

export type DnsEvent = {
  kind: string;
  timestamp: string;
  domain?: string;
  direction?: string;
  sourceIp?: string;
  destinationIp?: string;
  transport?: string;
  action?: string;
  reason?: string;
};

export type SummaryEvent = {
  kind: string;
  timestamp: string;
  pairCounts?: PairCount[];
};

export type SnapshotPayload = {
  kind: string;
  events: Array<SummaryEvent | DnsEvent>;
};

const apiBase = "/api";

export async function fetchPairCounts(): Promise<PairCount[]> {
  const res = await fetch(`${apiBase}/events`);
  if (!res.ok) {
    throw new Error("failed to load events");
  }
  const body = await res.json();
  if (!Array.isArray(body.events)) {
    return [];
  }
  const summaries = (body.events as SummaryEvent[]).filter((event) => event.kind === "ip_pair_summary");
  const latest = summaries.at(-1);
  return latest?.pairCounts ?? [];
}

export async function fetchDnsEvents(limit = 200): Promise<DnsEvent[]> {
  const res = await fetch(`${apiBase}/events`);
  if (!res.ok) {
    throw new Error("failed to load events");
  }
  const body = await res.json();
  if (!Array.isArray(body.events)) {
    return [];
  }
  const dnsEvents = (body.events as DnsEvent[]).filter((event) => event.kind === "dns");
  return dnsEvents.slice(-limit).reverse();
}

type EventCallbacks = {
  onOpen?: () => void;
  onClose?: () => void;
  onPairSummary?: (counts: PairCount[]) => void;
  onDnsBatch?: (events: DnsEvent[]) => void;
  onDnsEvent?: (event: DnsEvent) => void;
};

export function subscribeToEvents(callbacks: EventCallbacks): () => void {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const url = `${protocol}://${window.location.host}/ws/dns`;
  const socket = new WebSocket(url);

  socket.onopen = () => callbacks.onOpen?.();
  socket.onclose = () => callbacks.onClose?.();
  socket.onmessage = (message) => {
    try {
      const payload = JSON.parse(message.data) as SummaryEvent | DnsEvent | SnapshotPayload;
      if (payload?.kind === "snapshot" && Array.isArray((payload as SnapshotPayload).events)) {
        const snapshot = payload as SnapshotPayload;
        const summaries = snapshot.events.filter((event) => event.kind === "ip_pair_summary") as SummaryEvent[];
        const latest = summaries.at(-1);
        if (latest?.pairCounts) {
          callbacks.onPairSummary?.(latest.pairCounts);
        }
        const dnsEvents = snapshot.events.filter((event) => event.kind === "dns") as DnsEvent[];
        if (dnsEvents.length > 0) {
          callbacks.onDnsBatch?.(dnsEvents);
        }
        return;
      }

      if ((payload as SummaryEvent).kind === "ip_pair_summary") {
        const summary = payload as SummaryEvent;
        if (summary.pairCounts) {
          callbacks.onPairSummary?.(summary.pairCounts);
        }
        return;
      }

      if ((payload as DnsEvent).kind === "dns") {
        callbacks.onDnsEvent?.(payload as DnsEvent);
        return;
      }
    } catch (err) {
      console.error("invalid websocket payload", err);
    }
  };

  return () => socket.close();
}


export async function fetchBlocklist(): Promise<string[]> {
  const res = await fetch(`${apiBase}/rules`);
  if (!res.ok) {
    throw new Error("failed to load blocklist");
  }
  const body = await res.json();
  return Array.isArray(body.domains) ? body.domains : [];
}

export async function updateBlocklist(domains: string[]): Promise<void> {
  const res = await fetch(`${apiBase}/rules`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domains }),
  });
  if (!res.ok) {
    throw new Error("failed to update blocklist");
  }
}
