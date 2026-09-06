import React, { ChangeEvent, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  AlertTriangle,
  Activity,
  ArrowDownUp,
  BadgeCheck,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  Compass,
  Download,
  FileSearch,
  Filter,
  Globe2,
  HardDriveUpload,
  ListTree,
  Network,
  Palette,
  RadioTower,
  Route,
  Search,
  ScrollText,
  Server,
  Shield,
  Shuffle,
  SlidersHorizontal,
  Upload,
  XCircle,
} from "lucide-react";
import "./styles.css";

type Direction =
  | "EAST_WEST"
  | "NORTH_SOUTH_INBOUND"
  | "NORTH_SOUTH_OUTBOUND"
  | "UNKNOWN";

type Confidence = "HIGH" | "MEDIUM" | "LOW";
type ColorPalette = "forest" | "ocean" | "slate" | "amber";

const colorPalettes: { id: ColorPalette; label: string }[] = [
  { id: "forest", label: "Forest" },
  { id: "ocean", label: "Ocean" },
  { id: "slate", label: "Slate" },
  { id: "amber", label: "Amber" },
];

type PolicyRule = {
  id: string;
  ruleName?: string;
  action: string;
  source: string[];
  destination: string[];
  protocol: string[];
  sourcePort: string[];
  destinationPort: string[];
  appId: string[];
  geolocation: string[];
  logging: string;
  sourceZone?: string[];
  destinationZone?: string[];
  ingressInterface?: string;
  egressInterface?: string;
  enabled?: boolean;
  hitCount?: number;
  policyType: "ASA_ACL" | "FTD_ACP" | "PREFILTER" | "UNKNOWN";
  direction: Direction;
  directionConfidence: Confidence;
  directionReason?: string;
  sourceLine?: string;
};

type InterfaceInfo = {
  id: string;
  hardware?: string;
  logical?: string;
  nameif?: string;
  zone?: string;
  ip?: string;
  mask?: string;
  securityLevel?: number;
  vlan?: string;
  status?: string;
  role: "inside" | "outside" | "dmz" | "transit" | "unknown";
};

type RouteInfo = {
  id: string;
  iface?: string;
  destination: string;
  mask?: string;
  nextHop?: string;
  metric?: string;
  kind: "default" | "static" | "dynamic";
  sourceLine: string;
};

type NatInfo = {
  id: string;
  section?: string;
  sourceInterface?: string;
  destinationInterface?: string;
  mode: "static" | "dynamic" | "identity" | "unknown";
  source: string;
  translated?: string;
  destination?: string;
  translatedDestination?: string;
  service?: string;
  translatedService?: string;
  dns: boolean;
  routeLookup: boolean;
  inactive: boolean;
  objectName?: string;
  objectDefinition?: string;
  sourceLine: string;
};

type Finding = {
  id: string;
  severity: "info" | "warning" | "critical";
  label: string;
  detail: string;
  evidence?: string;
};

type SyslogEvent = {
  id: string;
  timestamp?: string;
  facility: string;
  severity: number;
  severityLabel: string;
  messageId: string;
  message: string;
  sourceLine: string;
};

type SyslogHost = {
  id: string;
  interface?: string;
  address: string;
  protocol?: string;
  port?: string;
  sourceLine: string;
};

type SyslogInfo = {
  enabled: boolean;
  timestamps: boolean;
  bufferedLevel?: string;
  trapLevel?: string;
  bufferSize?: string;
  hosts: SyslogHost[];
  sourceInterfaces: string[];
  disabledMessageIds: string[];
  events: SyslogEvent[];
  configLines: string[];
};

type FailoverInterface = {
  id: string;
  name: string;
  address?: string;
  status: string;
  sourceLine: string;
};

type FailoverInfo = {
  configured: boolean;
  status: string;
  localUnit?: string;
  thisHost?: string;
  peerHost?: string;
  lanInterface?: string;
  statefulInterface?: string;
  communication?: string;
  polltime?: string;
  lastFailure?: string;
  interfaces: FailoverInterface[];
  history: string[];
  sourceLines: string[];
};

type BestPracticeCheck = {
  id: string;
  category: "Visibility" | "Management" | "Policy" | "Resilience" | "Platform";
  title: string;
  status: "pass" | "attention" | "not-observed";
  priority: "critical" | "high" | "medium" | "low";
  appliesTo: "ASA" | "FTD" | "BOTH";
  summary: string;
  recommendation: string;
  evidence: string[];
};

type NetworkObjectKind = "ip" | "host" | "network" | "fqdn" | "range" | "reference";

type NetworkObject = {
  id: string;
  name: string;
  kind: NetworkObjectKind;
  value: string;
  mask?: string;
  fqdnVersion?: string;
  parentGroup?: string;
  sourceLine: string;
};

type Analysis = {
  fileName: string;
  size: number;
  parsedAt: string;
  hostname?: string;
  platform: "ASA" | "FTD" | "UNKNOWN";
  model?: string;
  version?: string;
  uptime?: string;
  haState?: string;
  contexts: string[];
  interfaces: InterfaceInfo[];
  routes: RouteInfo[];
  nats: NatInfo[];
  rules: PolicyRule[];
  findings: Finding[];
  sectionHints: string[];
  syslog: SyslogInfo;
  failover: FailoverInfo;
  bestPractices: BestPracticeCheck[];
  networkObjects: NetworkObject[];
};

type SortKey =
  | "tuple"
  | "action"
  | "source"
  | "destination"
  | "protocol"
  | "destinationPort"
  | "direction"
  | "hitCount";

declare global {
  interface Document {
    modelContext?: {
      registerTool: (
        tool: {
          name: string;
          title?: string;
          description: string;
          inputSchema: object;
          annotations?: { readOnlyHint?: boolean; untrustedContentHint?: boolean };
          execute: (input: unknown) => unknown | Promise<unknown>;
        },
        options?: { signal?: AbortSignal },
      ) => void | Promise<void>;
    };
  }
}

const sampleConfig = `: Saved
hostname edge-fw-01
ASA Version 9.18(4)
Hardware: Firepower 2110, 16384 MB RAM
ntp server 10.20.40.10 source inside prefer
ssh version 2
ssh 10.20.0.0 255.255.0.0 inside
aaa authentication ssh console LOCAL
failover
failover lan unit primary
failover lan interface FAILOVER GigabitEthernet1/8
failover link STATE GigabitEthernet1/7
Failover On
This host: Primary - Active
Other host: Secondary - Standby Ready
Failover LAN Interface: FAILOVER GigabitEthernet1/8 (up)
Stateful Failover Logical Update Interface: STATE GigabitEthernet1/7 (up)
Interface outside (203.0.113.10): Normal (Monitored)
Interface inside (10.20.0.1): Normal (Monitored)
Last Failover at: 11:42:08 CDT Sep 5 2026
interface GigabitEthernet1/1
 nameif outside
 security-level 0
 ip address 203.0.113.10 255.255.255.248
interface GigabitEthernet1/2
 nameif inside
 security-level 100
 ip address 10.20.0.1 255.255.0.0
interface GigabitEthernet1/3
 nameif dmz
 security-level 50
 ip address 172.16.20.1 255.255.255.0
route outside 0.0.0.0 0.0.0.0 203.0.113.9 1
route inside 10.30.0.0 255.255.0.0 10.20.0.2 1
object network WEB-SERVER
 host 172.16.20.25
object network INSIDE-USERS
 subnet 10.20.0.0 255.255.0.0
object network UPDATE-SERVICE
 fqdn v4 updates.example.com
name 10.20.40.25 SYSLOG-COLLECTOR
object-group network INTERNAL-SERVERS
 network-object host 10.20.30.15
 network-object 10.30.0.0 255.255.0.0
 network-object object WEB-SERVER
nat (inside,outside) source dynamic INSIDE-USERS interface
nat (dmz,outside) source static WEB-SERVER WEB-SERVER service tcp www www
access-list OUTSIDE-IN extended permit tcp any object WEB-SERVER eq www
access-list OUTSIDE-IN extended deny ip any any log
access-list INSIDE-OUT extended permit tcp object INSIDE-USERS any eq https
access-list INSIDE-OUT extended permit udp object INSIDE-USERS any eq domain
access-list INSIDE-EW extended permit tcp 10.20.10.0 255.255.255.0 10.30.20.0 255.255.255.0 eq 443
access-group OUTSIDE-IN in interface outside
access-group INSIDE-OUT in interface inside
access-group INSIDE-EW in interface inside
logging enable
logging timestamp
logging buffer-size 1048576
logging buffered informational
logging trap warnings
logging source-interface inside
logging host inside 10.20.40.25 tcp/1470
Sep 06 2026 11:58:02 %ASA-6-302013: Built inbound TCP connection 184 for outside:198.51.100.44/53521 to dmz:172.16.20.25/443
Sep 06 2026 11:58:12 %ASA-4-106023: Deny tcp src outside:198.51.100.72/42012 dst inside:10.20.10.15/22 by access-group OUTSIDE-IN
Sep 06 2026 11:59:01 %ASA-5-111008: User admin executed the show running-config command
show conn count
12 in use, 220 most used
`;

const privateNetworks = [
  { label: "10.0.0.0/8", test: /^10\./ },
  { label: "172.16.0.0/12", test: /^172\.(1[6-9]|2\d|3[0-1])\./ },
  { label: "192.168.0.0/16", test: /^192\.168\./ },
  { label: "100.64.0.0/10", test: /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./ },
];

const roleHints = {
  outside: ["outside", "wan", "internet", "untrust", "external"],
  inside: ["inside", "lan", "trust", "corp", "internal", "users"],
  dmz: ["dmz", "guest", "partner", "public"],
  transit: ["transit", "vpn", "mpls", "sdwan", "vti"],
};

const syslogSeverityLabels = [
  "Emergency",
  "Alert",
  "Critical",
  "Error",
  "Warning",
  "Notification",
  "Informational",
  "Debugging",
];

function splitLines(text: string) {
  return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
}

function inferRole(name?: string, securityLevel?: number): InterfaceInfo["role"] {
  const value = (name || "").toLowerCase();
  for (const [role, hints] of Object.entries(roleHints)) {
    if (hints.some((hint) => value.includes(hint))) return role as InterfaceInfo["role"];
  }
  if (securityLevel === 0) return "outside";
  if (typeof securityLevel === "number" && securityLevel >= 90) return "inside";
  if (typeof securityLevel === "number" && securityLevel > 0) return "dmz";
  return "unknown";
}

function looksPrivate(token: string) {
  const ips = token.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  if (token.toLowerCase().includes("any")) return false;
  return ips.some((ip) => privateNetworks.some((network) => network.test.test(ip)));
}

function looksPublic(token: string) {
  const ips = token.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  return ips.some((ip) => !privateNetworks.some((network) => network.test.test(ip)));
}

function formatList(values?: string[]) {
  if (!values || values.length === 0) return "-";
  return values.join(", ");
}

function parseEndpoint(tokens: string[], start: number) {
  const current = tokens[start]?.toLowerCase();
  if (!current) return { value: ["any"], next: start };
  if (current === "any" || current === "any4" || current === "any6") {
    return { value: [tokens[start]], next: start + 1 };
  }
  if (current === "host" && tokens[start + 1]) {
    return { value: [`host ${tokens[start + 1]}`], next: start + 2 };
  }
  if ((current === "object" || current === "object-group") && tokens[start + 1]) {
    return { value: [`${tokens[start]} ${tokens[start + 1]}`], next: start + 2 };
  }
  if (tokens[start + 1]?.match(/^\d{1,3}(?:\.\d{1,3}){3}$/)) {
    return { value: [`${tokens[start]} ${tokens[start + 1]}`], next: start + 2 };
  }
  return { value: [tokens[start]], next: start + 1 };
}

function parsePort(tokens: string[], start: number) {
  const op = tokens[start]?.toLowerCase();
  if (["eq", "lt", "gt", "neq"].includes(op) && tokens[start + 1]) {
    return { value: [`${tokens[start]} ${tokens[start + 1]}`], next: start + 2 };
  }
  if (op === "range" && tokens[start + 1] && tokens[start + 2]) {
    return { value: [`range ${tokens[start + 1]}-${tokens[start + 2]}`], next: start + 3 };
  }
  return { value: ["any"], next: start };
}

function inferDirection(rule: Partial<PolicyRule>, interfaces: InterfaceInfo[]) {
  const ingress = interfaces.find((item) => item.nameif === rule.ingressInterface);
  const egress = interfaces.find((item) => item.nameif === rule.egressInterface);
  const sourceText = formatList(rule.source);
  const destinationText = formatList(rule.destination);
  const sourcePrivate = looksPrivate(sourceText);
  const destinationPrivate = looksPrivate(destinationText);
  const sourcePublic = looksPublic(sourceText) || sourceText.toLowerCase().includes("any");
  const destinationPublic = looksPublic(destinationText) || destinationText.toLowerCase().includes("any");

  if (ingress?.role === "outside") {
    return {
      direction: "NORTH_SOUTH_INBOUND" as Direction,
      directionConfidence: "HIGH" as Confidence,
      directionReason: `Ingress interface ${ingress.nameif} is classified as outside.`,
    };
  }
  if (ingress?.role === "inside" && destinationPublic && !destinationPrivate) {
    return {
      direction: "NORTH_SOUTH_OUTBOUND" as Direction,
      directionConfidence: "HIGH" as Confidence,
      directionReason: `Inside-origin traffic targets public or any destination.`,
    };
  }
  if (ingress?.role === "inside" && destinationPrivate) {
    return {
      direction: "EAST_WEST" as Direction,
      directionConfidence: "MEDIUM" as Confidence,
      directionReason: `Inside-origin traffic targets private addressing.`,
    };
  }
  if (egress?.role === "outside") {
    return {
      direction: "NORTH_SOUTH_OUTBOUND" as Direction,
      directionConfidence: "MEDIUM" as Confidence,
      directionReason: `Egress interface ${egress.nameif} is classified as outside.`,
    };
  }
  if (sourcePrivate && destinationPrivate) {
    return {
      direction: "EAST_WEST" as Direction,
      directionConfidence: "LOW" as Confidence,
      directionReason: "Both endpoints appear to use private address space.",
    };
  }
  if (sourcePublic && destinationPrivate) {
    return {
      direction: "NORTH_SOUTH_INBOUND" as Direction,
      directionConfidence: "LOW" as Confidence,
      directionReason: "Source appears public or any, destination appears private.",
    };
  }
  if (sourcePrivate && destinationPublic) {
    return {
      direction: "NORTH_SOUTH_OUTBOUND" as Direction,
      directionConfidence: "LOW" as Confidence,
      directionReason: "Source appears private, destination appears public or any.",
    };
  }
  return {
    direction: "UNKNOWN" as Direction,
    directionConfidence: "LOW" as Confidence,
    directionReason: "Insufficient zone, interface, or endpoint evidence.",
  };
}

function buildBestPracticeChecks({
  lines,
  platform,
  rules,
  syslog,
  failover,
  version,
}: {
  lines: string[];
  platform: Analysis["platform"];
  rules: PolicyRule[];
  syslog: SyslogInfo;
  failover: FailoverInfo;
  version: string;
}) {
  const cleanLines = lines.map((line) => line.trim()).filter(Boolean);
  const evidenceFor = (...patterns: RegExp[]) => cleanLines.filter((line) => patterns.some((pattern) => pattern.test(line))).slice(0, 4);
  const has = (...patterns: RegExp[]) => evidenceFor(...patterns).length > 0;
  const checks: BestPracticeCheck[] = [];
  const add = (check: BestPracticeCheck) => checks.push(check);

  const remoteLoggingReady = syslog.enabled && syslog.hosts.length > 0;
  add({
    id: "central-logging",
    category: "Visibility",
    title: "Central system logging",
    status: remoteLoggingReady ? "pass" : syslog.configLines.length ? "attention" : "not-observed",
    priority: "high",
    appliesTo: "BOTH",
    summary: remoteLoggingReady
      ? `${syslog.hosts.length} remote collector${syslog.hosts.length === 1 ? " is" : "s are"} configured with global logging enabled.`
      : "A complete global logging and remote-collector configuration was not confirmed.",
    recommendation: "Enable system logging and send operational events to at least one protected remote collector with an intentional severity threshold.",
    evidence: [...syslog.configLines.filter((line) => /logging (?:enable|host|trap)/i.test(line)).slice(0, 4)],
  });

  add({
    id: "logging-timestamps",
    category: "Visibility",
    title: "Timestamped event records",
    status: syslog.timestamps || has(/^clock timezone\b/i, /^service timestamps\b/i) ? "pass" : "not-observed",
    priority: "medium",
    appliesTo: "BOTH",
    summary: syslog.timestamps ? "Syslog timestamping is configured." : "A logging timestamp directive was not found in the supplied text.",
    recommendation: "Include timestamps in event records so incidents can be correlated across the firewall, manager, and SIEM.",
    evidence: evidenceFor(/^logging timestamp\b/i, /^service timestamps\b/i, /^clock timezone\b/i),
  });

  const ntpEvidence = evidenceFor(/^ntp server\b/i, /^timesync\b/i, /NTP.*(?:synch|peer|server)/i);
  add({
    id: "trusted-time",
    category: "Platform",
    title: "Trusted time synchronization",
    status: ntpEvidence.length ? "pass" : "not-observed",
    priority: "high",
    appliesTo: "BOTH",
    summary: ntpEvidence.length ? "An NTP or time-synchronization configuration signal was detected." : "No NTP server or synchronization signal was detected.",
    recommendation: "Synchronize the firewall and its manager to trusted NTP servers; use authenticated NTP where the platform and release support it.",
    evidence: ntpEvidence,
  });

  if (ntpEvidence.length) {
    add({
      id: "authenticated-ntp",
      category: "Platform",
      title: "Authenticated NTP",
      status: has(/^ntp authenticate\b/i, /^ntp server\b.*\bkey\b/i, /NTP.*auth/i) ? "pass" : "attention",
      priority: "medium",
      appliesTo: "BOTH",
      summary: has(/^ntp authenticate\b/i, /^ntp server\b.*\bkey\b/i, /NTP.*auth/i)
        ? "Authentication material or an authenticated NTP directive was detected."
        : "NTP is present, but authentication was not confirmed from the supplied text.",
      recommendation: "Protect time synchronization with a supported authentication method and trusted server allowlisting.",
      evidence: evidenceFor(/^ntp authenticate\b/i, /^ntp server\b/i, /NTP.*auth/i),
    });
  }

  const denyRules = rules.filter((rule) => /deny|block/i.test(rule.action));
  const unloggedDenyRules = denyRules.filter((rule) => /disabled|not specified/i.test(rule.logging));
  add({
    id: "deny-rule-logging",
    category: "Policy",
    title: "Denied connection visibility",
    status: denyRules.length ? (unloggedDenyRules.length ? "attention" : "pass") : "not-observed",
    priority: "medium",
    appliesTo: "BOTH",
    summary: denyRules.length
      ? `${denyRules.length - unloggedDenyRules.length} of ${denyRules.length} parsed deny/block rules have logging enabled or explicitly set.`
      : "No deny or block rules were parsed for this check.",
    recommendation: "Log security-relevant deny/block decisions while tuning noisy rules to avoid unnecessary event volume.",
    evidence: denyRules.slice(0, 4).map((rule) => rule.sourceLine || rule.ruleName || rule.id),
  });

  const broadAllows = rules.filter((rule) => /permit|allow|trust/i.test(rule.action) && formatList(rule.source).toLowerCase().includes("any") && formatList(rule.destination).toLowerCase().includes("any"));
  add({
    id: "broad-allow-rules",
    category: "Policy",
    title: "Broad allow-rule review",
    status: rules.length ? (broadAllows.length ? "attention" : "pass") : "not-observed",
    priority: "high",
    appliesTo: "BOTH",
    summary: broadAllows.length ? `${broadAllows.length} parsed allow rule${broadAllows.length === 1 ? " is" : "s are"} broad in both source and destination.` : "No parsed allow rule was broad in both source and destination.",
    recommendation: "Validate business need, narrow source, destination, service, identity, or application scope, and document unavoidable broad access.",
    evidence: broadAllows.slice(0, 4).map((rule) => rule.sourceLine || rule.ruleName || rule.id),
  });

  const snmpSecure = has(/^snmp-server (?:group|user)\b.*\bv3\b.*\b(?:priv|aes)\b/i);
  const snmpLegacy = has(/^snmp-server community\b/i, /^snmp-server (?:group|user)\b.*\bv[12]c?\b/i);
  add({
    id: "snmp-protection",
    category: "Management",
    title: "Protected SNMP access",
    status: snmpSecure ? "pass" : snmpLegacy ? "attention" : "not-observed",
    priority: "high",
    appliesTo: "BOTH",
    summary: snmpSecure ? "SNMPv3 privacy or encryption indicators were detected." : snmpLegacy ? "A legacy or community-based SNMP configuration was detected." : "No SNMP configuration was observed.",
    recommendation: "If SNMP is required, use SNMPv3 authentication and privacy with read-only access and tightly scoped management sources.",
    evidence: evidenceFor(/^snmp-server\b/i),
  });

  if (platform !== "FTD") {
    const telnetEvidence = evidenceFor(/^telnet\s+\S+\s+\S+\s+\S+/i);
    const sshEvidence = evidenceFor(/^ssh\s+\S+\s+\S+\s+\S+/i, /^ssh version\s+2/i);
    add({
      id: "asa-secure-management",
      category: "Management",
      title: "Restricted SSH management",
      status: telnetEvidence.length ? "attention" : sshEvidence.length ? "pass" : "not-observed",
      priority: "critical",
      appliesTo: "ASA",
      summary: telnetEvidence.length ? "A Telnet management access statement was detected." : sshEvidence.length ? "SSH management scope or SSHv2 configuration was detected without a Telnet access statement." : "SSH management scope was not confirmed.",
      recommendation: "Use SSHv2 instead of Telnet and restrict management access to dedicated, trusted administration networks.",
      evidence: [...telnetEvidence, ...sshEvidence].slice(0, 4),
    });

    const aaaEvidence = evidenceFor(/^aaa authentication (?:ssh|http|enable) console\b/i, /^aaa-server\b/i);
    const externalAaa = has(/^aaa authentication (?:ssh|http|enable) console\s+(?!LOCAL\b)\S+/i, /^aaa-server\b/i);
    add({
      id: "asa-admin-aaa",
      category: "Management",
      title: "Administrative AAA",
      status: externalAaa ? "pass" : aaaEvidence.length ? "attention" : "not-observed",
      priority: "high",
      appliesTo: "ASA",
      summary: externalAaa ? "External AAA configuration signals were detected." : aaaEvidence.length ? "Administrative authentication appears to rely on the local database." : "Administrative AAA was not confirmed.",
      recommendation: "Use TACACS+ or RADIUS for administrator authentication, authorization, and accounting, retaining protected local recovery access.",
      evidence: aaaEvidence,
    });
  }

  if (platform !== "FTD") {
    const unhealthy = failover.interfaces.filter((item) => !/normal/i.test(item.status));
    add({
      id: "asa-ha-readiness",
      category: "Resilience",
      title: "Failover readiness",
      status: !failover.configured ? "not-observed" : unhealthy.length || !/standby ready/i.test(failover.peerHost || "") ? "attention" : "pass",
      priority: "high",
      appliesTo: "ASA",
      summary: !failover.configured
        ? "Failover configuration was not detected; confirm whether high availability is required."
        : unhealthy.length
          ? `${unhealthy.length} monitored interface${unhealthy.length === 1 ? " is" : "s are"} not reporting Normal.`
          : `${failover.thisHost || failover.localUnit || "Local unit"} and ${failover.peerHost || "peer state not detected"}.`,
      recommendation: "For HA deployments, confirm the peer is ready, critical interfaces are monitored, and failover alerts are exported and tested.",
      evidence: failover.sourceLines.slice(0, 4),
    });

    if (failover.configured) {
      add({
        id: "asa-stateful-failover",
        category: "Resilience",
        title: "Stateful failover link",
        status: failover.statefulInterface ? "pass" : "attention",
        priority: "medium",
        appliesTo: "ASA",
        summary: failover.statefulInterface ? "A stateful update interface was detected." : "A dedicated stateful failover link was not confirmed.",
        recommendation: "Use stateful failover when session continuity is required, and size or dedicate the state link for the deployment's traffic and configuration scale.",
        evidence: evidenceFor(/^failover link\b/i, /^Stateful Failover .* Interface:/i),
      });
    }
  }

  if (platform !== "ASA") {
    const threatSignals = evidenceFor(/intrusion (?:policy|event)/i, /file (?:policy|event)/i, /malware (?:policy|event)/i, /security intelligence/i, /(?:FTD|SFIMS)-\d-43000[1-5]:/i);
    add({
      id: "ftd-threat-eventing",
      category: "Visibility",
      title: "Threat-event export",
      status: threatSignals.length && syslog.hosts.length ? "pass" : threatSignals.length || syslog.hosts.length ? "attention" : "not-observed",
      priority: "high",
      appliesTo: "FTD",
      summary: threatSignals.length && syslog.hosts.length ? "Threat-event signals and a remote syslog destination were detected." : "A complete threat-event export path was not confirmed.",
      recommendation: "Prioritize external export of intrusion, malware, file, and Security Intelligence events; verify the applicable ACP and platform logging settings.",
      evidence: [...threatSignals, ...syslog.hosts.map((host) => host.sourceLine)].slice(0, 4),
    });

    const sshAcl = evidenceFor(/configure ssh-access-list/i, /ssh-access-list/i);
    add({
      id: "ftd-ssh-scope",
      category: "Management",
      title: "Restricted management SSH",
      status: sshAcl.length ? "pass" : "not-observed",
      priority: "high",
      appliesTo: "FTD",
      summary: sshAcl.length ? "An FTD SSH access-list restriction was detected." : "An SSH management-source restriction was not observed.",
      recommendation: "Limit FTD management-interface SSH access to approved administrative source networks.",
      evidence: sshAcl,
    });
  }

  add({
    id: "platform-identification",
    category: "Platform",
    title: "Platform and release identified",
    status: platform !== "UNKNOWN" && Boolean(version) ? "pass" : "attention",
    priority: "medium",
    appliesTo: "BOTH",
    summary: platform !== "UNKNOWN" && version ? `${platform} ${version} was detected.` : "The platform or software release could not be identified reliably.",
    recommendation: "Confirm the exact platform and release, then validate lifecycle, advisories, and recommended software against Cisco's current guidance.",
    evidence: evidenceFor(/(?:ASA|FTD|Firepower Threat Defense|Cisco Adaptive Security Appliance) Version/i),
  });

  return checks.filter((check) => platform === "UNKNOWN" || check.appliesTo === "BOTH" || check.appliesTo === platform);
}

function parseShowTech(text: string, fileName = "sample-show-tech.txt"): Analysis {
  const lines = splitLines(text);
  const interfaces: InterfaceInfo[] = [];
  const routes: RouteInfo[] = [];
  const nats: NatInfo[] = [];
  const rules: PolicyRule[] = [];
  const findings: Finding[] = [];
  const networkObjects: NetworkObject[] = [];
  const networkObjectKeys = new Set<string>();
  const syslog: SyslogInfo = {
    enabled: false,
    timestamps: false,
    hosts: [],
    sourceInterfaces: [],
    disabledMessageIds: [],
    events: [],
    configLines: [],
  };
  const failover: FailoverInfo = {
    configured: false,
    status: "Not detected",
    interfaces: [],
    history: [],
    sourceLines: [],
  };
  const contexts = new Set<string>();
  const aclBindings = new Map<string, string>();
  const sectionHints = new Set<string>();

  let hostname = "";
  let version = "";
  let model = "";
  let uptime = "";
  let haState = "";
  let platform: Analysis["platform"] = "UNKNOWN";
  let currentInterface: InterfaceInfo | null = null;
  let currentNetworkObject: { name: string; definition?: string } | null = null;
  let currentNetworkGroup: string | null = null;

  const addNetworkObject = (object: Omit<NetworkObject, "id">) => {
    const key = [object.name, object.kind, object.value, object.mask, object.fqdnVersion, object.parentGroup].join("|").toLowerCase();
    if (networkObjectKeys.has(key)) return;
    networkObjectKeys.add(key);
    networkObjects.push({ ...object, id: `network-object-${networkObjects.length + 1}` });
  };

  lines.forEach((raw, index) => {
    const line = raw.trim();
    if (!line) return;
    const lower = line.toLowerCase();

    if (lower.includes("show running-config")) sectionHints.add("Running configuration");
    if (lower.includes("show access-list")) sectionHints.add("Access-list detail");
    if (lower.includes("show route")) sectionHints.add("Routing table");
    if (lower.includes("show nat")) sectionHints.add("NAT detail");
    if (lower.includes("show failover")) sectionHints.add("Failover state");
    if (lower.includes("show conn")) sectionHints.add("Connection usage");
    if (lower.includes("show logging") || lower.startsWith("logging ") || /%[A-Z0-9_]+-\d-\d+:/.test(line)) sectionHints.add("Syslog & logging");

    const hostnameMatch = line.match(/^hostname\s+(.+)$/i);
    if (hostnameMatch) hostname = hostnameMatch[1];

    const versionMatch = line.match(/(?:ASA|Cisco Adaptive Security Appliance) Version\s+(.+)$/i);
    if (versionMatch) {
      platform = "ASA";
      version = versionMatch[1];
    }
    const ftdMatch = line.match(/(?:Firepower Threat Defense|FTD) Version\s+(.+)$/i);
    if (ftdMatch) {
      platform = "FTD";
      version = ftdMatch[1];
    }
    if (lower.includes("firepower threat defense")) platform = "FTD";
    if (lower.includes("cisco adaptive security appliance") || lower.startsWith("asa version")) platform = "ASA";

    const hardwareMatch = line.match(/^Hardware:\s*([^,]+)/i) || line.match(/^Model:\s*(.+)$/i);
    if (hardwareMatch) model = hardwareMatch[1].trim();

    const uptimeMatch = line.match(/^(.+)\s+up\s+(.+)$/i);
    if (uptimeMatch && lower.includes("up")) uptime = uptimeMatch[2].trim();

    if (lower.includes("failover")) {
      if (lower.includes("active")) haState = "Failover active/standby indicators found";
      else if (!haState) haState = "Failover configuration present";
      failover.configured = true;
      failover.sourceLines.push(line);
      if (/^failover\s+on$/i.test(line)) failover.status = "On";
      else if (/^no\s+failover$/i.test(line)) failover.status = "Off";

      const unitMatch = line.match(/^failover\s+lan\s+unit\s+(primary|secondary)$/i);
      if (unitMatch) failover.localUnit = unitMatch[1];
      const lanMatch = line.match(/^failover\s+lan\s+interface\s+(\S+)\s+(.+)$/i) || line.match(/^Failover LAN Interface:\s*(.+)$/i);
      if (lanMatch) failover.lanInterface = lanMatch.slice(1).filter(Boolean).join(" · ");
      const stateMatch = line.match(/^failover\s+link\s+(\S+)\s+(.+)$/i) || line.match(/^Stateful Failover .* Interface:\s*(.+)$/i);
      if (stateMatch) failover.statefulInterface = stateMatch.slice(1).filter(Boolean).join(" · ");
      const commMatch = line.match(/^Communication State:\s*(.+)$/i);
      if (commMatch) failover.communication = commMatch[1];
      const pollMatch = line.match(/^Poll frequency\s+(.+)$/i);
      if (pollMatch) failover.polltime = pollMatch[1];
      const lastMatch = line.match(/^Last Failover at:\s*(.+)$/i);
      if (lastMatch) failover.lastFailure = lastMatch[1];
    }

    const thisHostMatch = line.match(/^This host:\s*(.+)$/i);
    if (thisHostMatch) {
      failover.configured = true;
      failover.thisHost = thisHostMatch[1];
      failover.sourceLines.push(line);
    }
    const peerHostMatch = line.match(/^(?:Other host|Other host Secondary):\s*(.+)$/i);
    if (peerHostMatch) {
      failover.configured = true;
      failover.peerHost = peerHostMatch[1];
      failover.sourceLines.push(line);
    }
    const failoverInterfaceMatch = line.match(/^Interface\s+([^\s(]+)(?:\s+\(([^)]+)\))?:\s*(.+)$/i);
    if (failoverInterfaceMatch && /(?:normal|failed|waiting|monitored|unmonitored|unknown)/i.test(failoverInterfaceMatch[3])) {
      failover.interfaces.push({
        id: `failover-interface-${failover.interfaces.length + 1}`,
        name: failoverInterfaceMatch[1],
        address: failoverInterfaceMatch[2],
        status: failoverInterfaceMatch[3],
        sourceLine: line,
      });
      failover.sourceLines.push(line);
    }
    if (/^Stateful Failover Logical Update Statistics/i.test(line) || /^Stateful Obj/i.test(line) || /^Failover History/i.test(line) || /^\d{2}:\d{2}:\d{2}\s+/.test(line)) {
      failover.history.push(line);
    }

    if (/^logging(?:\s|$)/i.test(line) || /^no logging(?:\s|$)/i.test(line)) {
      syslog.configLines.push(line);
      if (/^logging enable$/i.test(line)) syslog.enabled = true;
      if (/^no logging enable$/i.test(line)) syslog.enabled = false;
      if (/^logging timestamp$/i.test(line)) syslog.timestamps = true;
      const bufferedMatch = line.match(/^logging buffered\s+(\S+)/i);
      if (bufferedMatch) syslog.bufferedLevel = bufferedMatch[1];
      const trapMatch = line.match(/^logging trap\s+(\S+)/i);
      if (trapMatch) syslog.trapLevel = trapMatch[1];
      const bufferSizeMatch = line.match(/^logging buffer-size\s+(\S+)/i);
      if (bufferSizeMatch) syslog.bufferSize = bufferSizeMatch[1];
      const sourceMatch = line.match(/^logging source-interface\s+(\S+)/i);
      if (sourceMatch && !syslog.sourceInterfaces.includes(sourceMatch[1])) syslog.sourceInterfaces.push(sourceMatch[1]);
      const disabledMatch = line.match(/^no logging message\s+(\d+)/i);
      if (disabledMatch) syslog.disabledMessageIds.push(disabledMatch[1]);
      const hostMatch = line.match(/^logging host\s+(\S+)\s+(\S+)(?:\s+(tcp|udp)(?:\/(\d+))?)?/i);
      if (hostMatch) {
        syslog.hosts.push({
          id: `syslog-host-${syslog.hosts.length + 1}`,
          interface: hostMatch[1],
          address: hostMatch[2],
          protocol: hostMatch[3],
          port: hostMatch[4],
          sourceLine: line,
        });
      }
    }

    const syslogMatch = line.match(/^(.*?)%([A-Z0-9_]+)-(\d)-(\d+):\s*(.*)$/i);
    if (syslogMatch) {
      const severity = Number(syslogMatch[3]);
      syslog.events.push({
        id: `syslog-event-${syslog.events.length + 1}`,
        timestamp: syslogMatch[1].trim() || undefined,
        facility: syslogMatch[2].toUpperCase(),
        severity,
        severityLabel: syslogSeverityLabels[severity] || `Level ${severity}`,
        messageId: syslogMatch[4],
        message: syslogMatch[5],
        sourceLine: line,
      });
    }

    const contextMatch = line.match(/^context\s+(.+)$/i);
    if (contextMatch) contexts.add(contextMatch[1]);

    if (!raw.startsWith(" ") && !/^interface\s+/i.test(line)) currentInterface = null;
    if (!raw.startsWith(" ") && !/^object network\s+/i.test(line)) currentNetworkObject = null;
    if (!raw.startsWith(" ") && !/^object-group network\s+/i.test(line)) currentNetworkGroup = null;

    const nameObjectMatch = line.match(/^name\s+(\S+)\s+(\S+)(?:\s+description\s+.+)?$/i);
    if (nameObjectMatch) {
      addNetworkObject({
        name: nameObjectMatch[2],
        kind: "ip",
        value: nameObjectMatch[1],
        sourceLine: line,
      });
    }

    const objectGroupMatch = line.match(/^object-group network\s+(.+)$/i);
    if (objectGroupMatch) {
      currentInterface = null;
      currentNetworkObject = null;
      currentNetworkGroup = objectGroupMatch[1];
      return;
    }

    const objectMatch = line.match(/^object network\s+(.+)$/i);
    if (objectMatch) {
      currentInterface = null;
      currentNetworkObject = { name: objectMatch[1] };
      return;
    }

    if (currentNetworkObject && raw.startsWith(" ")) {
      const hostMatch = line.match(/^host\s+(\S+)$/i);
      const subnetMatch = line.match(/^subnet\s+(\S+)\s+(\S+)$/i);
      const rangeMatch = line.match(/^range\s+(\S+)\s+(\S+)$/i);
      const fqdnMatch = line.match(/^fqdn(?:\s+(v4|v6))?\s+(\S+)$/i);
      if (hostMatch) {
        currentNetworkObject.definition = line;
        addNetworkObject({ name: currentNetworkObject.name, kind: "host", value: hostMatch[1], sourceLine: line });
      } else if (subnetMatch) {
        currentNetworkObject.definition = line;
        addNetworkObject({ name: currentNetworkObject.name, kind: "network", value: subnetMatch[1], mask: subnetMatch[2], sourceLine: line });
      } else if (rangeMatch) {
        currentNetworkObject.definition = line;
        addNetworkObject({ name: currentNetworkObject.name, kind: "range", value: `${rangeMatch[1]} – ${rangeMatch[2]}`, sourceLine: line });
      } else if (fqdnMatch) {
        currentNetworkObject.definition = line;
        addNetworkObject({ name: currentNetworkObject.name, kind: "fqdn", value: fqdnMatch[2], fqdnVersion: fqdnMatch[1]?.toUpperCase(), sourceLine: line });
      }
    }

    if (currentNetworkGroup && raw.startsWith(" ")) {
      const groupHostMatch = line.match(/^network-object host\s+(\S+)$/i);
      const groupObjectMatch = line.match(/^(?:network-object object|group-object)\s+(\S+)$/i);
      const groupNetworkMatch = line.match(/^network-object\s+(\S+)\s+(\S+)$/i);
      if (groupHostMatch) {
        addNetworkObject({ name: currentNetworkGroup, kind: "host", value: groupHostMatch[1], parentGroup: currentNetworkGroup, sourceLine: line });
      } else if (groupObjectMatch) {
        addNetworkObject({ name: currentNetworkGroup, kind: "reference", value: groupObjectMatch[1], parentGroup: currentNetworkGroup, sourceLine: line });
      } else if (groupNetworkMatch) {
        addNetworkObject({ name: currentNetworkGroup, kind: "network", value: groupNetworkMatch[1], mask: groupNetworkMatch[2], parentGroup: currentNetworkGroup, sourceLine: line });
      }
    }

    const intMatch = line.match(/^interface\s+(.+)$/i);
    if (intMatch) {
      currentInterface = {
        id: `if-${interfaces.length + 1}`,
        hardware: intMatch[1],
        logical: intMatch[1],
        role: "unknown",
      };
      interfaces.push(currentInterface);
      return;
    }

    if (currentInterface && raw.startsWith(" ")) {
      const nameifMatch = line.match(/^nameif\s+(.+)$/i);
      if (nameifMatch) {
        currentInterface.nameif = nameifMatch[1];
        currentInterface.zone = nameifMatch[1];
      }
      const zoneMatch = line.match(/^zone-member\s+security\s+(.+)$/i);
      if (zoneMatch) currentInterface.zone = zoneMatch[1];
      const ipMatch = line.match(/^ip address\s+(\S+)\s+(\S+)/i);
      if (ipMatch) {
        currentInterface.ip = ipMatch[1];
        currentInterface.mask = ipMatch[2];
      }
      const secMatch = line.match(/^security-level\s+(\d+)/i);
      if (secMatch) currentInterface.securityLevel = Number(secMatch[1]);
      const vlanMatch = line.match(/^vlan\s+(\d+)/i);
      if (vlanMatch) currentInterface.vlan = vlanMatch[1];
      if (lower.includes("shutdown")) currentInterface.status = "shutdown";
      currentInterface.role = inferRole(currentInterface.zone || currentInterface.nameif, currentInterface.securityLevel);
      return;
    }

    const routeMatch = line.match(/^route\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?/i);
    if (routeMatch) {
      routes.push({
        id: `route-${routes.length + 1}`,
        iface: routeMatch[1],
        destination: routeMatch[2],
        mask: routeMatch[3],
        nextHop: routeMatch[4],
        metric: routeMatch[5],
        kind: routeMatch[2] === "0.0.0.0" && routeMatch[3] === "0.0.0.0" ? "default" : "static",
        sourceLine: line,
      });
    }

    const routeTableMatch = line.match(/^[A-Z*]+\s+(\d+\.\d+\.\d+\.\d+)\/(\d+).+via\s+(\d+\.\d+\.\d+\.\d+),\s*(\S+)/i);
    if (routeTableMatch) {
      routes.push({
        id: `route-${routes.length + 1}`,
        iface: routeTableMatch[4],
        destination: `${routeTableMatch[1]}/${routeTableMatch[2]}`,
        nextHop: routeTableMatch[3],
        kind: routeTableMatch[1] === "0.0.0.0" ? "default" : "dynamic",
        sourceLine: line,
      });
    }

    const natMatch = line.match(/^nat\s+\(([^)]+)\)\s+(.+)$/i);
    if (natMatch) {
      const detail = natMatch[2];
      const interfaces = natMatch[1].split(",").map((value) => value.trim());
      const manualSource = detail.match(/\bsource\s+(static|dynamic)\s+(\S+)\s+(\S+)/i);
      const objectSource = detail.match(/^(static|dynamic)\s+(\S+)/i);
      const destination = detail.match(/\bdestination\s+(?:static|dynamic)\s+(\S+)\s+(\S+)/i);
      const service = detail.match(/\bservice\s+(\S+)\s+(\S+)\s+(\S+)/i);
      const modeToken = (manualSource?.[1] || objectSource?.[1] || "unknown").toLowerCase();
      const originalSource = manualSource?.[2] || currentNetworkObject?.name || detail;
      const translatedSource = manualSource?.[3] || objectSource?.[2];
      const mode = originalSource === translatedSource ? "identity" : modeToken === "static" || modeToken === "dynamic" ? modeToken : "unknown";
      nats.push({
        id: `nat-${nats.length + 1}`,
        section: natMatch[1],
        sourceInterface: interfaces[0] || undefined,
        destinationInterface: interfaces[1] || undefined,
        mode,
        source: originalSource,
        translated: translatedSource,
        destination: destination?.[1],
        translatedDestination: destination?.[2],
        service: service ? `${service[1]} ${service[2]}` : undefined,
        translatedService: service?.[3],
        dns: /\bdns\b/i.test(detail),
        routeLookup: /\broute-lookup\b/i.test(detail),
        inactive: /\binactive\b/i.test(detail),
        objectName: currentNetworkObject?.name,
        objectDefinition: currentNetworkObject?.definition,
        sourceLine: line,
      });
    }

    const accessGroupMatch = line.match(/^access-group\s+(\S+)\s+in\s+interface\s+(\S+)/i);
    if (accessGroupMatch) aclBindings.set(accessGroupMatch[1], accessGroupMatch[2]);

    const aclMatch = line.match(/^access-list\s+(\S+)\s+(?:line\s+\d+\s+)?extended\s+(\S+)\s+(.+)$/i);
    if (aclMatch) {
      const aclName = aclMatch[1];
      const action = aclMatch[2].toLowerCase();
      const tokens = aclMatch[3].split(/\s+/);
      const protocol = tokens[0] || "ip";
      let next = 1;
      const src = parseEndpoint(tokens, next);
      next = src.next;
      const srcPort = parsePort(tokens, next);
      next = srcPort.next;
      const dst = parseEndpoint(tokens, next);
      next = dst.next;
      const dstPort = parsePort(tokens, next);
      const binding = aclBindings.get(aclName);
      const logging = tokens.slice(dstPort.next).some((token) => token.toLowerCase() === "log") ? "Enabled" : "Disabled";
      const partial: Partial<PolicyRule> = {
        action,
        source: src.value,
        destination: dst.value,
        protocol: [protocol],
        sourcePort: srcPort.value,
        destinationPort: dstPort.value,
        appId: [],
        geolocation: [],
        logging,
        ingressInterface: binding,
      };
      const direction = inferDirection(partial, interfaces);
      rules.push({
        id: `rule-${rules.length + 1}`,
        ruleName: aclName,
        action,
        source: src.value,
        destination: dst.value,
        protocol: [protocol],
        sourcePort: srcPort.value,
        destinationPort: dstPort.value,
        appId: [],
        geolocation: [],
        logging,
        ingressInterface: binding,
        enabled: true,
        policyType: "ASA_ACL",
        sourceLine: line,
        ...direction,
      });
    }

    const acpMatch =
      line.match(/^(?:access-control-rule|rule)\s+(.+)$/i) ||
      line.match(/^ACP\s+Rule\s*[:#-]\s*(.+)$/i);
    if (acpMatch) {
      const actionMatch = line.match(/\b(allow|trust|monitor|block|deny)\b/i);
      const sourceMatch = line.match(/\bsource(?:s|Zones?)?\s*[:=]\s*([^,;]+)/i);
      const destinationMatch = line.match(/\bdestination(?:s|Zones?)?\s*[:=]\s*([^,;]+)/i);
      const portMatch = line.match(/\b(?:dest(?:ination)?\s*)?port\s*[:=]\s*([^,;]+)/i);
      const protoMatch = line.match(/\bprotocol\s*[:=]\s*([^,;]+)/i);
      const sourceZoneMatch = line.match(/\bsource\s+zone\s*[:=]\s*([^,;]+)/i);
      const destZoneMatch = line.match(/\bdestination\s+zone\s*[:=]\s*([^,;]+)/i);
      const appIdMatch = line.match(/\b(?:app(?:lication)?(?:\s*id)?s?)\s*[:=]\s*(.+?)(?=,\s*(?:source|destination|protocol|port|logging|log|geo|countr)\b|;|$)/i);
      const sourceGeoMatch = line.match(/\bsource\s+(?:geo(?:location)?|countr(?:y|ies))\s*[:=]\s*([^,;]+)/i);
      const destinationGeoMatch = line.match(/\bdestination\s+(?:geo(?:location)?|countr(?:y|ies))\s*[:=]\s*([^,;]+)/i);
      const geoMatch = line.match(/\b(?:geo(?:location)?|countr(?:y|ies))\s*[:=]\s*([^,;]+)/i);
      const loggingMatch = line.match(/\b(?:logging|log)\s*[:=]\s*([^,;]+)/i);
      const appId = appIdMatch?.[1]
        ?.split(/\s*[,|]\s*/)
        .map((value) => value.trim())
        .filter(Boolean) || [];
      const geolocation = [
        sourceGeoMatch ? `Source: ${sourceGeoMatch[1].trim()}` : "",
        destinationGeoMatch ? `Destination: ${destinationGeoMatch[1].trim()}` : "",
        !sourceGeoMatch && !destinationGeoMatch && geoMatch ? geoMatch[1].trim() : "",
      ].filter(Boolean);
      const logging = loggingMatch?.[1]?.trim() || (/\blog(?:ging)?\b/i.test(line) ? "Enabled" : "Not specified");
      const partial: Partial<PolicyRule> = {
        action: (actionMatch?.[1] || "unknown").toLowerCase(),
        source: [sourceMatch?.[1]?.trim() || "any"],
        destination: [destinationMatch?.[1]?.trim() || "any"],
        protocol: [protoMatch?.[1]?.trim() || "ip"],
        sourcePort: ["any"],
        destinationPort: [portMatch?.[1]?.trim() || "any"],
        appId,
        geolocation,
        logging,
      };
      const direction = inferDirection(partial, interfaces);
      rules.push({
        id: `rule-${rules.length + 1}`,
        ruleName: acpMatch[1].trim(),
        action: partial.action || "unknown",
        source: partial.source || ["any"],
        destination: partial.destination || ["any"],
        protocol: partial.protocol || ["ip"],
        sourcePort: ["any"],
        destinationPort: partial.destinationPort || ["any"],
        appId,
        geolocation,
        logging,
        sourceZone: sourceZoneMatch ? [sourceZoneMatch[1].trim()] : undefined,
        destinationZone: destZoneMatch ? [destZoneMatch[1].trim()] : undefined,
        enabled: !lower.includes("disabled"),
        policyType: "FTD_ACP",
        sourceLine: line,
        ...direction,
      });
    }

    const hitMatch = line.match(/hitcnt=(\d+)/i);
    if (hitMatch && rules.length) rules[rules.length - 1].hitCount = Number(hitMatch[1]);
  });

  rules.forEach((rule) => {
    if (!rule.ingressInterface && rule.ruleName && aclBindings.has(rule.ruleName)) {
      rule.ingressInterface = aclBindings.get(rule.ruleName);
      Object.assign(rule, inferDirection(rule, interfaces));
    }
  });

  if (!hostname) {
    findings.push({
      id: "missing-hostname",
      severity: "warning",
      label: "Hostname not found",
      detail: "The parser did not find a hostname line. The file may be a partial export or a different show-tech format.",
    });
  }
  if (interfaces.length === 0) {
    findings.push({
      id: "missing-interfaces",
      severity: "critical",
      label: "No interfaces parsed",
      detail: "Interface sections were not found. Direction inference and zone summaries will be limited.",
    });
  }
  if (rules.length === 0) {
    findings.push({
      id: "missing-rules",
      severity: "warning",
      label: "No ACP or ACL rules parsed",
      detail: "No ASA access-list or recognizable FTD ACP rule lines were detected.",
    });
  }
  if (routes.some((route) => route.kind === "default")) {
    findings.push({
      id: "default-route",
      severity: "info",
      label: "Default route found",
      detail: "A default route was detected, which helps classify north-south paths.",
      evidence: routes.find((route) => route.kind === "default")?.sourceLine,
    });
  }
  if (nats.length > 0) {
    findings.push({
      id: "nat-present",
      severity: "info",
      label: "NAT policy present",
      detail: `${nats.length} NAT statement${nats.length === 1 ? "" : "s"} detected for translation review.`,
    });
  }
  if (failover.configured) {
    const unhealthy = failover.interfaces.filter((item) => !/normal/i.test(item.status));
    findings.push({
      id: "failover-state",
      severity: unhealthy.length ? "warning" : "info",
      label: unhealthy.length ? "Failover interface requires review" : "Failover configuration present",
      detail: unhealthy.length
        ? `${unhealthy.length} monitored failover interface${unhealthy.length === 1 ? "" : "s"} did not report Normal.`
        : `${failover.thisHost || failover.localUnit || "HA unit"}${failover.peerHost ? ` paired with ${failover.peerHost}` : " detected"}.`,
    });
  }
  if (syslog.configLines.length && !syslog.enabled) {
    findings.push({
      id: "syslog-disabled",
      severity: "warning",
      label: "Logging configuration found but logging is not enabled",
      detail: "Review the Syslog tab to confirm the global logging state and configured destinations.",
    });
  }
  const bestPractices = buildBestPracticeChecks({ lines, platform, rules, syslog, failover, version });

  return {
    fileName,
    size: text.length,
    parsedAt: new Date().toISOString(),
    hostname,
    platform,
    model,
    version,
    uptime,
    haState,
    contexts: Array.from(contexts),
    interfaces,
    routes,
    nats,
    rules,
    findings,
    sectionHints: Array.from(sectionHints),
    syslog,
    failover,
    bestPractices,
    networkObjects,
  };
}

function downloadJson(analysis: Analysis) {
  const blob = new Blob([JSON.stringify(analysis, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${analysis.hostname || "asa-ftd"}-analysis.json`;
  link.click();
  URL.revokeObjectURL(url);
}

function Badge({ children, tone = "neutral" }: { children: React.ReactNode; tone?: string }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

function EmptyState({ label }: { label: string }) {
  return <div className="empty-state">{label}</div>;
}

function SummaryCard({
  icon,
  label,
  value,
  detail,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  detail?: string;
}) {
  return (
    <section className="metric-card">
      <div className="metric-icon">{icon}</div>
      <div>
        <p>{label}</p>
        <strong>{value}</strong>
        {detail ? <span>{detail}</span> : null}
      </div>
    </section>
  );
}

function App() {
  const [analysis, setAnalysis] = useState<Analysis>(() => parseShowTech(sampleConfig, "sample-asa-show-tech.txt"));
  const [activeView, setActiveView] = useState("summary");
  const [query, setQuery] = useState("");
  const [directionFilter, setDirectionFilter] = useState("ALL");
  const [sortKey, setSortKey] = useState<SortKey>("tuple");
  const [sortAscending, setSortAscending] = useState(true);
  const [natQuery, setNatQuery] = useState("");
  const [natMode, setNatMode] = useState("ALL");
  const [syslogQuery, setSyslogQuery] = useState("");
  const [syslogSeverity, setSyslogSeverity] = useState("ALL");
  const [practiceQuery, setPracticeQuery] = useState("");
  const [practiceStatus, setPracticeStatus] = useState("ALL");
  const [objectQuery, setObjectQuery] = useState("");
  const [objectKind, setObjectKind] = useState("ALL");
  const [dragging, setDragging] = useState(false);
  const [colorPalette, setColorPalette] = useState<ColorPalette>(() => {
    const saved = window.localStorage.getItem("asa-analyzer-palette");
    return saved === "ocean" || saved === "slate" || saved === "amber" ? saved : "forest";
  });

  useEffect(() => {
    document.documentElement.dataset.palette = colorPalette;
    window.localStorage.setItem("asa-analyzer-palette", colorPalette);
  }, [colorPalette]);

  function cycleColorPalette() {
    const currentIndex = colorPalettes.findIndex((palette) => palette.id === colorPalette);
    setColorPalette(colorPalettes[(currentIndex + 1) % colorPalettes.length].id);
  }

  const directionCounts = useMemo(() => {
    return analysis.rules.reduce<Record<Direction, number>>(
      (acc, rule) => {
        acc[rule.direction] += 1;
        return acc;
      },
      { EAST_WEST: 0, NORTH_SOUTH_INBOUND: 0, NORTH_SOUTH_OUTBOUND: 0, UNKNOWN: 0 },
    );
  }, [analysis.rules]);

  const sortedRules = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    const filtered = analysis.rules.filter((rule) => {
      const haystack = [
        rule.ruleName,
        rule.action,
        formatList(rule.source),
        formatList(rule.destination),
        formatList(rule.protocol),
        formatList(rule.sourcePort),
        formatList(rule.destinationPort),
        formatList(rule.appId),
        formatList(rule.geolocation),
        rule.logging,
        rule.direction,
        rule.ingressInterface,
      ]
        .join(" ")
        .toLowerCase();
      const matchesQuery = !normalizedQuery || haystack.includes(normalizedQuery);
      const matchesDirection = directionFilter === "ALL" || rule.direction === directionFilter;
      return matchesQuery && matchesDirection;
    });

    return filtered.sort((a, b) => {
      const tuple = (rule: PolicyRule) =>
        [
          formatList(rule.source),
          formatList(rule.destination),
          formatList(rule.protocol),
          formatList(rule.sourcePort),
          formatList(rule.destinationPort),
        ].join("|");
      const read = (rule: PolicyRule) => {
        if (sortKey === "tuple") return tuple(rule);
        if (sortKey === "hitCount") return rule.hitCount ?? -1;
        return String(rule[sortKey] || "");
      };
      const left = read(a);
      const right = read(b);
      const result = typeof left === "number" && typeof right === "number" ? left - right : String(left).localeCompare(String(right));
      return sortAscending ? result : -result;
    });
  }, [analysis.rules, directionFilter, query, sortAscending, sortKey]);

  const filteredSyslogEvents = useMemo(() => {
    const normalizedQuery = syslogQuery.trim().toLowerCase();
    return analysis.syslog.events.filter((event) => {
      const matchesSeverity = syslogSeverity === "ALL" || event.severity === Number(syslogSeverity);
      const matchesQuery = !normalizedQuery || [event.facility, event.messageId, event.severityLabel, event.message, event.timestamp]
        .join(" ")
        .toLowerCase()
        .includes(normalizedQuery);
      return matchesSeverity && matchesQuery;
    });
  }, [analysis.syslog.events, syslogQuery, syslogSeverity]);

  const filteredNats = useMemo(() => {
    const normalizedQuery = natQuery.trim().toLowerCase();
    return analysis.nats.filter((nat) => {
      const matchesMode = natMode === "ALL" || nat.mode === natMode;
      const matchesQuery = !normalizedQuery || [
        nat.section,
        nat.sourceInterface,
        nat.destinationInterface,
        nat.mode,
        nat.source,
        nat.translated,
        nat.destination,
        nat.translatedDestination,
        nat.service,
        nat.translatedService,
        nat.objectName,
        nat.objectDefinition,
        nat.sourceLine,
      ].join(" ").toLowerCase().includes(normalizedQuery);
      return matchesMode && matchesQuery;
    });
  }, [analysis.nats, natMode, natQuery]);

  const syslogSeverityCounts = useMemo(() => {
    return analysis.syslog.events.reduce<Record<number, number>>((counts, event) => {
      counts[event.severity] = (counts[event.severity] || 0) + 1;
      return counts;
    }, {});
  }, [analysis.syslog.events]);

  const filteredBestPractices = useMemo(() => {
    const normalizedQuery = practiceQuery.trim().toLowerCase();
    const priorityRank = { critical: 0, high: 1, medium: 2, low: 3 };
    const statusRank = { attention: 0, "not-observed": 1, pass: 2 };
    return analysis.bestPractices
      .filter((check) => {
        const matchesStatus = practiceStatus === "ALL" || check.status === practiceStatus;
        const matchesQuery = !normalizedQuery || [check.title, check.category, check.summary, check.recommendation, check.appliesTo]
          .join(" ")
          .toLowerCase()
          .includes(normalizedQuery);
        return matchesStatus && matchesQuery;
      })
      .sort((a, b) => statusRank[a.status] - statusRank[b.status] || priorityRank[a.priority] - priorityRank[b.priority]);
  }, [analysis.bestPractices, practiceQuery, practiceStatus]);

  const filteredNetworkObjects = useMemo(() => {
    const normalizedQuery = objectQuery.trim().toLowerCase();
    return analysis.networkObjects.filter((object) => {
      const matchesKind = objectKind === "ALL" || object.kind === objectKind;
      const matchesQuery = !normalizedQuery || [
        object.name,
        object.kind,
        object.value,
        object.mask,
        object.fqdnVersion,
        object.parentGroup,
        object.sourceLine,
      ].join(" ").toLowerCase().includes(normalizedQuery);
      return matchesKind && matchesQuery;
    });
  }, [analysis.networkObjects, objectKind, objectQuery]);

  function handleFile(file?: File) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setAnalysis(parseShowTech(String(reader.result || ""), file.name));
      setActiveView("summary");
    };
    reader.readAsText(file);
  }

  function handleInput(event: ChangeEvent<HTMLInputElement>) {
    handleFile(event.target.files?.[0]);
    event.target.value = "";
  }

  const viewButtons = [
    { id: "summary", label: "Summary", icon: <BarChart3 size={16} /> },
    { id: "interfaces", label: "Interfaces", icon: <Network size={16} /> },
    { id: "objects", label: "Objects", icon: <Globe2 size={16} /> },
    { id: "routing", label: "Routing", icon: <Route size={16} /> },
    { id: "nat", label: "NAT", icon: <Shuffle size={16} /> },
    { id: "rules", label: "Rules", icon: <ListTree size={16} /> },
    { id: "traffic", label: "Traffic Direction", icon: <Compass size={16} /> },
    { id: "syslog", label: "Syslog", icon: <ScrollText size={16} /> },
    { id: "failover", label: "Failover", icon: <RadioTower size={16} /> },
    { id: "practices", label: "Best Practices", icon: <BadgeCheck size={16} /> },
    { id: "raw", label: "Raw Findings", icon: <FileSearch size={16} /> },
  ];

  const totalClassified = analysis.rules.length - directionCounts.UNKNOWN;
  const classificationPct = analysis.rules.length ? Math.round((totalClassified / analysis.rules.length) * 100) : 0;
  const practicePassed = analysis.bestPractices.filter((check) => check.status === "pass").length;
  const practiceAttention = analysis.bestPractices.filter((check) => check.status === "attention").length;
  const practiceNotObserved = analysis.bestPractices.filter((check) => check.status === "not-observed").length;
  const practiceAssessed = practicePassed + practiceAttention;
  const practiceScore = practiceAssessed ? Math.round((practicePassed / practiceAssessed) * 100) : 0;

  useEffect(() => {
    const context = document.modelContext;
    if (!context?.registerTool) return;

    const lifecycle = new AbortController();
    const register = context.registerTool.bind(context);
    const safeRegister = (tool: Parameters<typeof register>[0]) => {
      try {
        void Promise.resolve(register(tool, { signal: lifecycle.signal })).catch(console.error);
      } catch (error) {
        console.error(error);
      }
    };

    safeRegister({
      name: "read_analysis_summary",
      title: "Read analysis summary",
      description: "Return the currently parsed firewall summary, object counts, and direction counts.",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      execute() {
        return {
          fileName: analysis.fileName,
          hostname: analysis.hostname,
          platform: analysis.platform,
          version: analysis.version,
          interfaces: analysis.interfaces.length,
          networkObjects: analysis.networkObjects.length,
          objectCounts: analysis.networkObjects.reduce<Record<string, number>>((counts, object) => {
            counts[object.kind] = (counts[object.kind] || 0) + 1;
            return counts;
          }, {}),
          routes: analysis.routes.length,
          natRules: analysis.nats.length,
          policyRules: analysis.rules.length,
          directionCounts,
          findings: analysis.findings.map(({ severity, label, detail }) => ({ severity, label, detail })),
          syslogEvents: analysis.syslog.events.length,
          syslogHosts: analysis.syslog.hosts.length,
          failoverStatus: analysis.failover.status,
          failoverPeer: analysis.failover.peerHost,
          bestPracticeChecks: analysis.bestPractices.map(({ id, title, status, priority, appliesTo, summary }) => ({ id, title, status, priority, appliesTo, summary })),
        };
      },
    });

    safeRegister({
      name: "set_rule_view",
      title: "Set rule view",
      description: "Open the rules view and apply optional search, direction filter, sort key, and sort direction.",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string" },
          direction: {
            type: "string",
            enum: ["ALL", "EAST_WEST", "NORTH_SOUTH_INBOUND", "NORTH_SOUTH_OUTBOUND", "UNKNOWN"],
          },
          sortKey: {
            type: "string",
            enum: ["tuple", "action", "source", "destination", "protocol", "destinationPort", "direction", "hitCount"],
          },
          ascending: { type: "boolean" },
        },
        additionalProperties: false,
      },
      annotations: { readOnlyHint: false, untrustedContentHint: false },
      execute(input) {
        const value = input && typeof input === "object" ? (input as Record<string, unknown>) : {};
        if (typeof value.query === "string") setQuery(value.query);
        if (typeof value.direction === "string") setDirectionFilter(value.direction);
        if (typeof value.sortKey === "string") setSortKey(value.sortKey as SortKey);
        if (typeof value.ascending === "boolean") setSortAscending(value.ascending);
        setActiveView("rules");
        return {
          activeView: "rules",
          query: typeof value.query === "string" ? value.query : query,
          direction: typeof value.direction === "string" ? value.direction : directionFilter,
          sortKey: typeof value.sortKey === "string" ? value.sortKey : sortKey,
          ascending: typeof value.ascending === "boolean" ? value.ascending : sortAscending,
        };
      },
    });

    return () => lifecycle.abort();
  }, [analysis, directionCounts, directionFilter, query, sortAscending, sortKey]);

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <span className="brand-mark">
            <Shield size={21} />
          </span>
          <div>
            <h1>ASA / FTD Show-Tech Analyzer</h1>
            <p>Local browser parsing for firewall configuration summaries and 5-tuple rule review.</p>
          </div>
        </div>
        <div className="header-actions">
          <button
            className="palette-button"
            type="button"
            onClick={cycleColorPalette}
            title="Change interface color"
            aria-label={`Change interface color. Current palette: ${colorPalettes.find((palette) => palette.id === colorPalette)?.label}`}
          >
            <Palette size={17} aria-hidden="true" />
            <span>Color: {colorPalettes.find((palette) => palette.id === colorPalette)?.label}</span>
            <span className="palette-dot" aria-hidden="true" />
          </button>
          <button className="icon-button" onClick={() => downloadJson(analysis)} title="Download JSON analysis" aria-label="Download JSON analysis">
            <Download size={18} />
          </button>
        </div>
      </header>

      <section
        className={`upload-band ${dragging ? "dragging" : ""}`}
        onDragEnter={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragOver={(event) => event.preventDefault()}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          handleFile(event.dataTransfer.files?.[0]);
        }}
      >
        <div className="upload-copy">
          <HardDriveUpload size={22} />
          <div>
            <strong>{analysis.fileName}</strong>
            <span>
              {analysis.platform} {analysis.version ? `Version ${analysis.version}` : "configuration"} · {analysis.size.toLocaleString()} characters parsed
            </span>
          </div>
        </div>
        <label className="upload-button">
          <Upload size={17} />
          <span>Upload show-tech</span>
          <input type="file" accept=".txt,.log,.cfg,.conf,text/plain" onChange={handleInput} />
        </label>
      </section>

      <nav className="view-tabs" aria-label="Analysis views">
        {viewButtons.map((button) => (
          <button
            key={button.id}
            className={activeView === button.id ? "active" : ""}
            onClick={() => setActiveView(button.id)}
          >
            {button.icon}
            <span>{button.label}</span>
          </button>
        ))}
      </nav>

      {activeView === "summary" && (
        <section className="panel-grid">
          <div className="summary-grid">
            <SummaryCard icon={<Shield size={18} />} label="Firewall" value={analysis.hostname || "Unknown"} detail={analysis.model || analysis.platform} />
            <SummaryCard icon={<Network size={18} />} label="Interfaces" value={analysis.interfaces.length} detail={`${analysis.interfaces.filter((item) => item.role !== "unknown").length} classified`} />
            <SummaryCard icon={<ListTree size={18} />} label="ACP / ACL Rules" value={analysis.rules.length} detail={`${classificationPct}% direction classified`} />
            <SummaryCard icon={<Shuffle size={18} />} label="NAT Rules" value={analysis.nats.length} detail={`${analysis.routes.length} route entries`} />
          </div>

          <section className="wide-panel">
            <div className="section-heading">
              <div>
                <h2>Executive Summary</h2>
                <p>High-signal ASA / FTD facts extracted from the show-tech text.</p>
              </div>
              <Badge tone={analysis.findings.some((finding) => finding.severity === "critical") ? "danger" : "good"}>
                {analysis.findings.filter((finding) => finding.severity !== "info").length} review item(s)
              </Badge>
            </div>
            <div className="summary-list">
              <span>Platform</span>
              <strong>{analysis.platform}</strong>
              <span>Software</span>
              <strong>{analysis.version || "Not detected"}</strong>
              <span>HA state</span>
              <strong>{analysis.haState || "No failover signal detected"}</strong>
              <span>Contexts</span>
              <strong>{analysis.contexts.length ? analysis.contexts.join(", ") : "Single or not detected"}</strong>
              <span>Sections recognized</span>
              <strong>{analysis.sectionHints.length ? analysis.sectionHints.join(", ") : "Configuration-style lines only"}</strong>
            </div>
          </section>

          <section className="wide-panel change-summary" aria-labelledby="change-summary-title">
            <div className="section-heading">
              <div>
                <h2 id="change-summary-title">Recent Changes</h2>
                <p>A quick summary of the latest analyzer improvements.</p>
              </div>
              <Badge tone="good">Updated</Badge>
            </div>
            <ul>
              <li><strong>Network object inventory:</strong> Review named IP aliases, hosts, subnets, ranges, FQDNs, and object-group members in one searchable view.</li>
              <li><strong>Richer rule analysis:</strong> ACP / ACL results now include application ID, geolocation, and logging details when present.</li>
              <li><strong>Flexible appearance:</strong> Use the palette control in the header to cycle through the available interface color themes.</li>
              <li><strong>Same local-first workflow:</strong> Uploaded show-tech files continue to be parsed in your browser.</li>
            </ul>
          </section>

          <section className="wide-panel">
            <div className="section-heading">
              <div>
                <h2>Review Queue</h2>
                <p>Parser warnings and configuration signals worth validating.</p>
              </div>
            </div>
            <div className="finding-list">
              {analysis.findings.map((finding) => (
                <article key={finding.id} className={`finding finding-${finding.severity}`}>
                  {finding.severity === "critical" ? <XCircle size={18} /> : finding.severity === "warning" ? <AlertTriangle size={18} /> : <CheckCircle2 size={18} />}
                  <div>
                    <strong>{finding.label}</strong>
                    <p>{finding.detail}</p>
                    {finding.evidence ? <code>{finding.evidence}</code> : null}
                  </div>
                </article>
              ))}
            </div>
          </section>
        </section>
      )}

      {activeView === "interfaces" && (
        <section className="wide-panel">
          <div className="section-heading">
            <div>
              <h2>Interfaces & Zones</h2>
              <p>Nameif, zone, addressing, security level, and inferred deployment role.</p>
            </div>
          </div>
          {analysis.interfaces.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Interface</th>
                    <th>Name / Zone</th>
                    <th>IP</th>
                    <th>Security</th>
                    <th>VLAN</th>
                    <th>Role</th>
                  </tr>
                </thead>
                <tbody>
                  {analysis.interfaces.map((item) => (
                    <tr key={item.id}>
                      <td>{item.hardware}</td>
                      <td>{item.zone || item.nameif || "-"}</td>
                      <td>{item.ip ? `${item.ip} ${item.mask || ""}` : "-"}</td>
                      <td>{item.securityLevel ?? "-"}</td>
                      <td>{item.vlan || "-"}</td>
                      <td><Badge tone={item.role}>{item.role}</Badge></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState label="No interface sections were detected." />
          )}
        </section>
      )}

      {activeView === "objects" && (
        <section className="panel-grid object-view">
          <div className="summary-grid">
            <SummaryCard icon={<Globe2 size={18} />} label="All mappings" value={analysis.networkObjects.length} detail={`${filteredNetworkObjects.length} currently shown`} />
            <SummaryCard icon={<Server size={18} />} label="Hosts" value={analysis.networkObjects.filter((object) => object.kind === "host").length} detail="Single-address objects" />
            <SummaryCard icon={<Network size={18} />} label="Networks" value={analysis.networkObjects.filter((object) => object.kind === "network").length} detail="Subnet and mask pairs" />
            <SummaryCard icon={<Globe2 size={18} />} label="FQDNs" value={analysis.networkObjects.filter((object) => object.kind === "fqdn").length} detail={`${analysis.networkObjects.filter((object) => object.kind === "ip" || object.kind === "range").length} IP aliases or ranges`} />
          </div>

          <section className="wide-panel">
            <div className="section-heading">
              <div>
                <h2>Network Object Inventory</h2>
                <p>Named IP aliases, hosts, subnets, ranges, FQDNs, and object-group members found in the uploaded configuration.</p>
              </div>
              <Badge tone="neutral">{filteredNetworkObjects.length} shown</Badge>
            </div>
            <div className="rule-toolbar object-toolbar">
              <label className="search-box">
                <Search size={16} />
                <input value={objectQuery} onChange={(event) => setObjectQuery(event.target.value)} placeholder="Search names, addresses, FQDNs, or groups" />
              </label>
              <label className="select-box">
                <Filter size={16} />
                <select value={objectKind} onChange={(event) => setObjectKind(event.target.value)}>
                  <option value="ALL">All object types</option>
                  <option value="ip">IP aliases</option>
                  <option value="host">Hosts</option>
                  <option value="network">Networks</option>
                  <option value="fqdn">FQDNs</option>
                  <option value="range">Ranges</option>
                  <option value="reference">Group references</option>
                </select>
                <ChevronDown size={15} />
              </label>
            </div>
            {filteredNetworkObjects.length ? (
              <div className="table-wrap">
                <table className="object-table">
                  <thead>
                    <tr>
                      <th>Object / Group</th>
                      <th>Type</th>
                      <th>Mapping</th>
                      <th>Scope</th>
                      <th>Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredNetworkObjects.map((object) => (
                      <tr key={object.id}>
                        <td><strong>{object.name}</strong></td>
                        <td><Badge tone={object.kind === "fqdn" ? "east" : object.kind === "host" ? "good" : object.kind === "network" ? "north" : "neutral"}>{object.kind}</Badge></td>
                        <td>
                          <strong>{object.value}{object.mask ? ` ${object.mask}` : ""}</strong>
                          {object.fqdnVersion ? <span>{object.fqdnVersion}</span> : null}
                        </td>
                        <td>{object.parentGroup ? `Member of ${object.parentGroup}` : object.kind === "ip" ? "Global name alias" : "Network object"}</td>
                        <td><code>{object.sourceLine}</code></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState label="No network objects match the current filters." />
            )}
          </section>
        </section>
      )}

      {activeView === "routing" && (
        <section className="wide-panel">
          <div className="section-heading">
            <div>
              <h2>Routing</h2>
              <p>Default, static, and dynamic route entries recognized in the file.</p>
            </div>
            <Badge tone="neutral">{analysis.routes.length} route(s)</Badge>
          </div>
          {analysis.routes.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Interface</th>
                    <th>Destination</th>
                    <th>Next Hop</th>
                    <th>Metric</th>
                  </tr>
                </thead>
                <tbody>
                  {analysis.routes.map((route) => (
                    <tr key={route.id}>
                      <td><Badge tone={route.kind === "default" ? "north" : "neutral"}>{route.kind}</Badge></td>
                      <td>{route.iface || "-"}</td>
                      <td>{route.mask ? `${route.destination} ${route.mask}` : route.destination}</td>
                      <td>{route.nextHop || "-"}</td>
                      <td>{route.metric || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState label="No route statements were detected." />
          )}
        </section>
      )}

      {activeView === "nat" && (
        <section className="panel-grid nat-view">
          <div className="summary-grid nat-summary-grid">
            <SummaryCard icon={<Shuffle size={18} />} label="NAT rules" value={analysis.nats.length} detail={`${filteredNats.length} currently shown`} />
            <SummaryCard icon={<ArrowDownUp size={18} />} label="Static" value={analysis.nats.filter((nat) => nat.mode === "static").length} detail="Fixed translations" />
            <SummaryCard icon={<Activity size={18} />} label="Dynamic" value={analysis.nats.filter((nat) => nat.mode === "dynamic").length} detail="PAT or dynamic pool" />
            <SummaryCard icon={<BadgeCheck size={18} />} label="Identity" value={analysis.nats.filter((nat) => nat.mode === "identity").length} detail={`${analysis.nats.filter((nat) => nat.inactive).length} inactive`} />
          </div>

          <section className="wide-panel">
            <div className="section-heading">
              <div>
                <h2>NAT Rule Details</h2>
                <p>Original and translated endpoints, interface path, service mapping, options, and source evidence.</p>
              </div>
              <Badge tone="neutral">{filteredNats.length} shown</Badge>
            </div>
            <div className="rule-toolbar nat-toolbar">
              <label className="search-box">
                <Search size={16} />
                <input value={natQuery} onChange={(event) => setNatQuery(event.target.value)} placeholder="Search objects, interfaces, addresses, services" />
              </label>
              <label className="select-box">
                <Filter size={16} />
                <select value={natMode} onChange={(event) => setNatMode(event.target.value)}>
                  <option value="ALL">All NAT types</option>
                  <option value="static">Static</option>
                  <option value="dynamic">Dynamic</option>
                  <option value="identity">Identity</option>
                  <option value="unknown">Unclassified</option>
                </select>
                <ChevronDown size={15} />
              </label>
            </div>
            {filteredNats.length ? (
              <div className="nat-rule-list">
                {filteredNats.map((nat, index) => (
                  <article
                    key={nat.id}
                    className="nat-rule-card"
                    style={{ "--nat-index": index } as React.CSSProperties}
                  >
                    <div className="nat-rule-topline">
                      <div className="nat-rule-title">
                        <span className="nat-rule-number">{String(index + 1).padStart(2, "0")}</span>
                        <div>
                          <h3>{nat.objectName || `${nat.mode.charAt(0).toUpperCase()}${nat.mode.slice(1)} translation`}</h3>
                          <span>{nat.sourceInterface || "any"} → {nat.destinationInterface || "any"}</span>
                        </div>
                      </div>
                      <div className="nat-rule-badges">
                        <Badge tone={nat.mode === "static" ? "north" : nat.mode === "dynamic" ? "east" : "neutral"}>{nat.mode}</Badge>
                        {nat.inactive ? <Badge tone="warning">Inactive</Badge> : <Badge tone="good">Active</Badge>}
                      </div>
                    </div>

                    <div className="nat-flow" aria-label={`Original source ${nat.source}, translated source ${nat.translated || "not detected"}`}>
                      <div className="nat-endpoint nat-original">
                        <span>Original source</span>
                        <strong>{nat.source}</strong>
                        <small>{nat.objectDefinition || "Object definition not retained"}</small>
                      </div>
                      <div className="nat-flow-arrow" aria-hidden="true"><span>→</span></div>
                      <div className="nat-endpoint nat-translated">
                        <span>Translated source</span>
                        <strong>{nat.translated || "Not detected"}</strong>
                        <small>{nat.mode === "dynamic" ? "Dynamic pool or interface PAT" : nat.mode === "identity" ? "Address preserved" : "Fixed mapping"}</small>
                      </div>
                    </div>

                    <div className="nat-detail-grid">
                      <div><span>Original destination</span><strong>{nat.destination || "Any"}</strong></div>
                      <div><span>Translated destination</span><strong>{nat.translatedDestination || "Unchanged"}</strong></div>
                      <div><span>Original service</span><strong>{nat.service || "Any service"}</strong></div>
                      <div><span>Translated service</span><strong>{nat.translatedService || "Unchanged"}</strong></div>
                    </div>

                    <div className="nat-options">
                      <span className={nat.dns ? "enabled" : ""}>DNS rewrite {nat.dns ? "on" : "off"}</span>
                      <span className={nat.routeLookup ? "enabled" : ""}>Route lookup {nat.routeLookup ? "on" : "off"}</span>
                      <span>Section {nat.section || "not detected"}</span>
                    </div>

                    <details>
                      <summary>Raw NAT statement</summary>
                      <code>{nat.sourceLine}</code>
                    </details>
                  </article>
                ))}
              </div>
            ) : (
              <EmptyState label="No NAT rules match the current filters." />
            )}
          </section>
        </section>
      )}

      {activeView === "rules" && (
        <section className="wide-panel">
          <div className="section-heading">
            <div>
              <h2>ACP / ACL Rules</h2>
              <p>Rules normalized into 5-tuple details, application identity, geolocation, and logging.</p>
            </div>
            <Badge tone="neutral">{sortedRules.length} shown</Badge>
          </div>
          <div className="rule-toolbar">
            <label className="search-box">
              <Search size={16} />
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search rules, objects, ports, directions" />
            </label>
            <label className="select-box">
              <Filter size={16} />
              <select value={directionFilter} onChange={(event) => setDirectionFilter(event.target.value)}>
                <option value="ALL">All directions</option>
                <option value="EAST_WEST">East-West</option>
                <option value="NORTH_SOUTH_INBOUND">North-South Inbound</option>
                <option value="NORTH_SOUTH_OUTBOUND">North-South Outbound</option>
                <option value="UNKNOWN">Unknown</option>
              </select>
              <ChevronDown size={15} />
            </label>
            <label className="select-box">
              <SlidersHorizontal size={16} />
              <select value={sortKey} onChange={(event) => setSortKey(event.target.value as SortKey)}>
                <option value="tuple">Sort by 5-tuple</option>
                <option value="action">Action</option>
                <option value="source">Source</option>
                <option value="destination">Destination</option>
                <option value="protocol">Protocol</option>
                <option value="destinationPort">Destination port</option>
                <option value="direction">Direction</option>
                <option value="hitCount">Hit count</option>
              </select>
              <ChevronDown size={15} />
            </label>
            <button className="compact-button" onClick={() => setSortAscending((value) => !value)}>
              <ArrowDownUp size={16} />
              <span>{sortAscending ? "Asc" : "Desc"}</span>
            </button>
          </div>
          {sortedRules.length ? (
            <div className="table-wrap rules-table">
              <table>
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Action</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Src Port</th>
                    <th>Dst Port</th>
                    <th>App ID</th>
                    <th>Geolocation</th>
                    <th>Logging</th>
                    <th>Direction</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedRules.map((rule) => (
                    <tr key={rule.id}>
                      <td>
                        <strong>{rule.ruleName || rule.id}</strong>
                        <span>{rule.policyType}{rule.ingressInterface ? ` · ${rule.ingressInterface}` : ""}</span>
                      </td>
                      <td><Badge tone={rule.action.includes("deny") || rule.action.includes("block") ? "danger" : "good"}>{rule.action}</Badge></td>
                      <td>{formatList(rule.source)}</td>
                      <td>{formatList(rule.destination)}</td>
                      <td>{formatList(rule.protocol)}</td>
                      <td>{formatList(rule.sourcePort)}</td>
                      <td>{formatList(rule.destinationPort)}</td>
                      <td>{formatList(rule.appId)}</td>
                      <td>{formatList(rule.geolocation)}</td>
                      <td>{rule.logging}</td>
                      <td>
                        <Badge tone={rule.direction === "EAST_WEST" ? "east" : rule.direction.includes("NORTH") ? "north" : "neutral"}>
                          {rule.direction.replace(/_/g, " ")}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState label="No rules match the current filters." />
          )}
        </section>
      )}

      {activeView === "traffic" && (
        <section className="split-grid">
          <section className="wide-panel">
            <div className="section-heading">
              <div>
                <h2>Deployment Usage</h2>
                <p>East-west and north-south counts inferred from zones, interfaces, routes, and endpoint addressing.</p>
              </div>
            </div>
            <div className="direction-bars">
              {[
                ["East-West", directionCounts.EAST_WEST, "east"],
                ["North-South Inbound", directionCounts.NORTH_SOUTH_INBOUND, "north"],
                ["North-South Outbound", directionCounts.NORTH_SOUTH_OUTBOUND, "north"],
                ["Unknown", directionCounts.UNKNOWN, "neutral"],
              ].map(([label, count, tone]) => {
                const pct = analysis.rules.length ? Math.max(4, Math.round((Number(count) / analysis.rules.length) * 100)) : 0;
                return (
                  <div className="bar-row" key={String(label)}>
                    <div>
                      <strong>{label}</strong>
                      <span>{count} rule{Number(count) === 1 ? "" : "s"}</span>
                    </div>
                    <div className="bar-track">
                      <span className={`bar-fill bar-${tone}`} style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </section>
          <section className="wide-panel">
            <div className="section-heading">
              <div>
                <h2>Inference Reasons</h2>
                <p>Each classified rule keeps the evidence trail used for direction assignment.</p>
              </div>
            </div>
            <div className="reason-list">
              {analysis.rules.slice(0, 10).map((rule) => (
                <article key={rule.id}>
                  <Badge tone={rule.directionConfidence === "HIGH" ? "good" : rule.directionConfidence === "MEDIUM" ? "north" : "neutral"}>
                    {rule.directionConfidence}
                  </Badge>
                  <div>
                    <strong>{rule.ruleName || rule.id}</strong>
                    <p>{rule.directionReason}</p>
                  </div>
                </article>
              ))}
            </div>
          </section>
        </section>
      )}

      {activeView === "syslog" && (
        <section className="panel-grid">
          <div className="summary-grid syslog-summary-grid">
            <SummaryCard icon={<Activity size={18} />} label="Logging" value={analysis.syslog.enabled ? "Enabled" : "Not confirmed"} detail={analysis.syslog.timestamps ? "Timestamps enabled" : "No timestamp directive"} />
            <SummaryCard icon={<Server size={18} />} label="Collectors" value={analysis.syslog.hosts.length} detail={analysis.syslog.sourceInterfaces.length ? `Source: ${analysis.syslog.sourceInterfaces.join(", ")}` : "Source interface not detected"} />
            <SummaryCard icon={<ScrollText size={18} />} label="Messages" value={analysis.syslog.events.length} detail={`${Object.keys(syslogSeverityCounts).length} severity level(s)`} />
            <SummaryCard icon={<AlertTriangle size={18} />} label="High severity" value={analysis.syslog.events.filter((event) => event.severity <= 3).length} detail="Emergency through error" />
          </div>

          <section className="split-grid">
            <section className="wide-panel">
              <div className="section-heading">
                <div>
                  <h2>Logging Posture</h2>
                  <p>Global state, thresholds, buffers, and message suppression.</p>
                </div>
                <Badge tone={analysis.syslog.enabled ? "good" : "warning"}>{analysis.syslog.enabled ? "Enabled" : "Review"}</Badge>
              </div>
              <div className="summary-list">
                <span>Buffered level</span><strong>{analysis.syslog.bufferedLevel || "Not detected"}</strong>
                <span>Remote trap level</span><strong>{analysis.syslog.trapLevel || "Not detected"}</strong>
                <span>Local buffer size</span><strong>{analysis.syslog.bufferSize ? `${Number(analysis.syslog.bufferSize).toLocaleString()} bytes` : "Not detected"}</strong>
                <span>Timestamping</span><strong>{analysis.syslog.timestamps ? "Configured" : "Not detected"}</strong>
                <span>Disabled message IDs</span><strong>{analysis.syslog.disabledMessageIds.length ? analysis.syslog.disabledMessageIds.join(", ") : "None detected"}</strong>
              </div>
            </section>

            <section className="wide-panel">
              <div className="section-heading">
                <div>
                  <h2>Collector Destinations</h2>
                  <p>Remote syslog endpoints and transport details.</p>
                </div>
                <Badge tone="neutral">{analysis.syslog.hosts.length} host(s)</Badge>
              </div>
              {analysis.syslog.hosts.length ? (
                <div className="table-wrap">
                  <table className="compact-table">
                    <thead><tr><th>Interface</th><th>Address</th><th>Transport</th><th>Port</th></tr></thead>
                    <tbody>{analysis.syslog.hosts.map((host) => (
                      <tr key={host.id}><td>{host.interface || "-"}</td><td>{host.address}</td><td>{host.protocol?.toUpperCase() || "Default"}</td><td>{host.port || "Default"}</td></tr>
                    ))}</tbody>
                  </table>
                </div>
              ) : <EmptyState label="No remote syslog hosts were detected." />}
            </section>
          </section>

          <section className="wide-panel">
            <div className="section-heading">
              <div>
                <h2>Message Explorer</h2>
                <p>Parsed ASA / FTD message IDs with timestamp, severity, facility, and full message text.</p>
              </div>
              <Badge tone="neutral">{filteredSyslogEvents.length} shown</Badge>
            </div>
            <div className="rule-toolbar syslog-toolbar">
              <label className="search-box">
                <Search size={16} />
                <input value={syslogQuery} onChange={(event) => setSyslogQuery(event.target.value)} placeholder="Search message ID, facility, text, or timestamp" />
              </label>
              <label className="select-box">
                <Filter size={16} />
                <select value={syslogSeverity} onChange={(event) => setSyslogSeverity(event.target.value)}>
                  <option value="ALL">All severities</option>
                  {syslogSeverityLabels.map((label, severity) => <option key={label} value={severity}>{severity} · {label}</option>)}
                </select>
                <ChevronDown size={15} />
              </label>
            </div>
            {filteredSyslogEvents.length ? (
              <div className="table-wrap">
                <table className="syslog-table">
                  <thead><tr><th>Time</th><th>Severity</th><th>Facility / ID</th><th>Message</th></tr></thead>
                  <tbody>{filteredSyslogEvents.map((event) => (
                    <tr key={event.id}>
                      <td>{event.timestamp || "-"}</td>
                      <td><Badge tone={event.severity <= 3 ? "danger" : event.severity === 4 ? "warning" : event.severity <= 6 ? "good" : "neutral"}>{event.severity} · {event.severityLabel}</Badge></td>
                      <td><strong>{event.facility}-{event.messageId}</strong></td>
                      <td>{event.message}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            ) : <EmptyState label="No syslog messages match the current filter." />}
          </section>
        </section>
      )}

      {activeView === "failover" && (
        <section className="panel-grid">
          <div className="summary-grid failover-summary-grid">
            <SummaryCard icon={<RadioTower size={18} />} label="Failover" value={analysis.failover.configured ? analysis.failover.status : "Not detected"} detail={analysis.failover.localUnit ? `${analysis.failover.localUnit} unit` : "Unit role not detected"} />
            <SummaryCard icon={<Shield size={18} />} label="This host" value={analysis.failover.thisHost || analysis.failover.localUnit || "Unknown"} detail="Local role and state" />
            <SummaryCard icon={<Server size={18} />} label="Peer host" value={analysis.failover.peerHost || "Not detected"} detail="Mate role and readiness" />
            <SummaryCard icon={<Activity size={18} />} label="Monitored interfaces" value={analysis.failover.interfaces.length} detail={`${analysis.failover.interfaces.filter((item) => /normal/i.test(item.status)).length} normal`} />
          </div>

          <section className="split-grid">
            <section className="wide-panel">
              <div className="section-heading">
                <div>
                  <h2>HA Pair Status</h2>
                  <p>Local and peer roles, communication state, and the last recorded transition.</p>
                </div>
                <Badge tone={analysis.failover.configured ? "good" : "neutral"}>{analysis.failover.configured ? "Configured" : "No signal"}</Badge>
              </div>
              <div className="summary-list">
                <span>Local unit</span><strong>{analysis.failover.localUnit || "Not detected"}</strong>
                <span>This host</span><strong>{analysis.failover.thisHost || "Not detected"}</strong>
                <span>Other host</span><strong>{analysis.failover.peerHost || "Not detected"}</strong>
                <span>Communication</span><strong>{analysis.failover.communication || "Not detected"}</strong>
                <span>Poll frequency</span><strong>{analysis.failover.polltime || "Not detected"}</strong>
                <span>Last failover</span><strong>{analysis.failover.lastFailure || "Not reported"}</strong>
              </div>
            </section>

            <section className="wide-panel">
              <div className="section-heading">
                <div>
                  <h2>Failover Links</h2>
                  <p>LAN and state synchronization interfaces used by the HA pair.</p>
                </div>
              </div>
              <div className="link-status-list">
                <article><RadioTower size={18} /><div><span>LAN failover interface</span><strong>{analysis.failover.lanInterface || "Not detected"}</strong></div></article>
                <article><ArrowDownUp size={18} /><div><span>Stateful update interface</span><strong>{analysis.failover.statefulInterface || "Not detected"}</strong></div></article>
              </div>
            </section>
          </section>

          <section className="wide-panel">
            <div className="section-heading">
              <div>
                <h2>Monitored Interface Health</h2>
                <p>Interface status reported by the failover subsystem.</p>
              </div>
              <Badge tone={analysis.failover.interfaces.some((item) => !/normal/i.test(item.status)) ? "warning" : "good"}>{analysis.failover.interfaces.some((item) => !/normal/i.test(item.status)) ? "Review" : "Healthy"}</Badge>
            </div>
            {analysis.failover.interfaces.length ? (
              <div className="table-wrap">
                <table className="compact-table">
                  <thead><tr><th>Interface</th><th>Address</th><th>Reported state</th></tr></thead>
                  <tbody>{analysis.failover.interfaces.map((item) => (
                    <tr key={item.id}><td>{item.name}</td><td>{item.address || "-"}</td><td><Badge tone={/normal/i.test(item.status) ? "good" : "warning"}>{item.status}</Badge></td></tr>
                  ))}</tbody>
                </table>
              </div>
            ) : <EmptyState label="No monitored failover interface rows were detected." />}
          </section>

          <section className="wide-panel">
            <div className="section-heading">
              <div>
                <h2>Failover Evidence</h2>
                <p>Configuration and state lines retained for operator validation.</p>
              </div>
              <Badge tone="neutral">{analysis.failover.sourceLines.length} lines</Badge>
            </div>
            <div className="raw-list">
              {analysis.failover.sourceLines.length ? analysis.failover.sourceLines.map((line, index) => <code key={`${line}-${index}`}>{line}</code>) : <EmptyState label="No failover evidence was detected." />}
            </div>
          </section>
        </section>
      )}

      {activeView === "practices" && (
        <section className="panel-grid">
          <div className="practice-hero wide-panel">
            <div>
              <span className="eyebrow">{analysis.platform === "UNKNOWN" ? "ASA + FTD baseline" : `${analysis.platform} baseline`}</span>
              <h2>Show-tech Best Practice Assessment</h2>
              <p>Evidence-based checks from the uploaded text. “Not observed” means the configuration could not be confirmed from this file—not that it is definitely absent.</p>
            </div>
            <div className="practice-score" aria-label={`${practiceScore} percent of assessed checks passed`}>
              <strong>{practiceScore}%</strong>
              <span>{practiceAssessed} assessed</span>
            </div>
          </div>

          <div className="summary-grid practice-summary-grid">
            <SummaryCard icon={<CheckCircle2 size={18} />} label="Passed" value={practicePassed} detail="Confirmed by evidence" />
            <SummaryCard icon={<AlertTriangle size={18} />} label="Needs attention" value={practiceAttention} detail="Prioritized remediation" />
            <SummaryCard icon={<FileSearch size={18} />} label="Not observed" value={practiceNotObserved} detail="Validate outside this file" />
            <SummaryCard icon={<Shield size={18} />} label="Applicable checks" value={analysis.bestPractices.length} detail={`${analysis.platform} assessment scope`} />
          </div>

          <section className="wide-panel">
            <div className="section-heading">
              <div>
                <h2>Prioritized Findings</h2>
                <p>Action items first, then unconfirmed controls and confirmed practices.</p>
              </div>
              <Badge tone="neutral">{filteredBestPractices.length} shown</Badge>
            </div>
            <div className="rule-toolbar practice-toolbar">
              <label className="search-box">
                <Search size={16} />
                <input value={practiceQuery} onChange={(event) => setPracticeQuery(event.target.value)} placeholder="Search category, control, or recommendation" />
              </label>
              <label className="select-box">
                <Filter size={16} />
                <select value={practiceStatus} onChange={(event) => setPracticeStatus(event.target.value)}>
                  <option value="ALL">All results</option>
                  <option value="attention">Needs attention</option>
                  <option value="not-observed">Not observed</option>
                  <option value="pass">Passed</option>
                </select>
                <ChevronDown size={15} />
              </label>
            </div>
            <div className="practice-list">
              {filteredBestPractices.map((check) => (
                <article className={`practice-item practice-${check.status}`} key={check.id}>
                  <div className="practice-item-icon" aria-hidden="true">
                    {check.status === "pass" ? <CheckCircle2 size={19} /> : check.status === "attention" ? <AlertTriangle size={19} /> : <FileSearch size={19} />}
                  </div>
                  <div className="practice-item-body">
                    <div className="practice-item-heading">
                      <div>
                        <span>{check.category} · {check.appliesTo}</span>
                        <h3>{check.title}</h3>
                      </div>
                      <div className="practice-badges">
                        <Badge tone={check.status === "pass" ? "good" : check.status === "attention" ? "warning" : "neutral"}>{check.status === "not-observed" ? "Not observed" : check.status}</Badge>
                        <Badge tone={check.priority === "critical" || check.priority === "high" ? "danger" : "neutral"}>{check.priority}</Badge>
                      </div>
                    </div>
                    <p>{check.summary}</p>
                    <div className="recommendation"><strong>Recommended:</strong> {check.recommendation}</div>
                    {check.evidence.length ? (
                      <details>
                        <summary>Evidence ({check.evidence.length})</summary>
                        <div className="practice-evidence">{check.evidence.map((line, index) => <code key={`${check.id}-${index}`}>{line}</code>)}</div>
                      </details>
                    ) : null}
                  </div>
                </article>
              ))}
            </div>
          </section>

          <section className="wide-panel guidance-panel">
            <div className="section-heading">
              <div>
                <h2>Cisco Guidance Used</h2>
                <p>Assessment logic is scoped to signals commonly available in show-tech and running configuration output.</p>
              </div>
            </div>
            <div className="guidance-links">
              <a href="https://secure.cisco.com/secure-firewall/docs/logging-best-practices" target="_blank" rel="noreferrer">Secure Firewall logging best practices</a>
              <a href="https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/hardening/threat_defense/cisco-secure-firewall-threat-defense-hardening-guide-v10.pdf" target="_blank" rel="noreferrer">Threat Defense hardening guide</a>
              <a href="https://www.cisco.com/c/en/us/td/docs/security/asa/asa918/configuration/general/asa-918-general-config/ha-failover.html" target="_blank" rel="noreferrer">ASA failover guidance</a>
              <a href="https://www.cisco.com/c/en/us/td/docs/security/asa/asa916/configuration/general/asa-916-general-config/monitor-syslog.html" target="_blank" rel="noreferrer">ASA logging guidance</a>
            </div>
          </section>
        </section>
      )}

      {activeView === "raw" && (
        <section className="wide-panel">
          <div className="section-heading">
            <div>
              <h2>Raw Findings</h2>
              <p>Evidence lines retained from parsed rules, NAT, and routes for manual validation.</p>
            </div>
            <Badge tone="neutral">{analysis.rules.length + analysis.nats.length + analysis.routes.length} lines</Badge>
          </div>
          <div className="raw-list">
            {[...analysis.rules.map((item) => item.sourceLine), ...analysis.nats.map((item) => item.sourceLine), ...analysis.routes.map((item) => item.sourceLine)]
              .filter(Boolean)
              .map((line, index) => (
                <code key={`${line}-${index}`}>{line}</code>
              ))}
          </div>
        </section>
      )}

      <footer className="app-footer">
        <Badge tone="good"><BadgeCheck size={13} /> Local-first</Badge>
        <span>Files are read by your browser session; no backend upload path is used.</span>
        <span><Globe2 size={14} /> ASA access-list and recognizable FTD ACP text formats supported in this MVP.</span>
      </footer>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
