import { ChangeEvent, DragEvent, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity, AlertTriangle, ArrowDownToLine, ArrowRight, ArrowUpRight, BarChart3,
  Check, CheckCircle2, ChevronDown, CircleHelp, Clock3, Command, Download,
  FileSearch, FileUp, Filter, Gauge, Globe2, HardDrive, Layers3, LockKeyhole,
  Menu, Network, Plus, RefreshCw, Search, Server, Settings2, Shield, ShieldAlert,
  ShieldCheck, SlidersHorizontal, Sparkles, Terminal, Trash2, UploadCloud,
  Wifi, X, Zap,
} from 'lucide-react';

type Page = 'Overview' | 'Packet explorer' | 'Blocking rules' | 'Reports' | 'Settings';
type Packet = {
  number: number; timestamp: string; source: string; destination: string; protocol: string;
  length: number; src_port?: number | null; dst_port?: number | null; info?: string; tcp_flags?: string;
};
type AppCount = { name: string; count: number; percentage: number };
type Domain = { domain: string; application: string };
type Analysis = {
  analysis_id: string; file_name: string; output_file_name: string;
  stats: { total_packets: number; total_bytes: number; tcp_packets: number; udp_packets: number; forwarded: number; dropped: number };
  protocol_breakdown: { name: string; count: number }[]; app_breakdown: AppCount[];
  detected_domains: Domain[]; packets: Packet[]; output_download_url: string; log?: string;
};
type Rule = { id: string; type: 'IP address' | 'Domain' | 'Application'; value: string; enabled: boolean };

const demoPackets: Packet[] = [
  { number: 1, timestamp: '14:32:08.142', source: '192.168.1.12:51724', destination: '142.250.72.14:443', protocol: 'TLS', length: 1514, info: 'Client Hello · www.google.com', tcp_flags: 'PSH, ACK' },
  { number: 2, timestamp: '14:32:08.145', source: '192.168.1.12:51724', destination: '142.250.72.14:443', protocol: 'TCP', length: 66, info: 'ACK', tcp_flags: 'ACK' },
  { number: 3, timestamp: '14:32:08.191', source: '192.168.1.8:53102', destination: '1.1.1.1:53', protocol: 'DNS', length: 82, info: 'Standard query A api.github.com' },
  { number: 4, timestamp: '14:32:08.208', source: '192.168.1.8:53102', destination: '1.1.1.1:53', protocol: 'DNS', length: 124, info: 'Standard query response' },
  { number: 5, timestamp: '14:32:08.226', source: '192.168.1.12:60441', destination: '185.199.108.133:443', protocol: 'TLS', length: 1298, info: 'Client Hello · github.com', tcp_flags: 'PSH, ACK' },
  { number: 6, timestamp: '14:32:08.269', source: '192.168.1.16:49822', destination: '151.101.1.69:443', protocol: 'TCP', length: 517, info: 'Application data', tcp_flags: 'PSH, ACK' },
  { number: 7, timestamp: '14:32:08.310', source: '192.168.1.12:51724', destination: '142.250.72.14:443', protocol: 'TLS', length: 1448, info: 'Encrypted application data', tcp_flags: 'PSH, ACK' },
  { number: 8, timestamp: '14:32:08.344', source: '192.168.1.2:68', destination: '192.168.1.1:67', protocol: 'UDP', length: 342, info: 'DHCP request' },
];
const demoApps: AppCount[] = [
  { name: 'HTTPS', count: 1842, percentage: 42 }, { name: 'Unknown', count: 1064, percentage: 24 },
  { name: 'DNS', count: 624, percentage: 14 }, { name: 'YouTube', count: 392, percentage: 9 },
  { name: 'GitHub', count: 268, percentage: 6 }, { name: 'Other', count: 220, percentage: 5 },
];
const demoDomains: Domain[] = [
  { domain: 'www.google.com', application: 'Google' }, { domain: 'github.com', application: 'GitHub' },
  { domain: 'www.youtube.com', application: 'YouTube' }, { domain: 'api.github.com', application: 'GitHub' },
];
const demoStats = { total_packets: 4410, total_bytes: 12840000, tcp_packets: 3137, udp_packets: 1273, forwarded: 4372, dropped: 38 };
const knownApps = ['YouTube', 'Google', 'Facebook', 'Instagram', 'Twitter/X', 'Netflix', 'Amazon', 'Microsoft', 'Apple', 'WhatsApp', 'Telegram', 'TikTok', 'Spotify', 'Zoom', 'Discord', 'GitHub'];
const navItems: { label: Page; icon: typeof Activity; note?: string }[] = [
  { label: 'Overview', icon: Gauge }, { label: 'Packet explorer', icon: Layers3 },
  { label: 'Blocking rules', icon: Shield }, { label: 'Reports', icon: BarChart3 }, { label: 'Settings', icon: Settings2 },
];
const formatNumber = (n: number) => new Intl.NumberFormat('en-US').format(n || 0);
const formatBytes = (bytes: number) => bytes >= 1_000_000 ? `${(bytes / 1_000_000).toFixed(2)} MB` : bytes >= 1000 ? `${(bytes / 1000).toFixed(1)} KB` : `${bytes} B`;

function App() {
  const [page, setPage] = useState<Page>('Overview');
  const [mobileNav, setMobileNav] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const [apiOnline, setApiOnline] = useState(false);
  const [engineReady, setEngineReady] = useState(false);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [useDemo, setUseDemo] = useState(true);
  const [search, setSearch] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('All protocols');
  const [ipDraft, setIpDraft] = useState('');
  const [domainDraft, setDomainDraft] = useState('');
  const [appDraft, setAppDraft] = useState('YouTube');
  const [ruleError, setRuleError] = useState('');
  const [rules, setRules] = useState<Rule[]>([]);
  const [lbs, setLbs] = useState(2);
  const [fps, setFps] = useState(2);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const refreshHealth = () => fetch('/api/health')
    .then((r) => r.ok ? r.json() : Promise.reject())
    .then((data) => { setApiOnline(true); setEngineReady(Boolean(data.engine_binary_available || data.compiler_available)); })
    .catch(() => { setApiOnline(false); setEngineReady(false); });

  useEffect(() => { refreshHealth(); }, []);

  const stats = analysis?.stats ?? (useDemo ? demoStats : { total_packets: 0, total_bytes: 0, tcp_packets: 0, udp_packets: 0, forwarded: 0, dropped: 0 });
  const packets = analysis?.packets ?? (useDemo ? demoPackets : []);
  const appCounts = analysis?.app_breakdown ?? (useDemo ? demoApps : []);
  const domains = analysis?.detected_domains ?? (useDemo ? demoDomains : []);
  const protocolCounts = analysis?.protocol_breakdown ?? (useDemo ? [{ name: 'TCP', count: 3137 }, { name: 'UDP', count: 1273 }, { name: 'Other', count: 0 }] : []);
  const activeRules = rules.filter((r) => r.enabled).length;

  const filteredPackets = useMemo(() => packets.filter((p) => {
    const all = `${p.number} ${p.timestamp} ${p.source} ${p.destination} ${p.protocol} ${p.info ?? ''}`.toLowerCase();
    return all.includes(search.toLowerCase()) && (protocolFilter === 'All protocols' || p.protocol.toLowerCase().includes(protocolFilter.toLowerCase()));
  }), [packets, search, protocolFilter]);

  const chooseFile = (nextFile?: File) => {
    if (!nextFile) return;
    if (!nextFile.name.toLowerCase().endsWith('.pcap')) {
      setError('Please select a classic .pcap file. PCAPNG is not supported by the current engine.');
      return;
    }
    setFile(nextFile);
    setError('');
  };
  const onFileInput = (event: ChangeEvent<HTMLInputElement>) => chooseFile(event.target.files?.[0]);
  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault(); setDragging(false); chooseFile(event.dataTransfer.files?.[0]);
  };

  const runAnalysis = async () => {
    if (!file) { setError('Choose a .pcap file before starting analysis.'); return; }
    if (!apiOnline) { setError('The analysis API is offline. Start the backend with the instructions in README_FRONTEND.md, then retry.'); return; }
    if (!engineReady) { setError('No compatible DPI engine or C++ compiler was detected. Install g++ / MinGW, clang++, or use a Visual Studio Developer PowerShell, then retry.'); return; }
    setRunning(true); setError(''); setSelectedPacket(null);
    const body = new FormData();
    body.append('file', file);
    body.append('lbs', String(lbs)); body.append('fps', String(fps));
    body.append('rules', JSON.stringify(rules.filter((r) => r.enabled)));
    try {
      const response = await fetch('/api/analyze', { method: 'POST', body });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || 'Analysis failed.');
      setAnalysis(result as Analysis); setUseDemo(false); setPage('Overview');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not analyze the capture.');
    } finally { setRunning(false); }
  };

  const addRule = (type: Rule['type'], value: string) => {
    const cleaned = value.trim();
    if (!cleaned) { setRuleError('Enter a value before adding a rule.'); return; }
    if (rules.some((r) => r.type === type && r.value.toLowerCase() === cleaned.toLowerCase())) { setRuleError('That rule already exists.'); return; }
    setRules((current) => [...current, { id: crypto.randomUUID(), type, value: cleaned, enabled: true }]);
    setRuleError('');
    if (type === 'IP address') setIpDraft(''); else if (type === 'Domain') setDomainDraft('');
  };
  const toggleRule = (id: string) => setRules((current) => current.map((r) => r.id === id ? { ...r, enabled: !r.enabled } : r));
  const removeRule = (id: string) => setRules((current) => current.filter((r) => r.id !== id));

  const go = (label: Page) => { setPage(label); setMobileNav(false); setSelectedPacket(null); };
  const resetToDemo = () => { setAnalysis(null); setUseDemo(true); setFile(null); setError(''); setSelectedPacket(null); };

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNav ? 'sidebar-open' : ''}`}>
        <div className="brand-row">
          <div className="brand-mark"><Activity size={20} strokeWidth={2.6} /></div>
          <div className="brand-copy"><span className="brand-name">PACKETSCOPE</span><span className="brand-caption">ADVANCED ANALYZER</span></div>
          <button className="icon-btn mobile-close" aria-label="Close menu" onClick={() => setMobileNav(false)}><X size={17} /></button>
        </div>
        <div className="workspace-chip"><div className="workspace-avatar"><Network size={15} /></div><div className="workspace-text"><strong>Local workspace</strong><span>Personal environment</span></div><ChevronDown size={15} className="muted-icon" /></div>
        <div className="sidebar-label">WORKSPACE</div>
        <nav className="nav-list" aria-label="Main navigation">
          {navItems.map(({ label, icon: Icon }) => <button key={label} onClick={() => go(label)} className={`nav-item ${page === label ? 'active' : ''}`}><Icon size={17} strokeWidth={1.9} /><span>{label}</span>{label === 'Blocking rules' && <span className="nav-count">{activeRules}</span>}{page === label && <span className="nav-active-dot" />}</button>)}
        </nav>
        <div className="sidebar-divider" />
        <div className="sidebar-label">CAPTURE</div>
        <div className="capture-mini"><div className={`capture-icon ${apiOnline && engineReady ? 'online' : ''}`}>{apiOnline && engineReady ? <Wifi size={15} /> : <Server size={15} />}</div><div className="capture-mini-text"><strong>{apiOnline && engineReady ? 'DPI engine ready' : apiOnline ? 'Compiler unavailable' : 'Engine offline'}</strong><span>{apiOnline && engineReady ? 'Ready to inspect PCAP' : apiOnline ? 'Install a C++ compiler' : 'Start local API to analyze'}</span></div><span className={`status-light ${apiOnline && engineReady ? 'green' : 'amber'}`} /></div>
        <div className="sidebar-bottom"><div className="help-card"><div className="help-icon"><CircleHelp size={16} /></div><div><strong>Need a hand?</strong><p>Review setup instructions and API status.</p><button onClick={() => go('Settings')}>Open settings <ArrowRight size={13} /></button></div></div><div className="sidebar-user"><div className="user-avatar">PA</div><div className="user-details"><strong>Packet Analyst</strong><span>Local session</span></div><button className="icon-btn" aria-label="User menu"><Settings2 size={16} /></button></div></div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="topbar-left"><button className="icon-btn mobile-menu" aria-label="Open menu" onClick={() => setMobileNav(true)}><Menu size={20} /></button><div className="breadcrumbs"><span>Workspace</span><span className="crumb-slash">/</span><strong>{page}</strong></div></div>
          <div className="topbar-actions"><div className={`engine-status ${apiOnline ? 'is-online' : ''}`}><span className="status-light" />{apiOnline ? 'API connected' : 'API offline'}</div><button className="icon-btn help-top" title="Settings" onClick={() => go('Settings')}><CircleHelp size={17} /></button><div className="top-avatar">PA</div></div>
        </header>

        <div className="page-content">
          {page === 'Overview' && <>
            <section className="page-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> NETWORK INTELLIGENCE</div><h1>Traffic overview<span className="heading-period">.</span></h1><p className="page-subtitle">Inspect packets, understand flows, and surface suspicious activity.</p></div><div className="heading-right"><span className={`data-mode ${analysis ? 'real-data' : ''}`}><span className="data-dot" />{analysis ? 'LIVE ANALYSIS' : useDemo ? 'DEMO PREVIEW' : 'NO DATA'}</span><button className="secondary-btn" onClick={resetToDemo}><RefreshCw size={14} /> Reset view</button></div></section>
            {!analysis && useDemo && <div className="demo-notice"><Sparkles size={15} /><span>You're viewing sample dashboard data. Upload a <strong>.pcap</strong> capture and run the engine to see real analysis results.</span><button onClick={() => setUseDemo(!useDemo)}>{useDemo ? 'Hide sample data' : 'Show sample data'}</button></div>}
            <section className="upload-panel">
              <div className="upload-copy"><div className="upload-symbol"><FileSearch size={21} /></div><div><h2>Analyze a capture</h2><p>Drop a Wireshark PCAP file to inspect protocols, domains, and blocking rules.</p></div></div>
              <div className={`drop-zone ${dragging ? 'drag-active' : ''} ${file ? 'has-file' : ''}`} onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={onDrop} onClick={() => fileRef.current?.click()} role="button" tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') fileRef.current?.click(); }}>
                <input ref={fileRef} type="file" accept=".pcap,application/vnd.tcpdump.pcap" onChange={onFileInput} hidden />
                <div className="drop-icon">{file ? <CheckCircle2 size={19} /> : <UploadCloud size={20} />}</div><div className="drop-text"><strong>{file ? file.name : 'Drop your PCAP file here'}</strong><span>{file ? `${(file.size / 1024).toFixed(1)} KB · Ready to analyze` : 'or click to browse · .pcap only'}</span></div>{file && <button className="file-remove" aria-label="Remove file" onClick={(e) => { e.stopPropagation(); setFile(null); if (fileRef.current) fileRef.current.value = ''; }}><X size={14} /></button>}
              </div>
              <button className="primary-btn analyze-btn" disabled={!file || running || !apiOnline || !engineReady} onClick={runAnalysis}>{running ? <><span className="spinner" /> Analyzing…</> : <><Zap size={15} fill="currentColor" /> Run analysis <ArrowRight size={15} /></>}</button>
              {error && <div className="error-message"><AlertTriangle size={14} />{error}</div>}
              {!apiOnline && <div className="upload-footnote"><AlertTriangle size={13} /> Backend not running — see <button onClick={() => go('Settings')}>setup instructions</button>.</div>}
              {apiOnline && !engineReady && <div className="upload-footnote"><AlertTriangle size={13} /> No compatible C++ compiler or DPI binary found — see <button onClick={() => go('Settings')}>setup instructions</button>.</div>}
            </section>

            <section className="metric-grid">
              <MetricCard label="Total packets" value={formatNumber(stats.total_packets)} detail={analysis ? 'From this capture' : 'Sample capture'} icon={Layers3} tone="cyan" trend={analysis ? 'Analyzed' : 'Preview'} />
              <MetricCard label="Data inspected" value={formatBytes(stats.total_bytes)} detail="Captured frame bytes" icon={HardDrive} tone="violet" trend="PCAP" />
              <MetricCard label="Forwarded" value={formatNumber(stats.forwarded)} detail={`${stats.total_packets ? ((stats.forwarded / stats.total_packets) * 100).toFixed(1) : '0.0'}% of packets`} icon={ShieldCheck} tone="green" trend="Allowed" />
              <MetricCard label="Dropped / blocked" value={formatNumber(stats.dropped)} detail="Matched blocking policy" icon={ShieldAlert} tone="orange" trend={stats.dropped ? 'Flagged' : 'Clear'} />
            </section>

            <section className="insight-grid">
              <div className="panel traffic-panel"><div className="panel-header"><div><h3>Protocol distribution</h3><p>Breakdown of packets by transport protocol</p></div><div className="panel-icon"><BarChart3 size={16} /></div></div><div className="protocol-total"><strong>{formatNumber(stats.total_packets)}</strong><span>packets captured</span></div><div className="protocol-bars">{(analysis ? protocolCounts : protocolCounts).filter((p) => p.count > 0).slice(0, 5).map((p, i) => <div className="protocol-row" key={p.name}><div className={`protocol-dot dot-${i % 5}`} /><div className="protocol-name">{p.name}</div><div className="protocol-bar-track"><div className={`protocol-bar bar-${i % 5}`} style={{ width: `${Math.max(2, stats.total_packets ? (p.count / stats.total_packets) * 100 : 0)}%` }} /></div><div className="protocol-number">{formatNumber(p.count)}</div><div className="protocol-percent">{stats.total_packets ? `${((p.count / stats.total_packets) * 100).toFixed(1)}%` : '0%'}</div></div>)}</div><div className="panel-foot"><span><span className="legend-dot legend-tcp" /> TCP {formatNumber(stats.tcp_packets)}</span><span><span className="legend-dot legend-udp" /> UDP {formatNumber(stats.udp_packets)}</span><span><span className="legend-dot legend-other" /> Other</span></div></div>
              <div className="panel apps-panel"><div className="panel-header"><div><h3>Application insights</h3><p>Traffic classification from DPI signals</p></div><button className="text-action" onClick={() => go('Reports')}>Full report <ArrowUpRight size={14} /></button></div><div className="app-list">{appCounts.slice(0, 5).map((app, i) => <div className="app-row" key={app.name}><div className={`app-avatar app-${i % 5}`}>{app.name.slice(0, 1).toUpperCase()}</div><div className="app-main"><div className="app-name-row"><strong>{app.name}</strong><span>{formatNumber(app.count)}</span></div><div className="app-bar-track"><div className={`app-bar appbar-${i % 5}`} style={{ width: `${Math.max(3, app.percentage)}%` }} /></div></div><span className="app-pct">{app.percentage.toFixed(1)}%</span></div>)}{appCounts.length === 0 && <EmptyState icon={Globe2} text="No application data yet" subtext="Run an analysis to populate classifications." />}</div><div className="panel-bottom-note"><ShieldCheck size={14} /><span>Classification depends on the domains and headers visible in the capture.</span></div></div>
            </section>

            <section className="panel packet-panel"><div className="panel-header packet-header"><div><h3>Packet stream</h3><p>Recent frames seen in the capture</p></div><div className="packet-controls"><div className="search-box"><Search size={14} /><input aria-label="Search packets" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search packets..." /></div><button className="secondary-btn compact" onClick={() => go('Packet explorer')}>Explore all <ArrowRight size={14} /></button></div></div><PacketTable packets={filteredPackets.slice(0, 6)} onSelect={setSelectedPacket} selected={selectedPacket} /><div className="table-footer"><span>Showing <strong>{Math.min(filteredPackets.length, 6)}</strong> of <strong>{formatNumber(packets.length)}</strong> loaded packet samples</span><button className="text-action" onClick={() => go('Packet explorer')}>Open packet explorer <ArrowRight size={14} /></button></div></section>
            {selectedPacket && <PacketDetail packet={selectedPacket} onClose={() => setSelectedPacket(null)} />}
          </>}

          {page === 'Packet explorer' && <>
            <section className="page-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> INSPECTION TOOLS</div><h1>Packet explorer<span className="heading-period">.</span></h1><p className="page-subtitle">Search and filter frame summaries from the active capture.</p></div><div className="heading-right"><span className={`data-mode ${analysis ? 'real-data' : ''}`}><span className="data-dot" />{analysis ? 'CAPTURE DATA' : useDemo ? 'DEMO PREVIEW' : 'NO DATA'}</span></div></section>
            <div className="explorer-toolbar"><div className="search-box large"><Search size={16} /><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search IPs, ports, protocol, packet info…" /></div><div className="select-wrap"><Filter size={14} /><select value={protocolFilter} onChange={(e) => setProtocolFilter(e.target.value)}><option>All protocols</option><option>TCP</option><option>UDP</option><option>DNS</option><option>TLS</option><option>ARP</option><option>ICMP</option></select><ChevronDown size={13} /></div><span className="result-count">{filteredPackets.length} samples</span></div>
            <section className="panel packet-panel explorer-table"><div className="panel-header"><div><h3>Captured frames</h3><p>{analysis ? `Source: ${analysis.file_name}` : 'Preview rows · upload a capture to inspect real packets'}</p></div><div className="mini-stat"><span>Total capture</span><strong>{formatNumber(stats.total_packets)}</strong></div></div><PacketTable packets={filteredPackets} onSelect={setSelectedPacket} selected={selectedPacket} /><div className="table-footer"><span>Showing packet samples returned by the current API (up to 250).</span>{analysis && <a className="text-action link-action" href={analysis.output_download_url}><Download size={14} /> Download filtered PCAP</a>}</div></section>
            {selectedPacket && <PacketDetail packet={selectedPacket} onClose={() => setSelectedPacket(null)} />}
            {!analysis && <div className="empty-banner"><FileUp size={17} /><div><strong>Ready for your capture</strong><p>Go to Overview to upload a .pcap file and run the analyzer.</p></div><button className="secondary-btn" onClick={() => go('Overview')}>Upload PCAP <ArrowRight size={14} /></button></div>}
          </>}

          {page === 'Blocking rules' && <>
            <section className="page-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> POLICY CONTROL</div><h1>Blocking rules<span className="heading-period">.</span></h1><p className="page-subtitle">Configure IP, domain, and application rules applied during analysis.</p></div><div className="heading-right"><span className="rule-count-chip"><Shield size={14} /> {activeRules} active rules</span></div></section>
            <div className="rule-summary-grid"><div className="panel rule-summary"><div className="summary-icon cyan-surface"><ShieldCheck size={18} /></div><div><span>Active rules</span><strong>{activeRules}</strong><small>Applied to next analysis</small></div></div><div className="panel rule-summary"><div className="summary-icon violet-surface"><Globe2 size={18} /></div><div><span>Domain rules</span><strong>{rules.filter((r) => r.enabled && r.type === 'Domain').length}</strong><small>Host / SNI matching</small></div></div><div className="panel rule-summary"><div className="summary-icon orange-surface"><LockKeyhole size={18} /></div><div><span>Application rules</span><strong>{rules.filter((r) => r.enabled && r.type === 'Application').length}</strong><small>Signature-based filtering</small></div></div></div>
            <section className="panel rules-editor"><div className="panel-header"><div><h3>Add a blocking rule</h3><p>Rules are saved in this browser session and sent with the next analysis.</p></div><div className="panel-icon"><Plus size={16} /></div></div><div className="rule-form-grid"><form onSubmit={(e) => { e.preventDefault(); addRule('IP address', ipDraft); }}><label htmlFor="rule-ip">IP address</label><div className="field-with-button"><input id="rule-ip" value={ipDraft} onChange={(e) => setIpDraft(e.target.value)} placeholder="192.168.1.50" /><button className="square-add" type="submit" aria-label="Add IP rule"><Plus size={16} /></button></div><small>Block traffic associated with an IP.</small></form><form onSubmit={(e) => { e.preventDefault(); addRule('Domain', domainDraft); }}><label htmlFor="rule-domain">Domain / pattern</label><div className="field-with-button"><input id="rule-domain" value={domainDraft} onChange={(e) => setDomainDraft(e.target.value)} placeholder="*.example.com" /><button className="square-add" type="submit" aria-label="Add domain rule"><Plus size={16} /></button></div><small>Match a domain surfaced by DPI.</small></form><form onSubmit={(e) => { e.preventDefault(); addRule('Application', appDraft); }}><label htmlFor="rule-app">Application</label><div className="field-with-button"><select id="rule-app" value={appDraft} onChange={(e) => setAppDraft(e.target.value)}>{knownApps.map((a) => <option key={a}>{a}</option>)}</select><button className="square-add" type="submit" aria-label="Add application rule"><Plus size={16} /></button></div><small>Filter known application signatures.</small></form></div>{ruleError && <div className="error-message rule-error"><AlertTriangle size={14} />{ruleError}</div>}</section>
            <section className="panel rules-list-panel"><div className="panel-header"><div><h3>Configured policies</h3><p>{rules.length} rules in your local workspace</p></div><button className="secondary-btn compact" onClick={() => setRules([])}><Trash2 size={14} /> Clear all</button></div><div className="rules-list">{rules.map((rule) => <div className={`rule-row ${!rule.enabled ? 'rule-disabled' : ''}`} key={rule.id}><div className={`rule-type-icon ${rule.type === 'IP address' ? 'ip-type' : rule.type === 'Domain' ? 'domain-type' : 'app-type'}`}>{rule.type === 'IP address' ? <Network size={16} /> : rule.type === 'Domain' ? <Globe2 size={16} /> : <Layers3 size={16} />}</div><div className="rule-info"><strong>{rule.value}</strong><span>{rule.type}</span></div><span className={`rule-state ${rule.enabled ? 'state-active' : 'state-paused'}`}><span />{rule.enabled ? 'Active' : 'Paused'}</span><button className={`toggle ${rule.enabled ? 'toggle-on' : ''}`} role="switch" aria-checked={rule.enabled} aria-label={`${rule.enabled ? 'Disable' : 'Enable'} ${rule.value}`} onClick={() => toggleRule(rule.id)}><span /></button><button className="icon-btn rule-delete" aria-label={`Delete ${rule.value}`} onClick={() => removeRule(rule.id)}><Trash2 size={15} /></button></div>)}{rules.length === 0 && <EmptyState icon={Shield} text="No blocking rules configured" subtext="Add an IP address, domain, or application rule above." />}</div><div className="rules-note"><AlertTriangle size={14} /><span>This tool processes saved PCAP files; it does not intercept or block live network traffic from your device.</span></div></section>
          </>}

          {page === 'Reports' && <>
            <section className="page-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> ANALYSIS OUTPUT</div><h1>Reports<span className="heading-period">.</span></h1><p className="page-subtitle">Review capture metrics, detected domains, and export the filtered PCAP.</p></div><div className="heading-right">{analysis && <a className="primary-btn link-btn" href={analysis.output_download_url}><Download size={15} /> Download filtered PCAP</a>}</div></section>
            <div className="report-banner"><div className="report-file-icon"><FileSearch size={22} /></div><div className="report-file-info"><strong>{analysis?.file_name ?? 'No capture analyzed yet'}</strong><span>{analysis ? `Analysis ID ${analysis.analysis_id} · output: ${analysis.output_file_name}` : 'Run an analysis from Overview to generate a report.'}</span></div><div className="report-stamp"><CheckCircle2 size={15} />{analysis ? 'Completed' : 'Waiting for capture'}</div></div>
            <div className="report-metrics"><ReportMetric title="Packets captured" value={formatNumber(stats.total_packets)} /> <ReportMetric title="Bytes inspected" value={formatBytes(stats.total_bytes)} /><ReportMetric title="Forwarded" value={formatNumber(stats.forwarded)} /><ReportMetric title="Dropped" value={formatNumber(stats.dropped)} /></div>
            <section className="panel report-table"><div className="panel-header"><div><h3>Detected domains / SNI</h3><p>Names surfaced from plaintext protocol metadata where available</p></div><span className="small-counter">{domains.length} detected</span></div><div className="domain-table"><div className="domain-head"><span>DOMAIN</span><span>CLASSIFICATION</span><span>STATUS</span></div>{domains.map((d) => <div className="domain-row" key={`${d.domain}-${d.application}`}><div><Globe2 size={15} /><strong>{d.domain}</strong></div><span className="domain-app">{d.application}</span><span className="detected-status"><span />Detected</span></div>)}{domains.length === 0 && <EmptyState icon={Globe2} text="No domain signals available" subtext="Upload a capture that includes supported TLS or HTTP handshakes." />}</div></section>
            <section className="panel report-table"><div className="panel-header"><div><h3>Application breakdown</h3><p>Packet count grouped by the DPI engine's classification</p></div></div><div className="app-report-list">{appCounts.map((a) => <div key={a.name} className="app-report-row"><span>{a.name}</span><div className="app-bar-track"><div className="app-bar appbar-0" style={{ width: `${a.percentage}%` }} /></div><strong>{formatNumber(a.count)}</strong><small>{a.percentage.toFixed(1)}%</small></div>)}{appCounts.length === 0 && <EmptyState icon={BarChart3} text="No report metrics yet" subtext="Run an analysis to populate the application breakdown." />}</div></section>
          </>}

          {page === 'Settings' && <>
            <section className="page-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> ENGINE CONFIGURATION</div><h1>Settings<span className="heading-period">.</span></h1><p className="page-subtitle">Tune the local DPI engine and confirm your frontend connection.</p></div><div className="heading-right"><span className={`connection-pill ${apiOnline ? 'connected' : ''}`}><span className="status-light" />{apiOnline ? 'Connected' : 'Not connected'}</span></div></section>
            <section className="panel settings-panel"><div className="panel-header"><div><h3>Processing configuration</h3><p>Applied to the next capture analysis.</p></div><div className="panel-icon"><SlidersHorizontal size={16} /></div></div><div className="setting-row"><div className="setting-icon"><Network size={17} /></div><div className="setting-main"><strong>Load balancer threads</strong><p>Distributes incoming packets across processing workers.</p></div><div className="setting-control"><button className="stepper-btn" onClick={() => setLbs((v) => Math.max(1, v - 1))} aria-label="Decrease load balancers">−</button><strong>{lbs}</strong><button className="stepper-btn" onClick={() => setLbs((v) => Math.min(8, v + 1))} aria-label="Increase load balancers">+</button></div></div><div className="setting-row"><div className="setting-icon violet-surface"><Zap size={17} /></div><div className="setting-main"><strong>Fast path workers per balancer</strong><p>Worker threads per load balancer; total workers: {lbs * fps}.</p></div><div className="setting-control"><button className="stepper-btn" onClick={() => setFps((v) => Math.max(1, v - 1))} aria-label="Decrease fast path workers">−</button><strong>{fps}</strong><button className="stepper-btn" onClick={() => setFps((v) => Math.min(8, v + 1))} aria-label="Increase fast path workers">+</button></div></div><div className="settings-tip"><Sparkles size={15} /><span>Start with 2 load balancers × 2 workers. Raise concurrency for larger files; higher values use more resources.</span></div></section>
            <section className="panel connection-panel"><div className="panel-header"><div><h3>Backend connection</h3><p>The UI talks to a local FastAPI service over <code>/api</code>.</p></div><button className="secondary-btn compact" onClick={refreshHealth}><RefreshCw size={14} /> Test connection</button></div><div className="connection-detail"><div className={`connection-big-icon ${apiOnline ? 'connected' : ''}`}>{apiOnline ? <Check size={22} /> : <Server size={22} />}</div><div><strong>{apiOnline ? 'Backend is responding' : 'Backend service not detected'}</strong><p>{!apiOnline ? 'Start the API in the backend folder, then restart or refresh this page.' : engineReady ? 'Health check succeeded and a compatible compiler or DPI executable is available.' : 'The API is online, but no compatible DPI executable or C++ compiler was detected.'}</p></div><span className={`connection-badge ${apiOnline ? 'ok' : 'offline'}`}>{apiOnline ? 'ONLINE' : 'OFFLINE'}</span></div><div className="setup-command"><div><Terminal size={15} /><span>PowerShell / terminal</span></div><code>cd backend; python -m pip install -r requirements.txt; python -m uvicorn app:app --reload</code><button className="copy-command" onClick={() => navigator.clipboard?.writeText('cd backend; python -m pip install -r requirements.txt; python -m uvicorn app:app --reload')} aria-label="Copy command"><Command size={14} /></button></div><div className="setup-command"><div><Terminal size={15} /><span>Frontend dev server</span></div><code>cd frontend; npm install; npm run dev</code><button className="copy-command" onClick={() => navigator.clipboard?.writeText('cd frontend; npm install; npm run dev')} aria-label="Copy command"><Command size={14} /></button></div></section>
            <section className="panel about-panel"><div className="about-icon"><ShieldCheck size={18} /></div><div><strong>Privacy by design</strong><p>Capture files are processed by your local backend. They are not uploaded to a third-party server by this frontend.</p></div></section>
          </>}
          <footer className="page-footer"><span><span className="footer-dot" /> PacketScope <span className="footer-divider">/</span> Advanced Packet Analyzer</span><span>Built for local traffic analysis <span className="footer-divider">·</span> v0.1.0</span></footer>
        </div>
      </main>
    </div>
  );
}

function MetricCard({ label, value, detail, icon: Icon, tone, trend }: { label: string; value: string; detail: string; icon: typeof Activity; tone: string; trend: string }) {
  return <div className="metric-card"><div className="metric-top"><span>{label}</span><div className={`metric-icon metric-${tone}`}><Icon size={17} /></div></div><div className="metric-value">{value}</div><div className="metric-bottom"><span>{detail}</span><span className={`metric-trend trend-${tone}`}>{tone === 'orange' ? <AlertTriangle size={12} /> : tone === 'green' ? <Check size={12} /> : <ArrowUpRight size={12} />}{trend}</span></div></div>;
}
function EmptyState({ icon: Icon, text, subtext }: { icon: typeof Activity; text: string; subtext: string }) {
  return <div className="empty-state"><div className="empty-icon"><Icon size={18} /></div><strong>{text}</strong><p>{subtext}</p></div>;
}
function PacketTable({ packets, onSelect, selected }: { packets: Packet[]; onSelect: (packet: Packet) => void; selected: Packet | null }) {
  return <div className="table-scroll"><table className="packet-table"><thead><tr><th>NO.</th><th>TIME</th><th>SOURCE</th><th>DESTINATION</th><th>PROTOCOL</th><th>LENGTH</th><th>INFO</th></tr></thead><tbody>{packets.map((p) => <tr key={`${p.number}-${p.timestamp}`} className={selected?.number === p.number ? 'selected-row' : ''} onClick={() => onSelect(p)} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') onSelect(p); }}><td className="packet-number">{String(p.number).padStart(4, '0')}</td><td className="time-cell">{p.timestamp}</td><td><span className="address-cell">{p.source}</span></td><td><span className="address-cell">{p.destination}</span></td><td><ProtocolBadge protocol={p.protocol} /></td><td className="length-cell">{formatNumber(p.length)} B</td><td className="info-cell">{p.info || '—'}</td></tr>)}{packets.length === 0 && <tr><td colSpan={7}><EmptyState icon={Search} text="No packets match this view" subtext="Try another search term or reset the protocol filter." /></td></tr>}</tbody></table></div>;
}
function ProtocolBadge({ protocol }: { protocol: string }) {
  const normalized = protocol.toUpperCase();
  const tone = normalized.includes('DNS') || normalized === 'UDP' ? 'proto-blue' : normalized.includes('TLS') || normalized.includes('HTTPS') ? 'proto-violet' : normalized === 'TCP' ? 'proto-cyan' : normalized === 'ARP' ? 'proto-orange' : 'proto-gray';
  return <span className={`protocol-badge ${tone}`}><span />{protocol}</span>;
}
function PacketDetail({ packet, onClose }: { packet: Packet; onClose: () => void }) {
  return <div className="panel packet-detail"><div className="panel-header"><div><h3>Frame #{packet.number} details</h3><p>Expanded packet summary</p></div><button className="icon-btn" onClick={onClose} aria-label="Close packet details"><X size={16} /></button></div><div className="detail-grid"><DetailItem label="Timestamp" value={packet.timestamp} /><DetailItem label="Protocol" value={packet.protocol} /><DetailItem label="Source" value={packet.source} /><DetailItem label="Destination" value={packet.destination} /><DetailItem label="Frame length" value={`${packet.length} bytes`} /><DetailItem label="TCP flags" value={packet.tcp_flags || 'Not applicable / unavailable'} /><div className="detail-wide"><span>Summary</span><strong>{packet.info || 'No extra metadata available'}</strong></div></div><p className="detail-note"><AlertTriangle size={13} /> This view contains decoded packet metadata, not the full raw packet payload.</p></div>;
}
function DetailItem({ label, value }: { label: string; value: string }) { return <div className="detail-item"><span>{label}</span><strong>{value}</strong></div>; }
function ReportMetric({ title, value }: { title: string; value: string }) { return <div className="panel report-metric"><span>{title}</span><strong>{value}</strong></div>; }

export default App;
