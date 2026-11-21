"""Read-only appliance UI behind platform authentication; snapshots only."""
import html
import hmac
from bounded_http import BoundedHTTPServer, DeadlineHTTPRequestHandler
import ipaddress
import json
import os
from pathlib import Path
import sys
import urllib.request

PRIVATE = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
STATUS_ROOT = Path('/run/arkpool-dashboard')


def page(env):
    address = ipaddress.IPv4Address(env['LAN_IP'])
    if not any(address in network for network in PRIVATE):
        raise ValueError('private LAN address required')
    port = env.get('LAN_PORT', '3333')
    tls_port = env.get('LAN_TLS_PORT', '3334')
    if any(not p.isdecimal() or not 1 <= int(p) <= 65535 for p in (port, tls_port)):
        raise ValueError('invalid port')
    tls = env.get('TLS_ENABLED', '0')
    if tls not in ('0', '1') or (tls == '1' and int(port) == int(tls_port)):
        raise ValueError('invalid TLS configuration')
    extra = (f'<p>Verified TLS is available on port <code>{int(tls_port)}</code>. '
             'Import the gateway CA before enabling TLS; keep certificate verification on.</p>' if tls == '1' else '')
    v2_values = [env.get(k, '') for k in ('V2_LAN_IP', 'V2_LAN_PORT', 'V2_AUTHORITY_PUBKEY')]
    v2_details = '<p class="setup-muted">V2 connection details are not configured for this installation.</p>'
    if any(v2_values):
        host, v2_port, authority = v2_values
        v2_address = ipaddress.IPv4Address(host)
        if not any(v2_address in network for network in PRIVATE):
            raise ValueError('private V2 listener required')
        if not v2_port.isdecimal() or not 1 <= int(v2_port) <= 65535:
            raise ValueError('invalid V2 port')
        if not 32 <= len(authority) <= 128 or any(c not in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in authority):
            raise ValueError('invalid public V2 authority encoding')
        v2_details = f'''<dl><dt>Host</dt><dd><code>{html.escape(host)}</code></dd>
<dt>Port</dt><dd><code>{int(v2_port)}</code></dd><dt>Protocol</dt><dd>Stratum V2 · extended channel</dd>
<dt>Security</dt><dd>Noise · require authentication</dd></dl>
<p class="key-label">Pool authority public key</p><code class="authority-key">{html.escape(authority)}</code>
<p>Use this key to verify ArkPool. Keep automatic V1 fallback disabled on the native V2 path.</p>'''
    v1_upstream = env.get('V1_UPSTREAM_PROTOCOL', 'SV1')
    if v1_upstream not in ('SV1', 'SV2'):
        raise ValueError('invalid V1 listener upstream protocol')
    v1_note = ('This legacy endpoint still uses V1 upstream. Move to the validated V2 path before requiring V2-only upstream.'
               if v1_upstream == 'SV1' else 'Your miner uses V1 locally; the configured translator uses authenticated V2 to ArkPool.')
    translation = env.get('V1_TRANSLATION_ENABLED', '1')
    if translation not in ('0', '1'):
        raise ValueError('invalid translator availability')
    if v1_upstream == 'SV2' and translation == '0':
        v1_note = 'V1 compatibility is disabled. Configure the exact Ark receive address in the gateway to enable translation. Native V2 remains available.'
    live = env.get('DASHBOARD_ENABLED', '0')
    if live not in ('0', '1') or (live == '1' and env.get('DASHBOARD_AUTH') != 'platform'):
        raise ValueError('authenticated platform dashboard required')
    client_ips = env.get('DASHBOARD_CLIENT_IPS', '0')
    if client_ips not in ('0', '1'):
        raise ValueError('invalid dashboard client-IP setting')
    miner_names = env.get('DASHBOARD_MINER_NAMES', '0')
    if miner_names not in ('0', '1'):
        raise ValueError('invalid dashboard miner-name setting')
    session_ip_header = '<th scope="col">Miner IP</th>' if client_ips == '1' else ''
    session_columns = 10 if client_ips == '1' else 9
    intro = '''<p class="setup-notice">This is setup information, <strong>not a live mining-health dashboard</strong>.
Opening this page does not prove the gateway, Tor paths or pool are ready.</p>'''
    if live == '1':
        intro = f'''<section class="overview" aria-labelledby="live-title">
<div class="section-heading"><h2 id="live-title">Gateway overview</h2>
<span id="status" class="status-pill neutral">Checking</span></div>
<p id="status-detail" class="status-detail" role="status" aria-live="polite">Waiting for a fresh gateway snapshot…</p>
<div class="cards"><div><span>Connected sessions</span><strong id="sessions">—</strong></div>
<div><span>Accepted responses</span><strong id="accepted">—</strong></div>
<div><span>Rejected responses</span><strong id="rejected">—</strong></div>
<div><span>Submitted shares</span><strong id="submitted">—</strong></div></div>
<div class="counter-notes">
<p id="scope">Counters belong to one gateway process, not lifetime history.</p>
<p id="unanswered" title="Pending: awaiting a pool response. Unanswered: tracking timed out or the connection ended. Untracked: correlation was unsafe or full. Unclear: response was neither acceptance nor rejection.">Pending and uncertain outcomes are not rejections.</p></div></section>
<div class="board"><section class="session-panel" aria-labelledby="sessions-title">
<h2 id="sessions-title">Active sessions</h2>
<div class="table-wrap" tabindex="0" role="region" aria-label="Active sessions table"><table>
<thead><tr><th scope="col">Session</th>{session_ip_header}<th scope="col">Miner → gateway</th><th scope="col">Gateway → ArkPool</th><th scope="col">Route</th><th scope="col">Jobs</th><th scope="col">Last job</th><th scope="col">Accepted</th><th scope="col" title="Sum of accepted share difficulty; use this to compare miners assigned different difficulties.">Accepted work</th><th scope="col">Rejected</th></tr></thead>
<tbody id="session-rows"><tr><td colspan="{session_columns}">Waiting for status…</td></tr></tbody></table></div>
<p class="note">Accepted work sums share difficulty so different miners compare fairly; it is not payout confirmation. Miner identities and payout addresses stay private.</p></section>
<section class="network-panel" aria-labelledby="network-title"><h2 id="network-title">Tor paths &amp; listener</h2><div class="paths">
<div class="path-row"><span>Tor A</span><span id="tor-1">unknown</span></div>
<div class="path-row"><span>Tor B</span><span id="tor-2">unknown</span></div>
<div class="path-row"><span>Tor stream policy</span><span id="isolation">unknown</span></div>
<div class="path-row"><span>LAN listener</span><span id="listener">unknown</span></div>
<div class="path-row"><span>Mining TLS</span><span id="tls">unknown</span></div></div>
<p id="tls-detail" class="note"></p>
<p id="route-choice" class="note">New connections: waiting for status…</p>
<p class="note">Times measure a test connection to ArkPool, not hashrate.
Working sessions stay on their route.</p></section></div>
<p id="updated" class="refresh-note">Refreshes every 10 seconds. Data older than 30 seconds is hidden.</p>
<noscript>JavaScript is needed for live status. Setup information below still works.</noscript>
<script src="/dashboard.js" defer></script>'''
    protocol_panel = ''
    if live == '1' and env.get('MINER_STATUS_ENABLED') == '1':
        protocol_panel = '''<section class="fleet-overview" aria-labelledby="fleet-title">
<div class="section-heading"><div><p class="eyebrow">YOUR MINING NETWORK</p><h2 id="fleet-title">At a glance</h2></div><span id="fleet-state" class="status-pill neutral" role="status">Checking</span></div>
<div class="fleet-cards">
<div class="fleet-card"><span>Total hashrate</span><strong id="fleet-rate">—</strong><small id="fleet-rate-note">Waiting for miner readings</small></div>
<div class="fleet-card"><span>Connected miners</span><strong id="fleet-count">—</strong><small id="fleet-count-note">Physical miners, not sessions</small></div>
<div class="fleet-card"><span>Upstream protocol</span><strong id="fleet-upstream">—</strong><small id="fleet-upstream-note">Verified from current connections</small></div>
<div class="fleet-card"><span>Active Tor paths</span><strong id="fleet-tor">—</strong><small>Paths carrying observed sessions</small></div>
</div></section>
<section class="hashrate-panel" aria-labelledby="hashrate-title">
<div class="section-heading"><div><p class="eyebrow">PERFORMANCE</p><h2 id="hashrate-title">Hashrate history</h2><p class="note">Last 24 hours · 15-minute samples</p></div><div class="chart-reading"><span>Current total</span><strong id="hashrate-total">—</strong></div></div>
<p id="hashrate-detail" class="note" aria-live="polite">Waiting for miner telemetry</p>
<div id="hashrate-chart"></div>
<p class="note">Actual observations only · Missing readings stay visible as gaps.</p>
</section><section class="protocol-panel" aria-labelledby="protocol-title">
<div class="section-heading"><div><h2 id="protocol-title">Miners</h2><p class="note">Physical miners · live telemetry</p></div><span id="protocol-preference" class="protocol-badge preferred">Checking preference</span></div>
<p id="protocol-warning" class="protocol-warning" role="status">Waiting for fresh protocol readings.</p>
<div id="protocol-miners" aria-live="polite"></div>
<p class="note">Share counts and uptime come from each miner. Miners unseen for 24 hours reappear when contacted.</p>
</section><script src="/protocol.js" defer></script>'''
    if protocol_panel:
        intro = intro.replace('Gateway overview', 'V1 gateway history')
        start = intro.index('<section class="session-panel"')
        end = intro.index('<section class="network-panel"', start)
        intro = intro[:start] + intro[end:]
        start = intro.index('<section class="network-panel"')
        end = intro.index('</section></div>', start) + len('</section>')
        network = '''<section class="network-panel" aria-labelledby="network-title"><h2 id="network-title">Tor connections</h2>
<table class="route-summary"><thead><tr><th scope="col">Connection type</th><th scope="col">Tor A</th><th scope="col">Tor B</th></tr></thead>
<tbody><tr><th scope="row">Native V2</th><td id="native-tor-A">Checking</td><td id="native-tor-B">Checking</td></tr>
<tr><th scope="row" id="compat-path-title">V1</th><td id="tor-1">Checking</td><td id="tor-2">Checking</td></tr></tbody></table>
<p class="note">Active sessions by transport. A/B identify Tor clients, not circuit IDs.</p>
<details class="connection-details"><summary>Connection details</summary><div class="paths">
<div class="path-row"><span>Tor stream policy</span><span id="isolation">unknown</span></div>
<div class="path-row"><span>LAN listener</span><span id="listener">unknown</span></div>
<div class="path-row"><span>Mining TLS</span><span id="tls">unknown</span></div></div>
<p id="tls-detail" class="note"></p><p id="route-choice" class="note"></p></details></section>'''
        intro = intro[:start] + network + intro[end:]
        intro = '<details class="gateway-diagnostics"><summary>Gateway diagnostics<span class="summary-hint">Pool acknowledgments · Tor paths · listener</span></summary><div class="diagnostics-content">' + intro + '</div></details>'
    deployment_badge = 'Live · Read-only' if protocol_panel else 'Experimental · Read-only'
    setup_open = '' if live == '1' else ' open'
    title = 'ArkPool Gateway' if live == '1' else 'ArkPool Gateway setup'
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>
:root{{color-scheme:dark;--bg:#080f19;--panel:#101c2b;--border:#26384b;--muted:#9caec1;--text:#edf4fb;--accent:#82e8c4}}
*{{box-sizing:border-box}}body{{background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif;margin:0}}
main{{max-width:1440px;margin:30px auto;padding:0 32px}}p{{margin:0}}h1,h2{{margin:0;line-height:1.3}}
h1{{font-size:25px;letter-spacing:-.6px}}h2{{font-size:18px;font-weight:650;letter-spacing:-.3px}}a{{color:#a5c8ff}}code{{font-size:13px}}
.masthead{{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:18px}}
.brand{{display:flex;align-items:center;gap:12px}}.brand-mark{{display:grid;place-items:center;width:40px;height:40px;border:1px solid #3b736d;border-radius:11px;background:#14332f;color:var(--accent);font-weight:750;font-size:15px}}
.brand-link{{color:inherit;text-decoration:none}}.brand-link:hover{{color:var(--accent)}}.subtitle{{color:var(--muted);font-size:13px;margin-top:3px}}.badge{{color:var(--muted);font-size:11px;border:1px solid var(--border);border-radius:20px;padding:5px 10px;white-space:nowrap}}
section{{background:var(--panel);border:1px solid var(--border);border-radius:18px;padding:24px;min-width:0}}
.section-heading{{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:7px}}
.status-pill{{display:inline-flex;align-items:center;gap:6px;border:1px solid #405069;border-radius:999px;background:#202c3d;color:#c6d1df;padding:3px 9px;font-size:11px;font-weight:700;line-height:1.4;white-space:nowrap}}
.status-pill::before{{content:'•';display:grid;place-items:center;width:14px;height:14px;border-radius:50%;background:#344258;font-size:10px}}
.status-pill.good{{border-color:#2e725f;background:#14372f;color:var(--accent)}}.status-pill.good::before{{content:'✓';background:#246451;color:#d8fff4}}
.status-pill.warn{{border-color:#765f34;background:#3b3020;color:#f5cb79}}.status-pill.warn::before{{content:'!';background:#6b5329;color:#fff1cb}}
.status-detail{{min-height:18px;margin:0 0 11px;color:var(--muted);font-size:12px}}.status-detail.warn{{color:#e8c47d}}
.cards{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}}
.cards div{{background:var(--bg);border:1px solid #253347;border-top:2px solid #456087;padding:10px 14px;border-radius:9px}}.cards div:nth-child(2){{border-top-color:#5cbba2}}.cards div:nth-child(3){{border-top-color:#b79359}}.cards div:nth-child(4){{border-top-color:#8272bd}}
.cards span{{display:block;color:var(--muted);font-size:12px}}.cards strong{{display:block;font-size:30px;line-height:1.25;font-weight:650;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}}
#accepted{{color:var(--accent)}}.counter-notes{{display:flex;flex-wrap:wrap;justify-content:space-between;gap:3px 16px;margin-top:10px;font-size:11px;color:var(--muted)}}
.board{{display:grid;grid-template-columns:minmax(0,1.8fr) minmax(285px,1fr);gap:12px;margin-top:12px}}
.board h2{{margin-bottom:10px}}.path-row{{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:7px 0;border-bottom:1px solid var(--border);font-size:12px}}.path-row:first-child{{padding-top:0}}.path-row:last-child{{border:0}}
.path-row span:last-child,.job-chip{{display:inline-block;border-radius:5px;background:#233145;color:#b6c5d6;padding:2px 7px;font-size:11px;text-align:right}}.path-row span.good,.job-chip.good{{background:#153a32;color:var(--accent)}}.path-row span.warn,.job-chip.warn{{background:#3b3020;color:#f5cb79}}
.good{{color:var(--accent)}}.warn{{color:#f5cb79}}.note{{color:var(--muted);font-size:11px;margin-top:10px}}
.table-wrap{{max-height:208px;overflow:auto;scrollbar-color:#43556c transparent;border-radius:6px}}
table{{width:100%;min-width:600px;border-collapse:collapse;text-align:left;font-size:12px;font-variant-numeric:tabular-nums}}
th,td{{padding:8px 9px;border-bottom:1px solid var(--border);white-space:nowrap}}th{{position:sticky;top:0;background:#182539;color:#b6c5d6;font-weight:550;font-size:11px}}
td[colspan]{{color:var(--muted);padding:24px 9px;text-align:center;white-space:normal}}
#updated{{font-size:11px;color:var(--muted);margin:9px 2px}}#tls-detail,#route-choice{{margin-top:4px;min-height:0;font-size:11px;color:var(--muted)}}#tls-detail:empty{{display:none}}.header-tools{{display:flex;align-items:center;gap:12px}}.site-link{{font-size:12px;text-decoration:none}}.site-link:hover{{text-decoration:underline}}
details{{background:var(--panel);border:1px solid var(--border);border-radius:10px;margin-top:12px}}
summary{{cursor:pointer;padding:11px 16px;font-size:13px;font-weight:600}}.summary-hint{{font-weight:400;color:var(--muted);font-size:12px;margin-left:12px}}
summary:hover{{color:var(--accent)}}:focus-visible{{outline:2px solid var(--accent);outline-offset:3px}}
.setup-grid{{display:grid;grid-template-columns:1fr 1fr;gap:24px;padding:4px 16px 16px}}.setup-block{{background:none;border:0;border-radius:0;padding:0}}
.setup-block h2{{margin-bottom:8px}}.setup-block p{{font-size:12px;color:var(--muted);margin:8px 0}}dl{{display:grid;grid-template-columns:140px minmax(0,1fr);gap:6px 12px;font-size:12px;margin:12px 0}}
dt{{color:var(--muted)}}dd{{margin:0;overflow-wrap:anywhere}}footer{{display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px 16px;margin:12px 2px;font-size:11px;color:var(--muted)}}
.setup-notice{{margin-bottom:16px;color:var(--muted)}}noscript{{display:block;color:#f5cb79;margin:10px 0}}
@media(min-width:761px) and (max-height:760px){{main{{margin:12px auto}}.masthead{{margin-bottom:12px}}section{{padding:12px}}}}
@media(max-width:760px){{main{{margin:16px auto;padding:0 14px}}.masthead{{align-items:flex-start;flex-direction:column;gap:8px}}h1{{font-size:22px}}.brand-mark{{display:none}}.badge{{font-size:10px;padding:4px 8px}}
.section-heading{{align-items:center}}.status-detail{{font-size:11px}}.cards{{grid-template-columns:repeat(2,minmax(0,1fr))}}.board,.setup-grid{{grid-template-columns:1fr}}.summary-hint{{display:none}}.setup-grid{{gap:12px}}dl{{grid-template-columns:110px minmax(0,1fr)}}}}
.hashrate-legend{{display:flex;gap:8px;flex-wrap:wrap;font-size:11px;margin-top:4px}}.hashrate-legend>span,.hashrate-legend>button{{display:inline-flex;align-items:center;gap:5px}}.hashrate-legend>button{{font:inherit;color:inherit;background:transparent;border:1px solid transparent;border-radius:6px;padding:6px;cursor:pointer}}.hashrate-legend>button:hover{{background:#172838;border-color:#354b61}}.hashrate-legend>button[aria-pressed="true"]{{background:#2d4660;border-color:#87a6c1}}.hashrate-legend>button:focus-visible{{outline:2px solid #75baff;outline-offset:2px}}.hashrate-legend svg{{width:12px!important;height:12px;flex-shrink:0}}.hashrate-complete,.hashrate-legend>button.hashrate-complete{{color:#8eefd0}}.hashrate-partial{{color:#e9bc70}}.gateway-connections{{padding:0 12px 12px}}.gateway-connections summary{{padding-left:0}}
.hashrate-panel{{margin-bottom:20px;background:linear-gradient(145deg,#102431,#101a2a 65%)}}
#hashrate-total{{font-size:clamp(24px,4vw,38px);font-variant-numeric:tabular-nums;color:#8eefd0;white-space:nowrap}}
#hashrate-chart{{width:100%;min-height:200px}}#hashrate-chart svg{{display:block;width:100%;height:auto}}
.protocol-panel{{margin-bottom:20px;background:var(--panel)}}
.protocol-panel .section-heading .note{{margin-top:3px}}.protocol-badge{{display:inline-flex;align-items:center;gap:6px;border:1px solid #45658d;border-radius:999px;padding:4px 10px;font-size:11px;font-weight:700;white-space:nowrap;color:#b8d6ff;background:#20344e}}
.protocol-badge.v2{{background:#153a32;color:#8eefd0;border-color:#397d67}}.protocol-badge.v1{{background:#352e20;color:#e9cc91;border-color:#6b5836}}.protocol-badge.unknown{{background:#263142;color:#c0c9d6;border-color:#4b586c}}
.protocol-warning{{font-size:12px;color:#f0d29d;background:#392e1d;border-left:3px solid #c69b51;padding:9px 12px;border-radius:5px;margin:8px 0 12px}}.protocol-warning[hidden]{{display:none}}
.protocol-path{{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}}
.protocol-miners{{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px}}.protocol-miner{{padding:12px;background:#0d1826;border:1px solid #304458;border-radius:9px}}.protocol-miner header{{display:flex;justify-content:space-between;gap:8px;align-items:center}}.protocol-miner .metrics{{display:flex;gap:18px;margin-top:10px;font-size:12px}}.protocol-miner .metrics strong{{display:block;font-size:19px;font-weight:650}}.protocol-miner .metrics span{{color:var(--muted);font-size:11px}}
body[data-protocol-view="1"] .board{{display:block}}
body[data-protocol-view="1"] .paths{{display:grid;grid-template-columns:1fr 1fr;gap:0 24px}}
.native-preferred{{border-color:#37a785;animation:preferred-glow 2.8s ease-in-out infinite}}
@keyframes preferred-glow{{0%,100%{{box-shadow:0 0 0 1px rgba(62,214,158,.12);border-color:#31866c}}50%{{box-shadow:0 0 0 2px rgba(62,214,158,.35),0 0 18px rgba(62,214,158,.18);border-color:#7ae0c3}}}}
@media(prefers-reduced-motion:reduce){{.native-preferred{{animation:none;border-color:#7ae0c3}}}}
.route-summary{{width:100%;min-width:0;table-layout:fixed;margin:12px 0 8px}}.route-summary th,.route-summary td{{white-space:normal;padding:10px;background:none}}.route-summary th:first-child{{width:50%}}.connection-details{{margin-top:12px}}.connection-details summary{{cursor:pointer;color:var(--muted)}}
.protocol-table{{width:100%;min-width:0;table-layout:fixed;font-size:12px;margin-top:20px}}
.protocol-table th{{white-space:normal;position:static;background:#132335;line-height:1.4}}
.protocol-table th:first-child{{width:15%}}.protocol-table th:nth-child(4){{width:7%}}.protocol-table th:nth-child(5){{width:12%}}
.protocol-table td{{white-space:normal;overflow-wrap:anywhere;vertical-align:middle;padding:18px 8px}}
.protocol-table .miner-name{{display:block;font-weight:650;color:#edf4fc}}.protocol-table .row-detail{{display:block;color:var(--muted);font-size:10px;margin-top:3px;line-height:1.5}}
.protocol-table .metric{{font-variant-numeric:tabular-nums;white-space:nowrap;font-weight:600}}
.protocol-table tbody tr:last-child td{{border-bottom:0}}.protocol-table tbody tr:hover{{background:#172836}}
@media(max-width:760px){{body[data-protocol-view="1"] .paths{{grid-template-columns:1fr}}.protocol-table,.protocol-table tbody{{display:block}}.protocol-table thead{{display:none}}.protocol-table tr{{display:grid;grid-template-columns:1fr 1fr;border:1px solid var(--border);border-radius:8px;margin:10px 0;padding:6px}}.protocol-table td{{display:block;border:0;min-width:0;padding:7px}}.protocol-table td:first-child{{grid-column:1/-1}}.protocol-table td:not(:first-child)::before{{content:attr(data-label);display:block;font-size:10px;color:var(--muted);margin-bottom:4px}}}}
.setup-choice{{background:#0d1826;border:1px solid #304458;border-radius:9px;padding:14px}}.setup-choice .section-heading h2{{margin:0}}.setup-choice dl{{grid-template-columns:120px 1fr}}.setup-footer{{display:grid;grid-template-columns:1fr 1fr;gap:24px;padding:0 16px 16px}}.authority-key{{display:block;padding:10px;background:#162636;border:1px solid #31465a;border-radius:6px;overflow-wrap:anywhere;user-select:all;font-size:12px}}.setup-choice .key-label{{font-size:11px;margin-bottom:5px}}.setup-choice .setup-caution{{border-left:2px solid #b79359;padding-left:9px;color:#e5c98d}}.setup-muted{{color:var(--muted)}}
@media(max-width:760px){{.setup-footer{{grid-template-columns:1fr;gap:12px}}}}
.v1-help-trigger{{font:inherit;cursor:pointer}}.v1-help-trigger:hover{{filter:brightness(1.2)}}.v1-help-trigger:focus-visible,.help-close:focus-visible,.help-settings:focus-visible{{outline:2px solid #8eefd0;outline-offset:3px}}
#v1-help{{color:var(--text);background:#132132;border:1px solid #526b82;border-radius:14px;width:min(520px,calc(100vw - 32px));max-height:calc(100dvh - 40px);overflow:auto;padding:22px;box-shadow:0 18px 60px #0009;font-size:14px}}
#v1-help::backdrop{{background:#0006}}#v1-help h2{{font-size:20px}}#v1-help h3{{font-size:15px;margin-top:20px}}#v1-help li{{margin:8px 0}}#v1-help ol{{padding-left:22px}}.help-close,.help-settings{{font:inherit;border:1px solid #526b82;border-radius:7px;padding:7px 12px;color:var(--text);background:#1d3447;cursor:pointer}}.help-settings{{display:inline-block;margin-top:6px;text-decoration:none}}
.native-path-summary{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;border-top:1px solid var(--border);padding-top:12px;margin-top:6px;font-size:12px}}.native-path-summary .note{{margin:0}}

/* Fleet overview: locally rendered, no external assets or chart dependencies. */
body{{background:radial-gradient(ellipse at 10% 0%,#14293b 0,transparent 55%),var(--bg);background-attachment:fixed}}
.masthead{{padding-bottom:22px;border-bottom:1px solid var(--border);margin-bottom:24px}}.brand-mark{{width:46px;height:46px;border-radius:15px;transform:rotate(-6deg);background:linear-gradient(135deg,#215e58,#152b40);letter-spacing:-1px}}.brand{{gap:16px}}.subtitle{{font-size:12px}}
.eyebrow{{font-size:10px;letter-spacing:1.8px;font-weight:700;color:#8aa9c2;margin:0 0 6px}}.fleet-overview{{padding:0;border:0;background:none;margin-bottom:24px}}.fleet-overview>.section-heading{{margin-bottom:16px}}
.fleet-cards{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}}.fleet-card{{position:relative;background:linear-gradient(150deg,#142738,#101b29);border:1px solid var(--border);border-radius:16px;padding:20px;min-width:0;overflow:hidden}}.fleet-card:before{{content:'';position:absolute;top:20px;left:0;width:3px;height:28px;border-radius:0 3px 3px 0;background:#77b6ef}}.fleet-card:first-child:before{{background:var(--accent)}}.fleet-card>span,.fleet-card small{{display:block;color:var(--muted);font-size:12px}}.fleet-card strong{{display:block;margin:10px 0 8px;font-size:clamp(23px,2.8vw,34px);font-weight:650;letter-spacing:-1px;line-height:1.2;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}}.fleet-card:first-child strong{{color:var(--accent)}}.fleet-card small{{font-size:11px;line-height:1.5}}
.chart-reading{{text-align:right}}.chart-reading>span{{display:block;color:var(--muted);font-size:11px}}.chart-reading strong{{display:block}}#hashrate-chart{{margin-top:18px;min-height:250px}}.hashrate-legend{{gap:8px;margin-top:12px}}.hashrate-legend>button{{border:1px solid var(--border);background:#0d1927;border-radius:9px;padding:9px 12px}}.hashrate-legend>button[aria-pressed="true"]{{background:#183347;border-color:#50748c}}.hashrate-legend>button:hover{{background:#1b3045}}.hashrate-panel .section-heading .note{{margin-top:4px}}
.gateway-diagnostics{{margin:20px 0}}.gateway-diagnostics>summary,#miner-setup>summary{{padding:18px 24px}}.diagnostics-content{{padding:0 20px 20px}}.diagnostics-content section{{background:#0e1927;padding:18px;border-radius:12px}}.diagnostics-content .cards strong{{font-size:24px}}.diagnostics-content .board{{margin-top:14px}}.diagnostics-content h2{{font-size:15px}}.gateway-connections{{border:0;border-top:1px solid var(--border);border-radius:0;margin-top:12px;padding:0}}.gateway-connections summary{{color:var(--muted);font-size:12px;padding:14px 0}}.protocol-panel>.note{{border-top:1px solid var(--border);padding-top:14px}}.protocol-table .miner-name{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}}.protocol-table .row-detail{{font-size:10px}}.protocol-table tbody tr:hover{{background:#14283a}}.protocol-table .metric{{font-size:13px}}.protocol-table td:first-child{{padding-left:12px}}.protocol-table th{{padding:12px 8px}}.protocol-table th:first-child{{border-radius:8px 0 0 8px}}.protocol-table th:last-child{{border-radius:0 8px 8px 0}}.connection-state{{display:inline-flex;align-items:center;gap:6px}}.connection-state:before{{content:'';width:5px;height:5px;border-radius:50%;background:currentColor;flex-shrink:0}}
.setup-grid{{gap:16px;padding:8px 24px 24px}}.setup-choice{{padding:20px;background:#0c1724;border-radius:12px}}.setup-footer{{padding:0 24px 24px}}.copy-row{{display:flex;gap:8px;align-items:flex-start}}.copy-row code{{flex:1;min-width:0;overflow-wrap:anywhere}}.copy-button{{font:inherit;font-size:11px;cursor:pointer;background:#1d3447;color:var(--text);border:1px solid #426078;border-radius:6px;padding:5px 9px;flex-shrink:0}}.copy-button:hover{{background:#2a465c}}.copy-feedback{{min-height:18px;color:var(--accent);font-size:11px;margin-top:8px}}.chart-empty{{display:grid;place-content:center;text-align:center;min-height:220px;border:1px dashed #34516b;border-radius:12px;color:var(--muted);padding:24px}}
@media(max-width:1100px){{.protocol-table,.protocol-table tbody{{display:block}}.protocol-table thead{{display:none}}.protocol-table tr{{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));border:1px solid var(--border);border-radius:12px;margin:12px 0;padding:10px}}.protocol-table td{{display:block;border:0;min-width:0;padding:10px}}.protocol-table td:first-child{{grid-column:1/-1;padding:8px 10px 14px;border-bottom:1px solid var(--border)}}.protocol-table td:not(:first-child)::before{{content:attr(data-label);display:block;font-size:10px;color:var(--muted);margin-bottom:6px}}}}
@media(max-width:760px){{main{{padding:0 16px;margin:20px auto}}.masthead{{padding-bottom:16px}}.masthead .brand-mark{{display:grid;width:38px;height:38px;font-size:13px}}.masthead .brand{{gap:10px}}.header-tools{{width:100%;justify-content:space-between}}.fleet-cards{{grid-template-columns:1fr 1fr;gap:10px}}.fleet-card{{padding:16px}}.fleet-card strong{{font-size:25px;letter-spacing:-.5px}}.fleet-card>span{{font-size:11px}}.fleet-card small{{font-size:10px}}#fleet-rate{{font-size:clamp(16px,5.1vw,22px);white-space:nowrap;line-height:1.37}}section{{padding:18px;border-radius:14px}}h2{{font-size:16px}}#hashrate-total{{font-size:22px}}.eyebrow{{font-size:9px}}.protocol-table tr{{grid-template-columns:1fr 1fr;padding:6px}}.protocol-table td{{padding:9px}}.diagnostics-content{{padding:0 12px 12px}}.gateway-diagnostics>summary,#miner-setup>summary{{padding:16px}}.setup-grid,.setup-footer{{padding:8px 14px 18px}}.setup-choice{{padding:16px}}.chart-reading>span{{font-size:10px}}.hashrate-legend>button{{padding:9px;font-size:11px}}.hashrate-legend>span{{padding:5px 0}}footer{{line-height:1.7}}}}

</style></head>
<body data-client-ips="{client_ips}" data-protocol-view="{1 if protocol_panel else 0}" data-miner-names="{miner_names}"><main><header class="masthead"><div class="brand"><span class="brand-mark" aria-hidden="true">AP</span>
<div><h1><a class="brand-link" href="https://arkpool.org" rel="noreferrer" aria-label="ArkPool.org home">{title}</a></h1><p class="subtitle">Your miners. Private connections. Ark payouts.</p></div></div>
<div class="header-tools"><a class="site-link" href="https://arkpool.org" rel="noreferrer">ArkPool.org ↗</a><span class="badge">{deployment_badge}</span></div></header>
<div id="v1-help" popover role="dialog" aria-labelledby="v1-help-title">
<div class="section-heading"><h2 id="v1-help-title">Why use Stratum V2?</h2><button type="button" class="help-close" popovertarget="v1-help" popovertargetaction="hide" aria-label="Close V1 help" autofocus>Close</button></div>
<p>V2 encrypts mining traffic and verifies the upstream server with an authority public key. It does not increase hashrate or guarantee a block.</p>
<h3>Enable it on a compatible miner</h3>
<ol><li>Check that your miner firmware supports native Stratum V2. Use a compatible, verified firmware release if an update is needed.</li>
<li>In the miner's pool settings, select V2 and copy the native V2 host, port and authority public key from this gateway's connection settings.</li>
<li>Require authentication, keep your payout address unchanged, then verify fresh jobs and accepted shares. A brief reconnect is expected.</li></ol>
<p><strong>V1-only miner?</strong> Keep using the V1 compatibility listener. The gateway can translate to authenticated V2 upstream; that does not encrypt the miner's V1 hop. Verified TLS can protect that local hop when supported.</p>
<p>Read each column separately: <strong>Miner → gateway</strong> describes the miner link. If <strong>Gateway → ArkPool</strong> shows V1, the gateway needs a compatible V2 update and configuration.</p>
<a id="v1-show-settings" href="#miner-setup" class="help-settings">View connection settings</a>
</div>
{protocol_panel}
{intro}
<details id="miner-setup"{setup_open}><summary>Connect a miner<span class="summary-hint">V2 preferred · compatibility settings · verification</span></summary>
<div class="setup-grid"><section class="setup-block setup-choice native-preferred"><div class="section-heading"><h2>Native Stratum V2</h2><span class="protocol-badge preferred">Preferred</span></div>
<p>Choose this when your miner supports V2. The connection stays V2 from the miner to ArkPool.</p>{v2_details}</section>
<section class="setup-block setup-choice"><div class="section-heading"><h2>Stratum V1 compatibility</h2><button type="button" class="protocol-badge v1 v1-help-trigger" popovertarget="v1-help" aria-label="V1: learn why and how to enable Stratum V2">V1 ⓘ</button></div>
<p>For miners that do not support native V2.</p><dl><dt>Host</dt><dd><code>{html.escape(str(address))}</code></dd>
<dt>Plain TCP port</dt><dd><code>{int(port)}</code></dd><dt>Local protocol</dt><dd>Stratum V1</dd>
<dt>Upstream protocol</dt><dd>{'V2' if v1_upstream == 'SV2' else 'V1 · legacy'}</dd></dl>{extra}
<p class="setup-caution">{v1_note}</p></section></div>
<div class="setup-footer"><section class="setup-block"><h2>Account settings</h2>
<p><strong>Username:</strong> your complete existing mainnet Ark receive address, unchanged. <strong>Password:</strong> use your existing pool password (normally <code>x</code>).</p>
<p>Never enter wallet keys or a seed phrase. This read-only page does not save or change miner settings.</p></section>
<section class="setup-block"><h2>Before you switch</h2><p>Save the current settings. Configure the host, port and protocol, then verify both connection badges, fresh jobs and a new accepted share.</p>
<p>Keep the listener private. Both Tor paths use your internet connection and hide your public IP address from ArkPool.</p></section></div></details>
<footer><p>No wallet access or mining controls. Accepted responses are not payments.</p>
<p><a href="https://arkpool.org" rel="noreferrer">ArkPool.org</a> ·
<a href="https://arkpool.org/#wallet" rel="noreferrer">Wallet guidance</a> ·
<a href="https://gitlab.com/arkpool/arkpool-gateway" rel="noreferrer">Documentation</a></p></footer>
</main></body></html>'''.encode()


def handler(content, status_root=None, status_token=None, status_only=False):
    protocol_script = Path(__file__).with_name('protocol.js').read_bytes() if os.environ.get('MINER_STATUS_ENABLED') == '1' and not status_only else None
    script = (Path(__file__).with_name('dashboard.js').read_bytes()
              if status_root is not None and not status_only else None)
    class SetupHandler(DeadlineHTTPRequestHandler):
        server_version = 'ArkPool'
        sys_version = ''
        def log_message(self, *_):
            pass  # No client addresses, paths or headers in application logs.

        def respond(self, head=False):
            self.response_ready()
            if len(self.path) > 2048:
                status, body, kind = 414, b'Request too long\n', 'text/plain'
            elif self.path == '/' and not status_only:
                status, body, kind = 200, content, 'text/html; charset=utf-8'
            elif self.path == '/health':
                service = 'status-api' if status_only else 'dashboard' if status_root is not None else 'setup-page'
                status, body, kind = 200, json.dumps({'service': service, 'status': 'ok', 'mining_verified': False}).encode(), 'application/json'
            elif self.path in ('/api/status', '/api/miners') and status_root is not None and (self.path == '/api/status' or protocol_script is not None):
                supplied = self.headers.get('Authorization', '')
                expected = '' if status_token is None else 'Bearer ' + status_token
                if status_token is not None and not hmac.compare_digest(supplied, expected):
                    status, body, kind = 401, b'Unauthorized\n', 'text/plain'
                else:
                    from dashboard_status import dashboard
                    if self.path == '/api/status':
                        data = dashboard(status_root)
                    else:
                        from miner_status import read_snapshot, with_gateway_evidence
                        data = with_gateway_evidence(read_snapshot(status_root, include_miner_ips=os.environ.get('DASHBOARD_CLIENT_IPS') == '1'), status_root)
                    status, body, kind = 200, json.dumps(data, allow_nan=False).encode(), 'application/json'
            elif self.path == '/protocol.js' and protocol_script is not None:
                status, body, kind = 200, protocol_script, 'text/javascript; charset=utf-8'
            elif self.path == '/dashboard.js' and script is not None:
                status, body, kind = 200, script, 'text/javascript; charset=utf-8'
            else:
                status, body, kind = 404, b'Not found\n', 'text/plain'
            self.send_response(status)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'")
            self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.close_connection = True
            if not head:
                self.wfile.write(body)

        def do_GET(self):
            self.respond()

        def do_HEAD(self):
            self.respond(head=True)

        def do_POST(self):
            self.response_ready()
            self.send_response(405)
            self.send_header('Allow', 'GET, HEAD')
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.close_connection = True

    return SetupHandler


class SetupServer(BoundedHTTPServer):
    pass


def main():
    if sys.argv[1:] == ['healthcheck']:
        with urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3) as response:
            if json.load(response).get('service') not in ('setup-page', 'dashboard', 'status-api'):
                raise ValueError('wrong service')
        return
    if sys.argv[1:] == ['status-api']:
        token = os.environ.get('DASHBOARD_STATUS_TOKEN', '')
        if len(token) != 64 or any(char not in '0123456789abcdef' for char in token):
            raise ValueError('64-character status token required')
        SetupServer(('0.0.0.0', 8080), handler(b'', STATUS_ROOT, token, True)).serve_forever()
        return
    if sys.argv[1:]:
        raise ValueError('unexpected arguments')
    content = page(os.environ)
    root = STATUS_ROOT if os.environ.get('DASHBOARD_ENABLED') == '1' else None
    SetupServer(('0.0.0.0', 8080), handler(content, root)).serve_forever()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Setup page unavailable; private details suppressed.', file=sys.stderr)
        sys.exit(1)
