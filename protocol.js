'use strict';
(() => {
  const el = id => document.getElementById(id);
  let deadline = 0;
  let chartSnapshot = null;
  let chartMiner = null;
  const showIPs = document.body.dataset.clientIps === '1';
  const minerLabel = (miner, fallback) => showIPs && miner.miner_ip ? miner.miner_ip : showNames ? miner.label : `Miner ${miner.miner_number || fallback}`;
  const showNames = document.body.dataset.minerNames === '1';
  const node = (tag, text, cls) => {
    const n = document.createElement(tag); n.textContent = text;
    if (cls) n.className = cls; return n;
  };
  const badge = protocol => {
    const n=node(protocol==='SV1'?'button':'span',protocol==='SV2'?'V2':protocol==='SV1'?'V1 ⓘ':'Unknown',
      `protocol-badge ${protocol==='SV2'?'v2':protocol==='SV1'?'v1 v1-help-trigger':'unknown'}`);
    if(protocol==='SV1') {
      n.type='button';n.setAttribute('popovertarget','v1-help');
      n.setAttribute('aria-label','V1: learn why and how to enable Stratum V2');
      n.title='Why V2, and how to enable it';
    }
    return n;
  };
  el('v1-show-settings')?.addEventListener('click',event=>{
    event.preventDefault();
    el('v1-help').hidePopover();
    const setup=el('miner-setup');setup.open=true;setup.scrollIntoView({block:'start',behavior:'smooth'});
    setup.querySelector('summary').focus({preventScroll:true});
  });
  const renderPaths = counts => {
    for(const name of ['A','B']) {
      const target=el('native-tor-'+name);
      if(target){target.textContent=counts?(counts[name]?`${counts[name]} active`:'Idle'):'Unavailable';target.className=counts&&counts[name]>0?'good':'';}
    }
  };
  const uptime = seconds => {
    const minutes=Math.floor(seconds/60);
    return minutes>=60?`${Math.floor(minutes/60)}h ${minutes%60}m`:`${minutes}m`;
  };
  const rateText = rate => rate >= 1000 ? `${(rate/1000).toFixed(2)} TH/s` : `${Math.round(rate)} GH/s`;
  const metric = (id, value) => { if(el(id))el(id).textContent=value; };
  const fleet = (snapshot, gateway) => {
    const data=snapshot?.state==='current'?snapshot.data:null;
    const g=gateway?.state==='current'?gateway.data:null;
    const miners=data?.miners || [];
    const connected=miners.filter(m=>m.available && m.connected && m.mining_target_verified);
    const reading=data?.hashrate;
    const complete=reading && Number.isFinite(reading.total_ghs) && reading.observed===reading.expected;
    metric('fleet-rate',complete?rateText(reading.total_ghs):'—');
    metric('fleet-rate-note',!reading?'Telemetry unavailable':complete?'Reported by your miners':`${reading.observed}/${reading.expected} miners reporting · partial`);
    metric('fleet-count',data?String(connected.length):'—');
    metric('fleet-count-note',data?`${miners.length} tracked in the last 24 hours`:'Miner telemetry unavailable');
    const verified=connected.length>0 && connected.every(m=>m.upstream_protocol==='SV2' && (m.protocol!=='SV2' || m.authenticated));
    metric('fleet-upstream',!data?'—':verified?'V2':connected.length?'Check links':'Idle');
    metric('fleet-upstream-note',verified?'Verified for connected miners':'See each protocol hop below');
    const routes=new Set();
    if(data?.native_route_counts)for(const route of ['A','B'])if(data.native_route_counts[route]>0)routes.add(route);
    if(g)for(const route of g.routes || [])if(route.active_sessions>0)routes.add(route.route==='tor-1'?'A':'B');
    metric('fleet-tor',!data || !g?'—':routes.size?[...routes].sort().join(' + '):'Idle');
    const uncertain=!data || !g || miners.some(m=>!m.available || !m.connected || !m.mining_target_verified || m.upstream_protocol==='unknown' || (m.protocol==='SV2' && !m.authenticated) || (m.job_age_seconds!==null && m.job_age_seconds>180));
    const state=el('fleet-state');
    if(state){state.textContent=!data?'Unavailable':uncertain?'Needs attention':connected.length?'Connected':'Idle';state.className='status-pill '+(uncertain?'warn':connected.length?'good':'neutral');}
  };
  // Add copy affordances only when JS is available. Plain HTTP falls back to
  // selecting the exact displayed value; clipboard access is never assumed.
  for(const code of document.querySelectorAll('#miner-setup dd code, #miner-setup .authority-key')) {
    const wrap=node('div','','copy-row');code.replaceWith(wrap);wrap.append(code);
    const button=node('button','Copy','copy-button');button.type='button';
    const label=code.closest('dd')?.previousElementSibling?.textContent || 'authority public key';
    button.setAttribute('aria-label',`Copy ${label}`);wrap.append(button);
    button.addEventListener('click',async()=>{
      let copied=false;
      try{if(navigator.clipboard && window.isSecureContext){await navigator.clipboard.writeText(code.textContent);copied=true;}}catch(_){}
      if(!copied){const selection=window.getSelection();const range=document.createRange();range.selectNodeContents(code);selection.removeAllRanges();selection.addRange(range);}
      let feedback=wrap.parentElement.querySelector('.copy-feedback');
      if(!feedback){feedback=node('p','','copy-feedback');feedback.setAttribute('role','status');wrap.parentElement.append(feedback);}
      feedback.textContent=copied?'Copied': 'Selected · use your browser’s Copy command';
    });
  }
  const chart = snapshot => {
    const total = el('hashrate-total'), detail = el('hashrate-detail'), graph = el('hashrate-chart');
    if (!total || !detail || !graph) return;
    chartSnapshot = snapshot;
    const focusedControl = graph.contains(document.activeElement) ? document.activeElement.dataset.chartMiner : undefined;
    graph.replaceChildren();
    const data = snapshot?.state === 'current' ? snapshot.data : null;
    const reading = data?.hashrate;
    const finite = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1e15;
    if (!reading) {total.textContent='—';detail.textContent='Current miner telemetry unavailable';graph.append(node('p','Waiting for fresh miner readings.','chart-empty'));return;}
    const complete = finite(reading.total_ghs) && reading.observed === reading.expected;
    total.textContent = complete ? rateText(reading.total_ghs) : '—';
    detail.textContent = reading.expected === 0 ? 'No miners contacted in the last 24 hours' : complete ? `${reading.observed}/${reading.expected} physical miners reporting` :
      `Partial · ${reading.observed}/${reading.expected} miners${finite(reading.known_ghs) ? ` · ${rateText(reading.known_ghs)} known` : ''}`;
    if(finite(reading.oldest_source_age_seconds)) detail.textContent += ` · Oldest source ${Math.round(reading.oldest_source_age_seconds)}s ago`;
    if (!data.history_available) {graph.append(node('p','History unavailable; current readings remain live.','chart-empty'));return;}
    const now = data.sampled_at + (snapshot.age_seconds || 0);
    const points = Array.isArray(data.hashrate_history) && data.hashrate_history.length <= 96 ? data.hashrate_history.filter(p =>
      finite(p.sampled_at) && p.sampled_at > now-86400 && p.sampled_at <= now) : [];
    const roster = (data.miners || []).filter(m => Number.isInteger(m.miner_number) && m.miner_number >= 1 && m.miner_number <= 8);
    if (chartMiner !== null && !roster.some(m => m.miner_number === chartMiner)) chartMiner = null;
    const visibleRoster = chartMiner === null ? roster : roster.filter(m => m.miner_number === chartMiner);
    const pointValue = p => chartMiner === null ? (finite(p.total_ghs) ? p.total_ghs : p.known_ghs) : p.miners?.[String(chartMiner)];
    const measured = points.filter(p => finite(pointValue(p)));
    if (!measured.length && chartMiner === null) {graph.append(node('p','History is starting. The first available observation appears here; new samples are recorded every 15 minutes.','chart-empty'));return;}
    const width = Math.max(250, Math.min(1400, graph.clientWidth || 800)), height = width<600?230:270;
    const left=62, right=12, top=16, bottom=32;
    const max = Math.max(1, ...measured.map(pointValue))*1.1;
    const x = t => left+(t-(now-86400))/86400*(width-left-right);
    const y = v => height-bottom-v/max*(height-top-bottom);
    const svg = (tag, attrs, text) => {
      const n=document.createElementNS('http://www.w3.org/2000/svg',tag);
      for (const [key,value] of Object.entries(attrs)) n.setAttribute(key,String(value));
      if(text !== undefined)n.textContent=text;return n;
    };
    const plot=svg('svg',{viewBox:`0 0 ${width} ${height}`,role:'img','aria-label':chartMiner === null ? 'Total and individual miner hashrate over the past 24 hours. Green shows complete totals; amber shows partial totals. Each miner has a separate color. Missing readings are gaps.' : `${minerLabel(visibleRoster[0])} hashrate over the past 24 hours, scaled to this miner. Missing readings are gaps.`});
    const fillDefs=svg('defs',{}), gradient=svg('linearGradient',{id:'hashrate-total-fill',x1:0,y1:0,x2:0,y2:1});
    gradient.append(svg('stop',{offset:'0%','stop-color':'#82e8c4','stop-opacity':0.16}),svg('stop',{offset:'100%','stop-color':'#82e8c4','stop-opacity':0.01}));fillDefs.append(gradient);plot.append(fillDefs);
    const gaps=[];
    if(measured.length) {
      const buckets=new Map(points.map(p=>[Math.floor(p.sampled_at/900),p]));
      const first=Math.floor(measured[0].sampled_at/900), last=Math.floor(points[points.length-1].sampled_at/900);
      for(let bucket=first;bucket<=last && bucket<first+97;bucket++) {
        const p=buckets.get(bucket);
        const missing=!p || !finite(chartMiner===null?p.total_ghs:pointValue(p));
        if(!missing)continue;
        const label=chartMiner===null && p && finite(p.known_ghs)?'Partial readings':'No reading';
        const previous=gaps[gaps.length-1];
        if(previous && previous.end===bucket && previous.label===label)previous.end=bucket+1;
        else gaps.push({start:bucket,end:bucket+1,label});
      }
    }
    if(gaps.length) {
      const defs=svg('defs',{}), pattern=svg('pattern',{id:'hashrate-gap-pattern',width:8,height:8,patternUnits:'userSpaceOnUse'});
      pattern.append(svg('rect',{width:8,height:8,fill:'#e9bc70','fill-opacity':0.06}));
      pattern.append(svg('path',{d:'M-2 2L2 -2M0 8L8 0M6 10L10 6',stroke:'#e9bc70','stroke-opacity':0.18,'stroke-width':1}));
      defs.append(pattern);plot.append(defs);
      for(const gap of gaps) {
        const start=Math.max(now-86400,gap.start*900), end=Math.min(now,gap.end*900);
        const xx=x(start), span=x(end)-xx;
        if(span<=0)continue;
        const band=svg('rect',{'data-history-gap':gap.label,x:xx,y:top,width:span,height:height-top-bottom,fill:'url(#hashrate-gap-pattern)',stroke:'#e9bc70','stroke-opacity':0.25,'stroke-dasharray':'3 3'});
        band.append(svg('title',{},`${gap.label} · ${new Date(start*1000).toLocaleString()} – ${new Date(end*1000).toLocaleString()}. No hashrate is inferred.`));
        plot.append(band);
        if(span>90)plot.append(svg('text',{x:xx+span/2,y:top+13,'text-anchor':'middle',fill:'#e9bc70','font-size':10},gap.label));
      }
    }
    for (const fraction of [0,0.5,1]) {
      const yy=y(max*fraction);
      plot.append(svg('line',{x1:left,x2:width-right,y1:yy,y2:yy,stroke:'#304458','stroke-width':1}));
      plot.append(svg('text',{x:left-8,y:yy+4,'text-anchor':'end',fill:'#a9b9ca','font-size':10},`${(max*fraction/(max>=1000?1000:1)).toFixed(max>=1000?2:0)} ${max>=1000?'TH/s':'GH/s'}`));
    }
    for (const [fraction,label] of [[0,'24h ago'],[0.5,'12h ago'],[1,'Now']])
      plot.append(svg('text',{x:left+fraction*(width-left-right),y:height-8,'text-anchor':fraction===0?'start':fraction===1?'end':'middle',fill:'#a9b9ca','font-size':11},label));
    for(const partial of chartMiner === null ? [false,true] : []) {
      let segment=[], previous=null;
      const color=partial?'#e9bc70':'#8eefd0';
      const flush=()=>{
        if(!partial && segment.length>1){const first=segment[0].split(',')[0],last=segment[segment.length-1].split(',')[0];plot.append(svg('polygon',{'data-total-area':'measured',points:`${first},${y(0)} ${segment.join(' ')} ${last},${y(0)}`,fill:'url(#hashrate-total-fill)'}));}
        if(segment.length>1)plot.append(svg('polyline',{points:segment.join(' '),fill:'none',stroke:color,'stroke-width':2,'stroke-linejoin':'round','stroke-dasharray':partial?'4 4':'none'}));
        segment=[];
      };
      for(const p of points) {
        const value=partial && !finite(p.total_ghs)?p.known_ghs:!partial?p.total_ghs:null;
        if(!finite(value)){flush();previous=null;continue;}
        if(previous!==null && Math.floor(p.sampled_at/900)-Math.floor(previous/900)!==1)flush();
        const xx=x(p.sampled_at), yy=y(value);
        segment.push(`${xx},${yy}`);previous=p.sampled_at;
        const dot=svg('circle',{cx:xx,cy:yy,r:measured.length===1?4.5:2.5,fill:color});
        dot.append(svg('title',{},`${new Date(p.sampled_at*1000).toLocaleString()} · ${partial?`Observed subtotal (${p.observed}/${p.expected})`:'Total'} ${rateText(value)}${finite(p.oldest_source_age_seconds)?` · Oldest source ${Math.round(p.oldest_source_age_seconds)}s`:''}`));plot.append(dot);
      }
      flush();
    }
    const colors=['#75baff','#d2a0ff','#ff9b87','#f0d877','#65d5e8','#ef9ed1','#b9d978','#c5d1df'];
    for(const miner of visibleRoster) {
      const label=minerLabel(miner);
      const color=colors[miner.miner_number-1];
      let segment=[], previous=null;
      const flush=()=>{
        if(segment.length>1)plot.append(svg('polyline',{'data-miner':miner.miner_number,points:segment.join(' '),fill:'none',stroke:color,'stroke-width':1.5,'stroke-linejoin':'round'}));
        segment=[];
      };
      for(const p of points) {
        const value=p.miners?.[String(miner.miner_number)];
        if(!finite(value)){flush();previous=null;continue;}
        if(previous!==null && Math.floor(p.sampled_at/900)-Math.floor(previous/900)!==1)flush();
        const xx=x(p.sampled_at), yy=y(value);
        segment.push(`${xx},${yy}`);previous=p.sampled_at;
        const marker=miner.miner_number%2 ? {tag:'rect',attrs:{x:xx-3.5,y:yy-3.5,width:7,height:7,rx:1}} : {tag:'circle',attrs:{cx:xx,cy:yy,r:2.5}};
        const dot=svg(marker.tag,{'data-miner':miner.miner_number,...marker.attrs,fill:color,stroke:'#101d2c','stroke-width':1});
        dot.append(svg('title',{},`${new Date(p.sampled_at*1000).toLocaleString()} · ${label} · ${rateText(value)}`));plot.append(dot);
      }
      flush();
    }
    graph.append(plot);
    const legend=node('div','','hashrate-legend');
    const control=(number,text,cls)=>{
      const button=node('button',text,cls);button.type='button';
      button.dataset.chartMiner=number===null?'all':String(number);
      button.setAttribute('aria-pressed',String(chartMiner===number));
      button.title=number===null?'Show all miners':'Show this miner on its own scale; select again to show all';
      button.addEventListener('click',()=>{chartMiner=chartMiner===number?null:number;chart(chartSnapshot);});
      return button;
    };
    legend.append(control(null,'● Total · all miners','hashrate-complete'));
    if(chartMiner===null && points.some(p=>!finite(p.total_ghs)&&finite(p.known_ghs))) legend.append(node('span','● Partial total','hashrate-partial'));
    if(gaps.length)legend.append(node('span','▧ Gaps / partial readings','hashrate-partial'));
    for(const miner of roster) {
      const item=control(miner.miner_number,'');
      const swatch=svg('svg',{width:12,height:12,viewBox:'0 0 12 12','aria-hidden':'true'});
      swatch.append(svg('circle',{cx:6,cy:6,r:4,fill:colors[miner.miner_number-1]}));
      const label=minerLabel(miner);
      item.append(swatch,node('span',`${label} · ${miner.available && miner.mining_target_verified && finite(miner.hashrate_ghs)?rateText(miner.hashrate_ghs):'Unavailable'}`));
      legend.append(item);
    }
    graph.append(legend);
    graph.append(node('p',chartMiner===null?'Select a miner to view its history on its own scale.':'Showing one miner · Select Total to compare all miners.','note'));
    if (!measured.length) graph.append(node('p','No recorded samples for this miner yet. Missing readings are not plotted as zero.','note'));
    if(focusedControl!==undefined) [...legend.querySelectorAll('button')].find(b=>b.dataset.chartMiner===focusedControl)?.focus({preventScroll:true});
    if(roster.length && !points.some(p => roster.some(m => finite(p.miners?.[String(m.miner_number)]))))
      graph.append(node('p','Per-miner history starts at the next 15-minute sample. The legend shows current rates.','note'));
    if(points.length<2) {
      const next=Math.max(1,Math.ceil((900-now%900)/60));
      graph.append(node('p',`${points.length} sample recorded · Next sample in about ${next} min. The 24-hour history fills as observations arrive.`,'note'));
    }

  };
  const unknown = () => {
    fleet(null,null);
    chart(null);
    renderPaths(null);
    el('protocol-preference').textContent = 'Protocol status unknown';
    el('protocol-preference').className = 'protocol-badge unknown';
    el('protocol-warning').hidden = false;
    el('protocol-warning').textContent = 'Fresh session readings are unavailable. Previous connection badges and counters are hidden.';
    el('protocol-miners').replaceChildren(node('p', 'Waiting for current miner and gateway readings.', 'note')); deadline = 0;
  };
  const render = (snapshot, legacy) => {
    fleet(snapshot,legacy.gateway);
    chart(snapshot);
    const nativeCurrent = snapshot.state === 'current';
    const gatewayCurrent = legacy.gateway?.state === 'current';
    if (!nativeCurrent && !gatewayCurrent) { unknown(); return; }
    const miners = nativeCurrent ? snapshot.data.miners : [];
    const sessions = gatewayCurrent ? legacy.gateway.data.sessions : [];
    const allKnown = nativeCurrent && gatewayCurrent && miners.every(m => m.available);
    const preferred = nativeCurrent && miners.length > 0 && miners.every(m => m.available && m.primary_protocol === 'SV2');
    el('protocol-preference').textContent = preferred ? 'V2 preferred' : 'Protocol status';
    el('protocol-preference').className = 'protocol-badge preferred';
    const active = miners.filter(m => m.available && m.connected);
    const gatewayUpstream=gatewayCurrent ? legacy.gateway.data.upstream_protocol || 'SV1' : 'unknown';
    const aggregate=gatewayCurrent && legacy.gateway.data.counter_basis==='aggregate_pool_acknowledgments';
    const onlyV1 = allKnown && active.length + sessions.length > 0 && active.every(m => m.protocol === 'SV1') && gatewayUpstream==='SV1';
    const bad = !allKnown || miners.some(m => !m.connected || m.protocol === 'unknown' || (m.protocol === 'SV2' && !m.authenticated) || (m.job_age_seconds!==null && m.job_age_seconds>180));
    el('protocol-warning').hidden = !onlyV1 && !bad;
    el('protocol-warning').textContent = onlyV1 ? 'V1 only. V2 adds encrypted, authenticated mining connections. Prefer V2 on supported miners.' : 'Some connections need attention: disconnected, stale work, or unverified telemetry. Check the miner rows below.';
    const table = node('table', '', 'protocol-table');
    const headings = [showIPs ? 'Miner IP' : 'Miner / session', 'Miner → gateway', 'Gateway → ArkPool', 'Tor path', 'Connection', 'Miner uptime', 'Hashrate', 'Accepted', 'Rejected', 'Last job'];
    const head = node('thead', ''); const hr = node('tr', '');
    for (const h of headings) { const th=node('th',h);th.scope='col';hr.append(th); } head.append(hr);table.append(head);
    let body = node('tbody', '');
    const add = (label, detail, local, upstream, state, rate, accepted, rejected, age, authenticated, route='unknown', duration='—') => {
      const row = node('tr','');
      const name = node('td','');name.append(node('span',label,'miner-name'));if(detail)name.append(node('span',detail,'row-detail'));row.append(name);
      const connection=node('div',''); connection.append(node('span',state,'connection-state '+(state==='Connected'?'good':'warn')));
      if(authenticated) connection.append(node('span','Authenticated','row-detail'));
      const path=node('span',route==='A'||route==='B'?route:'—','protocol-badge '+(route==='unknown'?'unknown':'preferred'));
      path.title=(local==='SV2'?'Native V2 gateway':upstream==='SV2'?'V1 → V2 translator':'Legacy V1 gateway')+' — selected Tor client, not a stable circuit identifier';
      const values=[badge(local),badge(upstream),path,connection,node('span',duration,'metric'),node('span',rate,'metric'),node('span',String(accepted??'—'),'metric'),node('span',String(rejected??'—'),'metric'),node('span',age)];
      values.forEach((value,i)=>{const cell=node('td','');cell.dataset.label=headings[i+1];cell.append(value);row.append(cell);});body.append(row);
    };
    for (const [index,m] of miners.entries()) {
      const label = minerLabel(m,index+1);
      if (!m.available) { add(label,'Miner telemetry unavailable','unknown','unknown','Unavailable','—','—','—','—',false);continue; }
      const authenticated=m.connected && m.protocol==='SV2' && m.authenticated;
      const stale=Number.isFinite(m.job_age_seconds) && m.job_age_seconds>180;
      const state=!m.connected?'Disconnected':stale?'Waiting for work':'Connected';
      const rate=m.hashrate_ghs>=1000?`${(m.hashrate_ghs/1000).toFixed(2)} TH/s`:`${Math.round(m.hashrate_ghs)} GH/s`;
      const detail=[m.fallback?'Fallback active':'',m.upstream_evidence==='matched_translator'?'V2 verified at gateway':'',Number.isFinite(m.source_age_seconds)?`Measured ${Math.round(m.source_age_seconds)}s ago`:''].filter(Boolean).join(' · ');
      add(label,detail,m.connected?m.protocol:'unknown',m.connected?m.upstream_protocol:'unknown',state,rate,m.accepted,m.rejected,m.job_age_seconds===null?'Unavailable':`${Math.round(m.job_age_seconds)}s ago`,authenticated,m.tor_route || 'unknown',uptime(m.uptime_seconds));
    }
    if (nativeCurrent && !miners.length) { const row=node('tr',''); const cell=node('td','No miners contacted in the last 24 hours. Returning miners appear automatically.','note'); cell.colSpan=headings.length; row.append(cell);body.append(row); }
    if (!nativeCurrent) add('Miner telemetry','Stale or unavailable','unknown','unknown','Unknown','—','—','—','—',false);
    table.append(body);
    const connectionTable=node('table','','protocol-table');const connectionHead=head.cloneNode(true);
    headings[5]='Connection uptime';connectionHead.querySelectorAll('th')[5].textContent=headings[5];connectionTable.append(connectionHead);
    body=node('tbody','');
    sessions.forEach((s,i)=>add(showNames && s.client_ip ? s.client_ip : `Connection ${i+1}`,s.miner_protocol==='SV2'?'Encrypted relay':aggregate?'Shared V2 channel · connection counters':`Gateway session ${i+1}`,s.miner_protocol||'SV1',gatewayUpstream,'Connected','—',s.accepted,s.rejected,s.job_state==='encrypted'?'Encrypted':s.last_job_age_seconds===null?'Not yet':`${Math.round(s.last_job_age_seconds)}s ago`,false,s.route==='tor-1'?'A':s.route==='tor-2'?'B':'unknown',s.uptime_seconds==null?'—':uptime(s.uptime_seconds)));
    if (!gatewayCurrent) add('V1 gateway sessions','Telemetry stale or unavailable','unknown','unknown','Unknown','—','—','—','—',false);
    connectionTable.append(body);
    const connections=node('details','','gateway-connections');
    connections.append(node('summary',`Gateway connections${gatewayCurrent?` (${sessions.length})`:''}`));
    connections.append(node('p','Transport details only. Multiple connections may belong to one physical miner; they do not add hashrate.','note'),connectionTable);
    renderPaths(nativeCurrent?snapshot.data.native_route_counts:null);
    const wasOpen=el('protocol-miners').querySelector('.gateway-connections')?.open;
    connections.open=Boolean(wasOpen);
    el('protocol-miners').replaceChildren(table,connections);
    const ages=[nativeCurrent?snapshot.age_seconds:0,gatewayCurrent?legacy.gateway.age_seconds:0];
    deadline=performance.now()+Math.max(0,30-Math.max(...ages))*1000;
  };
  const poll=async()=>{
    const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),3000);
    try {
      const get=async path=>{const r=await fetch(path,{cache:'no-store',credentials:'same-origin',signal:controller.signal});if(!r.ok)throw Error('unavailable');return r.json();};
      const [miners,gateway]=await Promise.all([get('/api/miners'),get('/api/status')]);render(miners,gateway);
    } catch (_) {unknown();} finally {clearTimeout(timer);setTimeout(poll,10000);}
  };
  const expire=()=>{if(deadline && performance.now()>=deadline)unknown();};
  let resizeTimer;
  window.addEventListener('resize',()=>{clearTimeout(resizeTimer);resizeTimer=setTimeout(()=>chart(chartSnapshot),150);});
  setInterval(expire,1000);document.addEventListener('visibilitychange',expire);poll();
})();
