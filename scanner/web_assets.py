from __future__ import annotations

DASHBOARD_HTML = ""  # set below to avoid triple-quote nesting issues
# NOTE: The inline JSX below still contains deprecated legacy Dashboard components
# kept temporarily for parity validation. They are no longer rendered by App().
_DASHBOARD_HTML_PARTS = [
    '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
    '<meta charset="UTF-8" />\n'
    '<meta name="viewport" content="width=device-width, initial-scale=1.0" />\n'
    '<title>VANTAGE — Security Workflow</title>\n'
    '<link rel="preconnect" href="https://fonts.googleapis.com" />\n'
    '<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700&family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet" />\n'
    '<script src="https://unpkg.com/react@18.3.1/umd/react.development.js" integrity="sha384-hD6/rw4ppMLGNu3tX5cjIb+uRZ7UkRJ6BPkLpg4hAu/6onKUg4lLsHAs9EBPT82L" crossorigin="anonymous"></script>\n'
    '<script src="https://unpkg.com/react-dom@18.3.1/umd/react-dom.development.js" integrity="sha384-u6aeetuaXnQ38mYT8rp6sbXaQe3NL9t+IBXmnYxwkUI2Hw4bsp2Wvmx4yRQF1uAm" crossorigin="anonymous"></script>\n'
    '<script src="https://unpkg.com/@babel/standalone@7.29.0/babel.min.js" integrity="sha384-m08KidiNqLdpJqLq95G/LEi8Qvjl/xUYll3QILypMoQ65QorJ9Lvtp2RXYGBFj1y" crossorigin="anonymous"></script>\n'
    "<style>\n"
    "  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }\n"
    "  html, body, #root { width: 100%; height: 100%; overflow: hidden; }\n"
    "  body {\n"
    "    background: #0F172A;\n"
    "    color: #CBD5E1;\n"
    '    font-family: "Inter", sans-serif;\n'
    "    font-size: 13px;\n"
    "  }\n"
    "  ::-webkit-scrollbar { width: 5px; height: 5px; }\n"
    "  ::-webkit-scrollbar-track { background: transparent; }\n"
    "  ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }\n"
    "  ::-webkit-scrollbar-thumb:hover { background: #475569; }\n"
    "  button { font-family: inherit; }\n"
    "  input { font-family: inherit; color: #94A3B8; }\n"
    "  input::placeholder { color: #334155; }\n"
    "  select option { background: #1E293B; }\n"
    "</style>\n"
    "</head>\n"
    "<body>\n"
    '<div id="root"></div>\n'
    '<script type="text/babel">\n',

    # ── inline JS ──
    r"""
const { useState, useEffect, useMemo, useCallback, useRef, useContext } = React;

// ── VANTAGE brand tokens ───────────────────────────────────────────────────────
const C = {
  navy:        "#0F172A",
  slateDark:   "#1E293B",
  slateMid:    "#334155",
  slate:       "#64748B",
  muted:       "#475569",
  ink:         "#CBD5E1",
  inkBright:   "#F1F5F9",
  blue:        "#3B82F6",
  blueDim:     "rgba(59,130,246,0.15)",
  blueBorder:  "rgba(59,130,246,0.45)",
  sky:         "#93C5FD",
  skyDim:      "#60A5FA",
  rowHover:    "#162032",
  selectedBg:  "rgba(59,130,246,0.10)",
};

const SEVERITY_COLOR = {
  critical: "#EF4444",
  high:     "#F97316",
  medium:   "#EAB308",
  low:      "#3B82F6",
  info:     "#64748B",
};
const STATUS_COLOR = {
  completed: "#22C55E",
  running:   "#3B82F6",
  failed:    "#EF4444",
  cancelled: "#64748B",
  pending:   "#64748B",
};

function valueOr(value, fallback) {
  return value === null || value === undefined ? fallback : value;
}

function objectOrEmpty(value) {
  return value && typeof value === "object" ? value : {};
}

function arrayOrEmpty(value) {
  return Array.isArray(value) ? value : [];
}

// ── Small atoms ────────────────────────────────────────────────────────────────
function SeverityBadge({ level }) {
  const c = SEVERITY_COLOR[level] || "#888";
  return (
    <span style={{display:"inline-block",padding:"1px 7px",borderRadius:3,fontSize:10,fontWeight:700,
      letterSpacing:"0.06em",textTransform:"uppercase",color:c,border:`1px solid ${c}`,opacity:0.9}}>
      {level}
    </span>
  );
}
function StatusBadge({ code }) {
  const color = code>=500?"#EF4444":code>=400?"#F97316":code>=300?"#EAB308":"#22C55E";
  return <span style={{color,fontFamily:"JetBrains Mono, monospace",fontSize:12,fontWeight:600}}>{code}</span>;
}
function Tag({ children, color }) {
  return (
    <span style={{display:"inline-block",padding:"1px 6px",borderRadius:2,fontSize:10,
      background:color||C.blueDim, color:color?"#fff":C.blue,
      fontFamily:"JetBrains Mono, monospace"}}>
      {children}
    </span>
  );
}
function SectionLabel({ children }) {
  return <div style={{fontSize:10,color:C.slate,letterSpacing:"0.12em",textTransform:"uppercase",marginBottom:6,marginTop:4}}>{children}</div>;
}
function EmptyState({ msg }) {
  return <div style={{fontSize:12,color:C.muted,padding:"24px 0",textAlign:"center"}}>{msg}</div>;
}
function LoadingState({ msg }) {
  return <div style={{fontSize:12,color:C.slate,padding:"24px 0",textAlign:"center"}}>{msg || "Loading..."}</div>;
}
function ErrorState({ msg }) {
  return <div style={{color:"#FCA5A5",border:"1px solid rgba(239,68,68,0.35)",borderRadius:6,padding:12,background:"rgba(239,68,68,0.08)",fontSize:12}}>{msg}</div>;
}
function KVTable({ rows }) {
  const filtered = (rows||[]).filter(Boolean);
  return (
    <div style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:4,marginBottom:12,overflow:"hidden"}}>
      {filtered.map(([k,v],i) => (
        <div key={k} style={{display:"flex",borderBottom:i<filtered.length-1?`1px solid ${C.slateMid}`:"none"}}>
          <div style={{width:120,padding:"6px 10px",fontSize:10,color:C.slate,borderRight:`1px solid ${C.slateMid}`,flexShrink:0}}>{k}</div>
          <div style={{padding:"6px 10px",fontSize:11,color:C.ink,fontFamily:"JetBrains Mono, monospace",flex:1}}>{v}</div>
        </div>
      ))}
    </div>
  );
}

// ── VANTAGE Logo ───────────────────────────────────────────────────────────────
function Logo() {
  return (
    <div style={{display:"flex",alignItems:"center",gap:14}}>
      <svg viewBox="0 0 48 56" width="28" height="33" xmlns="http://www.w3.org/2000/svg">
        <line x1="2" y1="4" x2="24" y2="48" stroke="#3B82F6" strokeWidth="2.5" strokeLinecap="round"/>
        <line x1="46" y1="4" x2="24" y2="48" stroke="#3B82F6" strokeWidth="2.5" strokeLinecap="round"/>
        <line x1="8" y1="16" x2="40" y2="16" stroke="#93C5FD" strokeWidth="1" strokeLinecap="round"/>
        <line x1="14" y1="28" x2="34" y2="28" stroke="#93C5FD" strokeWidth="1" strokeLinecap="round"/>
        <line x1="20" y1="40" x2="28" y2="40" stroke="#93C5FD" strokeWidth="1" strokeLinecap="round"/>
        <circle cx="8"  cy="16" r="2" fill="#60A5FA"/>
        <circle cx="40" cy="16" r="2" fill="#60A5FA"/>
        <circle cx="14" cy="28" r="2" fill="#60A5FA"/>
        <circle cx="34" cy="28" r="2" fill="#60A5FA"/>
        <circle cx="20" cy="40" r="2" fill="#60A5FA"/>
        <circle cx="28" cy="40" r="2" fill="#60A5FA"/>
        <polygon points="24,44 28,48 24,52 20,48" fill="#3B82F6"/>
        <circle cx="2"  cy="4"  r="2.5" fill="#3B82F6"/>
        <circle cx="46" cy="4"  r="2.5" fill="#3B82F6"/>
      </svg>
      <div>
        <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:16,fontWeight:700,letterSpacing:"0.15em",color:C.inkBright,lineHeight:1}}>VANTAGE</div>
        <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:6,letterSpacing:"0.38em",color:C.slateMid,marginTop:4}}>SECURITY WORKFLOW</div>
      </div>
    </div>
  );
}

// DEPRECATED: legacy vanilla UI — safe to remove after validation.
// The active React shell uses FindingsArtifactSidePanel instead.
// ── Artifact Viewer ────────────────────────────────────────────────────────────
function ArtifactViewer({ artifact, onClose }) {
  const [content, setContent] = useState("Loading…");
  useEffect(() => {
    const h = e => { if (e.key==="Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);
  useEffect(() => {
    if (!artifact?.path) return;
    fetch(`/api/dashboard/artifact?path=${encodeURIComponent(artifact.path)}`)
      .then(r => r.ok ? r.text() : r.json().then(j => Promise.reject(j.error||"Failed")))
      .then(setContent)
      .catch(err => setContent(`[ Error loading artifact: ${err} ]`));
  }, [artifact?.path]);
  return (
    <div style={{position:"fixed",inset:0,zIndex:100,background:"rgba(7,11,20,0.88)",display:"flex",alignItems:"center",justifyContent:"center"}} onClick={onClose}>
      <div onClick={e=>e.stopPropagation()} style={{width:"min(780px,90vw)",maxHeight:"80vh",background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:8,display:"flex",flexDirection:"column",boxShadow:"0 32px 80px rgba(0,0,0,0.8)"}}>
        <div style={{display:"flex",alignItems:"center",padding:"10px 16px",borderBottom:`1px solid ${C.slateMid}`,gap:10}}>
          <span style={{fontSize:12,fontFamily:"JetBrains Mono, monospace",color:C.blue,flex:1}}>{"▤"} {artifact.name}</span>
          <span style={{fontSize:10,color:C.slate}}>{artifact.module} {"·"} {artifact.size}</span>
          <button onClick={onClose} style={{background:"transparent",border:`1px solid ${C.slateMid}`,color:C.muted,borderRadius:3,padding:"2px 8px",cursor:"pointer",fontSize:12}}>{"✕"}</button>
        </div>
        <div style={{flex:1,overflowY:"auto",padding:16}}>
          <pre style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.ink,lineHeight:1.7,whiteSpace:"pre-wrap",wordBreak:"break-all"}}>{content}</pre>
        </div>
        <div style={{padding:"8px 16px",borderTop:`1px solid ${C.slateMid}`,fontSize:10,color:C.muted}}>Press ESC to close</div>
      </div>
    </div>
  );
}

// DEPRECATED: legacy vanilla Dashboard React tree — safe to remove after validation.
// All routes now navigate to AppShell + RunsDashboard / ExecutionPage / RunSummaryPage / FindingsPage.
// ── Host Navigator ─────────────────────────────────────────────────────────────
function HostNavigator({ hosts, selectedHost, onSelectHost, diffData, diffMode, visMode, onVisMode }) {
  const [filter, setFilter] = useState("");
  const filtered = hosts.filter(h => {
    const matchFilter = h.label.toLowerCase().includes(filter.toLowerCase());
    const matchVis = visMode==="all" || h.has_web;
    return matchFilter && matchVis;
  });
  return (
    <div style={{display:"flex",flexDirection:"column",height:"100%",borderRight:`1px solid ${C.slateMid}`}}>
      <div style={{padding:"10px 12px 8px",borderBottom:`1px solid ${C.slateMid}`}}>
        <div style={{fontSize:10,color:C.slate,letterSpacing:"0.1em",textTransform:"uppercase",marginBottom:8}}>Hosts {"·"} {filtered.length}/{hosts.length}</div>
        <input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="filter hosts…"
          style={{width:"100%",background:C.navy,border:`1px solid ${C.slateMid}`,borderRadius:3,padding:"4px 8px",fontSize:11,color:C.ink,outline:"none",fontFamily:"JetBrains Mono, monospace"}}
        />
        <div style={{display:"flex",gap:4,marginTop:8}}>
          {["all","web_only"].map(m => (
            <button key={m} onClick={()=>onVisMode(m)} style={{
              flex:1,padding:"3px 0",fontSize:10,
              background:visMode===m?C.blueDim:"transparent",
              border:`1px solid ${visMode===m?C.blue:C.slateMid}`,
              color:visMode===m?C.blue:C.slate,
              borderRadius:3,cursor:"pointer",
            }}>{m==="all"?"All":"Web only"}</button>
          ))}
        </div>
      </div>
      <div style={{flex:1,overflowY:"auto"}}>
        {filtered.length===0 && <div style={{padding:16,fontSize:11,color:C.slate,textAlign:"center"}}>No hosts matching</div>}
        {filtered.map(h => {
          const isSelected = selectedHost?.id===h.id;
          const diffState = diffMode && (diffData?.hosts?.[h.label]||diffData?.hosts?.[h.ip]);
          const diffColor = diffState==="added"?C.blue:diffState==="removed"?"#EF4444":null;
          return (
            <div key={h.id} onClick={()=>onSelectHost(isSelected?null:h)}
              style={{padding:"8px 12px",cursor:"pointer",background:isSelected?C.selectedBg:"transparent",
                borderLeft:`3px solid ${isSelected?C.blue:diffColor||"transparent"}`,
                borderBottom:`1px solid ${C.navy}`,transition:"background 0.12s"}}
              onMouseEnter={e=>{if(!isSelected)e.currentTarget.style.background=C.rowHover;}}
              onMouseLeave={e=>{if(!isSelected)e.currentTarget.style.background="transparent";}}
            >
              <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:3}}>
                {h.type==="domain"
                  ?<span style={{color:C.slate,fontSize:9}}>{"⬡"}</span>
                  :<span style={{color:C.slate,fontSize:9}}>{"◆"}</span>}
                <span style={{fontSize:12,fontFamily:"JetBrains Mono, monospace",
                  color:isSelected?C.sky:C.ink,
                  flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{h.label}</span>
                {diffState==="added" && <Tag>+new</Tag>}
              </div>
              <div style={{display:"flex",gap:8,paddingLeft:15}}>
                <span style={{fontSize:10,color:C.slate}}><span style={{color:C.muted}}>{h.ports_count}</span> ports</span>
                <span style={{fontSize:10,color:C.slate}}>
                  <span style={{color:h.findings_count>0?"#F97316":C.muted}}>{h.findings_count}</span> findings
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Service Panel ──────────────────────────────────────────────────────────────
function ServicePanel({ host, services, selectedPort, onSelectPort, diffData, diffMode }) {
  if (!host) return null;
  const portList = services[host.label]||[];
  return (
    <div style={{display:"flex",flexDirection:"column",height:"100%",borderRight:`1px solid ${C.slateMid}`}}>
      <div style={{padding:"10px 12px 8px",borderBottom:`1px solid ${C.slateMid}`}}>
        <div style={{fontSize:10,color:C.slate,letterSpacing:"0.1em",textTransform:"uppercase",marginBottom:2}}>Services</div>
        <div style={{fontSize:11,color:C.muted,fontFamily:"JetBrains Mono, monospace"}}>{host.label}</div>
      </div>
      <div style={{flex:1,overflowY:"auto"}}>
        {portList.length===0 && <EmptyState msg="No services"/>}
        {portList.map(svc => {
          const isSelected = selectedPort?.port===svc.port;
          const key=`${host.label}:${svc.port}`;
          const isNew = diffMode && diffData?.services?.[key]==="added";
          return (
            <div key={svc.id} onClick={()=>onSelectPort(isSelected?null:svc)}
              style={{padding:"9px 12px",cursor:"pointer",
                background:isSelected?C.selectedBg:"transparent",
                borderLeft:`3px solid ${isSelected?C.blue:isNew?"rgba(59,130,246,0.4)":"transparent"}`,
                borderBottom:`1px solid ${C.navy}`,transition:"background 0.12s"}}
              onMouseEnter={e=>{if(!isSelected)e.currentTarget.style.background=C.rowHover;}}
              onMouseLeave={e=>{if(!isSelected)e.currentTarget.style.background="transparent";}}
            >
              <div style={{display:"flex",alignItems:"center",gap:8}}>
                <span style={{fontSize:13,fontFamily:"JetBrains Mono, monospace",fontWeight:700,
                  color:isSelected?C.sky:svc.is_web?C.blue:C.ink,minWidth:36}}>{svc.port}</span>
                <div style={{flex:1}}>
                  <div style={{display:"flex",alignItems:"center",gap:6}}>
                    <span style={{fontSize:11,color:C.ink}}>{svc.service_name}</span>
                    {svc.is_web && <span style={{fontSize:9,color:C.blue,border:`1px solid rgba(59,130,246,0.4)`,borderRadius:2,padding:"0 4px"}}>WEB</span>}
                    {isNew && <Tag>+new</Tag>}
                  </div>
                  <div style={{fontSize:10,color:C.muted,marginTop:1,fontFamily:"JetBrains Mono, monospace"}}>{svc.banner}</div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Tab content ────────────────────────────────────────────────────────────────
function OverviewTab({ host, port, data, services }) {
  if (!port) {
    const portList = services[host.label]||[];
    return (
      <div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8,marginBottom:16}}>
          {[
            {label:"Open Ports",  value:portList.length,                     color:C.blue},
            {label:"Web Services",value:portList.filter(p=>p.is_web).length, color:C.sky},
            {label:"Total CVEs",  value:0,                                    color:"#F97316"},
            {label:"Critical",    value:0,                                    color:"#EF4444"},
          ].map(card => (
            <div key={card.label} style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:4,padding:"10px 12px"}}>
              <div style={{fontSize:22,fontFamily:"JetBrains Mono, monospace",color:card.color,fontWeight:700}}>{card.value}</div>
              <div style={{fontSize:10,color:C.slate,marginTop:2}}>{card.label}</div>
            </div>
          ))}
        </div>
        <SectionLabel>Services</SectionLabel>
        {portList.map(svc => (
          <div key={svc.id} style={{display:"flex",gap:10,alignItems:"center",padding:"6px 0",borderBottom:`1px solid ${C.navy}`}}>
            <span style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.blue,minWidth:40}}>{svc.port}</span>
            <span style={{fontSize:11,color:C.ink,minWidth:80}}>{svc.service_name}</span>
            <span style={{fontSize:10,color:C.muted,flex:1}}>{svc.banner}</span>
          </div>
        ))}
        {arrayOrEmpty(host.domain_mappings).length > 0 && (
          <div style={{marginTop:14}}>
            <SectionLabel>Mapped domains</SectionLabel>
            <div style={{display:"grid",gap:6}}>
              {arrayOrEmpty(host.domain_mappings).map((row, i) => (
                <div key={`${row.domain}-${i}`} style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
                  <a href={row.href} target="_blank" rel="noreferrer" style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.sky,textDecoration:"none"}}>{row.domain}</a>
                  <span style={{fontSize:10,color:C.slate}}>{row.source || ""}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }
  const modules=["port_scan","http_probe","domain_discovery","dir_enum","banner_probe"];
  const ms={
    port_scan:"executed",
    http_probe:port.is_web?"executed":"not_run",
    domain_discovery:"executed",
    dir_enum:port.is_web?"executed":"not_run",
    banner_probe:"executed",
  };
  return (
    <div>
      <SectionLabel>Modules</SectionLabel>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6,marginBottom:16}}>
        {modules.map(m => (
          <div key={m} style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:4,padding:"7px 10px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <span style={{fontSize:11,fontFamily:"JetBrains Mono, monospace",color:C.muted}}>{m}</span>
            <span style={{fontSize:10,color:ms[m]==="executed"?C.blue:C.slateMid}}>{ms[m]==="executed"?"✓ executed":"— not run"}</span>
          </div>
        ))}
      </div>
      {data?.overview && (
        <>
          <SectionLabel>Response</SectionLabel>
          <KVTable rows={[
            data.overview.status_code!=null && ["Status", <StatusBadge code={data.overview.status_code}/>],
            data.overview.title       && ["Title",        data.overview.title],
            data.overview.server      && ["Server",       data.overview.server],
            data.overview.content_type && ["Content-Type",data.overview.content_type],
            data.overview.response_time && ["Response Time",data.overview.response_time],
            data.overview.banner      && ["Banner",       data.overview.banner],
            data.overview.tls         && ["TLS",          typeof data.overview.tls==="string"?data.overview.tls:JSON.stringify(data.overview.tls)],
            data.overview.redirect_chain?.length>0 && ["Redirects", data.overview.redirect_chain.join(" → ")],
          ]}/>
        </>
      )}
    </div>
  );
}

function AllFindingsTab({ findings, diffData, diffMode }) {
  if (!findings||findings.length===0) return <EmptyState msg="No findings"/>;
  return (
    <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
      <thead>
        <tr style={{borderBottom:`1px solid ${C.slateMid}`}}>
          {["Port","Category","Severity","Title"].map(h=>(
            <th key={h} style={{textAlign:"left",padding:"4px 8px",fontSize:10,color:C.slate,letterSpacing:"0.08em",fontWeight:600}}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {findings.map((f,i)=>{
          const isNew=diffMode&&diffData?.findings?.[f.id]==="added";
          return (
            <tr key={f.id||i} style={{borderBottom:`1px solid ${C.navy}`,background:isNew?C.blueDim:"transparent"}}>
              <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",color:C.blue}}>{f.port}</td>
              <td style={{padding:"5px 8px",color:C.muted}}>{f.category}</td>
              <td style={{padding:"5px 8px"}}>{f.severity?<SeverityBadge level={f.severity}/>:<span style={{color:C.slate}}>—</span>}</td>
              <td style={{padding:"5px 8px",color:C.ink}}>
                <div style={{display:"flex",alignItems:"center",gap:6}}>{f.title||f.path}{isNew&&<Tag>+new</Tag>}</div>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function HttpTab({ findings, diffData, diffMode }) {
  if (!findings) return <EmptyState msg="Module not executed"/>;
  if (findings.length===0) return <EmptyState msg="No HTTP findings"/>;
  return (
    <div style={{display:"flex",flexDirection:"column",gap:6}}>
      {findings.map(f=>{
        const isNew=diffMode&&diffData?.findings?.[f.id]==="added";
        return (
          <div key={f.id} style={{background:C.slateDark,border:`1px solid ${isNew?C.blue:C.slateMid}`,borderRadius:4,padding:"10px 12px"}}>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
              <SeverityBadge level={f.severity}/>
              {f.type&&<Tag color="#1e3a5f">{f.type}</Tag>}
              <span style={{fontSize:12,color:C.ink,flex:1}}>{f.title}</span>
              {isNew&&<Tag>+new</Tag>}
            </div>
            {f.detail&&<div style={{fontSize:11,color:C.muted,paddingLeft:2}}>{f.detail}</div>}
          </div>
        );
      })}
    </div>
  );
}

function DirectoriesTab({ dirs }) {
  if (!dirs) return <EmptyState msg="Module not executed"/>;
  if (dirs.length===0) return <EmptyState msg="No directories found"/>;
  const interesting=dirs.filter(d=>d.status===200||d.status===301);
  return (
    <div>
      <div style={{marginBottom:10,fontSize:10,color:C.slate}}>{dirs.length} paths enumerated {"·"} <span style={{color:C.blue}}>{interesting.length} interesting</span></div>
      <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
        <thead>
          <tr style={{borderBottom:`1px solid ${C.slateMid}`}}>
            {["Path","Status","Size","Redirect"].map(h=>(
              <th key={h} style={{textAlign:"left",padding:"4px 8px",fontSize:10,color:C.slate,letterSpacing:"0.08em",fontWeight:600}}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {dirs.map(d=>(
            <tr key={d.id} style={{borderBottom:`1px solid ${C.navy}`}}>
              <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",color:d.status===200?C.blue:C.ink}}>{d.path}</td>
              <td style={{padding:"5px 8px"}}>{d.status?<StatusBadge code={d.status}/>:"—"}</td>
              <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",color:C.slate}}>{d.size||"—"}</td>
              <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",color:C.slate,fontSize:10}}>{d.redirect||"—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CVETab({ cves, diffData, diffMode }) {
  if (!cves) return <EmptyState msg="Module not executed"/>;
  if (cves.length===0) return <EmptyState msg="No CVEs matched"/>;
  return (
    <div style={{display:"flex",flexDirection:"column",gap:6}}>
      {cves.map(c=>{
        const isNew=diffMode&&diffData?.findings?.[c.id]==="added";
        return (
          <div key={c.id} style={{background:C.slateDark,border:`1px solid ${isNew?C.blue:C.slateMid}`,borderRadius:4,padding:"10px 12px"}}>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:5}}>
              <SeverityBadge level={c.severity}/>
              <span style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.sky}}>{c.cve_id}</span>
              {c.cvss>0&&<span style={{marginLeft:"auto",fontSize:11,fontFamily:"JetBrains Mono, monospace",color:SEVERITY_COLOR[c.severity]}}>CVSS {c.cvss}</span>}
              {isNew&&<Tag>+new</Tag>}
            </div>
            <div style={{fontSize:12,color:C.ink,marginBottom:4}}>{c.title}</div>
            <div style={{display:"flex",gap:12,fontSize:10,color:C.slate}}>
              {c.affected&&<span>Affected: <span style={{color:C.muted}}>{c.affected}</span></span>}
              {c.fixed_in&&<span>Fixed: <span style={{color:C.blue}}>{c.fixed_in}</span></span>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function ArtifactsTab({ artifacts, onOpen }) {
  if (!artifacts||artifacts.length===0) return <EmptyState msg="No artifacts"/>;
  return (
    <div style={{display:"flex",flexDirection:"column",gap:6}}>
      {artifacts.map(a=>(
        <div key={a.id} style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:4,padding:"10px 12px",display:"flex",alignItems:"center",gap:10}}>
          <div style={{fontSize:18,color:C.slateMid}}>{"▤"}</div>
          <div style={{flex:1}}>
            <div style={{fontSize:12,color:C.ink,fontFamily:"JetBrains Mono, monospace"}}>{a.name}</div>
            <div style={{fontSize:10,color:C.slate,marginTop:2}}><span style={{color:C.muted}}>{a.module}</span> {"·"} {a.size}</div>
          </div>
          {a.path&&(
            <button onClick={()=>onOpen(a)} style={{padding:"4px 10px",fontSize:11,background:"transparent",border:`1px solid ${C.slateMid}`,color:C.muted,borderRadius:3,cursor:"pointer"}}
              onMouseEnter={e=>{e.currentTarget.style.borderColor=C.blue;e.currentTarget.style.color=C.blue;}}
              onMouseLeave={e=>{e.currentTarget.style.borderColor=C.slateMid;e.currentTarget.style.color=C.muted;}}
            >View output</button>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Findings Panel ─────────────────────────────────────────────────────────────
function FindingsPanel({ host, port, services, findings, diffData, diffMode, onOpenArtifact }) {
  const [activeTab, setActiveTab] = useState("overview");
  useEffect(()=>{setActiveTab("overview");},[host?.id,port?.port]);
  const key = host&&port ? `${host.label}:${port.port}` : null;
  const data = key ? findings[key] : null;
  const allFindings = useMemo(()=>{
    if (!host||port) return null;
    const portList=services[host.label]||[];
    const rows=[];
    portList.forEach(svc=>{
      const k=`${host.label}:${svc.port}`;
      const fd=findings[k];
      if (!fd) return;
      (fd.http||[]).forEach(f=>rows.push({...f,port:svc.port,category:"HTTP"}));
      (fd.cves||[]).forEach(f=>rows.push({...f,port:svc.port,category:"CVE"}));
      (fd.directories||[]).forEach(f=>rows.push({...f,port:svc.port,category:"Dir"}));
    });
    return rows;
  },[host,port,services,findings]);

  if (!host) return (
    <div style={{display:"flex",alignItems:"center",justifyContent:"center",height:"100%",flexDirection:"column",gap:10}}>
      <svg viewBox="0 0 48 56" width="36" height="42" xmlns="http://www.w3.org/2000/svg" style={{opacity:0.15}}>
        <line x1="2" y1="4" x2="24" y2="48" stroke="#3B82F6" strokeWidth="2.5" strokeLinecap="round"/>
        <line x1="46" y1="4" x2="24" y2="48" stroke="#3B82F6" strokeWidth="2.5" strokeLinecap="round"/>
        <line x1="8" y1="16" x2="40" y2="16" stroke="#93C5FD" strokeWidth="1" strokeLinecap="round"/>
        <line x1="14" y1="28" x2="34" y2="28" stroke="#93C5FD" strokeWidth="1" strokeLinecap="round"/>
        <line x1="20" y1="40" x2="28" y2="40" stroke="#93C5FD" strokeWidth="1" strokeLinecap="round"/>
        <polygon points="24,44 28,48 24,52 20,48" fill="#3B82F6"/>
        <circle cx="2"  cy="4"  r="2.5" fill="#3B82F6"/>
        <circle cx="46" cy="4"  r="2.5" fill="#3B82F6"/>
      </svg>
      <div style={{fontSize:13,color:C.muted}}>Select a host to view findings</div>
    </div>
  );

  let tabs;
  if (!port) {
    tabs=[{id:"overview",label:"Overview"},{id:"all",label:"All Findings"}];
  } else if (port.is_web) {
    tabs=[{id:"overview",label:"Overview"},{id:"http",label:"HTTP"},{id:"directories",label:"Directories"},{id:"cves",label:"CVE"},{id:"artifacts",label:"Artifacts"}];
  } else {
    tabs=[{id:"overview",label:"Overview"},{id:"cves",label:"CVE"},{id:"artifacts",label:"Artifacts"}];
  }
  const tc={http:data?.http?.length??0,directories:data?.directories?.length??0,cves:data?.cves?.length??0,artifacts:data?.artifacts?.length??0,all:allFindings?.length??0};

  return (
    <div style={{display:"flex",flexDirection:"column",height:"100%"}}>
      <div style={{padding:"8px 16px",borderBottom:`1px solid ${C.slateMid}`,display:"flex",alignItems:"center",gap:6}}>
        <span style={{fontSize:11,fontFamily:"JetBrains Mono, monospace",color:C.blue}}>{host.label}</span>
        {port&&<><span style={{color:C.slateMid}}>{"›"}</span><span style={{fontSize:11,fontFamily:"JetBrains Mono, monospace",color:C.ink}}>:{port.port}</span><span style={{fontSize:11,color:C.slate}}>{port.service_name}</span></>}
        {!port&&<span style={{fontSize:10,color:C.slate}}>{"— all services"}</span>}
      </div>
      <div style={{display:"flex",gap:0,borderBottom:`1px solid ${C.slateMid}`,padding:"0 16px"}}>
        {tabs.map(t=>{
          const count=tc[t.id];
          const active=activeTab===t.id;
          return (
            <button key={t.id} onClick={()=>setActiveTab(t.id)} style={{padding:"8px 12px 7px",fontSize:12,background:"transparent",border:"none",
              borderBottom:`2px solid ${active?C.blue:"transparent"}`,
              color:active?C.sky:C.muted,
              cursor:"pointer",marginBottom:-1,display:"flex",alignItems:"center",gap:5}}>
              {t.label}
              {count>0&&<span style={{fontSize:10,padding:"1px 5px",borderRadius:10,
                background:active?C.blueDim:C.slateDark,
                color:active?C.blue:C.slate}}>{count}</span>}
            </button>
          );
        })}
      </div>
      <div style={{flex:1,overflowY:"auto",padding:"12px 16px"}}>
        {activeTab==="overview"    && <OverviewTab host={host} port={port} data={data} services={services}/>}
        {activeTab==="all"         && <AllFindingsTab findings={allFindings} diffData={diffData} diffMode={diffMode}/>}
        {activeTab==="http"        && <HttpTab findings={data?.http} diffData={diffData} diffMode={diffMode}/>}
        {activeTab==="directories" && <DirectoriesTab dirs={data?.directories}/>}
        {activeTab==="cves"        && <CVETab cves={data?.cves} diffData={diffData} diffMode={diffMode}/>}
        {activeTab==="artifacts"   && <ArtifactsTab artifacts={data?.artifacts} onOpen={onOpenArtifact}/>}
      </div>
    </div>
  );
}

// ── Dashboard ──────────────────────────────────────────────────────────────────
function Dashboard({ runs, loading, onSelectRun }) {
  return (
    <div style={{display:"flex",flexDirection:"column",height:"100%"}}>
      <div style={{padding:"0 28px",height:56,display:"flex",alignItems:"center",borderBottom:`1px solid ${C.slateMid}`,gap:16,flexShrink:0}}>
        <Logo/>
        <div style={{flex:1}}/>
        <a href="/" style={{padding:"6px 16px",fontSize:11,fontWeight:600,textDecoration:"none",
          background:C.blueDim,border:`1px solid ${C.blueBorder}`,
          color:C.sky,borderRadius:4,cursor:"pointer",letterSpacing:"0.04em"}}>+ New Scan</a>
      </div>
      <div style={{flex:1,overflowY:"auto",padding:"24px 28px"}}>
        <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:28}}>
          {[
            {label:"Total Runs",    value:runs.length,                                               color:C.ink},
            {label:"Completed",     value:runs.filter(r=>r.status==="completed").length,             color:"#22C55E"},
            {label:"Total Hosts",   value:runs.reduce((a,r)=>a+(r.host_count||0),0),                color:C.sky},
            {label:"Total Findings",value:runs.reduce((a,r)=>a+(r.finding_count||0),0),             color:"#F97316"},
          ].map(s=>(
            <div key={s.label} style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:6,padding:"16px 18px"}}>
              <div style={{fontSize:30,fontFamily:"JetBrains Mono, monospace",fontWeight:700,color:s.color}}>{loading?"…":s.value}</div>
              <div style={{fontSize:10,color:C.slate,marginTop:4,letterSpacing:"0.06em",textTransform:"uppercase"}}>{s.label}</div>
            </div>
          ))}
        </div>
        <div style={{fontSize:10,color:C.slate,letterSpacing:"0.12em",textTransform:"uppercase",marginBottom:12,
          fontFamily:"'Orbitron',sans-serif"}}>Recent Runs</div>
        {loading ? (
          <div style={{textAlign:"center",padding:40,color:C.slate}}>Loading runs…</div>
        ) : runs.length===0 ? (
          <div style={{textAlign:"center",padding:40,color:C.slate}}>No runs yet. <a href="/" style={{color:C.blue}}>Start a scan</a>.</div>
        ) : (
          <div style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:6,overflow:"hidden"}}>
            <table style={{width:"100%",borderCollapse:"collapse"}}>
              <thead>
                <tr style={{borderBottom:`1px solid ${C.slateMid}`}}>
                  {["Run ID","Name","Target","Status","Hosts","Findings","Duration","Date"].map(h=>(
                    <th key={h} style={{textAlign:"left",padding:"9px 14px",fontSize:10,color:C.slate,fontWeight:600,letterSpacing:"0.08em"}}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {runs.map((run,i)=>(
                  <tr key={run.id}
                    onClick={()=>run.status==="completed"&&onSelectRun(run)}
                    style={{borderBottom:i<runs.length-1?`1px solid ${C.navy}`:"none",
                      cursor:run.status==="completed"?"pointer":"default",
                      opacity:(run.status==="failed"||run.status==="cancelled")?0.45:1,
                      transition:"background 0.1s"}}
                    onMouseEnter={e=>{if(run.status==="completed")e.currentTarget.style.background=C.rowHover;}}
                    onMouseLeave={e=>{e.currentTarget.style.background="transparent";}}
                  >
                    <td style={{padding:"10px 14px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.muted}}>{run.id}</td>
                    <td style={{padding:"10px 14px",fontSize:12,color:C.ink,fontWeight:500}}>{run.name}</td>
                    <td style={{padding:"10px 14px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.ink}}>{run.target_display || run.target}</td>
                    <td style={{padding:"10px 14px"}}>
                      <span style={{fontSize:11,color:STATUS_COLOR[run.status]||C.slate,display:"flex",alignItems:"center",gap:5}}>
                        <span style={{width:6,height:6,borderRadius:"50%",background:STATUS_COLOR[run.status]||C.slate,display:"inline-block",flexShrink:0}}></span>
                        {run.status}
                      </span>
                    </td>
                    <td style={{padding:"10px 14px",fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.ink}}>{run.host_count}</td>
                    <td style={{padding:"10px 14px",fontFamily:"JetBrains Mono, monospace",fontSize:12,color:run.finding_count>0?"#F97316":C.slate}}>{run.finding_count}</td>
                    <td style={{padding:"10px 14px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>{run.duration||"—"}</td>
                    <td style={{padding:"10px 14px",fontSize:11,color:C.slate}}>{(run.created_at||"").slice(0,10)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Findings Layout ────────────────────────────────────────────────────────────
// ── Run Overview (전체 집계) ────────────────────────────────────────────────────
function RunOverview({ run, report }) {
  const hosts    = report?.hosts    || [];
  const services = report?.services || {};
  const findings = report?.findings || {};

  // 전체 집계
  const allPorts = useMemo(() => {
    const rows = [];
    hosts.forEach(h => {
      (services[h.label] || []).forEach(svc => {
        rows.push({ host: h.label, ...svc });
      });
    });
    return rows;
  }, [hosts, services]);

  const allCVEs = useMemo(() => {
    const rows = [];
    Object.entries(findings).forEach(([key, fd]) => {
      const [host, port] = key.split(":");
      (fd.cves || []).forEach(c => rows.push({ ...c, host, port }));
    });
    return rows.sort((a,b) => {
      const order = { critical:0, high:1, medium:2, low:3, info:4 };
      return (order[a.severity]??5) - (order[b.severity]??5);
    });
  }, [findings]);

  const allDirs = useMemo(() => {
    const rows = [];
    Object.entries(findings).forEach(([key, fd]) => {
      const [host, port] = key.split(":");
      (fd.directories || []).forEach(d => {
        if (d.status === 200 || d.status === 301 || d.status === 302)
          rows.push({ ...d, host, port });
      });
    });
    return rows.sort((a,b) => (a.status===200?0:1) - (b.status===200?0:1));
  }, [findings]);

  const allHTTP = useMemo(() => {
    const rows = [];
    Object.entries(findings).forEach(([key, fd]) => {
      const [host, port] = key.split(":");
      (fd.http || []).forEach(f => rows.push({ ...f, host, port }));
    });
    return rows.sort((a,b) => {
      const order = { critical:0, high:1, medium:2, low:3, info:4 };
      return (order[a.severity]??5) - (order[b.severity]??5);
    });
  }, [findings]);

  const webHosts  = hosts.filter(h => h.has_web).length;
  const critCVEs  = allCVEs.filter(c => c.severity === "critical" || c.severity === "high").length;
  const openDirs  = allDirs.filter(d => d.status === 200).length;
  const webPorts  = allPorts.filter(p => p.is_web).length;

  const SEV = { critical:"#EF4444", high:"#F97316", medium:"#EAB308", low:"#3B82F6", info:"#64748B" };

  const StatCard = ({ label, value, color, sub }) => (
    <div style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:5,padding:"14px 16px",minWidth:0}}>
      <div style={{fontSize:28,fontFamily:"JetBrains Mono, monospace",fontWeight:700,color:color||C.ink,lineHeight:1}}>{value}</div>
      <div style={{fontSize:10,color:C.slate,marginTop:4,letterSpacing:"0.08em",textTransform:"uppercase"}}>{label}</div>
      {sub&&<div style={{fontSize:10,color:C.muted,marginTop:2}}>{sub}</div>}
    </div>
  );

  const Section = ({ title, count, accent, children }) => (
    <div style={{border:`1px solid ${C.slateMid}`,borderRadius:5,overflow:"hidden",marginBottom:14}}>
      <div style={{display:"flex",alignItems:"center",gap:8,padding:"8px 14px",borderBottom:`1px solid ${C.slateMid}`,background:C.slateDark,borderLeft:`3px solid ${accent||C.blue}`}}>
        <span style={{fontSize:10,fontWeight:700,letterSpacing:"0.12em",textTransform:"uppercase",color:C.muted,flex:1}}>{title}</span>
        {count!=null&&<span style={{fontSize:10,padding:"1px 7px",borderRadius:10,background:"rgba(59,130,246,0.12)",color:C.blue,fontFamily:"JetBrains Mono, monospace"}}>{count}</span>}
      </div>
      <div style={{padding:"10px 14px"}}>{children}</div>
    </div>
  );

  return (
    <div style={{height:"100%",overflowY:"auto",padding:"20px 24px"}}>

      {/* ── 요약 카드 ── */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(6,1fr)",gap:10,marginBottom:20}}>
        <StatCard label="Hosts"       value={hosts.length}       color={C.ink}/>
        <StatCard label="Web Hosts"   value={webHosts}           color={C.sky}/>
        <StatCard label="Open Ports"  value={allPorts.length}    color={C.ink}/>
        <StatCard label="Web Ports"   value={webPorts}           color={C.sky}/>
        <StatCard label="CVEs"        value={allCVEs.length}     color={critCVEs>0?"#F97316":C.ink} sub={critCVEs>0?`${critCVEs} high/critical`:null}/>
        <StatCard label="HTTP Issues" value={allHTTP.length}     color={allHTTP.length>0?"#EAB308":C.ink}/>
      </div>

      {/* ── 호스트 & 포트 매트릭스 ── */}
      <Section title="Hosts & Services" count={hosts.length} accent={C.blue}>
        <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
          <thead>
            <tr style={{borderBottom:`1px solid ${C.slateMid}`}}>
              {["Host","IP","Ports","Web","Findings"].map(h=>(
                <th key={h} style={{textAlign:"left",padding:"4px 8px",fontSize:10,color:C.slate,fontWeight:600,letterSpacing:"0.08em"}}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {hosts.map(h=>{
              const svcList = services[h.label]||[];
              const webSvcs = svcList.filter(s=>s.is_web);
              return (
                <tr key={h.id} style={{borderBottom:`1px solid ${C.navy}`}}>
                  <td style={{padding:"6px 8px",fontFamily:"JetBrains Mono, monospace",color:C.blue}}>{h.label}</td>
                  <td style={{padding:"6px 8px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.muted}}>{h.ip||"—"}</td>
                  <td style={{padding:"6px 8px"}}>
                    <div style={{display:"flex",flexWrap:"wrap",gap:3}}>
                      {svcList.map(s=>(
                        <span key={s.id} style={{fontSize:10,padding:"1px 5px",borderRadius:2,fontFamily:"JetBrains Mono, monospace",
                          background:s.is_web?"rgba(59,130,246,0.12)":"rgba(100,116,139,0.12)",
                          color:s.is_web?C.sky:C.muted,
                          border:`1px solid ${s.is_web?"rgba(59,130,246,0.3)":C.slateMid}`}}>
                          {s.port}
                        </span>
                      ))}
                      {svcList.length===0&&<span style={{color:C.muted,fontSize:11}}>—</span>}
                    </div>
                  </td>
                  <td style={{padding:"6px 8px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:webSvcs.length>0?C.blue:C.muted}}>
                    {webSvcs.length>0?webSvcs.map(s=>s.port).join(", "):"—"}
                  </td>
                  <td style={{padding:"6px 8px",fontFamily:"JetBrains Mono, monospace",fontSize:12,
                    color:h.findings_count>0?"#F97316":C.muted}}>{h.findings_count}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Section>

      {/* ── CVE 전체 목록 ── */}
      <Section title="Candidate CVEs" count={allCVEs.length} accent="#F97316">
        {allCVEs.length===0
          ? <div style={{fontSize:12,color:C.muted,padding:"8px 0"}}>No CVE candidates found.</div>
          : (
          <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
            <thead>
              <tr style={{borderBottom:`1px solid ${C.slateMid}`}}>
                {["Severity","CVE","CVSS","Title","Host","Port","Fixed In"].map(h=>(
                  <th key={h} style={{textAlign:"left",padding:"4px 8px",fontSize:10,color:C.slate,fontWeight:600,letterSpacing:"0.08em"}}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {allCVEs.map((c,i)=>(
                <tr key={c.id||i} style={{borderBottom:`1px solid ${C.navy}`}}>
                  <td style={{padding:"5px 8px"}}><SeverityBadge level={c.severity}/></td>
                  <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.sky}}>{c.cve_id||"—"}</td>
                  <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:SEV[c.severity]||C.muted}}>{c.cvss>0?c.cvss:"—"}</td>
                  <td style={{padding:"5px 8px",color:C.ink,maxWidth:240,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{c.title}</td>
                  <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.muted}}>{c.host}</td>
                  <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.muted}}>{c.port}</td>
                  <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:"#22C55E"}}>{c.fixed_in||"—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      {/* ── HTTP 헤더/설정 이슈 ── */}
      <Section title="HTTP Findings" count={allHTTP.length} accent="#EAB308">
        {allHTTP.length===0
          ? <div style={{fontSize:12,color:C.muted,padding:"8px 0"}}>No HTTP findings.</div>
          : (
          <div style={{display:"flex",flexDirection:"column",gap:6}}>
            {allHTTP.map((f,i)=>(
              <div key={f.id||i} style={{display:"flex",alignItems:"flex-start",gap:10,padding:"8px 10px",
                background:C.navy,border:`1px solid ${C.slateMid}`,borderRadius:4}}>
                <div style={{flexShrink:0,marginTop:1}}><SeverityBadge level={f.severity}/></div>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:2,flexWrap:"wrap"}}>
                    <span style={{fontSize:12,color:C.ink,fontWeight:500}}>{f.title}</span>
                    {f.type&&<span style={{fontSize:10,padding:"1px 5px",borderRadius:2,background:"rgba(100,116,139,0.15)",color:C.muted,fontFamily:"JetBrains Mono, monospace"}}>{f.type}</span>}
                  </div>
                  {f.detail&&<div style={{fontSize:11,color:C.muted}}>{f.detail}</div>}
                </div>
                <div style={{flexShrink:0,textAlign:"right"}}>
                  <div style={{fontSize:10,fontFamily:"JetBrains Mono, monospace",color:C.blue}}>{f.host}</div>
                  <div style={{fontSize:10,fontFamily:"JetBrains Mono, monospace",color:C.muted}}>:{f.port}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* ── 주요 디렉토리/경로 ── */}
      <Section title="Interesting Paths" count={allDirs.length} accent="#22C55E">
        {allDirs.length===0
          ? <div style={{fontSize:12,color:C.muted,padding:"8px 0"}}>No interesting paths found.</div>
          : (
          <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
            <thead>
              <tr style={{borderBottom:`1px solid ${C.slateMid}`}}>
                {["Host","Port","Path","Status","Size","Redirect"].map(h=>(
                  <th key={h} style={{textAlign:"left",padding:"4px 8px",fontSize:10,color:C.slate,fontWeight:600,letterSpacing:"0.08em"}}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {allDirs.map((d,i)=>{
                const sc = d.status;
                const scColor = sc>=500?"#EF4444":sc>=400?"#F97316":sc>=300?"#EAB308":"#22C55E";
                return (
                  <tr key={d.id||i} style={{borderBottom:`1px solid ${C.navy}`}}>
                    <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.blue}}>{d.host}</td>
                    <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.muted}}>{d.port}</td>
                    <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",color:sc===200?C.sky:C.ink,maxWidth:200,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{d.path}</td>
                    <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",fontWeight:600,color:scColor}}>{sc}</td>
                    <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.muted}}>{d.size||"—"}</td>
                    <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.muted,maxWidth:160,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{d.redirect||"—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Section>

      {/* ── 열린 포트 전체 ── */}
      <Section title="All Open Ports" count={allPorts.length} accent={C.sky}>
        {allPorts.length===0
          ? <div style={{fontSize:12,color:C.muted,padding:"8px 0"}}>No open ports recorded.</div>
          : (
          <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
            <thead>
              <tr style={{borderBottom:`1px solid ${C.slateMid}`}}>
                {["Host","Port","Protocol","Service","Banner","Web"].map(h=>(
                  <th key={h} style={{textAlign:"left",padding:"4px 8px",fontSize:10,color:C.slate,fontWeight:600,letterSpacing:"0.08em"}}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {allPorts.map((p,i)=>(
                <tr key={p.id||i} style={{borderBottom:`1px solid ${C.navy}`}}>
                  <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.blue}}>{p.host}</td>
                  <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",fontWeight:700,color:p.is_web?C.sky:C.ink}}>{p.port}</td>
                  <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.muted}}>{p.protocol}</td>
                  <td style={{padding:"5px 8px",fontSize:11,color:C.ink}}>{p.service_name}</td>
                  <td style={{padding:"5px 8px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.muted,maxWidth:200,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{p.banner||"—"}</td>
                  <td style={{padding:"5px 8px"}}>
                    {p.is_web&&<span style={{fontSize:9,color:C.blue,border:`1px solid rgba(59,130,246,0.4)`,borderRadius:2,padding:"0 4px",fontFamily:"JetBrains Mono, monospace"}}>WEB</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

    </div>
  );
}

// ── Findings Layout ─────────────────────────────────────────────────────────────
function FindingsLayout({ run, allRuns, onBack, report, reportLoading }) {
  const [mainTab,      setMainTab]      = useState("overview");
  const [selectedHost, setSelectedHost] = useState(null);
  const [selectedPort, setSelectedPort] = useState(null);
  const [visMode,      setVisMode]      = useState("all");
  const [artifact,     setArtifact]     = useState(null);
  const [diffMode,     setDiffMode]     = useState(false);
  const [compareRunId, setCompareRunId] = useState(()=>{
    const others=allRuns.filter(r=>r.id!==run.id&&r.status==="completed");
    return others.length>0?others[0].id:"";
  });
  const [diffData, setDiffData] = useState(null);

  const hosts    = report?.hosts    || [];
  const services = report?.services || {};
  const findings = report?.findings || {};

  useEffect(()=>{
    if (!diffMode||!compareRunId){setDiffData(null);return;}
    fetch(`/api/dashboard/runs/${encodeURIComponent(run.id)}/diff?baseline=${encodeURIComponent(compareRunId)}`)
      .then(r=>r.json()).then(setDiffData).catch(()=>setDiffData(null));
  },[diffMode,compareRunId,run.id]);

  const handleSelectHost = h => { setSelectedHost(h); setSelectedPort(null); };

  // 탭 스타일 헬퍼
  const tabBtn = (id, label) => {
    const active = mainTab === id;
    return (
      <button key={id} onClick={()=>setMainTab(id)} style={{
        padding:"6px 16px", fontSize:12, background:"transparent",
        border:"none", borderBottom:`2px solid ${active?C.blue:"transparent"}`,
        color:active?C.sky:C.muted, cursor:"pointer", marginBottom:-1,
        fontWeight:active?600:400, transition:"color 0.12s",
      }}>{label}</button>
    );
  };

  return (
    <div style={{display:"flex",flexDirection:"column",height:"100%"}}>
      {/* ── Top bar ── */}
      <div style={{height:56,display:"flex",alignItems:"center",padding:"0 16px",borderBottom:`1px solid ${C.slateMid}`,gap:12,flexShrink:0}}>
        <Logo/>
        <button onClick={onBack} style={{padding:"4px 10px",fontSize:11,background:"transparent",border:`1px solid ${C.slateMid}`,color:C.muted,borderRadius:3,cursor:"pointer"}}>{"← Runs"}</button>
        <div style={{width:1,height:20,background:C.slateMid}}/>
        <span style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.blue,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:200}}>{run.id}</span>
        <span style={{fontSize:12,color:C.muted,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:140}}>{run.name}</span>
        <span style={{fontSize:11,fontFamily:"JetBrains Mono, monospace",color:C.slateMid,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:160}}>{run.target_display || run.target}</span>
        <div style={{flex:1}}/>
        <div style={{display:"flex",alignItems:"center",gap:8}}>
          {diffMode&&allRuns.filter(r=>r.id!==run.id&&r.status==="completed").length>0&&(
            <select value={compareRunId} onChange={e=>setCompareRunId(e.target.value)}
              style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,color:C.ink,borderRadius:3,padding:"4px 8px",fontSize:11,fontFamily:"JetBrains Mono, monospace",outline:"none"}}>
              {allRuns.filter(r=>r.id!==run.id&&r.status==="completed").map(r=>(
                <option key={r.id} value={r.id}>{r.id} {"—"} {r.name}</option>
              ))}
            </select>
          )}
          <button onClick={()=>setDiffMode(!diffMode)} style={{padding:"4px 12px",fontSize:11,borderRadius:3,cursor:"pointer",
            background:diffMode?C.blueDim:"transparent",
            border:`1px solid ${diffMode?C.blue:C.slateMid}`,
            color:diffMode?C.sky:C.muted,
            fontWeight:diffMode?600:400}}>{"⊕ Diff"}</button>
        </div>
      </div>

      {/* ── 메인 탭 바 ── */}
      <div style={{display:"flex",borderBottom:`1px solid ${C.slateMid}`,padding:"0 16px",flexShrink:0,background:C.navy}}>
        {tabBtn("overview","Overview")}
        {tabBtn("hosts","Hosts")}
      </div>

      {/* ── 콘텐츠 ── */}
      {reportLoading ? (
        <div style={{display:"flex",alignItems:"center",justifyContent:"center",flex:1,color:C.slate}}>Loading report…</div>
      ) : mainTab === "overview" ? (
        <RunOverview run={run} report={report}/>
      ) : (
        <div style={{display:"flex",flex:1,minHeight:0,overflow:"hidden"}}>
          <div style={{width:200,flexShrink:0,height:"100%",overflow:"hidden"}}>
            <HostNavigator hosts={hosts} selectedHost={selectedHost} onSelectHost={handleSelectHost} diffData={diffData} diffMode={diffMode} visMode={visMode} onVisMode={setVisMode}/>
          </div>
          <div style={{width:selectedHost?200:0,flexShrink:0,height:"100%",overflow:"hidden",transition:"width 0.18s ease"}}>
            <ServicePanel host={selectedHost} services={services} selectedPort={selectedPort} onSelectPort={p=>setSelectedPort(p)} diffData={diffData} diffMode={diffMode}/>
          </div>
          <div style={{flex:1,minWidth:0,height:"100%",overflow:"hidden"}}>
            <FindingsPanel host={selectedHost} port={selectedPort} services={services} findings={findings} diffData={diffData} diffMode={diffMode} onOpenArtifact={setArtifact}/>
          </div>
        </div>
      )}
      {artifact&&<ArtifactViewer artifact={artifact} onClose={()=>setArtifact(null)}/>}
    </div>
  );
}

// ── AppShell route utilities ───────────────────────────────────────────────────
function navigate(to) {
  window.history.pushState({}, "", to);
  window.dispatchEvent(new Event("vantage:navigate"));
}

const NEW_SCAN_PREFILL_STORAGE_KEY = "vantage:new-scan-prefill";

function openNewScanModal({ presetConfig, mode = "new" }) {
  try {
    const payload = { mode, prefill: presetConfig || null };
    window.sessionStorage.setItem(NEW_SCAN_PREFILL_STORAGE_KEY, JSON.stringify(payload));
  } catch {
    // ignore storage errors
  }
  navigate("/runs?newScan=1");
}

function summarizeDiffCounts(diffData) {
  const categories = objectOrEmpty(diffData?.categories);
  const entries = Object.values(categories);
  let added = 0;
  let removed = 0;
  entries.forEach(category=>{
    const c = objectOrEmpty(category);
    added += Number(c.added_count || arrayOrEmpty(c.added).length || 0);
    removed += Number(c.removed_count || arrayOrEmpty(c.removed).length || 0);
  });
  return { added, removed };
}

async function buildRerunPrefill(sourceRunId) {
  const cloned = await apiJson(`/api/runs/${encodeURIComponent(sourceRunId)}/clone-config`);
  const prefill = { source_run_id: sourceRunId, sourceRunId: sourceRunId, baseline_run_id: "", ...cloned };
  try {
    const runsPayload = await apiJson("/api/runs");
    const runs = arrayOrEmpty(runsPayload.runs);
    const sourceIdx = runs.findIndex(item=>String(item.run_id) === String(sourceRunId));
    if (sourceIdx >= 0) {
      const baseline = runs.slice(sourceIdx + 1).find(item=>String(item.status) === "completed");
      if (baseline?.run_id) {
        prefill.baseline_run_id = String(baseline.run_id);
        const diff = await apiJson(
          `/api/runs/${encodeURIComponent(sourceRunId)}/diff?baseline=${encodeURIComponent(String(baseline.run_id))}`,
        );
        const counts = summarizeDiffCounts(diff);
        prefill.source_change_summary = {
          baseline_run_id: String(baseline.run_id),
          added_total: counts.added,
          removed_total: counts.removed,
        };
      }
    }
  } catch {
    // best effort metadata only
  }
  return prefill;
}

function readRoute() {
  return {
    pathname: window.location.pathname,
    search: new URLSearchParams(window.location.search),
  };
}

function matchRoute(pathname) {
  const parts = pathname.split("/").filter(Boolean);
  const topPages = ["execution", "summary", "findings", "artifacts", "reports", "settings", "tools", "profiles", "wordlists"];
  if (pathname === "/runs" || pathname === "/runs/new") {
    return { page: "runs", runId: null };
  }
  if (parts.length === 1 && topPages.includes(parts[0])) {
    return { page: parts[0], runId: null };
  }
  if (parts.length === 3 && parts[0] === "runs" && topPages.includes(parts[2])) {
    return { page: parts[2], runId: decodeURIComponent(parts[1]) };
  }
  return { page: "runs", runId: null };
}

function useRoute() {
  const [route, setRoute] = useState(readRoute);
  useEffect(() => {
    const update = () => setRoute(readRoute());
    window.addEventListener("popstate", update);
    window.addEventListener("vantage:navigate", update);
    return () => {
      window.removeEventListener("popstate", update);
      window.removeEventListener("vantage:navigate", update);
    };
  }, []);
  return route;
}

async function apiJson(url, options = {}) {
  const response = await fetch(url, {
    headers: {"Content-Type":"application/json", ...(options.headers || {})},
    ...options,
  });
  const text = await response.text();
  let payload = {};
  if (text) {
    try { payload = JSON.parse(text); }
    catch { payload = {error: text}; }
  }
  if (!response.ok) {
    throw new Error(payload.error || `Request failed: ${response.status}`);
  }
  return payload;
}

async function apiText(url) {
  const response = await fetch(url);
  const text = await response.text();
  if (!response.ok) {
    throw new Error(text || `Request failed: ${response.status}`);
  }
  return text;
}

function AppShell({ active, runId, children, sidebarCollapsed, onToggleSidebar }) {
  const baseItems = [
    {key:"runs", label:"Runs", to:"/runs"},
    {key:"new", label:"New Scan", to:"/runs?newScan=1"},
    {key:"execution", label:"Execution", to:runId?`/runs/${encodeURIComponent(runId)}/execution`:"/execution"},
    {key:"summary", label:"Run Summary", to:runId?`/runs/${encodeURIComponent(runId)}/summary`:"/summary"},
    {key:"findings", label:"Findings", to:runId?`/runs/${encodeURIComponent(runId)}/findings`:"/findings"},
    {key:"artifacts", label:"Artifacts", to:runId?`/runs/${encodeURIComponent(runId)}/artifacts`:"/artifacts"},
    {key:"reports", label:"Reports", to:runId?`/runs/${encodeURIComponent(runId)}/reports`:"/reports"},
    {key:"settings", label:"Settings", to:runId?`/runs/${encodeURIComponent(runId)}/settings`:"/settings"},
  ];
  const navItem = item => {
    const selected = active === item.key;
    const disabled = !item.to;
    return (
      <button key={item.key} onClick={()=>item.to&&navigate(item.to)} disabled={disabled}
        title={sidebarCollapsed ? item.label : ""}
        style={{width:"100%",display:"flex",alignItems:"center",justifyContent:sidebarCollapsed?"center":"space-between",
          padding:sidebarCollapsed?"9px 6px":"9px 10px",border:`1px solid ${selected?C.blueBorder:"transparent"}`,
          borderRadius:5,background:selected?C.blueDim:"transparent",color:disabled?C.muted:(selected?C.sky:C.ink),
          fontSize:12,fontWeight:selected?700:500,cursor:disabled?"default":"pointer",textAlign:"left"}}>
        {sidebarCollapsed ? (
          <span style={{fontFamily:"JetBrains Mono, monospace"}}>{String(item.label || "?").slice(0,1)}</span>
        ) : (
          <>
            <span>{item.label}</span>
            {selected&&<span style={{width:5,height:5,borderRadius:"50%",background:C.blue}}/>}
          </>
        )}
      </button>
    );
  };
  return (
    <div data-app-shell="vantage" style={{display:"flex",width:"100%",height:"100%",background:C.navy}}>
      <aside data-sidebar-collapsed={sidebarCollapsed ? "yes" : "no"} style={{width:sidebarCollapsed ? 60 : 240,flexShrink:0,borderRight:`1px solid ${C.slateMid}`,background:"#0B1220",
        display:"flex",flexDirection:"column",padding:sidebarCollapsed ? "12px 8px" : 18,gap:12,transition:"width 180ms ease"}}>
        <div style={{display:"flex",alignItems:"center",justifyContent:sidebarCollapsed ? "center" : "space-between",gap:8}}>
          {!sidebarCollapsed && <Logo/>}
          <button
            type="button"
            onClick={onToggleSidebar}
            style={{...actionButtonStyle,padding:"6px 8px",fontSize:11,minWidth:sidebarCollapsed?36:64}}
            title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            data-sidebar-toggle="vantage"
          >
            {sidebarCollapsed ? ">>" : "<<"}
          </button>
        </div>
        <div style={{display:"grid",gap:6}}>{baseItems.map(navItem)}</div>
      </aside>
      <main style={{flex:1,minWidth:0,height:"100%",overflow:"hidden"}}>{children}</main>
    </div>
  );
}

function RunStatusPill({ run }) {
  const status = run.execution?.active ? "running" : (run.status || "pending");
  const color = STATUS_COLOR[status] || C.slate;
  return (
    <span style={{fontSize:11,color,display:"inline-flex",alignItems:"center",gap:6,textTransform:"capitalize"}}>
      <span style={{width:6,height:6,borderRadius:"50%",background:color,display:"inline-block"}}/>
      {status}
    </span>
  );
}

function runProgressLabel(run) {
  const progress = run.progress || {};
  if (progress.completion_percent !== undefined && progress.completion_percent !== null) {
    return `${Math.round(progress.completion_percent)}%`;
  }
  const counts = run.task_counts || {};
  const total = counts.total || 0;
  if (!total) return "—";
  return `${counts.completed || 0}/${total}`;
}

function runDuration(run) {
  if (!run.started_at) return "—";
  const end = run.completed_at ? new Date(run.completed_at) : new Date();
  const seconds = Math.max(0, Math.round((end - new Date(run.started_at)) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}

function RunsDashboard({ initialNewScanOpen }) {
  const toast = useToast();
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [modalOpen, setModalOpen] = useState(Boolean(initialNewScanOpen));
  const [rerunPrefill, setRerunPrefill] = useState(null);
  const [rerunSourceRunId, setRerunSourceRunId] = useState(null);
  const [modalMode, setModalMode] = useState("new");
  const [editConfigRunId, setEditConfigRunId] = useState("");
  const [editConfigRunStatus, setEditConfigRunStatus] = useState("");
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [deleteBusy, setDeleteBusy] = useState(false);

  const loadRuns = () => {
    setError("");
    return apiJson("/api/runs")
      .then(data=>setRuns(data.runs || []))
      .catch(err=>setError(err.message))
      .finally(()=>setLoading(false));
  };

  useEffect(()=>{ loadRuns(); const timer = setInterval(loadRuns, 5000); return ()=>clearInterval(timer); },[]);
  useEffect(()=>{ if (initialNewScanOpen) setModalOpen(true); },[initialNewScanOpen]);
  useEffect(()=>{
    if (!initialNewScanOpen) return;
    try {
      const raw = window.sessionStorage.getItem(NEW_SCAN_PREFILL_STORAGE_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw);
      const prefill = parsed?.prefill;
      if (prefill && typeof prefill === "object") {
        const sourceId = String(prefill.source_run_id || prefill.sourceRunId || "");
        setRerunSourceRunId(sourceId || null);
        setRerunPrefill(prefill);
      }
    } catch {
      // ignore parse error
    } finally {
      window.sessionStorage.removeItem(NEW_SCAN_PREFILL_STORAGE_KEY);
    }
  }, [initialNewScanOpen]);

  const filteredRuns = runs.filter(run => {
    const status = run.execution?.active ? "running" : (run.status || "pending");
    const haystack = `${run.run_id} ${run.target} ${run.target_display || ""} ${run.profile} ${run.status}`.toLowerCase();
    return (filter === "all" || status === filter) && haystack.includes(query.toLowerCase());
  });

  const cancelRun = run => {
    apiJson(`/api/runs/${encodeURIComponent(run.run_id)}/cancel`, {method:"POST", body:JSON.stringify({})})
      .then(()=>{
        toast.push({type:"warning", title:"Scan cancelled"});
        return loadRuns();
      })
      .catch(err=>setError(err.message));
  };

  const runDelete = async run => {
    if (!run?.run_id) return;
    setDeleteBusy(true);
    setError("");
    try {
      await apiJson(`/api/runs/${encodeURIComponent(run.run_id)}`, { method: "DELETE" });
      setDeleteTarget(null);
      toast.push({ type: "success", title: "Run deleted", description: String(run.run_id) });
      await loadRuns();
    } catch (err) {
      setError(err.message || "Delete failed");
      toast.push({ type: "error", title: "Delete failed", description: String(err.message || "") });
    } finally {
      setDeleteBusy(false);
    }
  };

  const rerunNowFromRun = async run => {
    setError("");
    try {
      const cloned = await apiJson(`/api/runs/${encodeURIComponent(run.run_id)}/clone-config`);
      const payload = {
        ...cloned,
        target: String(cloned.target || run.target || "").trim(),
        source_run_id: run.run_id,
        include_notes_context: true,
        auto_start: false,
      };
      const created = await apiJson("/api/runs", {method:"POST", body:JSON.stringify(payload)});
      const newRunId = created.run?.run_id || created.run_id;
      await apiJson(`/api/runs/${encodeURIComponent(newRunId)}/execute`, {method:"POST", body:JSON.stringify({})});
      toast.push({
        type: "success",
        title: "Re-run started",
        description: String(payload.target || newRunId),
        actionLabel: "View execution",
        onAction: () => navigate(`/runs/${encodeURIComponent(newRunId)}/execution`),
      });
      await loadRuns();
      navigate(`/runs/${encodeURIComponent(newRunId)}/execution`);
    } catch (err) {
      setError(err.message || "Failed to start re-run");
      toast.push({ type: "error", title: "Re-run failed", description: String(err.message || "Unable to re-run now") });
    }
  };

  const openRerunFromRun = async run => {
    setError("");
    try {
      const prefill = await buildRerunPrefill(String(run.run_id));
      setModalMode("rerun");
      setRerunSourceRunId(run.run_id);
      setEditConfigRunId("");
      setEditConfigRunStatus("");
      setRerunPrefill(prefill);
      setModalOpen(true);
      openNewScanModal({ presetConfig: prefill, mode: "rerun" });
      toast.push({
        type: "info",
        title: "Scan options loaded",
        description: "Review options before starting",
        priority: "low",
      });
    } catch (err) {
      setError(err.message || "Failed to load scan for edit & re-run");
      toast.push({ type: "error", title: "Edit & Re-run failed", description: String(err.message || "Unable to clone configuration") });
    }
  };

  const openEditConfigFromRun = async run => {
    setError("");
    try {
      const prefill = await apiJson(`/api/runs/${encodeURIComponent(run.run_id)}/clone-config`);
      setModalMode("edit-config");
      setRerunSourceRunId(null);
      setEditConfigRunId(String(run.run_id));
      setEditConfigRunStatus(String(run.execution?.active ? "running" : (run.status || "pending")));
      setRerunPrefill(prefill);
      setModalOpen(true);
      openNewScanModal({ presetConfig: prefill, mode: "edit-config" });
      toast.push({ type: "info", title: "Editing pending/running scan config", priority: "low" });
    } catch (err) {
      setError(err.message || "Failed to load config");
      toast.push({ type: "error", title: "Edit Config failed", description: String(err.message || "") });
    }
  };

  return (
    <div data-runs-dashboard="vantage" style={{height:"100%",display:"flex",flexDirection:"column",overflow:"hidden"}}>
      <div style={{height:66,display:"flex",alignItems:"center",gap:12,padding:"0 24px",borderBottom:`1px solid ${C.slateMid}`,flexShrink:0}}>
        <div>
          <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:18,letterSpacing:"0.08em",color:C.inkBright}}>Runs</div>
          <div style={{fontSize:11,color:C.slate}}>Scan run inventory and launch control</div>
        </div>
        <div style={{flex:1}}/>
        <input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search runs, targets, profiles"
          style={{width:280,background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:5,padding:"8px 10px",fontSize:12}}/>
        <button onClick={()=>{
          setModalMode("new");
          setRerunPrefill(null);
          setRerunSourceRunId(null);
          setEditConfigRunId("");
          setEditConfigRunStatus("");
          setModalOpen(true);
          navigate("/runs?newScan=1");
        }}
          style={{padding:"8px 14px",borderRadius:5,border:`1px solid ${C.blueBorder}`,background:C.blueDim,color:C.sky,fontWeight:700,cursor:"pointer"}}>
          + New Scan
        </button>
      </div>
      <div style={{padding:"14px 24px 0",display:"flex",gap:8,flexShrink:0}}>
        {["all","running","completed","failed","cancelled"].map(name=>(
          <button key={name} onClick={()=>setFilter(name)} style={{padding:"6px 10px",borderRadius:4,
            border:`1px solid ${filter===name?C.blueBorder:C.slateMid}`,background:filter===name?C.blueDim:C.slateDark,
            color:filter===name?C.sky:C.slate,textTransform:"capitalize",fontSize:11,cursor:"pointer"}}>
            {name}
          </button>
        ))}
      </div>
      <div style={{flex:1,overflow:"auto",padding:24}}>
        {error&&<div style={{marginBottom:12}}><ErrorState msg={error}/></div>}
        <div style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:7,overflow:"hidden"}}>
          <table style={{width:"100%",borderCollapse:"collapse"}}>
            <thead>
              <tr style={{borderBottom:`1px solid ${C.slateMid}`,background:"#111827"}}>
                {["Run ID","Target","Profile","Status","Progress","Hosts","Findings","Duration","Date","Actions"].map(h=>(
                  <th key={h} style={{textAlign:"left",padding:"10px 12px",fontSize:10,color:C.slate,letterSpacing:"0.08em",textTransform:"uppercase"}}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan="10" style={{padding:0}}><LoadingState msg="Loading runs..."/></td></tr>
              ) : filteredRuns.length === 0 ? (
                <tr><td colSpan="10" style={{padding:0}}><EmptyState msg="No runs match the current view."/></td></tr>
              ) : filteredRuns.map((run,i)=>(
                <tr key={run.run_id} style={{borderBottom:i<filteredRuns.length-1?`1px solid ${C.navy}`:"none"}}>
                  <td style={{padding:"10px 12px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.muted}}>{run.run_id}</td>
                  <td style={{padding:"10px 12px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.ink}}>{run.target_display || run.target}</td>
                  <td style={{padding:"10px 12px",fontSize:12,color:C.ink}}>{run.profile || "safe"}</td>
                  <td style={{padding:"10px 12px"}}><RunStatusPill run={run}/></td>
                  <td style={{padding:"10px 12px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.sky}}>{runProgressLabel(run)}</td>
                  <td style={{padding:"10px 12px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>—</td>
                  <td style={{padding:"10px 12px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>—</td>
                  <td style={{padding:"10px 12px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>{runDuration(run)}</td>
                  <td style={{padding:"10px 12px",fontSize:11,color:C.slate}}>{(run.created_at || "").slice(0,10)}</td>
                  <td style={{padding:"10px 12px"}}>
                    <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                      <button onClick={()=>navigate(`/runs/${encodeURIComponent(run.run_id)}/summary`)} style={actionButtonStyle}>Summary</button>
                      <button onClick={()=>navigate(`/runs/${encodeURIComponent(run.run_id)}/execution`)} style={actionButtonStyle}>Execution</button>
                      <button onClick={()=>navigate(`/runs/${encodeURIComponent(run.run_id)}/findings`)} style={actionButtonStyle}>Findings</button>
                      <button onClick={()=>rerunNowFromRun(run)} style={actionButtonStyle}>Re-run</button>
                      <button onClick={()=>openRerunFromRun(run)} style={actionButtonStyle}>Edit & Re-run</button>
                      {(run.status === "pending" || run.execution?.active || run.status === "running") && (
                        <button onClick={()=>openEditConfigFromRun(run)} style={actionButtonStyle}>Edit Config</button>
                      )}
                      {run.execution?.active && !run.execution?.cancel_requested && (
                        <button onClick={()=>cancelRun(run)} style={{...actionButtonStyle,color:"#FCA5A5",borderColor:"rgba(239,68,68,0.4)"}}>Cancel</button>
                      )}
                      <button
                        type="button"
                        onClick={()=>setDeleteTarget(run)}
                        disabled={run.execution?.active}
                        style={{...actionButtonStyle,color:run.execution?.active ? C.slate : "#FCA5A5",borderColor:run.execution?.active ? C.slateMid : "rgba(239,68,68,0.4)",opacity:run.execution?.active?0.5:1}}
                        title={run.execution?.active ? "Cancel the run before deleting" : "Delete this run"}
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {deleteTarget && (
        <div data-delete-run-confirm="vantage" style={{position:"fixed",inset:0,background:"rgba(2,6,23,0.78)",zIndex:60,display:"flex",alignItems:"center",justifyContent:"center",padding:24}}>
          <div style={{width:400,maxWidth:"100%",background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:8,padding:18}}>
            <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:15,color:C.inkBright}}>Delete run?</div>
            <div style={{marginTop:10,fontSize:12,color:C.ink,fontFamily:"JetBrains Mono, monospace"}}>{deleteTarget.run_id}</div>
            <div style={{marginTop:6,fontSize:11,color:C.slate}}>{deleteTarget.target}</div>
            <div style={{marginTop:14,fontSize:12,color:"#FCA5A5"}}>This cannot be undone. The run directory and state will be removed.</div>
            <div style={{marginTop:16,display:"flex",gap:10,justifyContent:"flex-end"}}>
              <button type="button" onClick={()=>!deleteBusy && setDeleteTarget(null)} disabled={deleteBusy} style={actionButtonStyle}>Cancel</button>
              <button
                type="button"
                onClick={()=>runDelete(deleteTarget)}
                disabled={deleteBusy}
                style={{padding:"7px 12px",border:"1px solid rgba(239,68,68,0.5)",borderRadius:5,background:"rgba(239,68,68,0.12)",color:"#FCA5A5",fontWeight:700,cursor:deleteBusy?"default":"pointer"}}
              >
                {deleteBusy ? "…" : "Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
      <NewScanModal
        open={modalOpen}
        rerunPrefill={rerunPrefill}
        rerunSourceRunId={rerunSourceRunId}
        modalMode={modalMode}
        editRunId={editConfigRunId}
        editRunStatus={editConfigRunStatus}
        onConsumeRerunPrefill={()=>setRerunPrefill(null)}
        onClose={()=>{
          setModalOpen(false);
          setRerunPrefill(null);
          setRerunSourceRunId(null);
          setEditConfigRunId("");
          setEditConfigRunStatus("");
          setModalMode("new");
          navigate("/runs");
        }}
        onUpdated={(runId, runStatus)=>{
          setModalOpen(false);
          setRerunPrefill(null);
          setRerunSourceRunId(null);
          setEditConfigRunId("");
          setEditConfigRunStatus("");
          setModalMode("new");
          loadRuns();
          toast.push({ type: "success", title: "Config updated", description: `${runId} (${runStatus})` });
        }}
        onCreated={(runId, started, createdTarget, meta)=>{
          setModalOpen(false);
          setModalMode("new");
          loadRuns();
          toast.push({
            type: "success",
            title: "Scan created",
            description: createdTarget || runId,
            actionLabel: "Go to execution",
            onAction: () => navigate(`/runs/${encodeURIComponent(runId)}/execution`),
          });
          const createdIds = arrayOrEmpty(meta?.createdRunIds);
          if (createdIds.length > 1) {
            toast.push({
              type: "info",
              title: `${createdIds.length} runs created`,
              description: `Bulk target mode completed (${createdIds.slice(0, 3).join(", ")}${createdIds.length > 3 ? ", ..." : ""})`,
              priority: "low",
              actionLabel: "Open runs",
              onAction: () => navigate("/runs"),
            });
          }
          if (started) {
            toast.push({ type: "info", title: "Scan started" });
          }
          navigate(`/runs/${encodeURIComponent(runId)}/${started?"execution":"summary"}`);
        }}
      />
    </div>
  );
}

const actionButtonStyle = {
  padding:"4px 7px",
  border:`1px solid ${C.slateMid}`,
  borderRadius:4,
  background:"transparent",
  color:C.sky,
  fontSize:10,
  cursor:"pointer",
};

const inputStyle = {
  width:"100%",
  background:"#0B1220",
  border:`1px solid ${C.slateMid}`,
  borderRadius:5,
  padding:"8px 9px",
  color:C.ink,
  fontSize:12,
};

function Field({ label, hint, children }) {
  return (
    <label style={{display:"grid",gap:5,fontSize:11,color:C.slate}}>
      <span>{label}</span>
      {children}
      {hint ? <span style={{fontWeight:400,fontSize:10,lineHeight:1.45,color:C.muted,whiteSpace:"pre-wrap"}}>{hint}</span> : null}
    </label>
  );
}

const SPEED_LEVELS = [
  "T1-","T1","T1+",
  "T2-","T2","T2+",
  "T3-","T3","T3+",
  "T4-","T4","T4+",
  "T5-","T5","T5+",
];

const SPEED_CONFIGS = {
  "T1-": { nmap_timing: "T1", httpx: { concurrency: 5, rate: 10 }, ffuf: { threads: 5, rate: 10 } },
  "T1":  { nmap_timing: "T1", httpx: { concurrency: 8, rate: 20 }, ffuf: { threads: 8, rate: 20 } },
  "T1+": { nmap_timing: "T1", httpx: { concurrency: 10, rate: 30 }, ffuf: { threads: 10, rate: 30 } },
  "T2-": { nmap_timing: "T2", httpx: { concurrency: 10, rate: 40 }, ffuf: { threads: 10, rate: 40 } },
  "T2":  { nmap_timing: "T2", httpx: { concurrency: 15, rate: 60 }, ffuf: { threads: 15, rate: 60 } },
  "T2+": { nmap_timing: "T2", httpx: { concurrency: 20, rate: 80 }, ffuf: { threads: 20, rate: 80 } },
  "T3-": { nmap_timing: "T3", httpx: { concurrency: 20, rate: 100 }, ffuf: { threads: 20, rate: 100 } },
  "T3":  { nmap_timing: "T3", httpx: { concurrency: 30, rate: 150 }, ffuf: { threads: 30, rate: 150 } },
  "T3+": { nmap_timing: "T3", httpx: { concurrency: 40, rate: 200 }, ffuf: { threads: 40, rate: 200 } },
  "T4-": { nmap_timing: "T4", httpx: { concurrency: 50, rate: 250 }, ffuf: { threads: 50, rate: 250 } },
  "T4":  { nmap_timing: "T4", httpx: { concurrency: 75, rate: 400 }, ffuf: { threads: 75, rate: 400 } },
  "T4+": { nmap_timing: "T4", httpx: { concurrency: 100, rate: 600 }, ffuf: { threads: 100, rate: 600 } },
  "T5-": { nmap_timing: "T5", httpx: { concurrency: 120, rate: 800 }, ffuf: { threads: 120, rate: 800 } },
  "T5":  { nmap_timing: "T5", httpx: { concurrency: 150, rate: 1000 }, ffuf: { threads: 150, rate: 1000 } },
  "T5+": { nmap_timing: "T5", httpx: { concurrency: 200, rate: 1500 }, ffuf: { threads: 200, rate: 1500 } },
};

const HIGH_SPEED_LEVELS = new Set(["T5-","T5","T5+"]);

const SCAN_MODES = [
  { id: "fast", label: "FAST", hint: "Top 1000 ports, faster Nmap, no directory scan (ffuf off)." },
  { id: "balanced", label: "BALANCED", hint: "Default project settings; good for most targets." },
  { id: "deep", label: "DEEP", hint: "Full port range, slower timing, version detection, recursion on." },
];

const NMAP_PORT_QUICK = [
  { value: "well-known", label: "IANA well-known (1-1023)" },
  { value: "top1000", label: "Top 1000 (nmap --top-ports 1000)" },
  { value: "1-65535", label: "전체 TCP (1-65535)" },
];

function formatScanModeLabel(modeRaw) {
  const m = String(modeRaw || "balanced").toLowerCase();
  if (m === "fast") return "FAST";
  if (m === "deep") return "DEEP";
  return "BALANCED";
}

function speedIndexForNmapTiming(t, fallbackIndex) {
  const want = String(t || "T3").toUpperCase();
  const i = SPEED_LEVELS.findIndex(l => (SPEED_CONFIGS[l] || {}).nmap_timing === want);
  return i >= 0 ? i : fallbackIndex;
}

function cidrPrefixFromTarget(targetRaw) {
  const target = String(targetRaw || "").trim();
  const match = target.match(/\/(\d{1,2})$/);
  if (!match) return null;
  const prefix = Number(match[1]);
  if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) return null;
  return prefix;
}

function recommendedCidrChunkSize(targetRaw) {
  const prefix = cidrPrefixFromTarget(targetRaw);
  if (prefix === null) return null;
  if (prefix <= 24) return 16;
  if (prefix <= 26) return 8;
  if (prefix <= 28) return 4;
  return 2;
}

function proxyValidationStatus(modeRaw, urlRaw) {
  const mode = String(modeRaw || "none").toLowerCase();
  const url = String(urlRaw || "").trim();
  if (mode === "none") return { level: "info", label: "Proxy disabled" };
  if (!url) return { level: "error", label: "Proxy URL required" };
  if (mode === "socks" && !url.toLowerCase().startsWith("socks5://")) {
    return { level: "error", label: "SOCKS requires socks5:// prefix" };
  }
  if (mode === "http" && !/^https?:\/\//i.test(url)) {
    return { level: "warn", label: "HTTP proxy should start with http:// or https://" };
  }
  return { level: "ok", label: "Proxy URL looks valid" };
}

function scanModeDeltaLines(scanMode) {
  const mode = String(scanMode || "balanced").toLowerCase();
  if (mode === "fast") {
    return [
      "Mode Δ FAST: nmap ports => top1000",
      "Mode Δ FAST: nmap timing => T4",
      "Mode Δ FAST: nmap version detection => off",
      "Mode Δ FAST: cidr chunk => 16",
      "Mode Δ FAST: dir recursion => off/depth 1",
    ];
  }
  if (mode === "deep") {
    return [
      "Mode Δ DEEP: nmap ports => 1-65535",
      "Mode Δ DEEP: nmap timing => T2",
      "Mode Δ DEEP: nmap version detection => on",
      "Mode Δ DEEP: cidr chunk => 64",
      "Mode Δ DEEP: dir recursion => on/depth 3",
    ];
  }
  return ["Mode Δ BALANCED: keep current values (minimal override)"];
}

function profileDeltaLines(profile) {
  const p = String(profile || "safe").toLowerCase();
  if (p === "safe") {
    return [
      "Profile Δ SAFE: httpx threads <= 10, default rate 25",
      "Profile Δ SAFE: ffuf threads <= 10",
      "Profile Δ SAFE: nmap timing cap T2",
    ];
  }
  if (p === "fast") {
    return [
      "Profile Δ FAST: keep configured threads/rate",
      "Profile Δ FAST: nmap uses selected timing directly",
    ];
  }
  return [
    "Profile Δ BALANCED: httpx threads <= 25, default rate 75",
    "Profile Δ BALANCED: ffuf threads <= 25",
    "Profile Δ BALANCED: nmap timing cap T3",
  ];
}

function NewScanModal({ open, onClose, onCreated, onUpdated, rerunPrefill, rerunSourceRunId, onConsumeRerunPrefill, modalMode = "new", editRunId = "", editRunStatus = "" }) {
  const MODULES = ["port_scan","http_probe","domain_discovery","dir_enum","banner_probe","subdomain_enum"];
  const defaultSpeedIndex = SPEED_LEVELS.indexOf("T3");
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState("safe");
  const [preset, setPreset] = useState("");
  const [scanMode, setScanMode] = useState("balanced");
  const [modules, setModules] = useState(["http_probe"]);
  const [presets, setPresets] = useState([]);
  const [wordlistEntries, setWordlistEntries] = useState([]);
  const [wordlistBundle, setWordlistBundle] = useState([]);
  const [wordlistPresets, setWordlistPresets] = useState([]);
  const [wlComboFocus, setWlComboFocus] = useState(false);
  const [wlComboQuery, setWlComboQuery] = useState("");
  const [defaultExtraHeadersText, setDefaultExtraHeadersText] = useState("");
  const [ffufExtCatalog, setFfufExtCatalog] = useState([]);
  const [ffufExtCustom, setFfufExtCustom] = useState("");
  const [extHintSvc, setExtHintSvc] = useState("");
  const [extHintTech, setExtHintTech] = useState("");
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [speedIndex, setSpeedIndex] = useState(defaultSpeedIndex);
  const [includeNotesContext, setIncludeNotesContext] = useState(true);
  const [autoRecommendationEnabled, setAutoRecommendationEnabled] = useState(true);
  const [form, setForm] = useState({
    ffuf_wordlist_path:"",
    ffuf_concurrency: 40,
    ffuf_parallel_enabled: true,
    ffuf_max_parallel_tasks: 3,
    proxy_mode: "none",
    proxy_url: "",
    ffuf_replay_proxy: "",
    ffuf_extensions: [],
    nmap_ports:"",
    nmap_timing_template: "T3",
    nmap_version_detection: true,
    extra_headers_text:"",
    cookies:"",
    bearer_token:"",
    host_header:"",
    scope_include:"",
    scope_exclude:"",
    dir_recursive_enabled:false,
    dir_recursive_max_depth:1,
    dir_recursive_max_paths_per_host:100,
    dir_recursive_same_host_only:true,
    cidr_split_enabled:true,
    cidr_split_max_hosts_per_chunk:32,
    cidr_split_target_interval_minutes:10,
    masscan_enabled:true,
    masscan_rate:10000,
    masscan_retries:2,
    naabu_enabled:true,
    naabu_rate:5000,
    naabu_retries:3,
    naabu_scan_type:"syn",
    subdomain_bruteforce_enabled:true,
    udp_scan_enabled:false,
    udp_scan_ports:"53,67,68,69,123,137,138,161,500,514,520,623,1434,1900,4500,5353,11211",
    js_render_enabled:false,
    js_render_timeout_seconds:15,
    js_render_max_hosts:50,
    spa_crawl_enabled:false,
    spa_crawl_max_depth:2,
    spa_crawl_max_pages:50,
    spa_crawl_same_origin_only:true,
    auth_login_enabled:false,
    auth_login_url:"",
    auth_username:"",
    auth_password:"",
    auth_username_field_hints:"username,email,user,login,userid,id",
    auth_password_field_hints:"password,passwd,pwd,pass",
    auth_login_success_keyword:"",
  });

  const applyWebScanMode = next => {
    const m = String(next || "balanced").toLowerCase();
    setScanMode(m);
    if (m === "balanced") {
      return;
    }
    if (m === "fast") {
      setForm(f => ({
        ...f,
        nmap_ports: "top1000",
        nmap_timing_template: "T4",
        nmap_version_detection: false,
        cidr_split_max_hosts_per_chunk: 16,
        dir_recursive_enabled: false,
        dir_recursive_max_depth: 1,
      }));
      setModules(cur => cur.filter(x => x !== "dir_enum"));
      setSpeedIndex(speedIndexForNmapTiming("T4", defaultSpeedIndex));
      return;
    }
    if (m === "deep") {
      setForm(f => ({
        ...f,
        nmap_ports: "1-65535",
        nmap_timing_template: "T2",
        nmap_version_detection: true,
        cidr_split_max_hosts_per_chunk: 64,
        dir_recursive_enabled: true,
        dir_recursive_max_depth: 3,
      }));
      setModules(cur => (cur.includes("dir_enum") ? cur : [...cur, "dir_enum"]));
      setSpeedIndex(speedIndexForNmapTiming("T2", defaultSpeedIndex));
    }
  };

  useEffect(()=>{
    if (!open || !rerunPrefill) return;
    const c = rerunPrefill;
    setTarget(String(c.target || ""));
    setProfile(String(c.profile || "safe"));
    setPreset("");
    setScanMode(String(c.scan_mode || "balanced").toLowerCase());
    setModules(Array.isArray(c.modules) && c.modules.length ? c.modules.slice() : ["http_probe"]);
    setForm(cur=>({
      ...cur,
      ffuf_wordlist_path: String(c.ffuf_wordlist_path || ""),
      ffuf_concurrency: Number(c.ffuf_concurrency) > 0 ? Number(c.ffuf_concurrency) : 40,
      ffuf_parallel_enabled: c.ffuf_parallel_enabled !== false,
      ffuf_max_parallel_tasks: Math.max(1, Math.min(64, Number(c.ffuf_max_parallel_tasks) || 3)),
      proxy_mode: String(c.proxy_mode || "none"),
      proxy_url: String(c.proxy_url || ""),
      ffuf_replay_proxy: String(c.ffuf_replay_proxy || ""),
      nmap_ports: String(c.nmap_ports || ""),
      nmap_timing_template: String(c.nmap_timing_template || "T3"),
      nmap_version_detection: c.nmap_version_detection !== false,
      extra_headers_text: String(c.extra_headers_text || ""),
      cookies: String(c.cookies || ""),
      bearer_token: String(c.bearer_token || ""),
      host_header: String(c.host_header || ""),
      scope_include: String(c.scope_include || ""),
      scope_exclude: String(c.scope_exclude || ""),
      dir_recursive_enabled: !!c.dir_recursive_enabled,
      dir_recursive_max_depth: Number(c.dir_recursive_max_depth || 1),
      dir_recursive_max_paths_per_host: Number(c.dir_recursive_max_paths_per_host || 100),
      dir_recursive_same_host_only: c.dir_recursive_same_host_only !== false,
      cidr_split_enabled: c.cidr_split_enabled !== false,
      cidr_split_max_hosts_per_chunk: Number(c.cidr_split_max_hosts_per_chunk || 32),
      cidr_split_target_interval_minutes: Number(c.cidr_split_target_interval_minutes || 10),
      ffuf_extensions: Array.isArray(c.ffuf_extensions) ? c.ffuf_extensions.map(String) : [],
      masscan_enabled: c.masscan_enabled !== false,
      masscan_rate: Math.max(100, Number(c.masscan_rate || 10000)),
      masscan_retries: Math.max(0, Number(c.masscan_retries ?? 2)),
      naabu_enabled: c.naabu_enabled !== false,
      naabu_rate: Math.max(100, Number(c.naabu_rate || 5000)),
      naabu_retries: Math.max(0, Number(c.naabu_retries ?? 3)),
      naabu_scan_type: (c.naabu_scan_type === "connect" ? "connect" : "syn"),
      subdomain_bruteforce_enabled: c.subdomain_bruteforce_enabled !== false,
      udp_scan_enabled: c.udp_scan_enabled === true,
      udp_scan_ports: String(c.udp_scan_ports || "53,67,68,69,123,137,138,161,500,514,520,623,1434,1900,4500,5353,11211"),
      js_render_enabled: c.js_render_enabled === true,
      js_render_timeout_seconds: Math.max(3, Number(c.js_render_timeout_seconds || 15)),
      js_render_max_hosts: Math.max(1, Number(c.js_render_max_hosts || 50)),
      spa_crawl_enabled: c.spa_crawl_enabled === true,
      spa_crawl_max_depth: Math.max(0, Number(c.spa_crawl_max_depth || 2)),
      spa_crawl_max_pages: Math.max(1, Number(c.spa_crawl_max_pages || 50)),
      spa_crawl_same_origin_only: c.spa_crawl_same_origin_only !== false,
      auth_login_enabled: c.auth_login_enabled === true,
      auth_login_url: String(c.auth_login_url || ""),
      auth_username: String(c.auth_username || ""),
      auth_password: String(c.auth_password || ""),
      auth_username_field_hints: String(c.auth_username_field_hints || "username,email,user,login,userid,id"),
      auth_password_field_hints: String(c.auth_password_field_hints || "password,passwd,pwd,pass"),
      auth_login_success_keyword: String(c.auth_login_success_keyword || ""),
    }));
    setAdvancedOpen(true);
    setSpeedIndex(speedIndexForNmapTiming(c.nmap_timing_template, defaultSpeedIndex));
    setIncludeNotesContext(c.include_notes_context !== false);
    setAutoRecommendationEnabled(c.auto_recommendation_enabled !== false);
    if (typeof onConsumeRerunPrefill === "function") onConsumeRerunPrefill();
  }, [open, rerunPrefill, onConsumeRerunPrefill, defaultSpeedIndex]);

  useEffect(()=>{
    if (!open) return;
    setError("");
    Promise.all([apiJson("/api/presets"), apiJson("/api/wordlists"), apiJson("/api/ffuf-extension-catalog")])
      .then(([presetPayload, wordlistPayload, extCat])=>{
        const presetRows = Object.entries(presetPayload.presets || {}).map(([key,value])=>({key, ...value}));
        setPresets(presetRows);
        const entries = arrayOrEmpty(wordlistPayload.wordlist_entries);
        setWordlistEntries(entries.length ? entries : (wordlistPayload.wordlists || []).map(p=>({path:p,label:p})));
        setWordlistBundle(arrayOrEmpty(wordlistPayload.wordlist_bundle));
        setWordlistPresets(arrayOrEmpty(wordlistPayload.recommended_presets));
        setDefaultExtraHeadersText(String(wordlistPayload.default_extra_headers_text || ""));
        setFfufExtCatalog(arrayOrEmpty(extCat.catalog));
      })
      .catch(err=>setError(err.message));
  }, [open]);

  useEffect(()=>{
    if (!open) return;
    const h = e => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  },[open,onClose]);

  useEffect(()=>{
    if (!open) {
      setWlComboFocus(false);
      setWlComboQuery("");
    }
  }, [open]);

  const isEditConfigMode = modalMode === "edit-config" && !!String(editRunId || "").trim();
  const isRunningEdit = isEditConfigMode && String(editRunStatus || "").toLowerCase() === "running";
  const isPendingEdit = isEditConfigMode && String(editRunStatus || "").toLowerCase() === "pending";
  const sourceRunLabel = String(rerunSourceRunId || rerunPrefill?.source_run_id || rerunPrefill?.sourceRunId || "").trim();
  const sourceRunCreatedAt = rerunPrefill?.source_created_at || rerunPrefill?.created_at || null;
  const baselineRunId = String(rerunPrefill?.baseline_run_id || rerunPrefill?.source_change_summary?.baseline_run_id || "").trim();
  const sourceNoteCount = Number(rerunPrefill?.source_note_count || 0);
  const sourceChangeSummary = objectOrEmpty(rerunPrefill?.source_change_summary);
  const changeAdded = Number(sourceChangeSummary.added_total || 0);
  const changeRemoved = Number(sourceChangeSummary.removed_total || 0);
  const cidrChunkRecommended = recommendedCidrChunkSize(target);
  const proxyStatus = proxyValidationStatus(form.proxy_mode, form.proxy_url);
  const selectedPreset = presets.find(item=>item.key === preset);
  const recommendedWordlistPreview = recommendedWordlistFromHint(`${extHintSvc} ${extHintTech}`);
  const recommendedExtensionsPreview = useMemo(()=>{
    const blob = `${extHintSvc} ${extHintTech}`.toLowerCase();
    const out = [];
    const add = ext => { if (!out.includes(ext)) out.push(ext); };
    if (blob.includes("wordpress")) [".php",".bak",".zip"].forEach(add);
    if (blob.includes("nginx")) [".php",".html"].forEach(add);
    if (blob.includes("iis")) [".aspx",".asp",".ashx"].forEach(add);
    if (blob.includes("node")) [".js",".json"].forEach(add);
    if (blob.includes("django")) [".py",".json"].forEach(add);
    return out.slice(0, 10);
  }, [extHintSvc, extHintTech]);
  const deltaLines = useMemo(()=>{
    const lines = [
      ...scanModeDeltaLines(scanMode),
      ...profileDeltaLines(profile),
    ];
    if (selectedPreset) {
      lines.push(`Preset Δ ${String(selectedPreset.label || selectedPreset.key)}: modules => ${arrayOrEmpty(selectedPreset.modules).join(", ") || "(none)"}`);
    } else {
      lines.push("Preset Δ Custom: no preset auto-overrides");
    }
    return lines;
  }, [scanMode, profile, selectedPreset]);

  const nmapQuickSelect = useMemo(()=>{
    const p = String(form.nmap_ports||"").trim().toLowerCase();
    if (!p) return "__custom__";
    return NMAP_PORT_QUICK.some(x=>x.value===p) ? p : "__custom__";
  }, [form.nmap_ports]);

  const wordlistShownLabel = useMemo(()=>{
    const norm = p => String(p||"").replace(/\\/g,"/");
    const path = form.ffuf_wordlist_path;
    const n = norm(path);
    const list = arrayOrEmpty(wordlistEntries);
    const hit = list.find(x=>norm(x.path)===n);
    if (hit) return hit.label;
    let p = n;
    for (const s of ["wordlists/SecLists-master/","wordlists/SecLists/","wordlists/"]) {
      if (p.startsWith(s)) return p.slice(s.length);
    }
    return p;
  }, [form.ffuf_wordlist_path, wordlistEntries]);

  const wlFiltered = useMemo(()=>{
    const norm = p => String(p||"").replace(/\\/g,"/");
    const q = norm(wlComboQuery).toLowerCase().trim();
    const list = arrayOrEmpty(wordlistEntries);
    if (!q) return list.slice(0, 500);
    return list.filter(e=>{
      const lab = String(e.label||"").toLowerCase();
      return lab.includes(q) || norm(e.path).toLowerCase().includes(q);
    }).slice(0, 500);
  }, [wordlistEntries, wlComboQuery]);

  if (!open) return null;

  const updateForm = (key, value) => setForm(current=>({...current, [key]: value}));
  const toggleFfufExt = ext => {
    setForm(f => {
      const cur = arrayOrEmpty(f.ffuf_extensions);
      const has = cur.includes(ext);
      const next = has ? cur.filter(x => x !== ext) : [...cur, ext];
      return {...f, ffuf_extensions: next};
    });
  };
  const mergeRecommendedExts = () => {
    if (!autoRecommendationEnabled) return;
    const u = `/api/recommended-extensions?service=${encodeURIComponent(extHintSvc)}&tech=${encodeURIComponent(extHintTech)}`;
    setError("");
    apiJson(u).then(d=>{
      const add = arrayOrEmpty(d.extensions);
      setForm(f=>{
        const cur = arrayOrEmpty(f.ffuf_extensions);
        const seen = new Set(cur);
        const next = [...cur];
        add.forEach(x=>{ if (!seen.has(x)) { seen.add(x); next.push(x); } });
        return {...f, ffuf_extensions: next};
      });
    }).catch(err=>setError(err.message));
  };
  const addCustomFfufExt = () => {
    let t = (ffufExtCustom || "").trim();
    if (!t) return;
    if (!t.startsWith(".")) t = `.${t}`;
    setForm(f=>{
      const cur = arrayOrEmpty(f.ffuf_extensions);
      if (cur.includes(t)) return f;
      return {...f, ffuf_extensions: [...cur, t]};
    });
    setFfufExtCustom("");
  };
  const speedLevel = SPEED_LEVELS[speedIndex] || "T3";
  const speedConfig = SPEED_CONFIGS[speedLevel] || SPEED_CONFIGS["T3"];
  const toggleModule = module => setModules(current => current.includes(module) ? current.filter(item=>item!==module) : [...current, module]);
  const applyPreset = value => {
    setPreset(value);
    const selected = presets.find(item=>item.key === value);
    if (!selected) return;
    setProfile(selected.profile || "safe");
    setModules(selected.modules || []);
    const defaults = selected.defaults || {};
    setForm(current=>({
      ...current,
      ffuf_wordlist_path: defaults.ffuf_wordlist_path || current.ffuf_wordlist_path,
      nmap_ports: defaults.nmap_ports || current.nmap_ports,
    }));
  };
  const submit = async startNow => {
    setError("");
    const targetLines = String(target || "")
      .split(/\r?\n/)
      .map(item=>item.trim())
      .filter(Boolean);
    if (targetLines.length === 0) {
      setError("Target is required.");
      return;
    }
    const targetPayload = String(target || "").trim();
    if (modules.length === 0) {
      setError("Select at least one module.");
      return;
    }
    const proxyMode = String(form.proxy_mode || "none").toLowerCase();
    const proxyUrl = String(form.proxy_url || "").trim();
    if (proxyMode !== "none" && !proxyUrl) {
      setError("Proxy URL is required when proxy mode is enabled.");
      return;
    }
    if (proxyMode === "socks" && proxyUrl && !proxyUrl.toLowerCase().startsWith("socks5://")) {
      setError("SOCKS mode requires socks5:// format.");
      return;
    }
    setSubmitting(true);
    try {
      if (isEditConfigMode) {
        const payload = isRunningEdit
          ? {
              ffuf_concurrency: form.ffuf_concurrency,
              ffuf_max_parallel_tasks: form.ffuf_max_parallel_tasks,
              ffuf_wordlist_path: form.ffuf_wordlist_path,
              ffuf_extensions: form.ffuf_extensions,
            }
          : {
              target: targetPayload,
              preset,
              profile,
              modules,
              scan_mode: scanMode,
              speed_level: speedLevel,
              speed_config: speedConfig,
              ...form,
              auto_recommendation_enabled: Boolean(autoRecommendationEnabled),
              include_notes_context: false,
            };
        const updated = await apiJson(`/api/runs/${encodeURIComponent(editRunId)}/config`, {method:"PATCH", body:JSON.stringify(payload)});
        if (typeof onUpdated === "function") {
          onUpdated(editRunId, String(updated?.run?.status || editRunStatus || "pending"));
        }
        return;
      }
      const payload = {
        target: targetPayload,
        preset,
        profile,
        modules,
        scan_mode: scanMode,
        speed_level: speedLevel,
        speed_config: speedConfig,
        ...form,
        auto_start: false,
        include_notes_context: Boolean(rerunSourceRunId) ? includeNotesContext : false,
        auto_recommendation_enabled: Boolean(autoRecommendationEnabled),
        source_run_id: rerunSourceRunId || "",
      };
      const created = await apiJson("/api/runs", {method:"POST", body:JSON.stringify(payload)});
      const runId = created.run?.run_id || created.run_id;
      if (startNow) {
        await apiJson(`/api/runs/${encodeURIComponent(runId)}/execute`, {method:"POST", body:JSON.stringify({})});
      }
      const label = targetLines.length === 1 ? targetLines[0] : `${targetLines.length} targets (단일 run)`;
      onCreated(runId, startNow, label, {createdRunIds: [runId], targetCount: targetLines.length});
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div data-new-scan-modal="vantage" data-rerun-scan={rerunSourceRunId ? "yes" : "no"} style={{position:"fixed",inset:0,background:"rgba(2,6,23,0.78)",zIndex:50,
      display:"flex",alignItems:"center",justifyContent:"center",padding:24}}>
      <div style={{width:720,maxHeight:"90vh",overflow:"auto",background:C.slateDark,border:`1px solid ${C.blueBorder}`,borderRadius:8,boxShadow:"0 24px 80px rgba(0,0,0,0.45)"}}>
        <div style={{display:"flex",alignItems:"center",padding:"16px 18px",borderBottom:`1px solid ${C.slateMid}`}}>
          <div>
            <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:15,color:C.inkBright,letterSpacing:"0.08em"}}>
              {isEditConfigMode ? "Edit Config" : (rerunSourceRunId ? "Re-run scan" : "New Scan")}
            </div>
            <div style={{fontSize:11,color:C.slate}}>
              {isEditConfigMode
                ? `Update configuration for ${editRunId}.`
                : rerunSourceRunId
                ? `Options copied from ${rerunSourceRunId}. Review and modify before starting.`
                : "Create a saved scan run without changing backend execution behavior."}
            </div>
            {!isEditConfigMode && !rerunSourceRunId ? (
              <div style={{marginTop:4,fontSize:10,color:C.muted,lineHeight:1.4}}>
                기본은 모드·대상·프로파일만으로 충분합니다. 속도 프리셋과 중복되는 옵션은 고급을 펼쳐 한 곳으로 모았습니다.
              </div>
            ) : null}
            {isPendingEdit && (
              <div style={{marginTop:6}}>
                <Tag color={C.blueDim}>Editing pending scan</Tag>
              </div>
            )}
            {isRunningEdit && (
              <div style={{marginTop:6}}>
                <Tag color="rgba(234,179,8,0.25)">Editing running scan (safe fields only)</Tag>
              </div>
            )}
            {isEditConfigMode && (
              <div style={{marginTop:6,fontSize:11,color:C.slate}}>
                Config changes will apply to upcoming tasks only.
              </div>
            )}
            {sourceRunLabel && (
              <div style={{marginTop:7,display:"flex",gap:10,alignItems:"center",flexWrap:"wrap",fontSize:10,color:C.slate,fontFamily:"JetBrains Mono, monospace"}}>
                <span>Source run: {sourceRunLabel}</span>
                {sourceRunCreatedAt ? <span>Created: {formatDateTime(sourceRunCreatedAt)}</span> : null}
                <span style={{padding:"1px 6px",borderRadius:999,border:`1px solid ${C.slateMid}`,color:C.ink}}>
                  Notes: {sourceNoteCount}
                </span>
                {(changeAdded > 0 || changeRemoved > 0) ? (
                  baselineRunId ? (
                    <button
                      type="button"
                      title="View detailed changes"
                      onClick={()=>navigate(`/runs/${encodeURIComponent(sourceRunLabel)}/findings?compare=${encodeURIComponent(baselineRunId)}`)}
                      style={{padding:"1px 6px",borderRadius:999,border:`1px solid ${C.blueBorder}`,color:C.sky,background:"transparent",cursor:"pointer"}}
                    >
                      Recent changes +{changeAdded} / -{changeRemoved}
                    </button>
                  ) : (
                    <span
                      title="View detailed changes"
                      style={{padding:"1px 6px",borderRadius:999,border:`1px solid ${C.slateMid}`,color:C.slate,opacity:0.7,cursor:"not-allowed"}}
                    >
                      Recent changes +{changeAdded} / -{changeRemoved}
                    </span>
                  )
                ) : null}
              </div>
            )}
            {rerunSourceRunId && (
              <label style={{marginTop:8,display:"inline-flex",gap:8,alignItems:"center",fontSize:11,color:C.ink}}>
                <input type="checkbox" checked={!!includeNotesContext} onChange={event=>setIncludeNotesContext(event.target.checked)}/>
                Re-run with notes context
              </label>
            )}
          </div>
          <div style={{flex:1}}/>
          <button onClick={onClose} style={{...actionButtonStyle,fontSize:14}}>×</button>
        </div>
        <div style={{padding:18,display:"grid",gap:12}} data-smart-scan-mode="vantage">
          {error&&<div style={{color:"#FCA5A5",fontSize:12,border:"1px solid rgba(239,68,68,0.35)",borderRadius:5,padding:9,background:"rgba(239,68,68,0.08)"}}>{error}</div>}
          <div>
            <div style={{fontSize:11,color:C.slate,marginBottom:7}}>Scan mode</div>
            <div style={{display:"grid",gap:8}}>
              {SCAN_MODES.map(row=>(
                <label key={row.id} style={{display:"grid",gridTemplateColumns:"20px 1fr",gap:8,alignItems:"start",padding:8,border:`1px solid ${scanMode === row.id ? C.blueBorder : C.slateMid}`,
                  borderRadius:5,background:scanMode === row.id ? C.blueDim : "transparent",cursor:"pointer"}}>
                  <input type="radio" name="scanMode" checked={scanMode === row.id} onChange={()=>applyWebScanMode(row.id)}/>
                  <div>
                    <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.ink,fontWeight:700}}>{row.label}</div>
                    <div style={{fontSize:10,color:C.slate,marginTop:3}}>{row.hint}</div>
                  </div>
                </label>
              ))}
            </div>
            <div style={{marginTop:6,fontSize:10,color:C.muted,lineHeight:1.45}}>
              각 모드는 nmap 포트 범위·타이밍·버전 탐지·디렉터리 스캔(모듈) 조합만 바꿉니다. 백엔드 동작은 그대로이며 실행 전 값만 조정합니다.
            </div>
          </div>
          <Field
            label="Target"
            hint={"승인된 대상만 입력하세요.\n줄바꿈으로 여러 줄을 넣으면 하나의 run으로 묶이며, 스코프에 등록되어 http_probe/port_scan 시드로 사용됩니다(IP·CIDR·도메인·URL 혼합 가능).\n고급의 Scope include는 추가 허용 목록으로 합쳐집니다."}
          >
            <textarea
              value={target}
              onChange={e=>setTarget(e.target.value)}
              placeholder={"example.com\nhttps://app.example\n127.0.0.1/28"}
              disabled={isRunningEdit}
              style={{...inputStyle,minHeight:72}}
            />
          </Field>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
            <Field
              label="Profile"
              hint="httpx/ffuf 동시 접속 한도와 nmap 최대 템플릿(safe=T2까지 등)을 제한합니다. balanced/fast는 같은 도구지만 상한을 완화합니다."
            >
              <select value={profile} onChange={e=>setProfile(e.target.value)} style={inputStyle}>
                {["safe","balanced","fast"].map(item=><option key={item} value={item}>{item}</option>)}
              </select>
            </Field>
            <Field
              label="Preset"
              hint="실행 과제 모듈·일부 기본값(워드리스트 등)을 한 번에 채웁니다. Custom이면 체크한 모듈만 사용합니다."
            >
              <select value={preset} onChange={e=>applyPreset(e.target.value)} style={inputStyle}>
                <option value="">Custom</option>
                {presets.map(item=><option key={item.key} value={item.key}>{item.label || item.key}</option>)}
              </select>
            </Field>
          </div>
          <details data-selection-delta-preview="vantage" style={{border:`1px solid ${C.slateMid}`,borderRadius:6,background:"#0B1220"}}>
            <summary style={{fontSize:11,color:C.slate,cursor:"pointer",padding:"10px 12px",listStylePosition:"outside"}}>
              Selection Delta Preview (프리셋·모드가 실제 어떤 기본값을 덮어쓰는지 요약 · 펼치기)
            </summary>
            <div style={{padding:"2px 12px 12px",display:"grid",gap:4}}>
              {deltaLines.map((line, idx)=>(
                <div key={`${line}-${idx}`} style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.ink}}>
                  {line}
                </div>
              ))}
            </div>
          </details>
          <div>
            <div style={{fontSize:11,color:C.slate,marginBottom:7}}>Modules</div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:8}}>
              {MODULES.map(module=>(
                <label key={module} style={{display:"flex",gap:6,alignItems:"center",padding:"8px 9px",border:`1px solid ${C.slateMid}`,borderRadius:5,fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.ink}}>
                  <input type="checkbox" checked={modules.includes(module)} onChange={()=>toggleModule(module)} disabled={isRunningEdit}/>
                  {module}
                </label>
              ))}
            </div>
            <div style={{marginTop:8,fontSize:10,color:C.muted,lineHeight:1.5}}>
              <span style={{color:C.slate}}>요약:</span>
              {' '}port_scan(nmap)·http_probe(httpx 생존/메타)·domain_discovery(DNS)·dir_enum(ffuf 경로)·banner_probe·subdomain_enum.
            </div>
            <details style={{marginTop:8,fontSize:10,color:C.muted,lineHeight:1.55}}>
              <summary style={{cursor:"pointer",color:C.slate}}>모듈 차이 · 실행 순서 (펼치기)</summary>
              <div style={{marginTop:6}}>
                <b>subdomain_enum</b> 외부 소스(SecurityTrails·crt.sh 등)로 <b>서브도메인 이름</b>을 수집합니다. 루트 도메인이 필요합니다.
                <br/><b>domain_discovery</b>는 이미 수집된 <b>http_probe·port_scan·TLS</b> 결과에서 IP↔호스트 매핑·PTR 등을 <b>상관</b>해 도메인 단서를 만듭니다. 전혀 다른 단계입니다.
                <br/><b>banner_probe</b>는 열린 포트에서 배너/서비스 문자열을 정리합니다.
                <br/>전형적 순서: subdomain_enum → http_probe → domain_discovery → port_scan → banner_probe → dir_enum (모듈 선택·의존 데이터에 따라 일부 생략).
              </div>
            </details>
          </div>
          <button onClick={()=>setAdvancedOpen(!advancedOpen)} style={{...actionButtonStyle,width:"fit-content"}}>
            {advancedOpen ? "Hide Advanced" : "Show Advanced"}
          </button>
          {advancedOpen&&(
            <div style={{display:"grid",gap:8,border:`1px solid ${C.slateMid}`,borderRadius:6,padding:12}}>
              <details style={{border:`1px solid ${C.slateMid}`,borderRadius:6,background:"#0B1220"}}>
                <summary style={{fontSize:12,color:C.ink,cursor:"pointer",padding:"10px 12px"}}>
                  속도 계획 (nmap 타이밍 · httpx · ffuf 권장치)
                </summary>
                <div style={{display:"grid",gap:10,padding:"6px 12px 12px"}}>
                  <div style={{display:"grid",gap:8,padding:10,border:`1px solid ${C.slateMid}`,borderRadius:5,background:"#0f172a"}}>
                    <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:12}}>
                      <span style={{fontSize:11,color:C.slate}}>Speed Control</span>
                      <span style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.sky}}>{speedLevel}</span>
                    </div>
                    <input
                      type="range"
                      min={0}
                      max={SPEED_LEVELS.length - 1}
                      step={1}
                      value={speedIndex}
                      onChange={e=>{
                        const idx = Number(e.target.value);
                        setSpeedIndex(idx);
                        const lvl = SPEED_LEVELS[idx] || "T3";
                        const sc = SPEED_CONFIGS[lvl] || SPEED_CONFIGS["T3"];
                        setForm(f=>({...f, nmap_timing_template: sc.nmap_timing}));
                      }}
                    />
                    <div style={{display:"flex",justifyContent:"space-between",fontSize:10,color:C.slate}}>
                      <span>느림</span>
                      <span>빠름</span>
                    </div>
                    <div style={{border:`1px solid ${C.slateMid}`,borderRadius:4,padding:"8px 10px",display:"grid",gap:3,fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.ink}}>
                      <div>nmap 템플릿(기본안): {speedConfig.nmap_timing}</div>
                      <div>httpx 권장: concurrency {speedConfig.httpx.concurrency} / rate {speedConfig.httpx.rate}</div>
                      <div>ffuf 권장(참고): threads {speedConfig.ffuf.threads} / rate {speedConfig.ffuf.rate}</div>
                    </div>
                    {HIGH_SPEED_LEVELS.has(speedLevel) && (
                      <div style={{fontSize:11,color:"#FCA5A5",border:"1px solid rgba(239,68,68,0.35)",borderRadius:4,padding:"8px 10px",background:"rgba(239,68,68,0.08)"}}>
                        Warning: 높은 속도 설정은 대상 시스템 부하와 차단 가능성을 높일 수 있습니다.
                      </div>
                    )}
                  </div>
                  <Field
                    label="ffuf_concurrency (-t)"
                    hint="실제 디렉터리 스캔(ffuf)에 쓰이는 값입니다. 위 표는 참고용이며, 버튼으로 동일 숫자를 복사할 수 있습니다."
                  >
                    <div style={{display:"flex",flexWrap:"wrap",gap:8,alignItems:"center"}}>
                      <input
                        type="number"
                        min={1}
                        max={200}
                        value={form.ffuf_concurrency}
                        onChange={e=>{
                          const n = Math.max(1, Math.min(200, Number(e.target.value) || 1));
                          updateForm("ffuf_concurrency", n);
                        }}
                        style={{...inputStyle,width:96}}
                      />
                      <button
                        type="button"
                        onClick={()=>{
                          const n = Math.max(1, Math.min(200, Number(speedConfig.ffuf?.threads) || 1));
                          updateForm("ffuf_concurrency", n);
                        }}
                        style={{...actionButtonStyle,whiteSpace:"nowrap"}}
                      >
                        Apply speed plan ffuf threads
                      </button>
                      <button type="button" onClick={()=>updateForm("ffuf_concurrency", 10)} style={{...actionButtonStyle,color:C.slate,whiteSpace:"nowrap"}}>Set 10</button>
                      <button type="button" onClick={()=>updateForm("ffuf_concurrency", 40)} style={{...actionButtonStyle,color:C.slate,whiteSpace:"nowrap"}}>Set 40</button>
                      <button type="button" onClick={()=>updateForm("ffuf_concurrency", 100)} style={{...actionButtonStyle,color:C.slate,whiteSpace:"nowrap"}}>Set 100</button>
                    </div>
                  </Field>
                </div>
              </details>

              <details style={{border:`1px solid ${C.slateMid}`,borderRadius:6,background:"#0B1220"}}>
                <summary style={{fontSize:12,color:C.ink,cursor:"pointer",padding:"10px 12px"}}>
                  포트 범위 · 대형 CIDR (체크포인트 분할)
                </summary>
                <div style={{display:"grid",gap:12,padding:"6px 12px 12px"}}>
                  <Field label="Nmap ports" hint="top1000: nmap --top-ports 1000(자주 쓰이는 TCP 1000개, IANA well-known 구간과 집합이 다름). well-known: IANA well-known 1-1023. 그 외 범위(예: 1-1024)는 아래 입력란에 직접 적으면 됩니다. 스캔 모드 변경 시 값이 덮어씌워질 수 있고, 비우면 프로젝트 기본을 따릅니다.">
                    <div style={{display:"grid",gap:8}}>
                      <select
                        value={nmapQuickSelect}
                        onChange={e=>{
                          const v = e.target.value;
                          if (v === "__custom__") return;
                          updateForm("nmap_ports", v);
                        }}
                        style={inputStyle}
                      >
                        <option value="__custom__">프리셋 선택 또는 아래에 직접 입력</option>
                        {NMAP_PORT_QUICK.map(row=><option key={row.value} value={row.value}>{row.label}</option>)}
                      </select>
                      <input value={form.nmap_ports} onChange={e=>updateForm("nmap_ports", e.target.value)} placeholder="예: 80,443-445, top1000, well-known, 1-1024, 1-65535" style={inputStyle}/>
                    </div>
                  </Field>
                  <label style={{display:"flex",gap:8,alignItems:"center",fontSize:12,color:C.ink}}>
                    <input type="checkbox" checked={Boolean(form.nmap_version_detection)} onChange={e=>updateForm("nmap_version_detection", e.target.checked)} disabled={isRunningEdit}/>
                    Nmap 서비스 버전 탐지 (-sV, 느려질 수 있음)
                  </label>
                  <div style={{fontSize:11,color:C.slate,marginTop:2}}>고속 포트 디스커버리 (병렬 실행, 결과 합집합 → nmap 서비스 탐지)</div>
                  <label style={{display:"flex",gap:8,alignItems:"center",fontSize:12,color:C.ink}}>
                    <input type="checkbox" checked={Boolean(form.masscan_enabled)} onChange={e=>updateForm("masscan_enabled", e.target.checked)} disabled={isRunningEdit}/>
                    Masscan (stateless SYN, 가장 빠름)
                  </label>
                  {form.masscan_enabled&&(
                    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginLeft:24}}>
                      <Field label="Masscan rate (pps)" hint="초당 패킷 수. 높을수록 빠르나 손실율 증가. 권장: 1000–50000.">
                        <input type="number" min={100} max={10000000} value={form.masscan_rate} onChange={e=>updateForm("masscan_rate", Math.max(100, Number(e.target.value)||10000))} style={inputStyle} disabled={isRunningEdit}/>
                      </Field>
                      <Field label="Masscan retries" hint="포트당 SYN 재전송 횟수. 손실 보정. 권장: 1–3.">
                        <input type="number" min={0} max={10} value={form.masscan_retries} onChange={e=>updateForm("masscan_retries", Math.max(0, Math.min(10, Number(e.target.value)||0)))} style={inputStyle} disabled={isRunningEdit}/>
                      </Field>
                    </div>
                  )}
                  <label style={{display:"flex",gap:8,alignItems:"center",fontSize:12,color:C.ink}}>
                    <input type="checkbox" checked={Boolean(form.naabu_enabled)} onChange={e=>updateForm("naabu_enabled", e.target.checked)} disabled={isRunningEdit}/>
                    Naabu (재시도 내장, 서로 다른 탐지로 masscan 누락 보완)
                  </label>
                  {form.naabu_enabled&&(
                    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12,marginLeft:24}}>
                      <Field label="Naabu rate (pps)" hint="masscan보다 낮게 권장. 정확도 우선이면 1000–5000.">
                        <input type="number" min={100} max={1000000} value={form.naabu_rate} onChange={e=>updateForm("naabu_rate", Math.max(100, Number(e.target.value)||5000))} style={inputStyle} disabled={isRunningEdit}/>
                      </Field>
                      <Field label="Naabu retries" hint="포트당 재시도. 권장: 2–4.">
                        <input type="number" min={0} max={10} value={form.naabu_retries} onChange={e=>updateForm("naabu_retries", Math.max(0, Math.min(10, Number(e.target.value)||0)))} style={inputStyle} disabled={isRunningEdit}/>
                      </Field>
                      <Field label="Naabu scan type" hint="syn은 root/cap_net_raw 필요. connect는 무권한이지만 느림.">
                        <select value={form.naabu_scan_type} onChange={e=>updateForm("naabu_scan_type", e.target.value)} style={inputStyle} disabled={isRunningEdit}>
                          <option value="syn">syn (-s s)</option>
                          <option value="connect">connect (-s c)</option>
                        </select>
                      </Field>
                    </div>
                  )}
                  <div style={{fontSize:10,color:C.slate,lineHeight:1.5,marginLeft:24}}>
                    둘 다 설치되면 병렬 실행 후 발견 포트의 합집합을 nmap에 전달합니다. 미설치 도구는 조용히 건너뜁니다. 둘 다 없으면 nmap 단독 풀스캔으로 대체.
                  </div>
                  <div style={{fontSize:11,color:C.slate}}>대형 IPv4 대역에서는 port_scan 태스크를 잘게 나눠 중간 저장합니다.</div>
                  <label style={{display:"flex",gap:8,alignItems:"center",fontSize:12,color:C.ink}}>
                    <input type="checkbox" checked={form.cidr_split_enabled} onChange={e=>updateForm("cidr_split_enabled", e.target.checked)} disabled={isRunningEdit}/>
                    Split /24+ IPv4 CIDR into smaller port_scan chunks
                  </label>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                    <Field label="Hosts per chunk (max)" hint="/24 근처는 16처럼 작게 두는 편이 안전합니다.">
                      <div style={{display:"grid",gap:8}}>
                        <input
                          type="range"
                          min={1}
                          max={256}
                          step={1}
                          value={Math.max(1, Math.min(256, Number(form.cidr_split_max_hosts_per_chunk) || 1))}
                          onChange={e=>updateForm("cidr_split_max_hosts_per_chunk", Number(e.target.value))}
                          disabled={isRunningEdit}
                          data-cidr-chunk-slider="vantage"
                        />
                        <div style={{display:"flex",gap:8,alignItems:"center"}}>
                          <input
                            type="number"
                            min={1}
                            max={256}
                            value={form.cidr_split_max_hosts_per_chunk}
                            onChange={e=>updateForm("cidr_split_max_hosts_per_chunk", Math.max(1, Math.min(256, Number(e.target.value) || 1)))}
                            disabled={isRunningEdit}
                            style={inputStyle}
                          />
                          {cidrChunkRecommended ? (
                            <button
                              type="button"
                              onClick={()=>updateForm("cidr_split_max_hosts_per_chunk", cidrChunkRecommended)}
                              style={{
                                padding:"6px 10px",
                                borderRadius:999,
                                border:`1px solid ${C.blueBorder}`,
                                background:C.blueDim,
                                color:C.sky,
                                fontSize:11,
                                fontWeight:700,
                                cursor:"pointer",
                                whiteSpace:"nowrap",
                              }}
                              title="Apply recommended chunk size"
                            >
                              Recommend {cidrChunkRecommended}
                            </button>
                          ) : null}
                        </div>
                        <div style={{fontSize:10,color:C.slate,fontFamily:"JetBrains Mono, monospace"}}>
                          Recommended: /24 -> 16 hosts, /26 -> 8 hosts
                          {cidrChunkRecommended ? ` | 현재 대상 제안: ${cidrChunkRecommended}` : ""}
                        </div>
                      </div>
                    </Field>
                    <Field label="Target checkpoint interval (min)" hint="청크가 끝날 때 저장 주기입니다. 긴 실행에 유리합니다.">
                      <input type="number" min={1} max={1440} value={form.cidr_split_target_interval_minutes} onChange={e=>updateForm("cidr_split_target_interval_minutes", Number(e.target.value))} style={inputStyle}/>
                    </Field>
                  </div>
                </div>
              </details>

              <details style={{border:`1px solid ${C.slateMid}`,borderRadius:6,background:"#0B1220"}}>
                <summary style={{fontSize:12,color:C.ink,cursor:"pointer",padding:"10px 12px"}}>
                  서브도메인 발견 (dnsx 브루트포스)
                </summary>
                <div style={{display:"grid",gap:10,padding:"6px 12px 12px"}}>
                  <label style={{display:"flex",gap:8,alignItems:"center",fontSize:12,color:C.ink}}>
                    <input type="checkbox" checked={Boolean(form.subdomain_bruteforce_enabled)} onChange={e=>updateForm("subdomain_bruteforce_enabled", e.target.checked)} disabled={isRunningEdit}/>
                    DNS 브루트포스 활성화 (dnsx — 공통 서브도메인 접두사 ~70개 자동 시도)
                  </label>
                  <div style={{fontSize:10,color:C.slate,lineHeight:1.5}}>
                    dnsx 미설치 시 조용히 건너뜁니다. 설치: <span style={{fontFamily:"JetBrains Mono, monospace",color:C.sky}}>go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest</span>
                  </div>
                </div>
              </details>

              <details style={{border:`1px solid ${C.slateMid}`,borderRadius:6,background:"#0B1220"}}>
                <summary style={{fontSize:12,color:C.ink,cursor:"pointer",padding:"10px 12px"}}>
                  UDP 스캔 (DNS · SNMP · NTP 등)
                </summary>
                <div style={{display:"grid",gap:10,padding:"6px 12px 12px"}}>
                  <label style={{display:"flex",gap:8,alignItems:"center",fontSize:12,color:C.ink}}>
                    <input type="checkbox" checked={Boolean(form.udp_scan_enabled)} onChange={e=>updateForm("udp_scan_enabled", e.target.checked)} disabled={isRunningEdit}/>
                    UDP 포트 스캔 활성화 (nmap -sU — root/Administrator 권한 필요)
                  </label>
                  {form.udp_scan_enabled&&(
                    <Field label="UDP ports" hint="protocol-specific 응답이 있는 포트만 권장. 너무 많으면 매우 느려짐.">
                      <input value={form.udp_scan_ports} onChange={e=>updateForm("udp_scan_ports", e.target.value)} style={inputStyle} disabled={isRunningEdit}/>
                    </Field>
                  )}
                  <div style={{fontSize:10,color:C.slate,lineHeight:1.5}}>
                    DNS recursor 노출, SNMP public, NTP amplification 등 흔한 미스컨피그 탐지에 효과적. 권한 없으면 자동 건너뜀.
                  </div>
                </div>
              </details>

              <details style={{border:`1px solid ${C.slateMid}`,borderRadius:6,background:"#0B1220"}}>
                <summary style={{fontSize:12,color:C.ink,cursor:"pointer",padding:"10px 12px"}}>
                  JS 렌더링 · SPA 크롤링 (Playwright)
                </summary>
                <div style={{display:"grid",gap:10,padding:"6px 12px 12px"}}>
                  <label style={{display:"flex",gap:8,alignItems:"center",fontSize:12,color:C.ink}}>
                    <input type="checkbox" checked={Boolean(form.js_render_enabled)} onChange={e=>updateForm("js_render_enabled", e.target.checked)} disabled={isRunningEdit}/>
                    JS 렌더링 활성화 (헤드리스 Chromium — React/Vue SPA 동적 라우트 발견)
                  </label>
                  {form.js_render_enabled&&(
                    <>
                      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginLeft:24}}>
                        <Field label="Timeout (초)" hint="페이지당 렌더링 최대 대기 시간.">
                          <input type="number" min={3} max={120} value={form.js_render_timeout_seconds} onChange={e=>updateForm("js_render_timeout_seconds", Math.max(3, Math.min(120, Number(e.target.value)||15)))} style={inputStyle} disabled={isRunningEdit}/>
                        </Field>
                        <Field label="최대 호스트 수" hint="렌더링은 비싸므로 캡 권장.">
                          <input type="number" min={1} max={10000} value={form.js_render_max_hosts} onChange={e=>updateForm("js_render_max_hosts", Math.max(1, Number(e.target.value)||50))} style={inputStyle} disabled={isRunningEdit}/>
                        </Field>
                      </div>
                      <label style={{display:"flex",gap:8,alignItems:"center",fontSize:12,color:C.ink,marginLeft:24}}>
                        <input type="checkbox" checked={Boolean(form.spa_crawl_enabled)} onChange={e=>updateForm("spa_crawl_enabled", e.target.checked)} disabled={isRunningEdit}/>
                        SPA 재귀 크롤링 (DOM 링크 따라가기)
                      </label>
                      {form.spa_crawl_enabled&&(
                        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12,marginLeft:48}}>
                          <Field label="크롤 depth" hint="시작 페이지 기준 깊이.">
                            <input type="number" min={0} max={8} value={form.spa_crawl_max_depth} onChange={e=>updateForm("spa_crawl_max_depth", Math.max(0, Math.min(8, Number(e.target.value)||2)))} style={inputStyle} disabled={isRunningEdit}/>
                          </Field>
                          <Field label="최대 페이지" hint="전체 크롤 페이지 캡.">
                            <input type="number" min={1} max={10000} value={form.spa_crawl_max_pages} onChange={e=>updateForm("spa_crawl_max_pages", Math.max(1, Number(e.target.value)||50))} style={inputStyle} disabled={isRunningEdit}/>
                          </Field>
                          <Field label="Same-origin only">
                            <select value={form.spa_crawl_same_origin_only ? "yes" : "no"} onChange={e=>updateForm("spa_crawl_same_origin_only", e.target.value === "yes")} style={inputStyle} disabled={isRunningEdit}>
                              <option value="yes">yes (권장)</option>
                              <option value="no">no</option>
                            </select>
                          </Field>
                        </div>
                      )}
                    </>
                  )}
                  <div style={{fontSize:10,color:C.slate,lineHeight:1.5}}>
                    Playwright + Chromium 필요 (~150MB). XHR/fetch 엔드포인트와 DOM 링크를 자동 추출해 ffuf가 못 찾는 SPA 라우트를 발견.
                    설치: <span style={{fontFamily:"JetBrains Mono, monospace",color:C.sky}}>pip install playwright && python -m playwright install chromium</span>
                  </div>
                </div>
              </details>

              <details style={{border:`1px solid ${C.slateMid}`,borderRadius:6,background:"#0B1220"}}>
                <summary style={{fontSize:12,color:C.ink,cursor:"pointer",padding:"10px 12px"}}>
                  인증 폼 자동 로그인 (Playwright)
                </summary>
                <div style={{display:"grid",gap:10,padding:"6px 12px 12px"}}>
                  <label style={{display:"flex",gap:8,alignItems:"center",fontSize:12,color:C.ink}}>
                    <input type="checkbox" checked={Boolean(form.auth_login_enabled)} onChange={e=>updateForm("auth_login_enabled", e.target.checked)} disabled={isRunningEdit}/>
                    로그인 폼 자동 제출 → 세션 쿠키를 후속 스캔에 주입
                  </label>
                  {form.auth_login_enabled&&(
                    <div style={{display:"grid",gap:10,marginLeft:24}}>
                      <Field label="Login URL" hint="로그인 폼이 있는 페이지의 전체 URL.">
                        <input value={form.auth_login_url} onChange={e=>updateForm("auth_login_url", e.target.value)} placeholder="https://app.example.com/login" style={inputStyle} disabled={isRunningEdit}/>
                      </Field>
                      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                        <Field label="Username">
                          <input value={form.auth_username} onChange={e=>updateForm("auth_username", e.target.value)} autoComplete="off" style={inputStyle} disabled={isRunningEdit}/>
                        </Field>
                        <Field label="Password">
                          <input type="password" value={form.auth_password} onChange={e=>updateForm("auth_password", e.target.value)} autoComplete="new-password" style={inputStyle} disabled={isRunningEdit}/>
                        </Field>
                      </div>
                      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                        <Field label="Username field hints" hint="콤마 구분. 필드 name/id/placeholder에서 이 단어 매칭.">
                          <input value={form.auth_username_field_hints} onChange={e=>updateForm("auth_username_field_hints", e.target.value)} style={inputStyle} disabled={isRunningEdit}/>
                        </Field>
                        <Field label="Password field hints">
                          <input value={form.auth_password_field_hints} onChange={e=>updateForm("auth_password_field_hints", e.target.value)} style={inputStyle} disabled={isRunningEdit}/>
                        </Field>
                      </div>
                      <Field label="Success URL keyword (선택)" hint="로그인 성공 후 리디렉션 URL에 들어가는 단어 (예: dashboard, home). 비우면 휴리스틱 사용.">
                        <input value={form.auth_login_success_keyword} onChange={e=>updateForm("auth_login_success_keyword", e.target.value)} style={inputStyle} disabled={isRunningEdit}/>
                      </Field>
                    </div>
                  )}
                  <div style={{fontSize:10,color:"#FCD34D",lineHeight:1.5}}>
                    ⚠ 자격 증명은 워크스페이스 설정 파일에 평문 저장됩니다. 본 도구는 로컬 단독 동작이지만, run 결과를 공유하기 전 password 필드 마스킹 권장.
                  </div>
                </div>
              </details>

              <details style={{border:`1px solid ${C.slateMid}`,borderRadius:6,background:"#0B1220"}}>
                <summary style={{fontSize:12,color:C.ink,cursor:"pointer",padding:"10px 12px"}}>
                  디렉터리 스캔 (ffuf 워드리스트 · 병렬)
                </summary>
                <div style={{display:"grid",gap:12,padding:"6px 12px 12px"}}>
                  <div style={{display:"flex",flexWrap:"wrap",gap:8,alignItems:"center"}}>
                    <span style={{fontSize:10,color:C.slate}}>프로젝트:</span>
                    {arrayOrEmpty(wordlistBundle).map(b=>(
                      <button
                        key={b.path}
                        type="button"
                        title={b.path}
                        onClick={()=>updateForm("ffuf_wordlist_path", b.path)}
                        style={{...actionButtonStyle,fontSize:10,padding:"4px 8px",whiteSpace:"nowrap"}}
                      >
                        {b.label}{b.size_human && b.lines_human ? ` · ${b.size_human} · ${b.lines_human}` : ""}
                      </button>
                    ))}
                  </div>
                  <div style={{display:"flex",flexWrap:"wrap",gap:8,alignItems:"center"}}>
                    <span style={{fontSize:10,color:C.slate}}>추천 프리셋 (SecLists 경로는 짧게 표시):</span>
                    {arrayOrEmpty(wordlistPresets).map(p=>(
                      <button
                        key={p.label}
                        type="button"
                        title={p.path}
                        onClick={()=>updateForm("ffuf_wordlist_path", p.path)}
                        style={{...actionButtonStyle,fontSize:10,padding:"4px 8px",whiteSpace:"nowrap"}}
                      >
                        {p.short_label ? `${p.label} · ${p.short_label}` : p.label}{p.size_human && p.lines_human ? ` · ${p.size_human} · ${p.lines_human}` : ""}
                      </button>
                    ))}
                  </div>
                  <Field label="Wordlist" hint="목록에는 SecLists 공통 접두사를 뺀 짧은 경로만 보입니다. 줄 수는 개행 기준(워드 후보 개수). 전체 경로는 선택 시에만 설정됩니다.">
                    <div style={{position:"relative"}}>
                      <input
                        value={wlComboFocus ? wlComboQuery : wordlistShownLabel}
                        onFocus={()=>{
                          setWlComboFocus(true);
                          setWlComboQuery(wordlistShownLabel);
                        }}
                        onChange={e=>setWlComboQuery(e.target.value)}
                        onBlur={()=>{
                          setWlComboFocus(false);
                          const norm = p=>String(p||"").replace(/\\/g,"/");
                          const q = wlComboQuery.trim();
                          const list = arrayOrEmpty(wordlistEntries);
                          const byLabel = list.find(e=>e.label===q);
                          const byPath = list.find(e=>norm(e.path)===norm(q));
                          const resolved = byLabel?.path ?? byPath?.path ?? q;
                          updateForm("ffuf_wordlist_path", resolved);
                        }}
                        placeholder="Discovery/DNS/… 검색"
                        style={inputStyle}
                        autoComplete="off"
                      />
                      {wlComboFocus ? (
                        <div
                          style={{
                            position:"absolute",
                            zIndex:30,
                            left:0,
                            right:0,
                            top:"100%",
                            marginTop:4,
                            maxHeight:260,
                            overflowY:"auto",
                            border:`1px solid ${C.slateMid}`,
                            borderRadius:6,
                            background:"#0f172a",
                            boxShadow:"0 10px 28px rgba(0,0,0,0.5)",
                          }}
                        >
                          {wlFiltered.length===0 ? (
                            <div style={{padding:10,fontSize:11,color:C.muted}}>일치하는 워드리스트가 없습니다.</div>
                          ) : wlFiltered.map(item=>(
                            <button
                              key={item.path}
                              type="button"
                              onMouseDown={e=>{ e.preventDefault(); }}
                              onClick={()=>{
                                updateForm("ffuf_wordlist_path", item.path);
                                setWlComboQuery(item.label);
                                setWlComboFocus(false);
                              }}
                              style={{
                                display:"block",
                                width:"100%",
                                textAlign:"left",
                                padding:"8px 10px",
                                border:"none",
                                borderBottom:`1px solid ${C.slateMid}`,
                                background:"transparent",
                                color:C.ink,
                                cursor:"pointer",
                                fontSize:11,
                                fontFamily:"inherit",
                              }}
                            >
                              <div style={{fontWeight:600,lineHeight:1.35}}>{item.label}</div>
                              <div style={{fontSize:10,color:C.slate,marginTop:3}}>
                                {[item.size_human, item.lines_human].filter(Boolean).join(" · ")}
                              </div>
                            </button>
                          ))}
                        </div>
                      ) : null}
                    </div>
                  </Field>
                  <div style={{fontSize:11,color:C.slate}}>Recursive directory scan (재귀 디렉터리; 기본 비권장, 보수적)</div>
                  <label style={{display:"flex",gap:8,alignItems:"center",fontSize:12,color:C.ink}}>
                    <input type="checkbox" checked={form.dir_recursive_enabled} onChange={e=>updateForm("dir_recursive_enabled", e.target.checked)}/>
                    Enable recursive directory enumeration
                  </label>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                    <Field label="Recursive max depth"><input type="number" min={0} max={32} value={form.dir_recursive_max_depth} onChange={e=>updateForm("dir_recursive_max_depth", Number(e.target.value))} style={inputStyle}/></Field>
                    <Field label="Max paths / host (recursive)" hint="폭발적 요청 방지 한도입니다."><input type="number" min={1} max={1000000} value={form.dir_recursive_max_paths_per_host} onChange={e=>updateForm("dir_recursive_max_paths_per_host", Number(e.target.value))} style={inputStyle}/></Field>
                  </div>
                  <Field label="FFUF replay proxy (ip:port)" hint="Burp 등으로 결과를 재전달할 때 사용(선택).">
                    <input value={form.ffuf_replay_proxy} onChange={e=>updateForm("ffuf_replay_proxy", e.target.value)} placeholder="127.0.0.1:8080" style={inputStyle}/>
                  </Field>
                  <label style={{display:"flex",gap:8,alignItems:"center",fontSize:12,color:C.ink}}>
                    <input type="checkbox" checked={form.ffuf_parallel_enabled} onChange={e=>updateForm("ffuf_parallel_enabled", e.target.checked)}/>
                    Parallel base-URL directory scans
                  </label>
                  <Field label="Max parallel base-URL tasks" hint="여러 호스트/베이스 URL을 동시에 ffuf 할 때 동시 실행 수 상한입니다.">
                    <input type="number" min={1} max={64} value={form.ffuf_max_parallel_tasks} onChange={e=>updateForm("ffuf_max_parallel_tasks", Math.max(1, Math.min(64, Number(e.target.value) || 1)))} style={inputStyle}/>
                  </Field>
                </div>
              </details>

              <details style={{border:`1px solid ${C.slateMid}`,borderRadius:6,background:"#0B1220"}}>
                <summary style={{fontSize:12,color:C.ink,cursor:"pointer",padding:"10px 12px"}}>
                  확장자 · 서비스/기술 힌트 · 자동 추천
                </summary>
                <div style={{display:"grid",gap:10,padding:"6px 12px 12px"}}>
                  <label style={{display:"flex",gap:8,alignItems:"center",fontSize:12,color:C.ink}}>
                    <input type="checkbox" checked={autoRecommendationEnabled} onChange={e=>setAutoRecommendationEnabled(e.target.checked)}/>
                    Enable auto recommendation (extensions + wordlist)
                  </label>
                  <div style={{display:"grid",gap:4,fontSize:10,color:C.slate,fontFamily:"JetBrains Mono, monospace"}}>
                    <div>Recommended extensions: {recommendedExtensionsPreview.length ? recommendedExtensionsPreview.join(", ") : "(no hint yet)"}</div>
                    <div>Recommended wordlist: {recommendedWordlistPreview}</div>
                  </div>
                  <div style={{fontSize:10,color:C.muted}}>
                    확장자를 고르지 않으면 UI에는 (auto)로 보이며, 실행 중 dir_enum이 http_probe에서 본 기술 스택·포트 서비스 문자열을 반영해 자동 확장자·워드리스트 후보를 고릅니다(모달 힌트는 실행 전 참고용).
                  </div>
                  <div style={{display:"flex",flexWrap:"wrap",gap:8,alignItems:"center"}}>
                    {ffufExtCatalog.map(ext=>(
                      <label key={ext} style={{display:"inline-flex",gap:5,alignItems:"center",fontSize:11,color:C.ink,
                        border:`1px solid ${(arrayOrEmpty(form.ffuf_extensions).includes(ext)?C.blueBorder:C.slateMid)}`,
                        borderRadius:4,padding:"4px 7px",cursor:"pointer",background:arrayOrEmpty(form.ffuf_extensions).includes(ext)?C.blueDim:"transparent"}}>
                        <input type="checkbox" checked={arrayOrEmpty(form.ffuf_extensions).includes(ext)} onChange={()=>toggleFfufExt(ext)}/>
                        {ext}
                      </label>
                    ))}
                  </div>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:10,alignItems:"end"}}>
                    <Field label="Hint: nmap service" hint="배너·서비스 이름 힌트로 확장자 추천에 반영됩니다.">
                      <input value={extHintSvc} onChange={e=>setExtHintSvc(e.target.value)} placeholder="e.g. nginx" style={inputStyle}/>
                    </Field>
                    <Field label="Hint: httpx / tech" hint="httpx 기술 스택 힌트입니다.">
                      <input value={extHintTech} onChange={e=>setExtHintTech(e.target.value)} placeholder="e.g. PHP/8.2" style={inputStyle}/>
                    </Field>
                    <div>
                      <button type="button" onClick={mergeRecommendedExts} style={{...actionButtonStyle,width:"100%",marginTop:16}}>Merge API recommendations</button>
                    </div>
                  </div>
                  <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
                    <input
                      value={ffufExtCustom}
                      onChange={e=>setFfufExtCustom(e.target.value)}
                      onKeyDown={e=>{ if (e.key === "Enter") { e.preventDefault(); addCustomFfufExt(); } }}
                      placeholder="Custom .ext"
                      style={{...inputStyle,flex:1,minWidth:160}}
                    />
                    <button type="button" onClick={addCustomFfufExt} style={actionButtonStyle}>Add custom</button>
                    <button type="button" onClick={()=>updateForm("ffuf_extensions", [])} style={{...actionButtonStyle,color:C.slate}}>Clear all</button>
                  </div>
                  <div style={{fontSize:10,color:C.slate,fontFamily:"JetBrains Mono, monospace"}}>
                    Selected: {(arrayOrEmpty(form.ffuf_extensions).length ? arrayOrEmpty(form.ffuf_extensions).join(", ") : "(auto)")}
                  </div>
                </div>
              </details>

              <details style={{border:`1px solid ${C.slateMid}`,borderRadius:6,background:"#0B1220"}}>
                <summary style={{fontSize:12,color:C.ink,cursor:"pointer",padding:"10px 12px"}}>
                  Proxy (전역)
                </summary>
                <div style={{display:"grid",gap:12,padding:"6px 12px 12px"}}>
                  <div style={{fontSize:10,color:C.slate,fontFamily:"JetBrains Mono, monospace"}}>SOCKS mode expects socks5://IP:PORT</div>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                    <Field label="Proxy mode" hint="none이면 직접 연결입니다.">
                      <select value={form.proxy_mode} onChange={e=>updateForm("proxy_mode", e.target.value)} style={inputStyle}>
                        <option value="none">none</option>
                        <option value="http">http</option>
                        <option value="socks">socks</option>
                      </select>
                    </Field>
                    <Field
                      label="Proxy URL"
                      hint={form.proxy_mode === "none" ? "프록시를 쓰지 않을 때는 비워 두세요. Proxy URL status: Proxy disabled" : `Proxy URL status: ${proxyStatus.label}. SOCKS는 socks5://호스트:포트 형식.`}
                    >
                      <input value={form.proxy_url} onChange={e=>updateForm("proxy_url", e.target.value)} placeholder="socks5://127.0.0.1:9050" style={inputStyle}/>
                    </Field>
                  </div>
                </div>
              </details>

              <details style={{border:`1px solid ${C.slateMid}`,borderRadius:6,background:"#0B1220"}}>
                <summary style={{fontSize:12,color:C.ink,cursor:"pointer",padding:"10px 12px"}}>
                  HTTP 헤더 · 쿠키 · 스코프
                </summary>
                <div style={{display:"grid",gap:12,padding:"6px 12px 12px"}}>
                  <Field
                    label="Extra headers"
                    hint={`요청마다 붙일 추가 헤더(한 줄에 Header: Value). 비우면 브라우저형 기본 헤더가 자동 적용됩니다.\n기본 세트 예시:\n${defaultExtraHeadersText ? defaultExtraHeadersText.split("\n").slice(0,5).join("\n") : "(로드 중)"}${defaultExtraHeadersText.split("\n").length > 5 ? "\n…" : ""}`}
                  >
                    <textarea value={form.extra_headers_text} onChange={e=>updateForm("extra_headers_text", e.target.value)} placeholder={defaultExtraHeadersText || "Header: Value"} style={{...inputStyle,minHeight:58}}/>
                  </Field>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12}}>
                    <Field label="Cookies" hint="세션 쿠키 문자열(선택)."><input value={form.cookies} onChange={e=>updateForm("cookies", e.target.value)} placeholder="name=value" style={inputStyle}/></Field>
                    <Field label="Bearer token" hint="Authorization Bearer(선택)."><input value={form.bearer_token} onChange={e=>updateForm("bearer_token", e.target.value)} placeholder="eyJ..." style={inputStyle}/></Field>
                    <Field label="Host header" hint="가상 호스트 지정(선택)."><input value={form.host_header} onChange={e=>updateForm("host_header", e.target.value)} placeholder="virtual.example" style={inputStyle}/></Field>
                  </div>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                    <Field
                      label="Scope include"
                      hint={"추가로 허용할 대상만 나열합니다(한 줄에 하나). Target에 여러 줄을 넣은 경우와 합쳐집니다.\n예시:\n  api.example.com\n  10.20.30.0/28\n  https://staging.internal/app"}
                    >
                      <textarea value={form.scope_include} onChange={e=>updateForm("scope_include", e.target.value)} placeholder={"예: api.example.com\n10.20.30.0/28\nhttps://staging.internal"} style={{...inputStyle,minHeight:64}}/>
                    </Field>
                    <Field
                      label="Scope exclude"
                      hint={"스캔에서 빼고 싶은 호스트·URL·CIDR(한 줄에 하나).\n예시:\n  192.168.1.1\n  old-bastion.corp.local\n  172.16.0.0/12"}
                    >
                      <textarea value={form.scope_exclude} onChange={e=>updateForm("scope_exclude", e.target.value)} placeholder={"예: 192.168.1.1\nold-bastion.corp.local\n172.16.0.0/12"} style={{...inputStyle,minHeight:64}}/>
                    </Field>
                  </div>
                </div>
              </details>
            </div>
          )}
        </div>
        <div style={{display:"flex",justifyContent:"flex-end",gap:10,padding:"14px 18px",borderTop:`1px solid ${C.slateMid}`}}>
          <button onClick={onClose} disabled={submitting} style={actionButtonStyle}>Cancel</button>
          {isEditConfigMode ? (
            <button onClick={()=>submit(false)} disabled={submitting} style={{padding:"7px 12px",border:`1px solid ${C.blueBorder}`,borderRadius:5,background:C.blueDim,color:C.sky,fontWeight:700,cursor:"pointer"}}>
              Save Config
            </button>
          ) : (
            <>
              <button onClick={()=>submit(false)} disabled={submitting} style={{...actionButtonStyle,color:C.ink}}>Create Scan</button>
              <button onClick={()=>submit(true)} disabled={submitting} style={{padding:"7px 12px",border:`1px solid ${C.blueBorder}`,borderRadius:5,background:C.blueDim,color:C.sky,fontWeight:700,cursor:"pointer"}}>
                Create & Start
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function PlaceholderPage({ title, runId }) {
  return (
    <div data-placeholder-page="vantage" style={{height:"100%",padding:28,overflow:"auto"}}>
      <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:22,color:C.inkBright,letterSpacing:"0.08em"}}>{title}</div>
      <div style={{marginTop:8,fontSize:12,color:C.slate}}>This route is wired into the React shell. Page content lands in a later phase.</div>
      <div style={{marginTop:18,display:"inline-block",fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.sky,
        border:`1px solid ${C.slateMid}`,borderRadius:5,padding:"8px 10px"}}>{runId}</div>
    </div>
  );
}

function PageFrame({ title, subtitle, children }) {
  return (
    <div style={{height:"100%",display:"flex",flexDirection:"column",overflow:"hidden"}}>
      <div style={{height:66,display:"flex",alignItems:"center",gap:12,padding:"0 24px",borderBottom:`1px solid ${C.slateMid}`,flexShrink:0}}>
        <div>
          <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:18,letterSpacing:"0.08em",color:C.inkBright}}>{title}</div>
          {subtitle&&<div style={{fontSize:11,color:C.slate}}>{subtitle}</div>}
        </div>
      </div>
      <div style={{flex:1,overflow:"auto",padding:24}}>{children}</div>
    </div>
  );
}

function RunPickerPage({ page, title, subtitle }) {
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(()=>{
    apiJson("/api/runs")
      .then(data=>{ setRuns(arrayOrEmpty(data.runs)); setError(""); })
      .catch(err=>setError(err.message || "Failed to load runs"))
      .finally(()=>setLoading(false));
  },[]);
  return (
    <PageFrame title={title} subtitle={subtitle || "Select a run to open this workspace view."}>
      {error&&<ErrorState msg={error}/>}
      {loading ? <LoadingState msg="Loading runs..."/> : (
        runs.length===0 ? (
          <div style={{display:"grid",gap:12,maxWidth:520}}>
            <EmptyState msg="No runs are available yet."/>
            <button type="button" onClick={()=>navigate("/runs?newScan=1")} style={{...actionButtonStyle,width:160,padding:"8px 10px"}}>+ New Scan</button>
          </div>
        ) : (
          <div style={{display:"grid",gap:8,maxWidth:880}}>
            {runs.map(run=>(
              <button key={run.run_id} type="button" onClick={()=>navigate(`/runs/${encodeURIComponent(run.run_id)}/${page}`)}
                style={{textAlign:"left",border:`1px solid ${C.slateMid}`,borderRadius:7,padding:12,background:C.slateDark,color:C.ink,cursor:"pointer"}}>
                <div style={{display:"flex",gap:10,alignItems:"center",justifyContent:"space-between"}}>
                  <span style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.sky}}>{run.run_id}</span>
                  <RunStatusPill run={run}/>
                </div>
                <div style={{marginTop:6,fontSize:12,color:C.slate}}>{run.target_display || run.target}</div>
              </button>
            ))}
          </div>
        )
      )}
    </PageFrame>
  );
}

const MODULE_OPTIONS = ["subdomain_enum","http_probe","domain_discovery","dir_enum","port_scan","banner_probe"];

function SettingsPanel({ label, children }) {
  return (
    <div style={{border:`1px solid ${C.slateMid}`,borderRadius:7,padding:14,background:C.slateDark}}>
      {label&&<SectionLabel>{label}</SectionLabel>}
      {children}
    </div>
  );
}

function ToolsEditor({ embedded=false }) {
  const [data, setData] = useState(null);
  const [edits, setEdits] = useState({});
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const load = useCallback(()=>{
    return apiJson("/api/system/tools").then(payload=>{
      setData(payload);
      setEdits(Object.fromEntries(arrayOrEmpty(payload.tools).map(tool=>[tool.name, tool.configured_path || ""])));
      setError("");
    }).catch(err=>setError(err.message || "Failed to load tools"));
  },[]);
  useEffect(()=>{ load(); },[load]);
  const save = () => {
    setSaving(true);
    apiJson("/api/system/tools", {method:"PATCH", body:JSON.stringify({tools: edits})})
      .then(payload=>{ setData(payload); setEdits(Object.fromEntries(arrayOrEmpty(payload.tools).map(tool=>[tool.name, tool.configured_path || ""]))); setError(""); })
      .catch(err=>setError(err.message || "Failed to save tools"))
      .finally(()=>setSaving(false));
  };
  const body = !data ? <LoadingState msg="Checking tools..."/> : (
    <div style={{display:"grid",gap:10}}>
      {arrayOrEmpty(data.tools).map(tool=>(
        <div key={tool.name} style={{display:"grid",gridTemplateColumns:"130px minmax(0,1fr) auto",gap:10,alignItems:"center",borderBottom:`1px solid ${C.slateMid}`,paddingBottom:10}}>
          <div>
            <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:13,color:C.inkBright}}>{tool.name}</div>
            <Tag color={tool.installed?"rgba(34,197,94,0.22)":"rgba(239,68,68,0.22)"}>{tool.installed?"ready":"missing"}</Tag>
          </div>
          <div>
            <input
              value={edits[tool.name] || ""}
              onChange={e=>setEdits(prev=>({...prev, [tool.name]: e.target.value}))}
              placeholder={tool.path || "absolute path or command name"}
              style={inputStyle}
            />
            <div style={{marginTop:5,fontFamily:"JetBrains Mono, monospace",fontSize:10,color:C.slate,wordBreak:"break-all"}}>{tool.custom ? "custom" : "auto"}: {tool.path || "not resolved"}</div>
            {tool.version&&<div style={{marginTop:4,fontSize:10,color:C.ink}}>{tool.version}</div>}
            {tool.error&&<div style={{marginTop:4,fontSize:10,color:"#FCA5A5"}}>{tool.error}</div>}
          </div>
          <button type="button" onClick={()=>setEdits(prev=>({...prev, [tool.name]: ""}))} style={actionButtonStyle}>Auto</button>
        </div>
      ))}
      <div style={{display:"flex",justifyContent:"flex-end"}}>
        <button type="button" onClick={save} disabled={saving} style={{...actionButtonStyle,padding:"7px 10px"}}>{saving?"Saving...":"Save Tools"}</button>
      </div>
    </div>
  );
  if (embedded) {
    return <SettingsPanel label="Tools">{error&&<ErrorState msg={error}/>} {body}</SettingsPanel>;
  }
  return <PageFrame title="Tools" subtitle="Scanner binary locations used by new runs.">{error&&<ErrorState msg={error}/>} {body}</PageFrame>;
}

function ToolInstaller({ embedded=false }) {
  const [status, setStatus] = useState(null);
  const [error, setError] = useState("");
  const [installing, setInstalling] = useState({});
  const [results, setResults] = useState({});
  const load = useCallback(()=>{
    return apiJson("/api/system/tools/install-status").then(payload=>{
      setStatus(payload);
      setError("");
    }).catch(err=>setError(err.message || "Failed to load install status"));
  },[]);
  useEffect(()=>{ load(); },[load]);
  const installOne = (name) => {
    setInstalling(prev=>({...prev, [name]: true}));
    apiJson("/api/system/tools/install", {method:"POST", body:JSON.stringify({tools:[name]})})
      .then(payload=>{
        setStatus(payload.status);
        const r = arrayOrEmpty(payload.results).find(x=>x.name===name);
        if (r) setResults(prev=>({...prev, [name]: r}));
      })
      .catch(err=>setError(err.message || `install ${name} failed`))
      .finally(()=>setInstalling(prev=>({...prev, [name]: false})));
  };
  const installAll = () => {
    const missing = arrayOrEmpty(status?.tools).filter(t=>!t.installed).map(t=>t.name);
    if (!missing.length) return;
    missing.forEach(n=>setInstalling(prev=>({...prev, [n]: true})));
    apiJson("/api/system/tools/install", {method:"POST", body:JSON.stringify({tools: missing})})
      .then(payload=>{
        setStatus(payload.status);
        const next = {};
        for (const r of arrayOrEmpty(payload.results)) next[r.name] = r;
        setResults(prev=>({...prev, ...next}));
      })
      .catch(err=>setError(err.message || "bulk install failed"))
      .finally(()=>setInstalling({}));
  };
  const body = !status ? <LoadingState msg="Checking tool installation status..."/> : (
    <div style={{display:"grid",gap:10}}>
      <div style={{display:"flex",gap:10,alignItems:"center",flexWrap:"wrap"}}>
        <Tag color={status.go_available?"rgba(34,197,94,0.22)":"rgba(239,68,68,0.22)"}>
          {status.go_available ? `Go: ${status.go_version}` : "Go runtime: NOT FOUND"}
        </Tag>
        <Tag color="rgba(56,189,248,0.18)">Platform: {status.platform}</Tag>
        <div style={{flex:1}}/>
        <button type="button" onClick={installAll} disabled={Object.values(installing).some(Boolean)}
          style={{...actionButtonStyle,padding:"6px 12px",background:C.blueDim,color:C.sky,borderColor:C.blueBorder}}>
          Install all missing
        </button>
        <button type="button" onClick={load} style={{...actionButtonStyle,padding:"6px 12px"}}>Refresh</button>
      </div>
      {!status.go_available&&(
        <div style={{padding:10,border:`1px solid ${C.slateMid}`,borderRadius:6,background:"#1F1A0A",fontSize:11,color:"#FCD34D",lineHeight:1.6}}>
          <b>Go runtime is required for most tools.</b> Install it first:<br/>
          <span style={{fontFamily:"JetBrains Mono, monospace"}}>
            macOS: brew install go &nbsp;·&nbsp;
            Windows: winget install GoLang.Go &nbsp;·&nbsp;
            Linux: sudo apt install golang-go
          </span>
        </div>
      )}
      {arrayOrEmpty(status.tools).map(tool=>{
        const result = results[tool.name];
        const busy = installing[tool.name];
        return (
          <div key={tool.name} style={{display:"grid",gridTemplateColumns:"130px minmax(0,1fr) auto",gap:10,alignItems:"start",borderBottom:`1px solid ${C.slateMid}`,paddingBottom:10}}>
            <div>
              <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:13,color:C.inkBright}}>{tool.name}</div>
              <Tag color={tool.installed?"rgba(34,197,94,0.22)":"rgba(239,68,68,0.22)"}>
                {tool.installed ? "installed" : "missing"}
              </Tag>
              <div style={{marginTop:4,fontSize:10,color:C.slate}}>{tool.type}</div>
            </div>
            <div>
              <div style={{fontSize:11,color:C.ink,wordBreak:"break-all"}}>{tool.path || "—"}</div>
              {tool.version&&<div style={{marginTop:4,fontSize:10,color:C.slate}}>{tool.version}</div>}
              <div style={{marginTop:4,fontFamily:"JetBrains Mono, monospace",fontSize:10,color:C.slate}}>
                ${tool.install_hint}
              </div>
              {tool.notes&&<div style={{marginTop:4,fontSize:10,color:"#FCD34D"}}>⚠ {tool.notes}</div>}
              {result&&!result.success&&(
                <details style={{marginTop:6,fontSize:10,color:"#FCA5A5"}}>
                  <summary style={{cursor:"pointer"}}>install failed — show details</summary>
                  <pre style={{whiteSpace:"pre-wrap",margin:"4px 0 0",fontFamily:"JetBrains Mono, monospace",fontSize:10,color:C.slate}}>{result.message}{"\n"}{result.stderr||result.stdout||""}</pre>
                </details>
              )}
              {result&&result.success&&(
                <div style={{marginTop:4,fontSize:10,color:"#86EFAC"}}>✓ {result.message}</div>
              )}
            </div>
            <button
              type="button"
              onClick={()=>installOne(tool.name)}
              disabled={busy || (tool.installed && !result)}
              style={{...actionButtonStyle,padding:"6px 10px",whiteSpace:"nowrap",
                background:tool.installed?"transparent":C.blueDim,
                color:tool.installed?C.slate:C.sky,
                borderColor:tool.installed?C.slateMid:C.blueBorder}}
            >
              {busy ? "Installing..." : (tool.installed ? "Reinstall" : "Install")}
            </button>
          </div>
        );
      })}
    </div>
  );
  if (embedded) {
    return <SettingsPanel label="Tool Installer">{error&&<ErrorState msg={error}/>} {body}</SettingsPanel>;
  }
  return <PageFrame title="Tool Installer" subtitle="Install missing external scanners (subzy, gau, naabu, dnsx, nmap, masscan, ...).">{error&&<ErrorState msg={error}/>} {body}</PageFrame>;
}

function ProfilesEditor({ embedded=false }) {
  const [profiles, setProfiles] = useState(null);
  const [form, setForm] = useState({key:"", label:"", description:"", profile:"balanced", modules:["http_probe","dir_enum"], defaults:"{}"});
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const load = useCallback(()=>{
    return apiJson("/api/presets")
      .then(payload=>{ setProfiles(Object.entries(payload.presets || {}).map(([key,value])=>({key, ...value}))); setError(""); })
      .catch(err=>setError(err.message || "Failed to load profiles"));
  },[]);
  useEffect(()=>{ load(); },[load]);
  const toggleModule = module => {
    setForm(prev=>{
      const current = new Set(arrayOrEmpty(prev.modules));
      current.has(module) ? current.delete(module) : current.add(module);
      return {...prev, modules: MODULE_OPTIONS.filter(item=>current.has(item))};
    });
  };
  const save = () => {
    let defaults = {};
    try { defaults = form.defaults.trim() ? JSON.parse(form.defaults) : {}; }
    catch { setError("Defaults JSON is invalid"); return; }
    setSaving(true);
    apiJson("/api/profiles", {
      method:"POST",
      body:JSON.stringify({key:form.key, label:form.label, description:form.description, profile:form.profile, modules:form.modules, defaults}),
    }).then(payload=>{
      setProfiles(Object.entries(payload.presets || {}).map(([key,value])=>({key, ...value})));
      setForm({key:"", label:"", description:"", profile:"balanced", modules:["http_probe","dir_enum"], defaults:"{}"});
      setError("");
    }).catch(err=>setError(err.message || "Failed to save profile")).finally(()=>setSaving(false));
  };
  const remove = key => {
    apiJson(`/api/profiles/${encodeURIComponent(key)}`, {method:"DELETE"})
      .then(payload=>{ setProfiles(Object.entries(payload.presets || {}).map(([k,value])=>({key:k, ...value}))); setError(""); })
      .catch(err=>setError(err.message || "Failed to delete profile"));
  };
  const body = !profiles ? <LoadingState msg="Loading profiles..."/> : (
    <div style={{display:"grid",gap:12}}>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(220px,1fr))",gap:10}}>
        {profiles.map(profile=>(
          <div key={profile.key} style={{border:`1px solid ${C.slateMid}`,borderRadius:6,padding:12,background:"#0B1220"}}>
            <div style={{display:"flex",justifyContent:"space-between",gap:8,alignItems:"start"}}>
              <div>
                <div style={{fontSize:14,fontWeight:700,color:C.inkBright}}>{profile.label || profile.key}</div>
                <div style={{marginTop:4,fontSize:11,color:C.slate,lineHeight:1.45}}>{profile.description}</div>
              </div>
              {profile.custom&&<Tag>custom</Tag>}
            </div>
            <div style={{marginTop:8,display:"flex",gap:5,flexWrap:"wrap"}}>{arrayOrEmpty(profile.modules).map(module=><Tag key={module}>{module}</Tag>)}</div>
            <div style={{marginTop:10,display:"flex",gap:6,flexWrap:"wrap"}}>
              <button type="button" onClick={()=>openNewScanModal({presetConfig:{preset:profile.key, modules:profile.modules, profile:profile.profile, ...objectOrEmpty(profile.defaults)}})} style={actionButtonStyle}>Use</button>
              {profile.custom&&<button type="button" onClick={()=>remove(profile.key)} style={{...actionButtonStyle,color:"#FCA5A5"}}>Delete</button>}
            </div>
          </div>
        ))}
      </div>
      <div style={{borderTop:`1px solid ${C.slateMid}`,paddingTop:12,display:"grid",gap:10}}>
        <div style={{display:"grid",gridTemplateColumns:"120px 1fr 140px",gap:8}}>
          <input value={form.key} onChange={e=>setForm(prev=>({...prev,key:e.target.value}))} placeholder="profile_key" style={inputStyle}/>
          <input value={form.label} onChange={e=>setForm(prev=>({...prev,label:e.target.value}))} placeholder="Display label" style={inputStyle}/>
          <select value={form.profile} onChange={e=>setForm(prev=>({...prev,profile:e.target.value}))} style={inputStyle}>
            {["safe","balanced","fast"].map(value=><option key={value} value={value}>{value}</option>)}
          </select>
        </div>
        <input value={form.description} onChange={e=>setForm(prev=>({...prev,description:e.target.value}))} placeholder="Description" style={inputStyle}/>
        <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
          {MODULE_OPTIONS.map(module=>(
            <label key={module} style={{display:"inline-flex",alignItems:"center",gap:5,fontSize:11,color:C.slate,border:`1px solid ${C.slateMid}`,borderRadius:4,padding:"4px 6px"}}>
              <input type="checkbox" checked={arrayOrEmpty(form.modules).includes(module)} onChange={()=>toggleModule(module)}/>
              {module}
            </label>
          ))}
        </div>
        <textarea value={form.defaults} onChange={e=>setForm(prev=>({...prev,defaults:e.target.value}))} style={{...inputStyle,minHeight:72,fontFamily:"JetBrains Mono, monospace"}} placeholder='{"nmap_ports":"80,443","ffuf_threads":20}'/>
        <div style={{display:"flex",justifyContent:"flex-end"}}>
          <button type="button" onClick={save} disabled={saving || !form.key || arrayOrEmpty(form.modules).length===0} style={{...actionButtonStyle,padding:"7px 10px"}}>{saving?"Saving...":"+ Save Profile"}</button>
        </div>
      </div>
    </div>
  );
  if (embedded) {
    return <SettingsPanel label="Profiles">{error&&<ErrorState msg={error}/>} {body}</SettingsPanel>;
  }
  return <PageFrame title="Profiles" subtitle="Built-in and custom scan profiles.">{error&&<ErrorState msg={error}/>} {body}</PageFrame>;
}

function WordlistsEditor({ embedded=false }) {
  const [data, setData] = useState(null);
  const [editing, setEditing] = useState(null);
  const [content, setContent] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const load = useCallback(()=>{
    return apiJson("/api/wordlists")
      .then(payload=>{ setData(payload); setError(""); })
      .catch(err=>setError(err.message || "Failed to load wordlists"));
  },[]);
  useEffect(()=>{ load(); },[load]);
  const edit = entry => {
    apiJson(`/api/wordlists/file?path=${encodeURIComponent(entry.path)}`)
      .then(payload=>{ setEditing(payload); setContent(payload.content || ""); setError(""); })
      .catch(err=>setError(err.message || "Failed to open wordlist"));
  };
  const save = () => {
    if (!editing) return;
    setSaving(true);
    apiJson("/api/wordlists/file", {method:"PATCH", body:JSON.stringify({path:editing.path, content})})
      .then(payload=>{ setEditing({...editing, ...payload, content}); return load(); })
      .catch(err=>setError(err.message || "Failed to save wordlist"))
      .finally(()=>setSaving(false));
  };
  const entries = arrayOrEmpty(data?.wordlist_entries);
  const visibleEntries = entries.slice(0, embedded ? 120 : 500);
  const hiddenCount = Math.max(0, entries.length - visibleEntries.length);
  const body = !data ? <LoadingState msg="Loading wordlists..."/> : (
    entries.length===0 ? <EmptyState msg="No .txt or .lst wordlists found under wordlists/."/> : (
      <div style={{display:"grid",gap:10}}>
        {editing&&(
          <div style={{border:`1px solid ${C.blueBorder}`,borderRadius:6,padding:12,background:C.selectedBg}}>
            <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.sky,marginBottom:8}}>{editing.path}</div>
            <textarea value={content} onChange={e=>setContent(e.target.value)} style={{...inputStyle,minHeight:embedded?140:260,fontFamily:"JetBrains Mono, monospace",resize:"vertical"}}/>
            <div style={{display:"flex",gap:8,justifyContent:"flex-end",marginTop:8}}>
              <button type="button" onClick={()=>setEditing(null)} style={actionButtonStyle}>Close</button>
              <button type="button" onClick={save} disabled={saving} style={{...actionButtonStyle,padding:"7px 10px"}}>{saving?"Saving...":"Save Wordlist"}</button>
            </div>
          </div>
        )}
        {hiddenCount>0&&<div style={{fontSize:12,color:C.slate}}>Showing first {visibleEntries.length} of {entries.length} discovered wordlists.</div>}
        <div data-wordlists-scroll="vantage" style={{maxHeight:embedded?260:420,overflow:"auto",border:`1px solid ${C.slateMid}`,borderRadius:6,background:"#0B1220"}}>
          <table style={{width:"100%",borderCollapse:"collapse"}}>
            <thead style={{position:"sticky",top:0,zIndex:1,background:"#0B1220"}}>
              <tr>{["Wordlist","Size","Lines","Action"].map(h=><th key={h} style={{textAlign:"left",padding:"8px 9px",fontSize:10,color:C.slate,textTransform:"uppercase",borderBottom:`1px solid ${C.slateMid}`}}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {visibleEntries.map(entry=>(
                <tr key={entry.path} style={{borderTop:`1px solid ${C.slateMid}`}}>
                  <td style={{padding:"8px 9px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.ink,wordBreak:"break-all"}}>{entry.label}</td>
                  <td style={{padding:"8px 9px",fontSize:11,color:C.slate,whiteSpace:"nowrap"}}>{entry.size_human}</td>
                  <td style={{padding:"8px 9px",fontSize:11,color:C.slate,whiteSpace:"nowrap"}}>{entry.lines_human}</td>
                  <td style={{padding:"8px 9px",display:"flex",gap:6}}>
                    <button type="button" onClick={()=>openNewScanModal({presetConfig:{ffuf_wordlist_path:entry.path, modules:["http_probe","dir_enum"]}})} style={actionButtonStyle}>Use</button>
                    <button type="button" onClick={()=>edit(entry)} disabled={!entry.editable} style={actionButtonStyle}>Edit</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    )
  );
  if (embedded) {
    return <SettingsPanel label="Wordlists">{error&&<ErrorState msg={error}/>} {body}</SettingsPanel>;
  }
  return <PageFrame title="Wordlists" subtitle="Workspace wordlists with editable .txt and .lst files.">{error&&<ErrorState msg={error}/>} {body}</PageFrame>;
}

function SystemToolsPage() {
  return <ToolsEditor/>;
}

function ProfilesPage() {
  return <ProfilesEditor/>;
}

function WordlistsPage() {
  return <WordlistsEditor/>;
}

function ArtifactsPage({ runId }) {
  const [rows, setRows] = useState([]);
  const [artifact, setArtifact] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(()=>{
    const load = runId
      ? apiJson(`/api/runs/${encodeURIComponent(runId)}`).then(view=>[view])
      : apiJson("/api/runs").then(data=>Promise.all(arrayOrEmpty(data.runs).map(run=>apiJson(`/api/runs/${encodeURIComponent(run.run_id)}`))));
    load.then(views=>{
      const artifacts = views.flatMap(view=>arrayOrEmpty(view.report?.artifacts?.items).map(item=>({...item, run_id:view.run?.run_id})));
      setRows(artifacts);
      setError("");
    }).catch(err=>setError(err.message || "Failed to load artifacts")).finally(()=>setLoading(false));
  },[runId]);
  return (
    <PageFrame title="Artifacts" subtitle={runId ? `Raw tool outputs for ${runId}` : "Raw tool outputs across all runs."}>
      {error&&<ErrorState msg={error}/>}
      {loading ? <LoadingState msg="Loading artifacts..."/> : (
        rows.length===0 ? <EmptyState msg="No artifacts have been saved yet."/> : <FindingsArtifactList rows={rows} onSelect={setArtifact}/>
      )}
      {artifact&&<FindingsArtifactSidePanel artifact={artifact} onClose={()=>setArtifact(null)}/>}
    </PageFrame>
  );
}

function ReportsPage({ runId }) {
  const [runs, setRuns] = useState([]);
  const [error, setError] = useState("");
  useEffect(()=>{
    apiJson("/api/runs")
      .then(data=>{ setRuns(arrayOrEmpty(data.runs)); setError(""); })
      .catch(err=>setError(err.message || "Failed to load reports"));
  },[]);
  const visible = runId ? runs.filter(run=>String(run.run_id) === String(runId)) : runs;
  return (
    <PageFrame title="Reports" subtitle={runId ? `HTML report for ${runId}` : "Review and open generated HTML reports."}>
      {error&&<ErrorState msg={error}/>}
      {visible.length===0 ? <EmptyState msg="No runs are available for reporting."/> : (
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(300px,1fr))",gap:12}}>
          {visible.map(run=>(
            <div key={run.run_id} style={{border:`1px solid ${C.slateMid}`,borderRadius:7,padding:14,background:C.slateDark,display:"grid",gap:12}}>
              <div>
                <div style={{display:"flex",justifyContent:"space-between",gap:10,alignItems:"center"}}>
                  <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.sky,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{run.run_id}</div>
                  <RunStatusPill run={run}/>
                </div>
                <div style={{marginTop:5,fontSize:13,color:C.inkBright,wordBreak:"break-word"}}>{run.target_display || run.target}</div>
                <KVTable rows={[
                  ["Profile", run.profile || run.config?.profile || "—"],
                  ["Progress", runProgressLabel(run)],
                  ["Hosts", run.host_count ?? run.hosts ?? "—"],
                  ["Findings", run.finding_count ?? run.findings ?? "—"],
                  ["Updated", formatDateTime(run.updated_at || run.created_at)],
                ]}/>
              </div>
              <div style={{display:"flex",gap:8,flexWrap:"wrap",justifyContent:"flex-end"}}>
                <button type="button" onClick={()=>navigate(`/runs/${encodeURIComponent(run.run_id)}/summary`)} style={{...actionButtonStyle,padding:"7px 9px"}}>Summary</button>
                <button type="button" onClick={()=>navigate(`/runs/${encodeURIComponent(run.run_id)}/findings`)} style={{...actionButtonStyle,padding:"7px 9px"}}>Findings</button>
                <button type="button" onClick={()=>window.open(`/api/runs/${encodeURIComponent(run.run_id)}/report.html`, "_blank", "noopener")} style={{...actionButtonStyle,padding:"7px 9px"}}>Open HTML</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </PageFrame>
  );
}

function WorkspaceDefaultsEditor() {
  const [settings, setSettings] = useState(null);
  const [form, setForm] = useState({
    profile:"safe",
    scan_mode:"balanced",
    nmap_ports:"1-1024",
    nmap_timing_template:"T3",
    nmap_version_detection:true,
    ffuf_wordlist_path:"wordlists/test.txt",
    httpx_threads:10,
    httpx_timeout_seconds:10,
    ffuf_threads:20,
    ffuf_concurrency:40,
    masscan_enabled:true,
    masscan_rate:10000,
    masscan_retries:2,
    naabu_enabled:true,
    naabu_rate:5000,
    naabu_retries:3,
    naabu_scan_type:"syn",
    subdomain_bruteforce_enabled:true,
  });
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const hydrate = payload => {
    const defaults = objectOrEmpty(payload.settings?.defaults);
    setSettings(payload);
    setForm(prev=>({
      ...prev,
      ...defaults,
      masscan_enabled: defaults.masscan_enabled !== false,
      masscan_rate: Number(defaults.masscan_rate || 10000),
      masscan_retries: Math.max(0, Number(defaults.masscan_retries ?? 2)),
      naabu_enabled: defaults.naabu_enabled !== false,
      naabu_rate: Number(defaults.naabu_rate || 5000),
      naabu_retries: Math.max(0, Number(defaults.naabu_retries ?? 3)),
      naabu_scan_type: (defaults.naabu_scan_type === "connect" ? "connect" : "syn"),
      subdomain_bruteforce_enabled: defaults.subdomain_bruteforce_enabled !== false,
    }));
    setError("");
  };
  useEffect(()=>{
    apiJson("/api/settings").then(hydrate).catch(err=>setError(err.message || "Failed to load settings"));
  },[]);
  const set = (key, value) => setForm(prev=>({...prev, [key]: value}));
  const numeric = value => {
    const n = Number(value);
    return Number.isFinite(n) ? n : 0;
  };
  const save = () => {
    setSaving(true);
    apiJson("/api/settings", {
      method:"PATCH",
      body:JSON.stringify({defaults:{
        profile: form.profile,
        scan_mode: form.scan_mode,
        nmap_ports: form.nmap_ports,
        nmap_timing_template: form.nmap_timing_template,
        nmap_version_detection: Boolean(form.nmap_version_detection),
        ffuf_wordlist_path: form.ffuf_wordlist_path,
        httpx_threads: numeric(form.httpx_threads),
        httpx_timeout_seconds: numeric(form.httpx_timeout_seconds),
        ffuf_threads: numeric(form.ffuf_threads),
        ffuf_concurrency: numeric(form.ffuf_concurrency),
        masscan_enabled: Boolean(form.masscan_enabled),
        masscan_rate: Math.max(100, numeric(form.masscan_rate) || 10000),
        masscan_retries: Math.max(0, Math.min(10, numeric(form.masscan_retries))),
        naabu_enabled: Boolean(form.naabu_enabled),
        naabu_rate: Math.max(100, numeric(form.naabu_rate) || 5000),
        naabu_retries: Math.max(0, Math.min(10, numeric(form.naabu_retries))),
        naabu_scan_type: (form.naabu_scan_type === "connect" ? "connect" : "syn"),
        subdomain_bruteforce_enabled: Boolean(form.subdomain_bruteforce_enabled),
      }}),
    }).then(hydrate).catch(err=>setError(err.message || "Failed to save settings")).finally(()=>setSaving(false));
  };
  return (
    <SettingsPanel label="Defaults">
      {error&&<ErrorState msg={error}/>}
      {!settings ? <LoadingState msg="Loading defaults..."/> : (
        <div style={{display:"grid",gap:10}}>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(180px,1fr))",gap:10}}>
            <Field label="Profile">
              <select value={form.profile} onChange={e=>set("profile", e.target.value)} style={inputStyle}>
                {["safe","balanced","fast"].map(value=><option key={value} value={value}>{value}</option>)}
              </select>
            </Field>
            <Field label="Scan mode">
              <select value={form.scan_mode} onChange={e=>set("scan_mode", e.target.value)} style={inputStyle}>
                {["fast","balanced","deep"].map(value=><option key={value} value={value}>{value}</option>)}
              </select>
            </Field>
            <Field label="Nmap ports"><input value={form.nmap_ports} onChange={e=>set("nmap_ports", e.target.value)} style={inputStyle}/></Field>
            <Field label="Nmap timing">
              <select value={form.nmap_timing_template} onChange={e=>set("nmap_timing_template", e.target.value)} style={inputStyle}>
                {["T2","T3","T4"].map(value=><option key={value} value={value}>{value}</option>)}
              </select>
            </Field>
            <Field label="FFUF wordlist"><input value={form.ffuf_wordlist_path} onChange={e=>set("ffuf_wordlist_path", e.target.value)} style={inputStyle}/></Field>
            <Field label="httpx threads"><input type="number" min={1} value={form.httpx_threads} onChange={e=>set("httpx_threads", Number(e.target.value))} style={inputStyle}/></Field>
            <Field label="httpx timeout"><input type="number" min={1} value={form.httpx_timeout_seconds} onChange={e=>set("httpx_timeout_seconds", Number(e.target.value))} style={inputStyle}/></Field>
            <Field label="ffuf threads"><input type="number" min={1} value={form.ffuf_threads} onChange={e=>set("ffuf_threads", Number(e.target.value))} style={inputStyle}/></Field>
            <Field label="ffuf concurrency"><input type="number" min={1} max={200} value={form.ffuf_concurrency} onChange={e=>set("ffuf_concurrency", Number(e.target.value))} style={inputStyle}/></Field>
          </div>
          <label style={{display:"inline-flex",gap:8,alignItems:"center",fontSize:12,color:C.slate}}>
            <input type="checkbox" checked={Boolean(form.nmap_version_detection)} onChange={e=>set("nmap_version_detection", e.target.checked)}/>
            Nmap version detection
          </label>
          <label style={{display:"inline-flex",gap:8,alignItems:"center",fontSize:12,color:C.slate}}>
            <input type="checkbox" checked={Boolean(form.masscan_enabled)} onChange={e=>set("masscan_enabled", e.target.checked)}/>
            Masscan (stateless SYN, 가장 빠름)
          </label>
          {form.masscan_enabled&&(
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginLeft:24}}>
              <Field label="Masscan rate (pps)">
                <input type="number" min={100} max={10000000} value={form.masscan_rate} onChange={e=>set("masscan_rate", Math.max(100, Number(e.target.value)||10000))} style={inputStyle}/>
              </Field>
              <Field label="Masscan retries">
                <input type="number" min={0} max={10} value={form.masscan_retries} onChange={e=>set("masscan_retries", Math.max(0, Math.min(10, Number(e.target.value)||0)))} style={inputStyle}/>
              </Field>
            </div>
          )}
          <label style={{display:"inline-flex",gap:8,alignItems:"center",fontSize:12,color:C.slate}}>
            <input type="checkbox" checked={Boolean(form.naabu_enabled)} onChange={e=>set("naabu_enabled", e.target.checked)}/>
            Naabu (재시도 내장 · masscan과 병렬 실행 시 합집합)
          </label>
          {form.naabu_enabled&&(
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:10,marginLeft:24}}>
              <Field label="Naabu rate (pps)">
                <input type="number" min={100} max={1000000} value={form.naabu_rate} onChange={e=>set("naabu_rate", Math.max(100, Number(e.target.value)||5000))} style={inputStyle}/>
              </Field>
              <Field label="Naabu retries">
                <input type="number" min={0} max={10} value={form.naabu_retries} onChange={e=>set("naabu_retries", Math.max(0, Math.min(10, Number(e.target.value)||0)))} style={inputStyle}/>
              </Field>
              <Field label="Naabu scan type">
                <select value={form.naabu_scan_type} onChange={e=>set("naabu_scan_type", e.target.value)} style={inputStyle}>
                  <option value="syn">syn</option>
                  <option value="connect">connect</option>
                </select>
              </Field>
            </div>
          )}
          <label style={{display:"inline-flex",gap:8,alignItems:"center",fontSize:12,color:C.slate}}>
            <input type="checkbox" checked={Boolean(form.subdomain_bruteforce_enabled)} onChange={e=>set("subdomain_bruteforce_enabled", e.target.checked)}/>
            DNS 브루트포스 (dnsx, 공통 서브도메인 ~70개)
          </label>
          <div style={{display:"flex",justifyContent:"flex-end"}}>
            <button type="button" onClick={save} disabled={saving} style={{...actionButtonStyle,padding:"7px 10px"}}>{saving?"Saving...":"Save Defaults"}</button>
          </div>
        </div>
      )}
    </SettingsPanel>
  );
}

function SettingsPage({ runId }) {
  const [runView, setRunView] = useState(null);
  const [error, setError] = useState("");
  useEffect(()=>{
    if (!runId) return;
    apiJson(`/api/runs/${encodeURIComponent(runId)}`)
      .then(view=>{ setRunView(view); setError(""); })
      .catch(err=>setError(err.message || "Failed to load run settings"));
  },[runId]);
  const config = objectOrEmpty(runView?.run?.config);
  const headers = objectOrEmpty(config.extra_headers);
  return (
    <PageFrame title="Settings" subtitle={runId ? `Run configuration and workspace defaults for ${runId}` : "Workspace defaults, tools, profiles, and wordlists."}>
      {error&&<ErrorState msg={error}/>}
      <div style={{display:"grid",gap:14}}>
        {runId&&(
          <SettingsPanel label="Run Config">
            <KVTable rows={[
              ["Target", runView?.run?.target || "Select a run for target-specific settings"],
              ["Profile", config.profile || "safe"],
              ["Scan mode", formatScanModeLabel(config.scan_mode || "balanced")],
              ["Nmap ports", config.nmap_ports || "1-1024"],
              ["FFUF wordlist", config.ffuf_wordlist_path || "wordlists/test.txt"],
              ["Extra headers", Object.keys(headers).length ? Object.keys(headers).join(", ") : "Default browser-like headers"],
            ]}/>
          </SettingsPanel>
        )}
        <WorkspaceDefaultsEditor/>
        <ToolsEditor embedded/>
        <ToolInstaller embedded/>
        <ProfilesEditor embedded/>
        <WordlistsEditor embedded/>
      </div>
    </PageFrame>
  );
}

function formatDateTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString();
}

function formatRelativeDuration(startIso, endIso) {
  if (!startIso) return "—";
  const start = new Date(startIso);
  const end = endIso ? new Date(endIso) : new Date();
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) return "—";
  const seconds = Math.max(0, Math.round((end - start) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

function taskStateColor(state) {
  const normalized = String(state || "").toLowerCase();
  if (normalized === "running") return C.blue;
  if (normalized === "completed") return "#22C55E";
  if (normalized === "failed") return "#EF4444";
  if (normalized === "pending" || normalized === "waiting") return "#EAB308";
  if (normalized === "skipped" || normalized === "cancelled") return C.muted;
  return C.slate;
}

function progressPercent(view) {
  const progress = view?.progress || {};
  const total = Number(progress.total_tasks || view?.tasks?.length || 0);
  const completed = Number(progress.completed_tasks || 0);
  if (!total) return 0;
  return Math.round((completed / total) * 100);
}

function pickPrimaryAction(view) {
  if (!view) return {kind:"none", label:"Loading"};
  const run = view.run || {};
  const counts = view.task_counts || {};
  if (view.execution?.active) return {kind:"cancel", label:"Cancel Run"};
  if (run.status === "completed") return {kind:"summary", label:"View Summary"};
  const pending = Number(counts.pending || 0);
  const failed = Number(counts.failed || 0);
  if (failed > 0 && pending === 0) return {kind:"retry", label:"Retry Failed"};
  if (pending > 0 || failed > 0) return {kind:run.started_at ? "resume" : "start", label:run.started_at ? "Resume" : "Start"};
  return {kind:"none", label:"No Action"};
}

function summarizeRun(view) {
  const run = view?.run || {};
  const report = view?.report || {};
  const sections = report.sections || {};
  const hostGroups = report.host_groups || [];
  const openPorts = sections.open_ports || [];
  const httpResults = sections.http_probe_results || [];
  const paths = sections.directory_findings || [];
  return {
    target: run.target_display || run.target || "—",
    profile: run.config?.profile || "—",
    scanMode: formatScanModeLabel(run.config?.scan_mode),
    status: run.status || "—",
    createdAt: formatDateTime(run.created_at),
    startedAt: formatDateTime(run.started_at),
    elapsed: formatRelativeDuration(run.started_at || run.created_at, run.completed_at),
    progress: `${progressPercent(view)}%`,
    hosts: hostGroups.length,
    aliveHosts: hostGroups.filter(host=>host.alive).length,
    openPorts: openPorts.length,
    httpEndpoints: httpResults.length,
    pathsFound: paths.length,
    findings: report.run_summary?.observed_finding_count || 0,
  };
}

function scanOptionsRows(configRaw) {
  const config = objectOrEmpty(configRaw);
  const modules = arrayOrEmpty(config.enabled_phases).map(item=>String(item)).filter(Boolean);
  const ffufExt = arrayOrEmpty(config.ffuf_extensions).map(item=>String(item)).filter(Boolean);
  const proxyMode = String(firstDefined(config.proxy_mode, "none") || "none");
  const proxyUrl = String(firstDefined(config.proxy_url, "") || "");
  const speed = objectOrEmpty(config.speed_config);
  const formatBool = value => (value ? "on" : "off");
  return [
    ["Profile", String(firstDefined(config.profile, "safe"))],
    ["Scan Mode", formatScanModeLabel(config.scan_mode)],
    ["Preset", String(firstDefined(config.preset, "custom"))],
    ["Modules", modules.length ? modules.join(", ") : "—"],
    ["Nmap Ports", String(firstDefined(config.nmap_ports, "—"))],
    ["Nmap Timing", String(firstDefined(config.nmap_timing_template, "—"))],
    ["Nmap Version Detection", formatBool(Boolean(config.nmap_version_detection))],
    ["FFUF Wordlist", String(firstDefined(config.ffuf_wordlist_path, "—")) || "—"],
    ["FFUF Concurrency", String(firstDefined(config.ffuf_concurrency, "—"))],
    ["FFUF Max Parallel", String(firstDefined(config.ffuf_max_parallel_tasks, "—"))],
    ["FFUF Recursion", formatBool(Boolean(config.dir_recursive_enabled))],
    ["FFUF Replay Proxy", String(firstDefined(config.ffuf_replay_proxy, "disabled")) || "disabled"],
    ["FFUF Extensions", ffufExt.length ? ffufExt.join(", ") : "auto"],
    ["Proxy", proxyMode === "none" ? "disabled" : `${proxyMode} ${proxyUrl || "(URL missing)"}`],
    ["Speed Level", String(firstDefined(config.speed_level, "—"))],
    ["Speed nmap", String(firstDefined(speed.nmap_timing, "—"))],
    ["Speed httpx", `${String(firstDefined(speed?.httpx?.concurrency, "—"))} / ${String(firstDefined(speed?.httpx?.rate, "—"))}`],
    ["Speed ffuf", `${String(firstDefined(speed?.ffuf?.threads, "—"))} / ${String(firstDefined(speed?.ffuf?.rate, "—"))}`],
  ];
}

function ExecutionOptionsCard({ config }) {
  return (
    <div data-execution-options="vantage" style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:7,padding:14}}>
      <SectionLabel>Scan Options</SectionLabel>
      <KVTable rows={scanOptionsRows(config)}/>
    </div>
  );
}

function ExecutionHeader({ runView, primary, secondary, busy, error, onPrimary, onSecondary, onRerunNow, onRerunEdit, progressInfo, qualityInfo }) {
  const run = runView?.run || {};
  const pct = Number(progressInfo?.barPercent || 0);
  const autoRec = runView?.run?.config?.auto_recommendation_enabled !== false;
  return (
    <div style={{padding:"18px 24px",borderBottom:`1px solid ${C.slateMid}`,display:"grid",gap:10,flexShrink:0}}>
      <div style={{display:"flex",alignItems:"center",gap:14}}>
        <div>
          <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:18,letterSpacing:"0.08em",color:C.inkBright}}>Run: {run.target_display || run.target || run.run_id || "Loading"}</div>
          <div style={{marginTop:5,fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>{run.run_id || ""}</div>
        </div>
        <RunStatusPill run={{...run, execution:runView?.execution}}/>
        <Tag color="#64748B">
          Scan mode: {formatScanModeLabel(runView?.run?.config?.scan_mode)}
        </Tag>
        <Tag color={autoRec ? C.blueDim : "rgba(100,116,139,0.25)"}>
          Auto Recommendation: {autoRec ? "ON" : "OFF"}
        </Tag>
        {runView?.execution?.active ? <Tag color="rgba(250,204,21,0.18)">Live tuning</Tag> : null}
        <Tag color="rgba(59,130,246,0.20)">Config changes apply to upcoming tasks only</Tag>
        <Tag color={C.blueDim}>
          {String(progressInfo?.label || "Progress: 0% (0/0 phases)")}
        </Tag>
        <Tag color={qualityInfo?.color || "#FCA5A5"}>
          Scan Quality: {String(qualityInfo?.label || "Incomplete")}
        </Tag>
        <div style={{flex:1}}/>
        <button onClick={onRerunNow} disabled={busy} style={actionButtonStyle}>Re-run</button>
        <button onClick={onRerunEdit} disabled={busy} style={actionButtonStyle}>Edit & Re-run</button>
        {secondary?.kind && secondary.kind !== "none" && (
          <button onClick={onSecondary} disabled={busy} style={actionButtonStyle}>{secondary.label}</button>
        )}
        {primary?.kind && primary.kind !== "none" && (
          <button onClick={onPrimary} disabled={busy} style={{padding:"8px 13px",borderRadius:5,border:`1px solid ${primary.kind==="cancel"?"rgba(239,68,68,0.45)":C.blueBorder}`,
            background:primary.kind==="cancel"?"rgba(239,68,68,0.10)":C.blueDim,color:primary.kind==="cancel"?"#FCA5A5":C.sky,fontWeight:700,cursor:busy?"default":"pointer"}}>
            {busy ? "Working..." : primary.label}
          </button>
        )}
      </div>
      <div style={{display:"grid",gap:6}}>
        <div style={{height:8,borderRadius:999,background:"#0B1220",border:`1px solid ${C.slateMid}`,overflow:"hidden"}}>
          <div style={{height:"100%",width:`${pct}%`,background:"linear-gradient(90deg, #2563EB 0%, #38BDF8 100%)"}}/>
        </div>
        <div style={{display:"flex",gap:10,alignItems:"center",flexWrap:"wrap",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>
          <span>{String(progressInfo?.label || "Progress: 0% (0/0 phases)")}</span>
          {progressInfo?.eta && <span>{progressInfo.eta}</span>}
        </div>
        <div style={{fontSize:11,color:C.slate}}>{String(qualityInfo?.detail || "")}</div>
      </div>
      {error&&<div style={{color:"#FCA5A5",fontSize:12}}>{error}</div>}
    </div>
  );
}

function RunStatsCard({ stats, progressInfo, qualityInfo }) {
  const rows = [
    ["Target", stats.target],
    ["Profile", stats.profile],
    ["Scan Mode", stats.scanMode],
    ["Status", stats.status],
    ["Created", stats.createdAt],
    ["Started", stats.startedAt],
    ["Elapsed", stats.elapsed],
    ["Progress", progressInfo?.label || stats.progress],
    ["ETA", progressInfo?.eta || "—"],
    ["Scan Quality", qualityInfo?.label || "—"],
    ["Hosts", stats.hosts],
    ["Alive Hosts", stats.aliveHosts],
    ["Open Ports", stats.openPorts],
    ["HTTP Endpoints", stats.httpEndpoints],
    ["Paths Found", stats.pathsFound],
  ];
  return (
    <div style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:7,padding:14}}>
      <SectionLabel>Run Summary</SectionLabel>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,minmax(0,1fr))",gap:10}}>
        {rows.map(([label,value])=>(
          <div key={label} style={{border:`1px solid ${C.slateMid}`,borderRadius:5,padding:"10px 11px",background:"#0B1220"}}>
            <div style={{fontSize:10,color:C.slate,textTransform:"uppercase",letterSpacing:"0.08em"}}>{label}</div>
            <div style={{marginTop:5,fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.ink,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{value ?? "—"}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function taskProgressLabel(task) {
  const progress = task.progress || {};
  if (progress.chunk_index && progress.chunk_total) {
    const lbl = progress.chunk_label ? ` ${String(progress.chunk_label).slice(0, 64)}` : "";
    const bits = [];
    if (typeof progress.cidr_estimated_remaining_min === "number" && isFinite(Number(progress.cidr_estimated_remaining_min))) {
      const eta = Number(progress.cidr_estimated_remaining_min);
      bits.push(eta > 0 && eta < 1 ? "~ <1 min remaining" : `~ ${Math.max(0, Math.round(eta))}m remaining`);
    }
    if (typeof progress.cidr_avg_chunk_min === "number" && isFinite(Number(progress.cidr_avg_chunk_min))) {
      bits.push(`(avg: ${Number(progress.cidr_avg_chunk_min).toFixed(1)}m/chunk)`);
    }
    const ds = progress.cidr_downstream_stage ? String(progress.cidr_downstream_stage) : "";
    if (ds && ds !== "chunk_done") {
      bits.push(`pipeline: ${ds.replace(/_/g, " ")}`);
    }
    return `Chunk ${progress.chunk_index}/${progress.chunk_total}${lbl}${bits.length ? " — " + bits.join(" ") : ""}`;
  }
  if (progress.percent !== undefined && progress.percent !== null) return `${Math.round(Number(progress.percent))}%`;
  if (progress.completed !== undefined && progress.total) return `${progress.completed}/${progress.total}`;
  return "—";
}

function canResumeCidrPortScan(task) {
  if (String(task?.module) !== "port_scan") return false;
  const c = task.cursor_json || {};
  if (!c.cidr_root) return false;
  if (!c.cidr_resume_in_progress) return false;
  const o = Number(c.cidr_next_offset);
  const t = Number(c.cidr_total_addresses);
  if (!Number.isFinite(o) || !Number.isFinite(t) || t <= 0) return false;
  if (o >= t) return false;
  const st = String(task.state || "");
  if (st === "running") return false;
  if (st !== "failed" && st !== "pending") return false;
  if (st === "failed" && !String(task.last_error || "").toLowerCase().includes("resumable")) return false;
  return true;
}

function TaskTimeline({ tasks, findingsByModule, onCidrResume, cidrResumeBusy }) {
  const rows = tasks || [];
  return (
    <div style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:7,padding:14}}>
      <SectionLabel>Execution Stack / Task Timeline</SectionLabel>
      {rows.length===0 ? <EmptyState msg="No execution tasks are saved for this run."/> : (
        <div style={{display:"grid",gap:8}}>
          {rows.map(task=>{
            const color = taskStateColor(task.state);
            const findings = task.progress?.findings_count ?? findingsByModule?.[task.module] ?? "—";
            const showCidr = canResumeCidrPortScan(task);
            return (
              <div key={task.task_id} style={{display:"grid",gridTemplateColumns:"180px 110px 90px 90px 1fr 100px 130px",gap:10,alignItems:"start",
                border:`1px solid ${C.slateMid}`,borderRadius:5,padding:"10px 11px",background:"#0B1220"}}>
                <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.ink}}>{task.module}</div>
                <div style={{display:"inline-flex",alignItems:"center",gap:6,color,fontSize:11,textTransform:"capitalize"}}>
                  <span style={{width:7,height:7,borderRadius:"50%",background:color}}/>
                  {task.state}
                </div>
                <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.sky}}>{taskProgressLabel(task)}</div>
                <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>{findings}</div>
                <div>
                  <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{task.scope || task.tool || task.task_id}</div>
                  {task.last_error&&<div style={{marginTop:4,color:"#FCA5A5",fontSize:11,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{task.last_error}</div>}
                  {(task.progress?.chunk_index && task.progress?.chunk_total) && (
                    <div style={{marginTop:6,maxWidth:300}}>
                      <div style={{height:6,borderRadius:999,background:"#111827",border:`1px solid ${C.slateMid}`,overflow:"hidden"}}>
                        <div
                          style={{
                            height:"100%",
                            width:`${Math.max(0, Math.min(100, Math.round((Number(task.progress.chunk_index) / Number(task.progress.chunk_total || 1)) * 100)))}%`,
                            background:"linear-gradient(90deg, #2563EB 0%, #38BDF8 100%)",
                          }}
                        />
                      </div>
                    </div>
                  )}
                </div>
                <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>{formatRelativeDuration(task.started_at, task.completed_at)}</div>
                <div style={{display:"flex",justifyContent:"flex-end",alignItems:"start"}}>
                  {showCidr && typeof onCidrResume === "function" ? (
                    <button type="button" onClick={onCidrResume} disabled={!!cidrResumeBusy} style={{...actionButtonStyle,padding:"6px 10px",fontSize:11}}>
                      {cidrResumeBusy ? "…" : "Resume scan"}
                    </button>
                  ) : <span style={{fontSize:10,color:C.slate}}>&nbsp;</span>}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function mergeCheckpointTaskLogs(tasks) {
  const out = [];
  (tasks || []).forEach(t=>{
    const ev = t && t.cursor_json && t.cursor_json.cidr_checkpoint_events;
    if (Array.isArray(ev)) {
      ev.forEach(e=>{
        if (!e || !e.message) return;
        out.push({
          timestamp: e.ts || e.timestamp,
          level: e.level || "info",
          module: e.module || t.module,
          message: e.message,
        });
      });
    }
    const scanWarnings = t && t.cursor_json && t.cursor_json.nmap_scan_warnings;
    if (Array.isArray(scanWarnings)) {
      scanWarnings.forEach(e=>{
        if (!e || !e.message) return;
        out.push({
          timestamp: e.ts || e.timestamp,
          level: e.level || "warning",
          module: e.module || t.module,
          message: e.message,
        });
      });
    }
    const statsLine = String(firstDefined(t?.cursor_json?.tool_progress?.stats_line, "") || "").trim();
    if (statsLine && String(t?.module || "") === "port_scan") {
      out.push({
        timestamp: t?.updated_at || null,
        level: "info",
        module: "port_scan",
        message: `[nmap stats] ${statsLine}`,
      });
    }
  });
  return out;
}

function mergeExecutionLogRows(apiLogs, tasks) {
  const ck = mergeCheckpointTaskLogs(tasks);
  const base = (apiLogs || []).map(x=>({...x}));
  const all = base.concat(ck);
  return all
    .filter(x=>x && (x.message || x.timestamp))
    .sort((a,b)=>{
      const ta = a.timestamp ? new Date(a.timestamp).getTime() : 0;
      const tb = b.timestamp ? new Date(b.timestamp).getTime() : 0;
      return ta - tb;
    })
    .slice(-220);
}

function phaseProgressFromTasks(tasks, currentModule = "", mode = "current") {
  const rows = arrayOrEmpty(tasks);
  const moduleOrder = [];
  const byModule = new Map();
  rows.forEach(task=>{
    const moduleName = String(task?.module || "").trim();
    if (!moduleName) return;
    if (!byModule.has(moduleName)) {
      byModule.set(moduleName, []);
      moduleOrder.push(moduleName);
    }
    byModule.get(moduleName).push(String(task?.state || ""));
  });
  const total = moduleOrder.length;
  if (total <= 0) return "(0/0)";
  const completed = moduleOrder.filter(moduleName=>byModule.get(moduleName).every(state=>state === "completed")).length;
  const currentIndex = Math.max(1, moduleOrder.indexOf(String(currentModule || "")) + 1);
  if (mode === "completed") return `(${Math.max(completed, currentIndex)}/${total})`;
  if (mode === "started" || mode === "failed" || mode === "checkpoint") return `(${currentIndex}/${total})`;
  return `(${completed}/${total})`;
}

function phaseProgressCounts(tasks) {
  const rows = arrayOrEmpty(tasks);
  const byModule = new Map();
  const etaCandidates = [];
  rows.forEach(task=>{
    const moduleName = String(task?.module || "").trim();
    if (!moduleName) return;
    if (!byModule.has(moduleName)) byModule.set(moduleName, []);
    byModule.get(moduleName).push(String(task?.state || ""));
    const etaMin = Number(firstDefined(task?.progress?.cidr_estimated_remaining_min, task?.cursor_json?.cidr_estimated_remaining_min, NaN));
    if (Number.isFinite(etaMin) && etaMin >= 0) etaCandidates.push(Math.round(etaMin));
  });
  const total = byModule.size;
  if (total <= 0) return { completed: 0, total: 0, percent: 0, etaMin: null };
  const completed = Array.from(byModule.values()).filter(states=>states.every(state=>state === "completed")).length;
  const percent = Math.max(0, Math.min(100, Math.round((completed / total) * 100)));
  return {
    completed,
    total,
    percent,
    etaMin: etaCandidates.length ? Math.max(0, Math.min(...etaCandidates)) : null,
  };
}

function formatProgress({ percent, completed, total, etaMin }) {
  const safeTotal = Math.max(0, Number(total || 0));
  const safeCompleted = Math.max(0, Number(completed || 0));
  const safePercent = Math.max(0, Math.min(100, Number(percent || 0)));
  const normalizedPercent = safeTotal > 0 ? Math.max(safePercent, Math.round((safeCompleted / safeTotal) * 100)) : safePercent;
  const done = normalizedPercent >= 100 || (safeTotal > 0 && safeCompleted >= safeTotal);
  return {
    label: `Progress: ${normalizedPercent}% (${safeCompleted}/${safeTotal} phases)`,
    eta: done
      ? "Completed"
      : (
        Number.isFinite(Number(etaMin)) && Number(etaMin) >= 0
          ? (Number(etaMin) > 0 && Number(etaMin) < 1 ? "~ <1 min remaining" : `~ ${Math.round(Number(etaMin))} min remaining`)
          : null
      ),
    barPercent: normalizedPercent,
  };
}

function taskEtaLabel(task) {
  const eta = Number(firstDefined(task?.progress?.cidr_estimated_remaining_min, task?.cursor_json?.cidr_estimated_remaining_min, NaN));
  if (!Number.isFinite(eta) || eta < 0) return "";
  if (eta > 0 && eta < 1) return "~ <1 min remaining";
  return `~ ${Math.max(0, Math.round(eta))} min remaining`;
}

function parseNmapStatsLine(statsLine) {
  const raw = String(statsLine || "").trim();
  if (!raw) return null;
  const percentMatch = raw.match(/(\d+(?:\.\d+)?)%\s*done/i);
  const remainingMatch = raw.match(/\((?:(\d+):)?(\d+):(\d+)\s+remaining\)/i);
  const elapsedMatch = raw.match(/\((?:(\d+):)?(\d+):(\d+)\s+elapsed\)/i);
  const speedMatch = raw.match(/([0-9]+(?:\.[0-9]+)?)\s*(pkt\/s|pps)/i);
  const etcMatch = raw.match(/ETC:\s*([0-9]{1,2}:[0-9]{2}(?::[0-9]{2})?)/i);
  const percent = percentMatch ? Math.max(0, Math.min(100, Math.round(Number(percentMatch[1])))) : null;
  let etaMin = null;
  if (remainingMatch) {
    const h = Number(remainingMatch[1] || 0);
    const m = Number(remainingMatch[2] || 0);
    const s = Number(remainingMatch[3] || 0);
    etaMin = Math.max(0, Math.round((h * 60) + m + (s / 60)));
  }
  let elapsedSec = null;
  if (elapsedMatch) {
    const h = Number(elapsedMatch[1] || 0);
    const m = Number(elapsedMatch[2] || 0);
    const s = Number(elapsedMatch[3] || 0);
    elapsedSec = Math.max(0, (h * 3600) + (m * 60) + s);
  }
  const scanRate = speedMatch ? `${speedMatch[1]} ${String(speedMatch[2] || "").toLowerCase()}` : "";
  const etcTime = etcMatch ? String(etcMatch[1] || "").trim() : "";
  if (percent === null && etaMin === null && elapsedSec === null && !scanRate && !etcTime) return null;
  return { percent, etaMin, elapsedSec, scanRate, etcTime, raw };
}

function pickPortScanTask(tasks) {
  const rows = arrayOrEmpty(tasks);
  return rows.find(task=>String(task?.module || "") === "port_scan" && String(firstDefined(task?.state, "")) === "running")
    || rows.find(task=>String(task?.module || "") === "port_scan" && String(firstDefined(task?.state, "")) === "pending")
    || rows.find(task=>String(task?.module || "") === "port_scan");
}

function nmapProgressColor(percentValue) {
  const pct = Number(percentValue || 0);
  if (pct < 30) return "#38BDF8";
  if (pct < 70) return "#FDE68A";
  return "#86EFAC";
}

function NmapProgressCard({ task, runConfig }) {
  const tool = objectOrEmpty(task?.cursor_json?.tool_progress);
  const parsed = parseNmapStatsLine(tool.stats_line);
  const percent = Number(firstDefined(tool.progress_percent, parsed?.percent, tool.percent, 0));
  const safePercent = Math.max(0, Math.min(100, Math.round(percent)));
  const etaMin = Number(firstDefined(
    tool.estimated_remaining_min,
    parsed?.etaMin,
    task?.progress?.cidr_estimated_remaining_min,
    task?.cursor_json?.cidr_estimated_remaining_min,
    NaN,
  ));
  const etaText = Number.isFinite(etaMin)
    ? (etaMin > 0 && etaMin < 1 ? "~ <1 min remaining" : `~ ${Math.max(0, Math.round(etaMin))} min remaining`)
    : "";
  const chunkIndex = Number(firstDefined(task?.progress?.chunk_index, task?.cursor_json?.cidr_chunk_index, 0));
  const chunkTotal = Number(firstDefined(task?.progress?.chunk_total, task?.cursor_json?.cidr_chunk_total, 0));
  const hasChunk = chunkIndex > 0 && chunkTotal > 0;
  const barColor = nmapProgressColor(safePercent);
  const cidrTarget = String(firstDefined(task?.cursor_json?.cidr_root, task?.scope, "") || "").trim();
  const totalHosts = Number(firstDefined(task?.cursor_json?.cidr_total_addresses, NaN));
  const scannedHosts = Number.isFinite(totalHosts) ? Math.max(0, Math.min(totalHosts, Math.round((safePercent / 100) * totalHosts))) : null;
  const elapsedSec = Number(firstDefined(parsed?.elapsedSec, NaN));
  const elapsedText = Number.isFinite(elapsedSec)
    ? `${Math.floor(elapsedSec / 60)}m ${Math.max(0, Math.floor(elapsedSec % 60))}s`
    : "n/a";
  const speedText = String(firstDefined(parsed?.scanRate, "") || "").trim() || "n/a";
  const timingRaw = String(firstDefined(runConfig?.nmap_timing_template, "") || "").trim().toUpperCase();
  const timingLevel = Number((timingRaw.match(/^T([0-5])$/) || [])[1] || NaN);
  const portsRaw = String(firstDefined(runConfig?.nmap_ports, "") || "");
  const slowReasons = [];
  if (portsRaw.includes("1-65535")) slowReasons.push("Large port range (1-65535)");
  if (Number.isFinite(timingLevel) && timingLevel <= 2) slowReasons.push(`Low timing profile (${timingRaw || "T2"})`);
  const showSlowHint = safePercent > 0 && safePercent < 95 && (etaMin >= 8 || speedText === "n/a") && slowReasons.length > 0;
  if (!task || (!tool.stats_line && !Number.isFinite(Number(tool.percent)))) return null;
  return (
    <div style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:7,padding:14}}>
      <SectionLabel>Port Scan Progress</SectionLabel>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:12,marginBottom:8}}>
        <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>
          {hasChunk ? `Chunk ${chunkIndex}/${chunkTotal}` : "Chunk info unavailable"}{Number.isFinite(scannedHosts) ? `  ${scannedHosts}/${totalHosts} hosts` : ""}
        </div>
        <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.inkBright}}>{safePercent}%</div>
      </div>
      <div style={{height:8,borderRadius:999,background:"#111827",border:`1px solid ${C.slateMid}`,overflow:"hidden"}}>
        <div style={{height:"100%",width:`${safePercent}%`,background:barColor,transition:"width 450ms ease, background 250ms ease"}}/>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"minmax(0,1fr) minmax(0,1fr)",gap:10,marginTop:10}}>
        <div style={{fontSize:11,color:C.slate,display:"flex",alignItems:"center",gap:6}}>
          <span>🌐</span>
          <span>Target CIDR: {cidrTarget || "n/a"}</span>
        </div>
        <div style={{fontSize:11,color:C.slate,textAlign:"right"}}>
          ETC: {String(firstDefined(parsed?.etcTime, "") || "").trim() || "n/a"}
        </div>
        <div style={{fontSize:11,color:C.slate}}>⏱ ETA: {etaText || "n/a"}</div>
        <div style={{fontSize:11,color:C.slate,textAlign:"right"}}>⚡ Speed: {speedText}</div>
        <div style={{fontSize:11,color:C.slate}}>Elapsed: {elapsedText}</div>
        <div style={{fontSize:11,color:C.slate,textAlign:"right"}}>{hasChunk ? `Chunk ${chunkIndex}/${chunkTotal}` : "Chunk n/a"}</div>
      </div>
      {showSlowHint && (
        <div style={{marginTop:8,padding:"7px 9px",borderRadius:6,border:`1px solid ${C.slateMid}`,background:"#111827"}}>
          <div style={{fontSize:11,color:"#FDE68A"}}>Slow scan detected: {slowReasons.join(" | ")}</div>
          <div style={{fontSize:11,color:C.slate,marginTop:3}}>Suggestion: Reduce port range or increase timing (T4)</div>
        </div>
      )}
      {!parsed && (
        <div style={{marginTop:8,fontSize:11,color:C.slate}} title={String(tool.stats_line || "")}>
          Raw stats fallback: {String(tool.stats_line || "").slice(0, 140)}
        </div>
      )}
      {parsed && !showSlowHint && (
        <div style={{marginTop:8,fontSize:11,color:C.slate}} title={parsed.raw}>
          {parsed.raw}
        </div>
      )}
    </div>
  );
}

function scanQualitySummary(tasks) {
  const rows = arrayOrEmpty(tasks);
  if (!rows.length) return { level: "incomplete", label: "Incomplete", color: "#FCA5A5", detail: "No scan tasks yet." };
  const qualities = rows
    .map(task=>String(firstDefined(task?.cursor_json?.scan_quality, "") || ""))
    .filter(Boolean);
  const hasIncomplete = qualities.includes("incomplete") || rows.some(task=>String(task?.state || "") === "failed");
  const hasPartial = qualities.includes("partial") || rows.some(task=>Boolean(task?.cursor_json?.possible_filtered || task?.cursor_json?.suspicious_result));
  if (hasIncomplete) {
    return { level: "incomplete", label: "Incomplete", color: "#FCA5A5", detail: "At least one task failed or ended resumable." };
  }
  if (hasPartial) {
    return { level: "partial", label: "Partial (possible filtering)", color: "#FDE68A", detail: "No open ports found quickly; firewall/ICMP/rate limiting may affect results." };
  }
  return { level: "full", label: "Full scan", color: "#86EFAC", detail: "Tasks completed without quality warnings." };
}

function LiveLogs({ logs }) {
  const ref = useRef(null);
  useEffect(()=>{ if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; },[logs]);
  const rows = (logs || []).slice(-200);
  return (
    <div style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:7,padding:14,minHeight:260,display:"flex",flexDirection:"column"}}>
      <SectionLabel>Live Logs</SectionLabel>
      {rows.length===0 ? <EmptyState msg="No live logs yet."/> : (
        <pre ref={ref} style={{flex:1,overflow:"auto",background:"#0B1220",border:`1px solid ${C.slateMid}`,borderRadius:5,padding:12,
          color:C.ink,fontFamily:"JetBrains Mono, monospace",fontSize:11,lineHeight:1.55,whiteSpace:"pre-wrap"}}>
          {rows.map(item=>{
            const stamp = item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : "--:--:--";
            const level = String(item.level || "info").toUpperCase();
            const module = item.module ? ` (${item.module})` : "";
            const data = item.data || {};
            const changedFields = data && typeof data === "object" ? data.changed_fields : null;
            const pairs = changedFields && typeof changedFields === "object"
              ? Object.entries(changedFields).slice(0, 3).map(([key, pair])=>{
                  const from = Array.isArray(pair) ? pair[0] : undefined;
                  const to = Array.isArray(pair) ? pair[1] : undefined;
                  return `${key}: ${String(from)} -> ${String(to)}`;
                })
              : [];
            const applyScope = data && typeof data.apply_scope === "string" ? data.apply_scope : "";
            const extra = [pairs.join(", "), applyScope].filter(Boolean).join(" | ");
            return `[${stamp}] [${level}]${module} ${item.message || ""}${extra ? ` | ${extra}` : ""}`;
          }).join("\n")}
        </pre>
      )}
    </div>
  );
}

function RecentArtifacts({ artifacts }) {
  const rows = artifacts || [];
  return (
    <div style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:7,padding:14}}>
      <SectionLabel>Recent Artifacts</SectionLabel>
      {rows.length===0 ? <EmptyState msg="No raw artifacts have been saved yet."/> : (
        <table style={{width:"100%",borderCollapse:"collapse"}}>
          <thead><tr>{["Path","Module/Tool","Size","Created"].map(h=><th key={h} style={{textAlign:"left",padding:"7px 8px",fontSize:10,color:C.slate,textTransform:"uppercase"}}>{h}</th>)}</tr></thead>
          <tbody>
            {rows.slice(-8).reverse().map(item=>(
              <tr key={item.artifact_id || item.path} style={{borderTop:`1px solid ${C.slateMid}`}}>
                <td style={{padding:"8px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.ink}}>{String(item.path || "").split(/[\\/]/).pop() || item.path || "artifact"}</td>
                <td style={{padding:"8px",fontSize:11,color:C.slate}}>{item.module || "—"} / {item.tool || "—"}</td>
                <td style={{padding:"8px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>{item.size_bytes ? `${(Number(item.size_bytes)/1024).toFixed(1)}KB` : "—"}</td>
                <td style={{padding:"8px",fontSize:11,color:C.slate}}>{formatDateTime(item.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function AutoDirscanTriggerPanel({ tasks }) {
  const rows = arrayOrEmpty(tasks)
    .filter(task=>String(task?.module || "") === "dir_enum" && String(task?.scope || "").startsWith("incremental:dir_enum:"))
    .map(task=>({
      taskId: String(task.task_id || ""),
      state: String(task.state || ""),
      triggerTask: String(firstDefined(task?.cursor_json?.trigger_task_id, "") || ""),
      scope: String(task.scope || ""),
      updatedAt: String(task.updated_at || ""),
    }));
  if (!rows.length) return null;
  return (
    <div style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:7,padding:14}}>
      <SectionLabel>Auto dirscan triggers</SectionLabel>
      <div style={{display:"grid",gap:7}}>
        {rows.slice(0, 8).map(item=>(
          <div key={item.taskId || item.scope} style={{border:`1px solid ${C.slateMid}`,borderRadius:6,padding:"8px 10px",background:"#0B1220"}}>
            <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.ink}}>
              {item.scope}
            </div>
            <div style={{marginTop:4,fontSize:10,color:C.slate}}>
              state={item.state} · trigger_task_id={item.triggerTask || "n/a"} · updated={item.updatedAt ? formatDateTime(item.updatedAt) : "n/a"}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ExecutionPage({ runId }) {
  const toast = useToast();
  const [runView, setRunView] = useState(null);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");
  const [actionBusy, setActionBusy] = useState(false);
  const prevStatusRef = useRef("");
  const taskStateRef = useRef(new Map());
  const checkpointSeenRef = useRef(new Set());

  const loadRun = () => apiJson(`/api/runs/${encodeURIComponent(runId)}`)
    .then(data=>{setRunView(data); setError(""); return data;})
    .catch(err=>{setError(err.message); throw err;})
    .finally(()=>setLoading(false));
  const loadLogs = () => apiJson(`/api/runs/${encodeURIComponent(runId)}/logs`)
    .then(data=>setLogs(data.items || []))
    .catch(()=>{});

  useEffect(()=>{
    setRunView(null);
    setLogs([]);
    setLoading(true);
    taskStateRef.current = new Map();
    checkpointSeenRef.current = new Set();
    prevStatusRef.current = "";
    loadRun().catch(()=>{});
    loadLogs();
  },[runId]);

  const rerunNow = async () => {
    if (!runView?.run?.run_id) return;
    setActionError("");
    setActionBusy(true);
    try {
      const sourceId = String(runView.run.run_id);
      const cloned = await apiJson(`/api/runs/${encodeURIComponent(sourceId)}/clone-config`);
      const payload = {
        ...cloned,
        target: String(cloned.target || runView.run.target || "").trim(),
        source_run_id: sourceId,
        include_notes_context: true,
        auto_start: false,
      };
      const created = await apiJson("/api/runs", { method:"POST", body:JSON.stringify(payload) });
      const newRunId = created.run?.run_id || created.run_id;
      await apiJson(`/api/runs/${encodeURIComponent(newRunId)}/execute`, { method:"POST", body:JSON.stringify({}) });
      navigate(`/runs/${encodeURIComponent(newRunId)}/execution`);
    } catch (err) {
      setActionError(err.message || "Re-run failed");
    } finally {
      setActionBusy(false);
    }
  };

  const rerunEdit = async () => {
    if (!runView?.run?.run_id) return;
    setActionError("");
    try {
      const sourceId = String(runView.run.run_id);
      const prefill = await buildRerunPrefill(sourceId);
      openNewScanModal({ presetConfig: prefill, mode: "rerun" });
    } catch (err) {
      setActionError(err.message || "Edit & Re-run failed");
    }
  };

  const isPolling = Boolean(runView?.execution?.active || ["pending","running"].includes(runView?.run?.status));
  useEffect(()=>{
    if (!isPolling) return;
    const runTimer = setInterval(()=>loadRun().catch(()=>{}), 2500);
    const logTimer = setInterval(loadLogs, 1500);
    return () => { clearInterval(runTimer); clearInterval(logTimer); };
  },[isPolling, runId]);

  const doAction = async kind => {
    setActionError("");
    if (kind === "summary") {
      navigate(`/runs/${encodeURIComponent(runId)}/summary`);
      return;
    }
    setActionBusy(true);
    try {
      if (kind === "cancel") {
        await apiJson(`/api/runs/${encodeURIComponent(runId)}/cancel`, {method:"POST", body:JSON.stringify({})});
        toast.push({type:"warning", title:"Scan cancelled"});
      } else {
        await apiJson(`/api/runs/${encodeURIComponent(runId)}/execute`, {method:"POST", body:JSON.stringify({})});
        toast.push({type:"info", title:`Scan started ${phaseProgressFromTasks(runView?.tasks, "", "current")}`, actionLabel:"View execution", onAction:()=>navigate(`/runs/${encodeURIComponent(runId)}/execution`)});
      }
      await loadRun();
      await loadLogs();
    } catch (err) {
      setActionError(err.message);
      toast.push({type:"error", title:"Scan failed", description: err.message, priority:"high", actionLabel:"Retry", onAction:()=>doAction("execute")});
    } finally {
      setActionBusy(false);
    }
  };

  useEffect(()=>{
    const current = String(runView?.run?.status || "");
    const prev = prevStatusRef.current;
    if (!current) return;
    if (prev && prev !== current) {
      if (current === "completed") {
        toast.push({
          type:"success",
          title:"Scan complete",
          actionLabel:"View results",
          onAction:()=>navigate(`/runs/${encodeURIComponent(runId)}/summary`),
        });
      } else if (current === "failed") {
        toast.push({type:"error", title:"Scan failed", description: String(runView?.run?.last_error || "Execution failed")});
      }
    }
    prevStatusRef.current = current;
  }, [runView?.run?.status, runId]);

  useEffect(()=>{
    if (!runView?.tasks) return;
    const previous = taskStateRef.current;
    const next = new Map();
    arrayOrEmpty(runView.tasks).forEach(task=>{
      const taskId = String(task.task_id || "");
      if (!taskId) return;
      const prevState = String(previous.get(taskId) || "");
      const nowState = String(task.state || "");
      next.set(taskId, nowState);
      if (!prevState || prevState === nowState) return;
      const moduleName = String(task.module || "task");
      const startedProgress = phaseProgressFromTasks(runView.tasks, moduleName, "started");
      const completedProgress = phaseProgressFromTasks(runView.tasks, moduleName, "completed");
      const failedProgress = phaseProgressFromTasks(runView.tasks, moduleName, "failed");
      const etaText = taskEtaLabel(task);
      if (nowState === "running") {
        const autoDirscan = moduleName === "dir_enum" && String(task.scope || "").startsWith("incremental:dir_enum:");
        toast.push({
          type:"info",
          title:`${moduleName} started ${startedProgress}`,
          description: autoDirscan ? "Auto-triggered from http_probe web response" : (etaText || undefined),
          priority:"low",
          actionLabel:"View execution",
          onAction:()=>navigate(`/runs/${encodeURIComponent(runId)}/execution`),
        });
      } else if (nowState === "completed") {
        toast.push({ type:"success", title:`${moduleName} completed ${completedProgress}`, description: etaText || undefined, priority:"low", actionLabel:"View results", onAction:()=>navigate(`/runs/${encodeURIComponent(runId)}/summary`) });
      } else if (nowState === "failed") {
        toast.push({ type:"error", title:`${moduleName} failed ${failedProgress}`, description:[String(task.last_error || "Task failed"), etaText].filter(Boolean).join(" — "), priority:"high", actionLabel:"Retry", onAction:()=>doAction("execute") });
      }
    });
    taskStateRef.current = next;
  }, [runView?.tasks, runId]);

  useEffect(()=>{
    arrayOrEmpty(runView?.tasks).forEach(task=>{
      const taskId = String(task.task_id || "");
      const checkpointEvents = arrayOrEmpty(task?.cursor_json?.cidr_checkpoint_events)
        .map(event=>({...event, toastTitle:"checkpoint reached"}));
      const warningEvents = arrayOrEmpty(task?.cursor_json?.nmap_scan_warnings)
        .map(event=>({...event, toastTitle: event.requires_privilege_escalation ? "SYN 스캔 권한 없음" : "nmap fallback"}));
      const events = checkpointEvents.concat(warningEvents);
      events.forEach(event=>{
        const key = `${taskId}|${String(firstDefined(event.ts, event.timestamp, event.message, ""))}`;
        if (!key || checkpointSeenRef.current.has(key)) return;
        checkpointSeenRef.current.add(key);
        const moduleName = String(task.module || "port_scan");
        const checkpointProgress = phaseProgressFromTasks(runView?.tasks, moduleName, "checkpoint");
        if (event.requires_privilege_escalation) {
          toast.push({
            type: "error",
            title: "SYN 스캔(-sS) 실패 — TCP connect(-sT)로 전환됨",
            description: "raw socket 권한이 없어 스텔스 스캔을 사용할 수 없습니다. sudo로 재실행하거나 nmap에 권한을 부여하세요.",
            priority: "high",
            actionLabel: "권한 부여 방법",
            onAction: ()=>navigate(`/runs/${encodeURIComponent(runId)}/execution`),
          });
        } else {
          toast.push({
            type: "warning",
            title: `${event.toastTitle || "checkpoint reached"} ${checkpointProgress}`,
            description: [String(event.message || `${task.module || "port_scan"} checkpoint`), taskEtaLabel(task)].filter(Boolean).join(" — "),
            priority: "low",
            actionLabel: "View execution",
            onAction: ()=>navigate(`/runs/${encodeURIComponent(runId)}/execution`),
          });
        }
      });
    });
  }, [runView?.tasks, runId]);

  const primary = pickPrimaryAction(runView);
  const counts = runView?.task_counts || {};
  const secondary = !runView?.execution?.active && primary.kind !== "retry" && Number(counts.failed || 0) > 0
    ? {kind:"retry", label:"Retry Failed"}
    : {kind:"none", label:""};
  const stats = summarizeRun(runView);
  const phaseProgress = phaseProgressCounts(runView?.tasks);
  const progressInfo = formatProgress(phaseProgress);
  const qualityInfo = scanQualitySummary(runView?.tasks);
  const report = runView?.report || {};
  const artifacts = report.artifacts?.items || [];
  const findingsByModule = report.findings?.by_module || {};
  const complete = runView?.run?.status === "completed";
  const activePortScanTask = pickPortScanTask(runView?.tasks);

  return (
    <div data-execution-page="vantage" style={{height:"100%",display:"flex",flexDirection:"column",overflow:"hidden"}}>
      <ExecutionHeader runView={runView} primary={primary} secondary={secondary} busy={actionBusy} error={actionError} progressInfo={progressInfo} qualityInfo={qualityInfo}
        onPrimary={()=>doAction(primary.kind)} onSecondary={()=>doAction(secondary.kind)} onRerunNow={rerunNow} onRerunEdit={rerunEdit}/>
      <div style={{flex:1,overflow:"auto",padding:24,display:"grid",gap:14}}>
        {loading&&<LoadingState msg="Loading execution state..."/>}
        {error&&<ErrorState msg={error}/>}
        {complete&&(
          <div style={{display:"flex",alignItems:"center",gap:12,border:"1px solid rgba(34,197,94,0.45)",borderRadius:7,padding:13,background:"rgba(34,197,94,0.08)"}}>
            <div style={{color:"#86EFAC",fontWeight:700}}>Scan complete</div>
            <button onClick={()=>navigate(`/runs/${encodeURIComponent(runId)}/summary`)} style={{...actionButtonStyle,color:"#86EFAC",borderColor:"rgba(34,197,94,0.45)"}}>View Summary</button>
          </div>
        )}
        {(()=>{
          const privWarnings = arrayOrEmpty(runView?.tasks).flatMap(t=>
            arrayOrEmpty(t?.cursor_json?.nmap_scan_warnings).filter(e=>e?.requires_privilege_escalation)
          );
          if (!privWarnings.length) return null;
          return (
            <div style={{border:"1px solid rgba(239,68,68,0.5)",borderRadius:7,padding:"12px 16px",background:"rgba(239,68,68,0.08)",display:"grid",gap:8}}>
              <div style={{display:"flex",alignItems:"center",gap:8}}>
                <span style={{color:"#F87171",fontWeight:700,fontSize:13}}>⚠ SYN 스캔(-sS) 실패 — TCP connect(-sT)로 전환됨</span>
              </div>
              <div style={{fontSize:12,color:C.slate,lineHeight:1.6}}>
                raw socket 권한이 없어 스텔스 스캔을 사용할 수 없습니다. 정확한 포트 스캔을 위해 아래 방법 중 하나로 권한을 부여하세요.
              </div>
              <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,background:"#0B1220",border:`1px solid ${C.slateMid}`,borderRadius:5,padding:"10px 12px",display:"grid",gap:6,color:C.inkBright}}>
                <div style={{color:C.muted,marginBottom:2}}>{"# 방법 1: 앱 전체를 sudo로 실행"}</div>
                <div>sudo python3 -m scanner.ui</div>
                <div style={{color:C.muted,marginTop:4}}>{"# 방법 2: nmap에만 권한 부여 (Linux)"}</div>
                <div>sudo setcap cap_net_raw+eip $(which nmap)</div>
                <div style={{color:C.muted,marginTop:4}}>{"# 방법 3: nmap setuid 설정 (macOS/Linux)"}</div>
                <div>sudo chmod u+s $(which nmap)</div>
              </div>
            </div>
          );
        })()}
        {runView&&<RunStatsCard stats={stats} progressInfo={progressInfo} qualityInfo={qualityInfo}/>}
        {runView&&<ExecutionOptionsCard config={runView?.run?.config}/>}
        {runView&&<TaskTimeline tasks={runView.tasks || []} findingsByModule={findingsByModule}
          onCidrResume={() => doAction("execute")} cidrResumeBusy={actionBusy}/>}
        {runView&&<NmapProgressCard task={activePortScanTask} runConfig={runView?.run?.config}/>}
        {runView&&<AutoDirscanTriggerPanel tasks={runView?.tasks}/>}
        <div style={{display:"grid",gridTemplateColumns:"minmax(0,1.2fr) minmax(340px,0.8fr)",gap:14,alignItems:"start"}}>
          <LiveLogs logs={mergeExecutionLogRows(logs, runView?.tasks)}/>
          <RecentArtifacts artifacts={artifacts}/>
        </div>
      </div>
    </div>
  );
}

function RunSummaryPage({ runId }) {
  const route = useRoute();
  const [runView, setRunView] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [allRuns, setAllRuns] = useState([]);
  const [compareRunId, setCompareRunId] = useState(route.search.get("compare") || "");
  const [diffData, setDiffData] = useState(null);

  const rerunNow = async () => {
    if (!runView?.run?.run_id) return;
    setError("");
    try {
      const sourceId = String(runView.run.run_id);
      const cloned = await apiJson(`/api/runs/${encodeURIComponent(sourceId)}/clone-config`);
      const payload = {
        ...cloned,
        target: String(cloned.target || runView.run.target || "").trim(),
        source_run_id: sourceId,
        include_notes_context: true,
        auto_start: false,
      };
      const created = await apiJson("/api/runs", { method:"POST", body:JSON.stringify(payload) });
      const newRunId = created.run?.run_id || created.run_id;
      await apiJson(`/api/runs/${encodeURIComponent(newRunId)}/execute`, { method:"POST", body:JSON.stringify({}) });
      navigate(`/runs/${encodeURIComponent(newRunId)}/execution`);
    } catch (err) {
      setError(err.message || "Re-run failed");
    }
  };

  const rerunEdit = async () => {
    if (!runView?.run?.run_id) return;
    setError("");
    try {
      const sourceId = String(runView.run.run_id);
      const prefill = await buildRerunPrefill(sourceId);
      openNewScanModal({ presetConfig: prefill, mode: "rerun" });
    } catch (err) {
      setError(err.message || "Edit & Re-run failed");
    }
  };

  useEffect(()=>{
    setRunView(null);
    setLoading(true);
    setError("");
    apiJson(`/api/runs/${encodeURIComponent(runId)}`)
      .then(data=>setRunView(data))
      .catch(err=>setError(err.message))
      .finally(()=>setLoading(false));
  },[runId]);
  useEffect(()=>{
    apiJson("/api/runs")
      .then(data=>setAllRuns(arrayOrEmpty(data.runs)))
      .catch(()=>setAllRuns([]));
  }, [runId]);
  useEffect(()=>{
    setCompareRunId(route.search.get("compare") || "");
  }, [route.search.get("compare")]);
  useEffect(()=>{
    if (!compareRunId) {
      setDiffData(null);
      return;
    }
    apiJson(`/api/runs/${encodeURIComponent(runId)}/diff?baseline=${encodeURIComponent(compareRunId)}`)
      .then(data=>setDiffData(data))
      .catch(()=>setDiffData(null));
  }, [runId, compareRunId]);

  const summary = summarizeReport(runView);
  const summaryQuality = scanQualitySummary(runView?.tasks);
  const compareOptions = arrayOrEmpty(allRuns)
    .filter(item=>String(item.id) !== String(runId) && String(item.status) === "completed")
    .map(item=>({id:String(item.id), label:String(firstDefined(item.display_name, item.target, item.id))}));
  const changeAlerts = useMemo(
    ()=>buildChangeAlerts({ diffData, runId, model: null }),
    [diffData, runId]
  );
  const onBaselineChange = nextId => {
    const params = new URLSearchParams(route.search.toString());
    if (nextId) params.set("compare", nextId);
    else params.delete("compare");
    navigate(`/runs/${encodeURIComponent(runId)}/summary${params.toString() ? `?${params.toString()}` : ""}`);
  };

  return (
    <div data-run-summary-page="vantage" style={{height:"100%",display:"flex",flexDirection:"column",overflow:"hidden"}}>
      <RunSummaryHeader runView={runView} runId={runId} onRerunNow={rerunNow} onRerunEdit={rerunEdit}/>
      <div style={{flex:1,overflow:"auto",padding:24,display:"grid",gap:14}}>
        {loading&&<LoadingState msg="Loading run summary..."/>}
        {error&&<ErrorState msg={error}/>}
        {runView&&(
          <>
            {!summary.hasData&&(
              <div style={{border:`1px solid ${C.slateMid}`,borderRadius:7,padding:16,background:C.slateDark}}>
                <EmptyState msg="No findings yet. Run has not produced results."/>
              </div>
            )}
            <SummaryCards runId={runId} stats={summary.cards}/>
            <div style={{border:`1px solid ${C.slateMid}`,borderRadius:7,padding:12,background:C.slateDark}}>
              <SectionLabel>Scan Quality</SectionLabel>
              <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
                <Tag color={summaryQuality.color}>{summaryQuality.label}</Tag>
                <span style={{fontSize:11,color:C.slate}}>{summaryQuality.detail}</span>
              </div>
            </div>
            <ChangeAlertsPanel
              alerts={changeAlerts}
              baselineRunId={compareRunId}
              compareOptions={compareOptions}
              onChangeBaseline={onBaselineChange}
            />
            <div style={{display:"grid",gridTemplateColumns:"minmax(0,1fr) minmax(320px,0.85fr)",gap:14,alignItems:"start"}}>
              <DistributionBars title="HTTP Status Distribution" rows={summary.statusBuckets}/>
              <DistributionBars title="Top Ports" rows={summary.portBuckets}/>
            </div>
            <RecentHostsTable runId={runId} rows={summary.hostRows}/>
          </>
        )}
      </div>
    </div>
  );
}

function countValue(items) {
  return Array.isArray(items) ? items.length : "—";
}

function evidenceValue(item, key) {
  const evidence = item?.evidence || {};
  return evidence[key];
}

function statusCodeOf(item) {
  const value = evidenceValue(item, "status_code");
  if (value === undefined || value === null || value === "") return null;
  return String(value);
}

function bucketRows(values, limit = 8) {
  const counts = new Map();
  values.filter(Boolean).forEach(value=>counts.set(value, (counts.get(value) || 0) + 1));
  const rows = Array.from(counts.entries())
    .map(([label,count])=>({label, count}))
    .sort((a,b)=>b.count-a.count || String(a.label).localeCompare(String(b.label)))
    .slice(0, limit);
  const max = Math.max(1, ...rows.map(row=>row.count));
  return rows.map(row=>({...row, width:Math.max(8, Math.round((row.count / max) * 100))}));
}

function summarizeReport(runView) {
  const report = runView?.report || {};
  const sections = report.sections || {};
  const hostGroups = Array.isArray(report.host_groups) ? report.host_groups : [];
  const openPorts = Array.isArray(sections.open_ports) ? sections.open_ports : null;
  const httpResults = Array.isArray(sections.http_probe_results) ? sections.http_probe_results : null;
  const directoryFindings = Array.isArray(sections.directory_findings) ? sections.directory_findings : null;
  const candidateCves = Array.isArray(sections.candidate_cves) ? sections.candidate_cves : null;
  const cveCount = candidateCves ? candidateCves.length : (report.run_summary?.candidate_cve_count ?? "—");

  const hostRows = hostGroups.map(host=>({
    host: host.host || "unknown",
    ipAddresses: Array.isArray(host.ip_addresses) ? host.ip_addresses : [],
    portsCount: Number(host.open_ports_count || 0),
    httpCount: Array.isArray(host.http_probe) ? host.http_probe.length : 0,
    directoriesCount: Number(host.directory_findings_count || 0),
    cveCount: Number(host.candidate_cve_count || 0),
  })).map(host=>({
    ...host,
    findingsCount: host.portsCount + host.httpCount + host.directoriesCount + host.cveCount,
  }));

  const httpStatusValues = [
    ...(httpResults || []),
    ...(directoryFindings || []),
  ].map(statusCodeOf);
  const portValues = (openPorts || []).map(item=>{
    const port = evidenceValue(item, "port");
    const protocol = evidenceValue(item, "protocol");
    if (!port) return null;
    return protocol ? `${protocol}/${port}` : String(port);
  });

  const hasData = hostGroups.length > 0
    || (openPorts && openPorts.length > 0)
    || (httpResults && httpResults.length > 0)
    || (directoryFindings && directoryFindings.length > 0)
    || (candidateCves && candidateCves.length > 0);

  return {
    hasData,
    cards: {
      hosts: Array.isArray(report.host_groups) ? hostGroups.length : "—",
      aliveHosts: Array.isArray(report.host_groups) ? hostGroups.filter(host=>host.alive).length : "—",
      openPorts: countValue(openPorts),
      httpEndpoints: countValue(httpResults),
      directories: countValue(directoryFindings),
      cveCandidates: cveCount,
    },
    statusBuckets: bucketRows(httpStatusValues),
    portBuckets: bucketRows(portValues),
    hostRows,
  };
}

function RunSummaryHeader({ runView, runId, onRerunNow, onRerunEdit }) {
  const run = runView?.run || {};
  const autoRec = runView?.run?.config?.auto_recommendation_enabled !== false;
  return (
    <div style={{padding:"18px 24px",borderBottom:`1px solid ${C.slateMid}`,display:"flex",alignItems:"center",gap:14,flexShrink:0}}>
      <div>
        <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:18,letterSpacing:"0.08em",color:C.inkBright}}>Run Summary</div>
        <div style={{marginTop:5,fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>{run.target_display || run.target || run.run_id || runId}</div>
      </div>
      <RunStatusPill run={{...run, execution:runView?.execution}}/>
      <Tag color="#64748B">Scan mode: {formatScanModeLabel(runView?.run?.config?.scan_mode)}</Tag>
      <Tag color={autoRec ? C.blueDim : "rgba(100,116,139,0.25)"}>Auto Recommendation: {autoRec ? "ON" : "OFF"}</Tag>
      <Tag color="rgba(59,130,246,0.20)">Config changes apply to upcoming tasks only</Tag>
      <div style={{flex:1}}/>
      <button onClick={onRerunNow} style={actionButtonStyle}>Re-run</button>
      <button onClick={onRerunEdit} style={actionButtonStyle}>Edit & Re-run</button>
      {["Compare","Preview Report","Export"].map(label=>(
        <button key={label} onClick={()=>{}} style={actionButtonStyle}>{label}</button>
      ))}
    </div>
  );
}

function SummaryCard({ label, value, hint, onClick }) {
  const [hover, setHover] = useState(false);
  const handleKey = event => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onClick();
    }
  };
  return (
    <div role="button" tabIndex="0" onClick={onClick} onKeyDown={handleKey} onMouseEnter={()=>setHover(true)} onMouseLeave={()=>setHover(false)}
      style={{border:`1px solid ${hover?C.blueBorder:C.slateMid}`,borderRadius:7,padding:"13px 14px",
        background:hover?C.blueDim:"#0B1220",cursor:"pointer",transition:"border-color 0.12s, background 0.12s"}}>
      <div style={{fontSize:10,color:C.slate,textTransform:"uppercase",letterSpacing:"0.1em"}}>{label}</div>
      <div style={{marginTop:7,fontFamily:"JetBrains Mono, monospace",fontSize:20,color:C.inkBright}}>{value ?? "—"}</div>
      <div style={{marginTop:4,fontSize:11,color:hover?C.sky:C.slate}}>{hint}</div>
    </div>
  );
}

function SummaryCards({ runId, stats }) {
  const go = tab => navigate(`/runs/${encodeURIComponent(runId)}/findings?tab=${encodeURIComponent(tab)}`);
  const cards = [
    ["Hosts", stats.hosts, "Host inventory", "hosts"],
    ["Alive Hosts", stats.aliveHosts, "Responsive assets", "hosts"],
    ["Open Ports", stats.openPorts, "Service exposure", "ports"],
    ["HTTP Endpoints", stats.httpEndpoints, "Web surfaces", "http"],
    ["Directories", stats.directories, "Discovered paths", "directories"],
    ["CVE Candidates", stats.cveCandidates, "Candidate only", "cve"],
  ];
  return (
    <div style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:7,padding:14}}>
      <SectionLabel>Summary Cards</SectionLabel>
      <div style={{display:"grid",gridTemplateColumns:"repeat(6,minmax(120px,1fr))",gap:10}}>
        {cards.map(([label,value,hint,tab])=>(
          <SummaryCard key={label} label={label} value={value} hint={hint} onClick={()=>go(tab)}/>
        ))}
      </div>
    </div>
  );
}

function DistributionBars({ title, rows }) {
  return (
    <div style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:7,padding:14}}>
      <SectionLabel>{title}</SectionLabel>
      {rows.length===0 ? <EmptyState msg="No data"/> : (
        <div style={{display:"grid",gap:9}}>
          {rows.map(row=>(
            <div key={row.label} style={{display:"grid",gridTemplateColumns:"82px 1fr 42px",gap:10,alignItems:"center"}}>
              <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.ink,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{row.label}</div>
              <div style={{height:8,background:"#0B1220",border:`1px solid ${C.slateMid}`,borderRadius:999,overflow:"hidden"}}>
                <div style={{width:`${row.width}%`,height:"100%",background:C.blue}}/>
              </div>
              <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.sky,textAlign:"right"}}>{row.count}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function RecentHostsTable({ runId, rows }) {
  const hostRows = rows || [];
  return (
    <div style={{background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:7,padding:14}}>
      <SectionLabel>Recent Hosts</SectionLabel>
      {hostRows.length===0 ? <EmptyState msg="No findings yet. Run has not produced results."/> : (
        <table style={{width:"100%",borderCollapse:"collapse"}}>
          <thead>
            <tr style={{borderBottom:`1px solid ${C.slateMid}`}}>
              {["Host / IP","Ports","HTTP","Findings"].map(header=>(
                <th key={header} style={{textAlign:"left",padding:"8px 9px",fontSize:10,color:C.slate,textTransform:"uppercase",letterSpacing:"0.08em"}}>{header}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {hostRows.slice(0,12).map((host,index)=>(
              <tr key={`${host.host}-${index}`} onClick={()=>navigate(`/runs/${encodeURIComponent(runId)}/findings?host=${encodeURIComponent(host.host)}`)}
                style={{borderTop:index===0?"none":`1px solid ${C.navy}`,cursor:"pointer"}}>
                <td style={{padding:"9px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.ink}}>
                  <div>{host.host}</div>
                  <div style={{marginTop:3,color:C.slate,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{host.ipAddresses.join(", ") || "—"}</div>
                </td>
                <td style={{padding:"9px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.sky}}>{host.portsCount}</td>
                <td style={{padding:"9px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.sky}}>{host.httpCount}</td>
                <td style={{padding:"9px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.sky}}>{host.findingsCount}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function firstDefined(...values) {
  return values.find(value => value !== undefined && value !== null && value !== "");
}

function findingEvidence(item) {
  return objectOrEmpty(item?.evidence);
}

function findingUrl(item) {
  const evidence = findingEvidence(item);
  return String(firstDefined(evidence.url, item?.target, "") || "");
}

function safeUrl(value) {
  try { return new URL(value); }
  catch {
    try { return new URL(`http://${value}`); }
    catch { return null; }
  }
}

function hostFromFinding(item, fallback = "Unknown host") {
  const evidence = findingEvidence(item);
  if (String(evidence.type || "") === "domain_mapping" && evidence.ip) {
    return String(evidence.ip);
  }
  if (String(evidence.type || "") === "banner" && evidence.host) {
    return String(evidence.host);
  }
  const url = safeUrl(String(firstDefined(evidence.url, item?.target, "") || ""));
  return String(firstDefined(evidence.host, evidence.hostname, url?.hostname, item?.host, fallback) || fallback);
}

function portProtocolFromFinding(item) {
  const evidence = findingEvidence(item);
  const url = safeUrl(String(firstDefined(evidence.url, item?.target, "") || ""));
  const protocol = String(firstDefined(evidence.protocol, url?.protocol?.replace(":", ""), "tcp") || "tcp").toLowerCase();
  let port = firstDefined(evidence.port, url?.port, protocol === "https" ? 443 : (protocol === "http" ? 80 : ""));
  port = port === "" ? "unknown" : String(port);
  return {port, protocol};
}

function makeServiceId(port, protocol) {
  return `${String(protocol || "tcp").toLowerCase()}/${String(port || "unknown")}`;
}

function serviceIsWeb(service) {
  const protocol = String(service?.protocol || "").toLowerCase();
  const name = String(service?.serviceName || "").toLowerCase();
  const port = Number(service?.port);
  return Boolean(service?.isWeb || ["http","https"].includes(protocol) || name.includes("http") || [80,443,8080,8443].includes(port));
}

function serviceLikelyScheme(service) {
  const protocol = String(service?.protocol || "").toLowerCase();
  const name = String(service?.serviceName || "").toLowerCase();
  const port = Number(service?.port || 0);
  if (protocol.includes("https") || name.includes("https") || [443, 8443].includes(port)) return "https";
  return "http";
}

function serviceTargetPayload(host, service) {
  const hostLabel = String(host?.label || "").trim();
  const port = Number(service?.port || 0);
  const scheme = serviceLikelyScheme(service);
  const base_url = (scheme === "https" && port === 443) || (scheme === "http" && port === 80)
    ? `${scheme}://${hostLabel}/`
    : `${scheme}://${hostLabel}:${port}/`;
  return {
    host: hostLabel,
    port,
    scheme,
    base_url,
    service_id: service?.id || null,
  };
}

function recommendedWordlistFromHint(techTextRaw) {
  const techText = String(techTextRaw || "").toLowerCase();
  if (techText.includes("wordpress")) return "wordlists/SecLists-master/Discovery/Web-Content/CMS/wordpress.txt";
  if (techText.includes("nginx")) return "wordlists/SecLists-master/Discovery/Web-Content/raft-medium-directories.txt";
  if (techText.includes("apache")) return "wordlists/SecLists-master/Discovery/Web-Content/apache.txt";
  return "wordlists/SecLists-master/Discovery/Web-Content/common.txt";
}

function serviceTechnologies(service) {
  const out = [];
  const seen = new Set();
  arrayOrEmpty(service?.findings?.http).forEach(item=>{
    const ev = findingEvidence(item);
    arrayOrEmpty(ev.technologies).forEach(tech=>{
      const t = String(tech || "").trim();
      const key = t.toLowerCase();
      if (!t || seen.has(key)) return;
      seen.add(key);
      out.push(t);
    });
  });
  return out.slice(0, 4);
}

const REASON_LABEL = {
  already_scanned: "Already scanned",
  duplicate_pending: "Already queued",
  duplicate_request: "Duplicate in request",
  out_of_scope: "Out of scope",
  invalid_target: "Invalid target",
  run_cancelled: "Run was cancelled",
  dir_enum_disabled: "Directory scan disabled",
};

function reasonLabel(reason) {
  const key = String(reason || "unknown");
  return REASON_LABEL[key] || "Unknown reason";
}

function summarizeSkippedReasonsFriendly(skippedTargets) {
  const counts = {};
  arrayOrEmpty(skippedTargets).forEach(item=>{
    const label = reasonLabel(item?.reason);
    counts[label] = (counts[label] || 0) + 1;
  });
  return Object.entries(counts)
    .map(([label, count])=>`${label} x${count}`)
    .join(", ");
}

const TOAST_TYPE_STYLES = {
  success: { icon: "✓", border: "rgba(34,197,94,0.55)", accent: "#166534", tint: "rgba(34,197,94,0.16)" },
  info: { icon: "ℹ", border: "rgba(59,130,246,0.55)", accent: "#1D4ED8", tint: "rgba(59,130,246,0.16)" },
  warning: { icon: "⚠", border: "rgba(234,179,8,0.55)", accent: "#A16207", tint: "rgba(234,179,8,0.16)" },
  error: { icon: "✕", border: "rgba(239,68,68,0.55)", accent: "#B91C1C", tint: "rgba(239,68,68,0.16)" },
};

const ToastContext = React.createContext({ push: () => {} });

function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const timersRef = useRef(new Map());
  const MAX_TOASTS = 3;
  const isSameToast = (a, b) => (
    String(a.type || "info") === String(b.type || "info")
    && String(a.title || "") === String(b.title || "")
    && String(a.description || "") === String(b.description || "")
  );
  const clearTimer = id => {
    const timer = timersRef.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timersRef.current.delete(id);
    }
  };
  const armTimer = toast => {
    if (toast.duration === 0 || toast.priority === "high") return;
    clearTimer(toast.id);
    const timer = setTimeout(() => {
      setToasts(prev => prev.filter(item => item.id !== toast.id));
      timersRef.current.delete(toast.id);
    }, toast.duration || 3500);
    timersRef.current.set(toast.id, timer);
  };

  const push = toast => {
    const normalized = {
      id: Date.now() + Math.floor(Math.random() * 10000),
      type: "info",
      priority: "normal",
      duration: 3500,
      count: 1,
      ...toast,
    };
    if (normalized.priority === "high" && toast.duration === undefined) {
      normalized.duration = 0;
    }
    setToasts(prev => {
      const idx = prev.findIndex(item => isSameToast(item, normalized));
      if (idx >= 0) {
        const merged = [...prev];
        const existing = merged[idx];
        merged[idx] = { ...existing, ...normalized, id: existing.id, count: Number(existing.count || 1) + 1 };
        armTimer(merged[idx]);
        return merged;
      }
      const next = [...prev, normalized];
      if (next.length > MAX_TOASTS) {
        const toDrop = next[0];
        clearTimer(toDrop.id);
        next.shift();
      }
      armTimer(normalized);
      return next;
    });
  };

  const removeToast = id => {
    clearTimer(id);
    setToasts(prev => prev.filter(item => item.id !== id));
  };

  return (
    <ToastContext.Provider value={{ push }}>
      {children}
      <ToastContainer toasts={toasts} onClose={removeToast}/>
    </ToastContext.Provider>
  );
}

function useToast() {
  return useContext(ToastContext);
}

function ToastContainer({ toasts, onClose }) {
  if (!arrayOrEmpty(toasts).length) return null;
  return (
    <div style={{position:"fixed",right:18,bottom:18,zIndex:95,display:"grid",gap:8,maxWidth:460}}>
      {arrayOrEmpty(toasts).map(toast=><ToastCard key={toast.id} toast={toast} onClose={()=>onClose(toast.id)}/>)}
    </div>
  );
}

function ToastCard({ toast, onClose }) {
  const t = TOAST_TYPE_STYLES[String(toast.type || "info")] || TOAST_TYPE_STYLES.info;
  const details = arrayOrEmpty(toast.details);
  const [openDetails, setOpenDetails] = useState(false);
  return (
    <div style={{minWidth:320,background:"#0B1220",border:`1px solid ${t.border}`,borderLeft:`4px solid ${t.accent}`,borderRadius:8,padding:"9px 11px",boxShadow:"0 10px 24px rgba(0,0,0,0.35)"}}>
      <div style={{display:"flex",gap:8,alignItems:"flex-start"}}>
        <div style={{width:18,height:18,borderRadius:4,display:"inline-flex",alignItems:"center",justifyContent:"center",fontSize:12,lineHeight:"18px",background:t.tint,color:C.inkBright}}>
          {t.icon}
        </div>
        <div style={{flex:1}}>
          <div style={{fontSize:12,color:C.inkBright,fontWeight:700}}>
            {toast.title}{Number(toast.count || 1) > 1 ? ` (x${toast.count})` : ""}
          </div>
          {toast.description&&<div style={{marginTop:3,fontSize:11,color:C.slate}}>{toast.description}</div>}
        </div>
        <button type="button" onClick={onClose} style={{...actionButtonStyle,padding:"3px 7px",fontSize:10}}>x</button>
      </div>
      {!!toast.actionLabel && typeof toast.onAction === "function" && (
        <div style={{marginTop:8,display:"flex",justifyContent:"flex-end"}}>
          <button type="button" onClick={toast.onAction} style={{...actionButtonStyle,padding:"4px 8px",fontSize:10,borderColor:t.border,color:C.inkBright}}>
            {toast.actionLabel} →
          </button>
        </div>
      )}
      {details.length>0 && (
        <div style={{marginTop:8}}>
          <button type="button" onClick={()=>setOpenDetails(!openDetails)} style={{...actionButtonStyle,padding:"4px 8px",fontSize:10}}>
            {openDetails ? "Hide details" : "View details"}
          </button>
          {openDetails&&(
            <div style={{marginTop:8,maxHeight:160,overflowY:"auto",display:"grid",gap:5}}>
              {details.map((item, idx)=>(
                <div key={`${item.base_url || item.host || "item"}-${idx}`} style={{fontSize:11,color:C.slate,fontFamily:"JetBrains Mono, monospace"}}>
                  {`${item.host || "unknown"}:${item.port || "—"} -> ${reasonLabel(item.reason)}`}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function serviceLabel(service) {
  if (!service) return "All services";
  const port = service.port || "unknown";
  const protocol = service.protocol || "tcp";
  const name = service.serviceName || "unknown service";
  return `${port}/${protocol} ${name}`;
}

function formatBytes(value) {
  const size = Number(value || 0);
  if (!size) return "—";
  if (size < 1024) return `${size}B`;
  return `${(size / 1024).toFixed(1)}KB`;
}

function dedupeFindings(items) {
  const seen = new Set();
  return arrayOrEmpty(items).filter(item=>{
    const key = String(firstDefined(item.finding_id, item.artifact_id, item.path, item.target, JSON.stringify(item)) || "");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function createFindingHost(id, label) {
  return {
    id,
    label,
    type:"unknown",
    portsCount:0,
    findingsCount:0,
    services:[],
    serviceMap:new Map(),
    hostLevelFindings:{http:[], directories:[], cve:[], artifacts:[], domainMappings:[], banners:[]},
    moduleAvailable:{http:false, directories:false, cve:false, artifacts:false, domainMappings:true, banners:true},
  };
}

function ensureFindingService(host, item, defaults = {}) {
  const parts = portProtocolFromFinding(item || {});
  const port = String(firstDefined(defaults.port, parts.port, "unknown") || "unknown");
  const protocol = String(firstDefined(defaults.protocol, parts.protocol, "tcp") || "tcp").toLowerCase();
  const id = makeServiceId(port, protocol);
  let service = host.serviceMap.get(id);
  if (!service) {
    const evidence = findingEvidence(item || {});
    service = {
      id,
      port,
      protocol,
      serviceName:String(firstDefined(defaults.serviceName, evidence.service, evidence.product, protocol === "https" ? "https" : (protocol === "http" ? "http" : "unknown service")) || "unknown service"),
      tech:arrayOrEmpty(evidence.technologies).join(", ") || String(firstDefined(evidence.product, evidence.version, "") || ""),
      isWeb:false,
      findings:{http:[], directories:[], cve:[], artifacts:[], banners:[]},
    };
    host.serviceMap.set(id, service);
    host.services.push(service);
  }
  return service;
}

function attachFinding(host, service, kind, item) {
  const container = service ? service.findings : host.hostLevelFindings;
  container[kind].push(item);
  if (kind === "http" || kind === "directories") {
    const webService = service || ensureFindingService(host, item, {});
    webService.isWeb = true;
  }
}

function addFindingToHost(host, kind, item) {
  const parts = portProtocolFromFinding(item);
  const hasServiceContext = parts.port !== "unknown" || ["http","https"].includes(parts.protocol);
  const service = hasServiceContext ? ensureFindingService(host, item, {}) : null;
  attachFinding(host, service, kind, item);
}

function buildFindingsModel(runView) {
  const report = runView?.report || {};
  const sections = report.sections || {};
  const hostGroups = arrayOrEmpty(report.host_groups);
  const artifacts = arrayOrEmpty(report.artifacts?.items);
  const hostsById = new Map();
  const moduleAvailable = {
    http: Array.isArray(sections.http_probe_results),
    directories: Array.isArray(sections.directory_findings),
    cve: Array.isArray(sections.candidate_cves),
    artifacts: Array.isArray(report.artifacts?.items),
    domainMappings: true,
    banners: true,
  };
  const getHost = label => {
    const normalized = String(label || "Unknown host").trim() || "Unknown host";
    const id = normalized === "Unknown host" ? "__unknown__" : normalized;
    if (!hostsById.has(id)) hostsById.set(id, createFindingHost(id, normalized));
    return hostsById.get(id);
  };

  hostGroups.forEach(group=>{
    const host = getHost(group.host || "Unknown host");
    host.moduleAvailable = {...moduleAvailable};
    arrayOrEmpty(group.open_ports).forEach(item=>{
      const evidence = findingEvidence(item);
      ensureFindingService(host, item, {port:evidence.port, protocol:evidence.protocol, serviceName:evidence.service || evidence.product});
    });
    arrayOrEmpty(group.http_probe).forEach(item=>addFindingToHost(host, "http", item));
    arrayOrEmpty(group.directory_findings).forEach(item=>addFindingToHost(host, "directories", item));
    arrayOrEmpty(group.candidate_cves).forEach(item=>addFindingToHost(host, "cve", item));
    arrayOrEmpty(group.artifacts).forEach(item=>attachFinding(host, null, "artifacts", item));
    arrayOrEmpty(group.domain_mappings).forEach(item=>{
      const ev = findingEvidence(item);
      const hkey = String(firstDefined(ev.ip, group.host) || "Unknown host");
      const h = getHost(hkey);
      h.hostLevelFindings.domainMappings.push(item);
    });
    arrayOrEmpty(group.banner_findings).forEach(item=>{
      const ev = findingEvidence(item);
      const h = getHost(String(firstDefined(ev.host, group.host) || "Unknown host"));
      const port = String(firstDefined(ev.port, "unknown") || "unknown");
      const protocol = String(firstDefined(ev.protocol, "tcp") || "tcp").toLowerCase();
      const service = ensureFindingService(h, item, {
        port,
        protocol,
        serviceName: String(firstDefined(ev.guessed_service, "unknown") || "unknown"),
      });
      service.findings.banners.push(item);
    });
  });

  if (hostGroups.length === 0) {
    arrayOrEmpty(sections.http_probe_results).forEach(item=>addFindingToHost(getHost(hostFromFinding(item)), "http", item));
    arrayOrEmpty(sections.open_ports).forEach(item=>{
      const host = getHost(hostFromFinding(item));
      const evidence = findingEvidence(item);
      ensureFindingService(host, item, {port:evidence.port, protocol:evidence.protocol, serviceName:evidence.service || evidence.product});
    });
    arrayOrEmpty(sections.directory_findings).forEach(item=>addFindingToHost(getHost(hostFromFinding(item)), "directories", item));
    arrayOrEmpty(sections.candidate_cves).forEach(item=>addFindingToHost(getHost(hostFromFinding(item)), "cve", item));
    arrayOrEmpty(sections.domain_mappings).forEach(item=>{
      const ev = findingEvidence(item);
      const h = getHost(String(firstDefined(ev.ip, hostFromFinding(item)) || "Unknown host"));
      h.hostLevelFindings.domainMappings.push(item);
    });
    arrayOrEmpty(sections.banner_findings).forEach(item=>{
      const ev = findingEvidence(item);
      const h = getHost(String(firstDefined(ev.host, hostFromFinding(item)) || "Unknown host"));
      const port = String(firstDefined(ev.port, "unknown") || "unknown");
      const protocol = String(firstDefined(ev.protocol, "tcp") || "tcp").toLowerCase();
      const service = ensureFindingService(h, item, {
        port,
        protocol,
        serviceName: String(firstDefined(ev.guessed_service, "unknown") || "unknown"),
      });
      service.findings.banners.push(item);
    });
  }
  artifacts.forEach(item=>{
    const metadata = objectOrEmpty(item.metadata);
    const host = getHost(firstDefined(metadata.host, metadata.hostname, item.host, "Unknown host"));
    attachFinding(host, null, "artifacts", item);
  });

  const hosts = Array.from(hostsById.values()).map(host=>{
    host.services.forEach(service=>{
      service.findings.http = dedupeFindings(service.findings.http);
      service.findings.directories = dedupeFindings(service.findings.directories);
      service.findings.cve = dedupeFindings(service.findings.cve);
      service.findings.artifacts = dedupeFindings(service.findings.artifacts);
      service.findings.banners = dedupeFindings(arrayOrEmpty(service.findings.banners));
      service.isWeb = serviceIsWeb(service) || service.findings.http.length > 0 || service.findings.directories.length > 0;
    });
    host.hostLevelFindings.http = dedupeFindings(host.hostLevelFindings.http);
    host.hostLevelFindings.directories = dedupeFindings(host.hostLevelFindings.directories);
    host.hostLevelFindings.cve = dedupeFindings(host.hostLevelFindings.cve);
    host.hostLevelFindings.artifacts = dedupeFindings(host.hostLevelFindings.artifacts);
    host.hostLevelFindings.domainMappings = dedupeFindings(host.hostLevelFindings.domainMappings);
    host.hostLevelFindings.banners = dedupeFindings(host.hostLevelFindings.banners);
    host.services.sort((a,b)=>Number(a.port || 999999)-Number(b.port || 999999) || a.id.localeCompare(b.id));
    host.portsCount = host.services.filter(service=>service.port !== "unknown").length;
    host.findingsCount = ["http","directories","cve","artifacts","domainMappings","banners"].reduce((sum, key)=>(
      sum + arrayOrEmpty(host.hostLevelFindings[key]).length + host.services.reduce((inner, service)=>inner + arrayOrEmpty(service.findings[key]).length, 0)
    ), 0);
    host.type = host.services.some(service=>service.isWeb) ? "web" : (host.services.length > 0 ? "non-web" : "unknown");
    delete host.serviceMap;
    return host;
  }).sort((a,b)=>a.label.localeCompare(b.label));
  return {hosts, moduleAvailable};
}

function bucketForScore(score) {
  if (score >= 90) return "critical";
  if (score >= 75) return "high";
  if (score >= 55) return "medium";
  if (score >= 30) return "low";
  return "info";
}

function normalizedConfidence(evidence) {
  const raw = Number(firstDefined(evidence.confidence, evidence.cve_confidence, 0));
  if (!Number.isFinite(raw) || raw <= 0) return 0;
  return raw <= 1 ? Math.round(raw * 100) : Math.round(raw);
}

function calculateFindingPriority({ finding, kind, service }) {
  const evidence = findingEvidence(finding);
  const reasons = [];
  let score = 0;
  const pathValue = String(firstDefined(evidence.path, safeUrl(findingUrl(finding))?.pathname, "") || "").toLowerCase();
  const sensitiveHints = ["/admin", "/backup", "/config", "/uploads", "/.git"];
  const hasSensitivePath = sensitiveHints.some(hint => pathValue.includes(hint));
  const isAdminRoute = pathValue.includes("/admin");
  const isCandidateOnly = Boolean(evidence.candidate_only || evidence.is_candidate || String(finding?.status || "").toLowerCase() === "candidate");
  const portNum = Number(firstDefined(evidence.port, service?.port, 0));
  const nonWebExposed = [22, 445, 3389].includes(portNum);
  const statusCode = Number(firstDefined(evidence.status_code, 0));

  if (kind === "cve") {
    const severity = String(firstDefined(evidence.severity, "info") || "info").toLowerCase();
    const sevScore = { critical: 96, high: 84, medium: 68, low: 46, info: 28 }[severity] || 28;
    score += sevScore;
    const conf = normalizedConfidence(evidence);
    if (conf > 0) score += Math.min(14, Math.round(conf / 10));
    reasons.push("CVE candidate");
    if (isCandidateOnly) score -= 5;
  }

  if (kind === "directories" || kind === "http") {
    if (serviceIsWeb(service)) {
      score += 14;
      reasons.push("Public web service");
    }
    if (hasSensitivePath) {
      score += 26;
      reasons.push("Sensitive path");
    }
    if (isAdminRoute) {
      score += 20;
      reasons.push("Exposed admin route");
    }
    if ([200, 401, 403].includes(statusCode)) score += 8;
  }

  if (kind === "port_scan" && nonWebExposed) {
    score += 60;
    reasons.push("Exposed non-web service");
  }

  if (kind !== "cve" && nonWebExposed && !serviceIsWeb(service)) {
    score += 40;
    reasons.push("Exposed non-web service");
  }

  const level = bucketForScore(score);
  const uniqueReasons = Array.from(new Set(reasons));
  return { score, level, reasons: uniqueReasons, candidateOnly: isCandidateOnly };
}

function buildPriorityQueue(model) {
  const rows = [];
  arrayOrEmpty(model?.hosts).forEach(host=>{
    arrayOrEmpty(host.services).forEach(service=>{
      const mapping = [
        ["http", "http"],
        ["directories", "directories"],
        ["cve", "cve"],
      ];
      mapping.forEach(([kind, tab])=>{
        arrayOrEmpty(service.findings?.[kind]).forEach(item=>{
          const p = calculateFindingPriority({ finding: item, kind, service });
          rows.push({
            id: String(firstDefined(item.finding_id, `${host.id}-${service.id}-${kind}-${rows.length}`)),
            hostId: host.id,
            hostLabel: host.label,
            serviceId: service.id,
            serviceLabel: serviceLabel(service),
            tab,
            finding: item,
            kind,
            score: p.score,
            level: p.level,
            reasons: p.reasons,
            candidateOnly: p.candidateOnly,
          });
        });
      });
    });
    arrayOrEmpty(host.hostLevelFindings?.cve).forEach(item=>{
      const p = calculateFindingPriority({ finding: item, kind: "cve", service: null });
      rows.push({
        id: String(firstDefined(item.finding_id, `${host.id}-host-cve-${rows.length}`)),
        hostId: host.id,
        hostLabel: host.label,
        serviceId: "",
        serviceLabel: "All services",
        tab: "cve",
        finding: item,
        kind: "cve",
        score: p.score,
        level: p.level,
        reasons: p.reasons,
        candidateOnly: p.candidateOnly,
      });
    });
    arrayOrEmpty(host.services).forEach(service=>{
      if (!serviceIsWeb(service) && [22, 445, 3389].includes(Number(service.port || 0))) {
        const p = calculateFindingPriority({ finding: { evidence: { port: Number(service.port || 0) } }, kind: "port_scan", service });
        rows.push({
          id: `${host.id}-${service.id}-port-exposure`,
          hostId: host.id,
          hostLabel: host.label,
          serviceId: service.id,
          serviceLabel: serviceLabel(service),
          tab: "overview",
          finding: { summary: `Exposed ${service.port}/${service.protocol} service` },
          kind: "port_scan",
          score: p.score,
          level: p.level,
          reasons: p.reasons,
          candidateOnly: false,
        });
      }
    });
  });
  return rows.sort((a,b)=>{
    const rank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    return (rank[b.level] - rank[a.level]) || (b.score - a.score) || String(a.hostLabel).localeCompare(String(b.hostLabel));
  });
}

function buildRecommendedActions({ model, aggregate, compareRunId, lastFfufSkipped }) {
  const actions = [];
  const hosts = arrayOrEmpty(model?.hosts);
  const sensitiveHints = ["/admin", "/backup", "/config", "/uploads", "/.git"];

  hosts.forEach(host => {
    const webServices = arrayOrEmpty(host.services).filter(serviceIsWeb);
    const hostDirCount =
      arrayOrEmpty(host.hostLevelFindings?.directories).length
      + webServices.reduce((sum, service)=>sum + arrayOrEmpty(service.findings?.directories).length, 0);
    if (webServices.length > 0 && hostDirCount === 0) {
      actions.push({
        id: `rec-ffuf-web-${host.id}`,
        type: "run_ffuf_web",
        title: "Run ffuf on discovered web services",
        reason: "Web services were found but directory findings are missing.",
        targetLabel: `${host.label} (${webServices.length} service(s))`,
        hostId: host.id,
        targets: webServices.map(service=>serviceTargetPayload(host, service)),
        actionLabel: "Run",
      });
    }
  });

  const sensitiveRows = arrayOrEmpty(aggregate?.allDirectories).filter(row=>{
    const p = String(row?.path || "").toLowerCase();
    return sensitiveHints.some(hint=>p.includes(hint));
  });
  if (sensitiveRows.length > 0) {
    const uniqueByHost = new Map();
    sensitiveRows.forEach(row=>{
      const key = String(row.host || "");
      if (!key || uniqueByHost.has(key)) return;
      uniqueByHost.set(key, row);
    });
    const targets = Array.from(uniqueByHost.values())
      .map(row=>{
        const host = hosts.find(h=>h.label === row.host || h.id === row.host);
        if (!host) return null;
        const service = arrayOrEmpty(host.services).find(s=>String(s.id) === String(row.serviceId)) || arrayOrEmpty(host.services).find(serviceIsWeb);
        if (!service) return null;
        return serviceTargetPayload(host, service);
      })
      .filter(Boolean);
    if (targets.length > 0) {
      actions.push({
        id: "rec-recursive-sensitive",
        type: "run_recursive_sensitive",
        title: "Run recursive ffuf from sensitive paths",
        reason: "Sensitive directories were discovered and may have deeper paths.",
        targetLabel: `${targets.length} host/service target(s)`,
        targets,
        sensitivePaths: sensitiveRows.slice(0, 6).map(row=>row.path),
        actionLabel: "Review & run",
      });
    }
  }

  const alreadyScanned = arrayOrEmpty(lastFfufSkipped).filter(item=>String(item?.reason) === "already_scanned");
  if (alreadyScanned.length > 0) {
    actions.push({
      id: "rec-rerun-force",
      type: "rerun_force",
      title: "Re-run with force",
      reason: "Some targets were skipped because they were already scanned.",
      targetLabel: `${alreadyScanned.length} skipped target(s)`,
      targets: alreadyScanned.map(item=>({
        host: item.host,
        port: item.port,
        scheme: item.port === 443 ? "https" : "http",
        base_url: item.base_url,
        service_id: null,
      })),
      actionLabel: "Re-run",
    });
  }

  const cveCount = arrayOrEmpty(aggregate?.allCve).length;
  if (cveCount > 0) {
    actions.push({
      id: "rec-review-cve",
      type: "review_cve",
      title: "Review CVE candidates",
      reason: "Candidate-only CVE matches need analyst verification.",
      targetLabel: `${cveCount} candidate(s)`,
      actionLabel: "Review",
    });
  }

  if (compareRunId && arrayOrEmpty(aggregate?.allOpenPorts).some(item=>serviceIsWeb(item))) {
    const targets = hosts.flatMap(host=>arrayOrEmpty(host.services).filter(serviceIsWeb).map(service=>serviceTargetPayload(host, service)));
    if (targets.length > 0) {
      actions.push({
        id: "rec-diff-new-web-ports",
        type: "run_ffuf_diff_web",
        title: "Run ffuf on newly discovered web ports",
        reason: "Diff mode is active; verify paths on web ports discovered in comparison.",
        targetLabel: `${targets.length} web target(s)`,
        targets,
        actionLabel: "Run",
      });
    }
  }

  return actions;
}

function PriorityQueueSection({ runId, rows }) {
  const levelColor = {
    critical: "#EF4444",
    high: "#F97316",
    medium: "#EAB308",
    low: "#3B82F6",
    info: "#64748B",
  };
  const top = arrayOrEmpty(rows).slice(0, 80);
  return (
    <div style={{border:`1px solid ${C.slateMid}`,borderRadius:8,padding:14,background:C.slateDark}}>
      <SectionLabel>Priority Queue</SectionLabel>
      {top.length===0 ? <EmptyState msg="No prioritized findings yet."/> : (
        <div style={{display:"grid",gap:8}}>
          {top.map(item=>(
            <button key={item.id} type="button" onClick={()=>{
              const params = new URLSearchParams();
              params.set("host", item.hostId);
              if (item.serviceId) params.set("service", item.serviceId);
              if (item.tab && item.tab !== "overview") params.set("tab", item.tab);
              navigate(`/runs/${encodeURIComponent(runId)}/findings?${params.toString()}`);
            }}
              style={{textAlign:"left",border:`1px solid ${C.slateMid}`,borderRadius:7,padding:"9px 10px",background:"#0B1220",cursor:"pointer"}}>
              <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
                <Tag color={levelColor[item.level]}>{String(item.level).toUpperCase()}</Tag>
                <span style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.sky}}>score {item.score}</span>
                <span style={{fontSize:11,color:C.ink}}>{item.hostLabel}</span>
                <span style={{fontSize:10,color:C.slate}}>{item.serviceLabel}</span>
                {item.candidateOnly && <Tag color="#FDE68A">Candidate</Tag>}
              </div>
              <div style={{marginTop:6,fontSize:12,color:C.ink}}>
                {String(firstDefined(item.finding?.summary, item.finding?.target, "Finding"))}
              </div>
              <div style={{marginTop:6,display:"flex",gap:6,flexWrap:"wrap"}}>
                {arrayOrEmpty(item.reasons).map(reason=><Tag key={`${item.id}-${reason}`} color={C.blueDim}>{reason}</Tag>)}
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function RecommendedActionsPanel({ items, onRun, onDismiss, title = "Recommended Actions" }) {
  const rows = arrayOrEmpty(items);
  return (
    <div style={{border:`1px solid ${C.slateMid}`,borderRadius:8,padding:14,background:C.slateDark}}>
      <SectionLabel>{title}</SectionLabel>
      {rows.length===0 ? <EmptyState msg="No recommendations right now."/> : (
        <div style={{display:"grid",gap:8}}>
          {rows.map(item=>(
            <div key={item.id} style={{border:`1px solid ${C.slateMid}`,borderRadius:7,padding:"10px 11px",background:"#0B1220"}}>
              <div style={{display:"flex",gap:8,alignItems:"center",justifyContent:"space-between"}}>
                <div style={{fontSize:12,color:C.inkBright,fontWeight:700}}>{item.title}</div>
                <Tag color={C.blueDim}>Recommended</Tag>
              </div>
              <div style={{marginTop:6,fontSize:11,color:C.slate}}>{item.reason}</div>
              {item.targetLabel&&<div style={{marginTop:5,fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.sky}}>{item.targetLabel}</div>}
              {arrayOrEmpty(item.sensitivePaths).length>0&&(
                <div style={{marginTop:6,display:"flex",gap:6,flexWrap:"wrap"}}>
                  {arrayOrEmpty(item.sensitivePaths).slice(0,4).map(path=><Tag key={`${item.id}-${path}`} color={C.blueDim}>{path}</Tag>)}
                </div>
              )}
              <div style={{marginTop:9,display:"flex",gap:8,justifyContent:"flex-end"}}>
                <button type="button" onClick={()=>onDismiss(item.id)} style={{...actionButtonStyle,padding:"5px 9px",fontSize:11}}>Dismiss</button>
                <button type="button" onClick={()=>onRun(item)} style={{...actionButtonStyle,padding:"5px 9px",fontSize:11,borderColor:C.blueBorder,color:C.sky}}>
                  {item.actionLabel || "Run"}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function diffItemsByCategory(diffData, key, bucket) {
  return arrayOrEmpty(diffData?.categories?.[key]?.[bucket]);
}

function extractHostFromDiffItem(item) {
  const target = String(item?.target || "");
  const parsed = safeUrl(target);
  if (parsed?.hostname) return parsed.hostname;
  const hostPortMatch = target.match(/^([^:]+):[a-z]+\/\d+$/i);
  if (hostPortMatch) return hostPortMatch[1];
  return String(firstDefined(item?.host, item?.hostname, "unknown"));
}

function extractPortFromDiffItem(item) {
  const evidence = findingEvidence(item);
  const fromEvidence = Number(firstDefined(evidence.port, item?.port, 0) || 0);
  if (fromEvidence > 0) return fromEvidence;
  const target = String(item?.target || "");
  const targetMatch = target.match(/\/(\d+)$/);
  if (targetMatch) return Number(targetMatch[1] || 0) || 0;
  return 0;
}

function diffItemPath(item) {
  const evidence = findingEvidence(item);
  const raw = String(firstDefined(evidence.path, safeUrl(item?.target)?.pathname, item?.path, "") || "");
  return normalizePath(raw || "/");
}

function isLikelyWebByPort(port) {
  return [80, 81, 443, 8000, 8080, 8081, 8443, 8888].includes(Number(port || 0));
}

function isLikelyWebByItem(item) {
  const evidence = findingEvidence(item);
  const service = String(firstDefined(evidence.service, evidence.name, item?.service, item?.summary, "") || "").toLowerCase();
  const target = String(item?.target || "").toLowerCase();
  const port = extractPortFromDiffItem(item);
  return service.includes("http") || service.includes("https") || target.includes("http") || isLikelyWebByPort(port);
}

function pathLooksAdmin(pathText) {
  const text = String(pathText || "").toLowerCase();
  return ["/admin", "/wp-admin", "/manager", "/console", "/login", "/dashboard"].some(hint=>text.includes(hint));
}

function serviceIdForHostPort(model, hostLabel, port) {
  const host = arrayOrEmpty(model?.hosts).find(h=>String(h.label) === String(hostLabel) || String(h.id) === String(hostLabel));
  if (!host) return "";
  const service = arrayOrEmpty(host.services).find(s=>Number(s.port || 0) === Number(port || 0));
  return service?.id || "";
}

function buildChangeAlerts({ diffData, runId, model }) {
  const alerts = [];
  const push = (kind, item, tab, severity, title, reason, opts = {}) => {
    const host = extractHostFromDiffItem(item);
    const port = extractPortFromDiffItem(item);
    const serviceId = opts.serviceId || serviceIdForHostPort(model, host, port);
    const path = diffItemPath(item);
    const params = new URLSearchParams();
    if (host && host !== "unknown") params.set("host", host);
    if (serviceId) params.set("service", serviceId);
    if (tab) params.set("tab", tab);
    const href = `/runs/${encodeURIComponent(runId)}/findings${params.toString() ? `?${params.toString()}` : ""}`;
    alerts.push({
      id: `${kind}-${item?.finding_id || item?.id || item?.target || alerts.length}`,
      kind,
      severity,
      title,
      reason,
      targetLabel: opts.targetLabel || String(item?.target || host || "unknown"),
      host,
      port,
      serviceId,
      path,
      href,
    });
  };

  diffItemsByCategory(diffData, "http_probe_results", "added").forEach(item=>{
    push("new_host", item, "http", "medium", "New host detected", "A host appears in current run but not in baseline.");
  });
  diffItemsByCategory(diffData, "http_probe_results", "removed").forEach(item=>{
    push("removed_host", item, "http", "info", "Host removed", "A host from baseline is not present in current run.");
  });
  diffItemsByCategory(diffData, "open_ports", "added").forEach(item=>{
    const port = extractPortFromDiffItem(item);
    const web = isLikelyWebByItem(item);
    push(
      web ? "new_web_service" : "new_open_port",
      item,
      "overview",
      "medium",
      web ? "New web service" : "New open port",
      web ? "A new HTTP-like service is exposed." : "A new network service port is open.",
      { targetLabel: `${extractHostFromDiffItem(item)}:${port || "?"}` }
    );
  });
  diffItemsByCategory(diffData, "open_ports", "removed").forEach(item=>{
    const port = extractPortFromDiffItem(item);
    push("closed_port", item, "overview", "info", "Port closed", "A previously open service is now closed.", {
      targetLabel: `${extractHostFromDiffItem(item)}:${port || "?"}`,
    });
  });
  diffItemsByCategory(diffData, "directory_findings", "added").forEach(item=>{
    const path = diffItemPath(item);
    const high = pathLooksAdmin(path);
    push(
      "new_directory",
      item,
      "directories",
      high ? "high" : "medium",
      high ? "New web admin path" : "New directory finding",
      high ? "A potentially sensitive admin/auth path is newly exposed." : "A new directory endpoint was discovered.",
      { targetLabel: `${extractHostFromDiffItem(item)} ${path}` }
    );
  });
  diffItemsByCategory(diffData, "candidate_cves", "added").forEach(item=>{
    push("new_cve_candidate", item, "cve", "high", "New CVE candidate", "Candidate vulnerability evidence changed from baseline.");
  });

  const score = {high:3, medium:2, info:1};
  return alerts.sort((a,b)=>(score[b.severity] || 0) - (score[a.severity] || 0) || a.title.localeCompare(b.title));
}

function buildNoteDiffAlerts({ runId, compareRunId, model, baselineNotes }) {
  const alerts = [];
  const currentServices = new Set();
  arrayOrEmpty(model?.hosts).forEach(host=>{
    const hostLabel = String(host.label || host.id || "").trim();
    if (!hostLabel) return;
    arrayOrEmpty(host.services).forEach(service=>{
      const port = Number(service.port || 0);
      const protocol = String(service.protocol || "tcp").toLowerCase();
      if (port <= 0) return;
      currentServices.add(`${hostLabel}|${port}|${protocol}`);
    });
  });

  arrayOrEmpty(baselineNotes).forEach((note, index)=>{
    const host = String(note.host || "").trim();
    const port = Number(note.port || 0);
    const protocol = String(note.protocol || "tcp").toLowerCase();
    if (!host || port <= 0) return;
    const key = `${host}|${port}|${protocol}`;
    if (currentServices.has(key)) return;
    const params = new URLSearchParams({ host, tab: "overview", compare: String(compareRunId || "") });
    const href = `/runs/${encodeURIComponent(runId)}/findings?${params.toString()}`;
    alerts.push({
      id: `note-removed-port-${note.id || index}`,
      kind: "note_removed_port",
      severity: "high",
      title: "Port removed with note context",
      reason: `Baseline note exists on ${host}:${port}/${protocol} but service is missing in current run.`,
      targetLabel: `${host}:${port}/${protocol}`,
      host,
      port,
      serviceId: "",
      path: "",
      href,
      notePreview: String(note.note || ""),
    });
  });

  return alerts;
}

function ChangeAlertsPanel({ alerts, baselineRunId, compareOptions, onChangeBaseline, title = "Change Alerts" }) {
  const levelColor = {high:"#FCA5A5", medium:"#FDE68A", info:"#93C5FD"};
  const counts = arrayOrEmpty(alerts).reduce((acc, row)=>{
    acc.total += 1;
    acc[row.severity] = (acc[row.severity] || 0) + 1;
    return acc;
  }, {total:0, high:0, medium:0, info:0});

  return (
    <div style={{border:`1px solid ${C.slateMid}`,borderRadius:8,padding:14,background:C.slateDark}}>
      <div style={{display:"flex",gap:10,alignItems:"center",justifyContent:"space-between",flexWrap:"wrap"}}>
        <SectionLabel>{title}</SectionLabel>
        <div style={{display:"flex",gap:6,alignItems:"center",flexWrap:"wrap"}}>
          <Tag color="#EF4444">High {counts.high}</Tag>
          <Tag color="#F59E0B">Medium {counts.medium}</Tag>
          <Tag color="#3B82F6">Info {counts.info}</Tag>
          <Tag color={C.blueDim}>Total {counts.total}</Tag>
        </div>
      </div>
      <div style={{marginTop:8,display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
        <span style={{fontSize:11,color:C.slate}}>Baseline run</span>
        <select value={baselineRunId} onChange={event=>onChangeBaseline(event.target.value)} style={{...inputStyle,maxWidth:260}}>
          <option value="">Select baseline</option>
          {arrayOrEmpty(compareOptions).map(row=>(
            <option key={row.id} value={row.id}>{row.label}</option>
          ))}
        </select>
      </div>
      {!baselineRunId ? (
        <div style={{marginTop:10}}><EmptyState msg="Select a baseline run to compare changes."/></div>
      ) : arrayOrEmpty(alerts).length===0 ? (
        <div style={{marginTop:10}}><EmptyState msg="No changes detected"/></div>
      ) : (
        <div style={{marginTop:10,display:"grid",gap:8}}>
          {arrayOrEmpty(alerts).map(item=>(
            <button key={item.id} type="button" onClick={()=>navigate(item.href)}
              style={{textAlign:"left",border:`1px solid ${C.slateMid}`,borderRadius:7,padding:"9px 10px",background:"#0B1220",cursor:"pointer"}}>
              <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
                <Tag color={levelColor[item.severity] || C.blueDim}>{String(item.severity || "info").toUpperCase()}</Tag>
                <span style={{fontSize:12,color:C.inkBright,fontWeight:700}}>{item.title}</span>
                <span style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.sky}}>{item.targetLabel}</span>
              </div>
              <div style={{marginTop:6,fontSize:11,color:C.slate}}>{item.reason}</div>
              {item.notePreview ? (
                <div style={{marginTop:6,fontSize:11,color:"#cbd5e1",fontStyle:"italic",whiteSpace:"pre-wrap",wordBreak:"break-word"}}>
                  Note: {item.notePreview}
                </div>
              ) : null}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function summarizeFindingsAggregate(model) {
  const hosts = arrayOrEmpty(model?.hosts);
  const portCounts = new Map();
  const directoryCounts = new Map();
  const allHttp = [];
  const allDirectories = [];
  const allCve = [];
  const allArtifacts = [];
  const uniquePortKeys = new Set();
  const globalUrls = [];
  const seenGlobalUrls = new Set();
  const allOpenPorts = [];
  const allDirectoryRows = [];

  hosts.forEach(host=>{
    arrayOrEmpty(host.hostLevelFindings?.http).forEach(item=>allHttp.push(item));
    arrayOrEmpty(host.hostLevelFindings?.directories).forEach(item=>allDirectories.push(item));
    arrayOrEmpty(host.hostLevelFindings?.cve).forEach(item=>allCve.push(item));
    arrayOrEmpty(host.hostLevelFindings?.artifacts).forEach(item=>allArtifacts.push(item));

    arrayOrEmpty(host.services).forEach(service=>{
      if (service.port !== "unknown") {
        const key = `${service.protocol}/${service.port}`;
        uniquePortKeys.add(key);
        portCounts.set(key, (portCounts.get(key) || 0) + 1);
        allOpenPorts.push({
          host: host.label,
          serviceId: service.id,
          port: service.port,
          protocol: service.protocol,
          serviceName: service.serviceName || "unknown",
        });
      }
      arrayOrEmpty(service.findings?.http).forEach(item=>allHttp.push(item));
      arrayOrEmpty(service.findings?.directories).forEach(item=>{
        allDirectories.push(item);
        const evidence = findingEvidence(item);
        const path = String(firstDefined(evidence.path, safeUrl(findingUrl(item))?.pathname, item.target, "/") || "/");
        directoryCounts.set(path, (directoryCounts.get(path) || 0) + 1);
        const parsedUrl = safeUrl(findingUrl(item));
        const hostLabel = serviceHostLabel(host, item);
        const scheme = isHttpsLike(service) ? "https" : "http";
        const port = Number(service.port || 0);
        const omitPort = (scheme === "http" && port === 80) || (scheme === "https" && port === 443);
        const contextPort = service.port === "unknown" ? "—" : String(service.port);
        const url = parsedUrl ? parsedUrl.toString() : `${scheme}://${hostLabel}${omitPort || !port ? "" : `:${port}`}${normalizePath(path)}`;
        allDirectoryRows.push({
          host: hostLabel,
          serviceId: service.id,
          path: normalizePath(path),
          url,
          hostContext: `${hostLabel}:${contextPort}`,
          status: firstDefined(evidence.status_code, null),
          size: firstDefined(evidence.content_length, evidence.size, null),
        });
      });
      arrayOrEmpty(service.findings?.cve).forEach(item=>allCve.push(item));
      arrayOrEmpty(service.findings?.artifacts).forEach(item=>allArtifacts.push(item));
    });
    arrayOrEmpty(host.hostLevelFindings?.directories).forEach(item=>{
      const evidence = findingEvidence(item);
      const parts = portProtocolFromFinding(item);
      const hostLabel = serviceHostLabel(host, item);
      const path = normalizePath(firstDefined(evidence.path, safeUrl(findingUrl(item))?.pathname, item.target, "/"));
      const parsedUrl = safeUrl(findingUrl(item));
      const scheme = parts.protocol === "https" || parts.port === "443" ? "https" : "http";
      const portNum = Number(parts.port || 0);
      const omitPort = (scheme === "http" && portNum === 80) || (scheme === "https" && portNum === 443);
      const url = parsedUrl ? parsedUrl.toString() : `${scheme}://${hostLabel}${omitPort || !portNum ? "" : `:${portNum}`}${path}`;
      allDirectoryRows.push({
        host: hostLabel,
        serviceId: "",
        path,
        url,
        hostContext: `${hostLabel}:${parts.port === "unknown" ? "—" : parts.port}`,
        status: firstDefined(evidence.status_code, null),
        size: firstDefined(evidence.content_length, evidence.size, null),
      });
    });
    buildDiscoveredUrls(host, null).forEach(row=>{
      if (seenGlobalUrls.has(row.url)) return;
      seenGlobalUrls.add(row.url);
      globalUrls.push({
        ...row,
        hostContext: hostPortContextForUrl(row.url, host.label),
      });
    });
  });

  const topPorts = Array.from(portCounts.entries())
    .map(([label, count])=>({label, count}))
    .sort((a,b)=>b.count-a.count || a.label.localeCompare(b.label))
    .slice(0, 8);
  const topDirectories = Array.from(directoryCounts.entries())
    .map(([label, count])=>({label, count}))
    .sort((a,b)=>b.count-a.count || a.label.localeCompare(b.label))
    .slice(0, 8);
  const sortedOpenPorts = allOpenPorts.sort((a,b)=>(
    a.host.localeCompare(b.host) || Number(a.port || 999999) - Number(b.port || 999999) || a.protocol.localeCompare(b.protocol)
  ));
  const sortedDirectories = allDirectoryRows.sort((a,b)=>(
    a.host.localeCompare(b.host) || a.path.localeCompare(b.path)
  ));

  return {
    hosts: hosts.length,
    webHosts: hosts.filter(host=>host.type === "web").length,
    ports: uniquePortKeys.size,
    http: dedupeFindings(allHttp).length,
    directories: dedupeFindings(allDirectories).length,
    cve: dedupeFindings(allCve).length,
    artifacts: dedupeFindings(allArtifacts).length,
    topPorts,
    topDirectories,
    globalUrls: globalUrls.slice(0, 12),
    allOpenPorts: sortedOpenPorts,
    allDirectories: sortedDirectories,
  };
}

function findingsForContext(host, service, key) {
  if (!host) return [];
  if (key === "domainMappings") {
    return arrayOrEmpty(host.hostLevelFindings?.domainMappings);
  }
  if (key === "banners") {
    if (service) {
      return arrayOrEmpty(service.findings?.banners);
    }
    return dedupeFindings(arrayOrEmpty(host.hostLevelFindings?.banners).concat(
      arrayOrEmpty(host.services).flatMap(item=>arrayOrEmpty(item.findings?.banners).map(finding=>({...finding, __service:item}))),
    ));
  }
  if (service) return arrayOrEmpty(service.findings?.[key]);
  return dedupeFindings([
    ...arrayOrEmpty(host.hostLevelFindings?.[key]),
    ...arrayOrEmpty(host.services).flatMap(item=>arrayOrEmpty(item.findings?.[key]).map(finding=>({...finding, __service:item}))),
  ]);
}

function serviceNotesForService(notes, hostLabel, service) {
  if (!hostLabel || !service) return [];
  const h = String(hostLabel);
  const port = Number(service.port);
  const prot = String(service.protocol || "tcp").toLowerCase();
  return arrayOrEmpty(notes).filter(n=>(
    String(n.host) === h
    && Number(n.port) === port
    && String(n.protocol || "tcp").toLowerCase() === prot
  ));
}

function serviceNotesForHostLabel(notes, hostLabel) {
  if (!hostLabel) return [];
  const h = String(hostLabel);
  return arrayOrEmpty(notes).filter(n=>String(n.host) === h);
}

function findServiceByNote(host, note) {
  if (!host || !note) return null;
  const port = Number(note.port);
  const protocol = String(note.protocol || "tcp").toLowerCase();
  return arrayOrEmpty(host.services).find(
    svc => Number(svc.port) === port && String(svc.protocol || "tcp").toLowerCase() === protocol,
  ) || null;
}

function noteBrowserUrl(hostLabel, note) {
  const host = String(hostLabel || note?.host || "").trim();
  if (!host) return null;
  const port = Number(note?.port || 0);
  if (![80, 443, 8080, 8443].includes(port)) return null;
  const scheme = port === 443 || port === 8443 ? "https" : "http";
  const omit = (scheme === "http" && port === 80) || (scheme === "https" && port === 443);
  return `${scheme}://${host}${omit ? "" : `:${port}`}/`;
}

function findingsTabsForHostService(host, service) {
  if (!host) return ["global"];
  if (service && !serviceIsWeb(service)) return ["overview","cve","artifacts"];
  return ["overview","http","directories","cve","artifacts"];
}

function findingPortLabel(item) {
  const service = item?.__service;
  if (service) return serviceLabel(service);
  const parts = portProtocolFromFinding(item || {});
  return parts.port === "unknown" ? "—" : `${parts.port}/${parts.protocol}`;
}

function isHttpsLike(service) {
  const protocol = String(service?.protocol || "").toLowerCase();
  const name = String(service?.serviceName || "").toLowerCase();
  const port = Number(service?.port || 0);
  return protocol === "https" || name.includes("https") || port === 443;
}

function normalizePath(value) {
  const text = String(value || "").trim();
  if (!text) return "/";
  return text.startsWith("/") ? text : `/${text}`;
}

function serviceHostLabel(host, item) {
  const url = safeUrl(findingUrl(item));
  return String(firstDefined(url?.hostname, host?.label, hostFromFinding(item), "unknown") || "unknown");
}

function buildDiscoveredUrls(host, service) {
  const webContext = !service || serviceIsWeb(service);
  if (!webContext) return [];
  const rows = [];
  const seen = new Set();
  const pushRow = row => {
    const key = `${row.url}|${row.source}|${row.serviceInfo || ""}`;
    if (seen.has(key)) return;
    seen.add(key);
    rows.push(row);
  };

  const httpRows = findingsForContext(host, service, "http");
  httpRows.forEach(item=>{
    const evidence = findingEvidence(item);
    const url = findingUrl(item);
    if (!url) return;
    const rowService = service || item.__service;
    pushRow({
      url,
      source: "HTTP",
      status: firstDefined(evidence.status_code, null),
      size: firstDefined(evidence.content_length, evidence.size, null),
      time: firstDefined(evidence.response_time_ms, evidence.time_ms, null),
      serviceInfo: service ? "" : serviceLabel(rowService),
    });
  });

  const directoryRows = findingsForContext(host, service, "directories");
  directoryRows.forEach(item=>{
    const evidence = findingEvidence(item);
    const explicitUrl = safeUrl(findingUrl(item));
    const rowService = service || item.__service;
    const fallbackService = rowService || {port:firstDefined(portProtocolFromFinding(item).port, "80"), protocol:firstDefined(portProtocolFromFinding(item).protocol, "http"), serviceName:"http"};
    const scheme = isHttpsLike(fallbackService) ? "https" : "http";
    const hostLabel = serviceHostLabel(host, item);
    const port = Number(fallbackService?.port || 0);
    const omitPort = (scheme === "http" && port === 80) || (scheme === "https" && port === 443);
    const path = normalizePath(firstDefined(evidence.path, explicitUrl?.pathname, item.target, "/"));
    const url = explicitUrl ? explicitUrl.toString() : `${scheme}://${hostLabel}${omitPort || !port ? "" : `:${port}`}${path}`;
    pushRow({
      url,
      source: "Directory",
      status: firstDefined(evidence.status_code, null),
      size: firstDefined(evidence.content_length, evidence.size, null),
      time: firstDefined(evidence.response_time_ms, evidence.time_ms, null),
      serviceInfo: service ? "" : serviceLabel(rowService || fallbackService),
    });
  });

  return rows.sort((a,b)=>a.url.localeCompare(b.url));
}

function defaultPortForProtocol(protocol) {
  if (protocol === "https:") return "443";
  if (protocol === "http:") return "80";
  return "";
}

function hostPortContextForUrl(url, fallbackHost = "unknown") {
  const parsed = safeUrl(url);
  if (!parsed) return `${fallbackHost}:—`;
  const host = parsed.hostname || fallbackHost;
  const port = parsed.port || defaultPortForProtocol(parsed.protocol) || "—";
  return `${host}:${port}`;
}

function generate_note_suggestion(service) {
  const port = Number(service?.port || 0);
  const name = String(service?.serviceName || service?.name || "").toLowerCase();
  const protocol = String(service?.protocol || "tcp").toLowerCase();
  const suggestions = [];
  const httpLike = name.includes("http") || [80, 443, 8080, 8443].includes(port);
  if (httpLike) {
    suggestions.push("HTTPS/HTTP service detected");
    suggestions.push("Possible web admin panel exposure");
    suggestions.push("Consider directory scan with ffuf");
  }
  if (name.includes("ssh") || port === 22) {
    suggestions.push("SSH exposed - review auth policy and hardening");
    suggestions.push("Check weak credentials and remote access controls");
  }
  if ([1433, 1521, 3306, 5432, 6379, 27017].includes(port)) {
    suggestions.push("Database service exposure detected");
    suggestions.push("Verify network ACL and trusted source restrictions");
  }
  if (suggestions.length === 0) {
    suggestions.push(`${protocol.toUpperCase()} service discovered`);
    suggestions.push("Review necessity and access policy for this port");
  }
  return suggestions.join("\n");
}

function ServiceNoteModal({ runId, variant, hostLabel, service, existingNote, initialText, onClose, onComplete, toast }) {
  const [text, setText] = useState(()=>(variant === "edit" && existingNote
    ? existingNote.note
    : (variant === "create" && (String(initialText || "").trim() || (service ? generate_note_suggestion(service) : "")))
  ) || "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const title = variant === "edit" ? "Edit note" : "Add note";
  const save = async () => {
    const t = String(text || "").trim();
    if (!t) {
      setErr("Note cannot be empty");
      return;
    }
    setBusy(true);
    setErr("");
    try {
      if (variant === "create") {
        await apiJson(`/api/runs/${encodeURIComponent(runId)}/service-notes`, {
          method:"POST",
          body:JSON.stringify({
            host: hostLabel,
            port: Number(service.port),
            protocol: String(service.protocol || "tcp"),
            service_name: String(service.serviceName || ""),
            note: t,
          }),
        });
        toast.push({ type:"success", title:"Note saved" });
      } else if (existingNote?.id) {
        await apiJson(`/api/runs/${encodeURIComponent(runId)}/service-notes/${encodeURIComponent(existingNote.id)}`, {
          method:"PATCH",
          body:JSON.stringify({ note: t }),
        });
        toast.push({ type:"success", title:"Note updated" });
      }
      onComplete();
      onClose();
    } catch (e) {
      setErr(e.message || "Request failed");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div style={{position:"fixed",inset:0,background:"rgba(2,6,23,0.66)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:80}} onClick={event=>{ if (event.target === event.currentTarget && !busy) onClose(); }}>
      <div data-service-note-modal="vantage" style={{width:480,maxWidth:"90vw",background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:10,padding:14}} onClick={e=>e.stopPropagation()}>
        <div style={{fontSize:14,color:C.inkBright,fontWeight:700}}>{title}</div>
        {variant === "create" && service && (
          <div style={{marginTop:6,fontSize:11,color:C.slate,fontFamily:"JetBrains Mono, monospace"}}>{hostLabel} · {service.port}/{service.protocol} · {service.serviceName}</div>
        )}
        {variant === "edit" && existingNote && (
          <div style={{marginTop:6,fontSize:11,color:C.slate,fontFamily:"JetBrains Mono, monospace"}}>{existingNote.host} · {existingNote.port}/{existingNote.protocol || "tcp"}</div>
        )}
        <textarea value={text} onChange={e=>setText(e.target.value)} placeholder="Your note..." rows={6}
          style={{...inputStyle,marginTop:12,width:"100%",minHeight:120,resize:"vertical",fontFamily:"inherit"}}/>
        {err ? <div style={{marginTop:8,fontSize:12,color:"#FCA5A5"}}>{err}</div> : null}
        <div style={{marginTop:12,display:"flex",justifyContent:"flex-end",gap:8}}>
          <button type="button" onClick={onClose} disabled={busy} style={actionButtonStyle}>Cancel</button>
          <button type="button" onClick={save} disabled={busy} style={{...actionButtonStyle,borderColor:C.blueBorder,color:C.sky}}>{busy ? "Saving..." : "Save"}</button>
        </div>
      </div>
    </div>
  );
}

function FindingsPage({ runId }) {
  const toast = useToast();
  const route = useRoute();
  const [runView, setRunView] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [visMode, setVisMode] = useState("all");
  const [artifact, setArtifact] = useState(null);
  const [followupDialog, setFollowupDialog] = useState(null);
  const [followupBusy, setFollowupBusy] = useState(false);
  const [followupError, setFollowupError] = useState("");
  const [dismissedRecommendations, setDismissedRecommendations] = useState({});
  const [lastFfufSkipped, setLastFfufSkipped] = useState([]);
  const [allRuns, setAllRuns] = useState([]);
  const [diffData, setDiffData] = useState(null);
  const [serviceNotes, setServiceNotes] = useState([]);
  const [baselineServiceNotes, setBaselineServiceNotes] = useState([]);
  const [noteModal, setNoteModal] = useState(null);

  const refreshServiceNotes = useCallback(()=>{
    apiJson(`/api/runs/${encodeURIComponent(runId)}/service-notes`)
      .then(data=>setServiceNotes(arrayOrEmpty(data.notes)))
      .catch(()=>setServiceNotes([]));
  }, [runId]);

  useEffect(()=>{
    setRunView(null);
    setLoading(true);
    setError("");
    apiJson(`/api/runs/${encodeURIComponent(runId)}`)
      .then(data=>setRunView(data))
      .catch(err=>setError(err.message))
      .finally(()=>setLoading(false));
  },[runId]);
  useEffect(()=>{
    apiJson("/api/runs")
      .then(data=>setAllRuns(arrayOrEmpty(data.runs)))
      .catch(()=>setAllRuns([]));
  }, [runId]);
  useEffect(()=>{ refreshServiceNotes(); }, [refreshServiceNotes]);

  const model = useMemo(()=>buildFindingsModel(runView),[runView]);
  const aggregate = useMemo(()=>summarizeFindingsAggregate(model),[model]);
  const priorityQueue = useMemo(()=>buildPriorityQueue(model),[model]);
  const hostParam = route.search.get("host") || "";
  const serviceParam = route.search.get("service") || "";
  const compareParam = route.search.get("compare") || "";
  const compareOptions = useMemo(
    ()=>arrayOrEmpty(allRuns)
      .filter(item=>String(item.id) !== String(runId) && String(item.status) === "completed")
      .map(item=>({id:String(item.id), label:String(firstDefined(item.display_name, item.target, item.id))})),
    [allRuns, runId]
  );
  const recommendations = useMemo(
    ()=>buildRecommendedActions({ model, aggregate, compareRunId: compareParam, lastFfufSkipped })
      .filter(item=>!dismissedRecommendations[item.id]),
    [model, aggregate, compareParam, lastFfufSkipped, dismissedRecommendations]
  );
  const selectedHost = model.hosts.find(host=>host.id === hostParam || host.label === hostParam) || null;
  const selectedService = selectedHost ? selectedHost.services.find(service=>service.id === serviceParam) || null : null;
  const availableTabs = findingsTabsForHostService(selectedHost, selectedService);
  const defaultTab = selectedHost ? "overview" : "global";
  const requestedTab = route.search.get("tab") || defaultTab;
  const activeTab = availableTabs.includes(requestedTab) ? requestedTab : defaultTab;

  useEffect(()=>{
    if (!compareParam) return;
    toast.push({
      type:"info",
      title:"Comparing runs",
      description: compareParam,
      priority:"low",
      actionLabel:"Open findings",
      onAction:()=>navigate(`/runs/${encodeURIComponent(runId)}/findings?compare=${encodeURIComponent(compareParam)}`),
    });
  }, [compareParam]);
  useEffect(()=>{
    if (!compareParam) {
      setDiffData(null);
      setBaselineServiceNotes([]);
      return;
    }
    apiJson(`/api/runs/${encodeURIComponent(runId)}/diff?baseline=${encodeURIComponent(compareParam)}`)
      .then(data=>setDiffData(data))
      .catch(()=>setDiffData(null));
    apiJson(`/api/runs/${encodeURIComponent(compareParam)}/service-notes`)
      .then(data=>setBaselineServiceNotes(arrayOrEmpty(data.notes)))
      .catch(()=>setBaselineServiceNotes([]));
  }, [runId, compareParam]);
  const changeAlerts = useMemo(
    ()=>[
      ...buildChangeAlerts({ diffData, runId, model }),
      ...buildNoteDiffAlerts({ runId, compareRunId: compareParam, model, baselineNotes: baselineServiceNotes }),
    ],
    [diffData, runId, model, compareParam, baselineServiceNotes]
  );

  const deleteServiceNote = async id => {
    if (!window.confirm("Delete this note?")) return;
    try {
      await apiJson(`/api/runs/${encodeURIComponent(runId)}/service-notes/${encodeURIComponent(id)}`, { method:"DELETE" });
      toast.push({ type:"success", title:"Note deleted" });
      refreshServiceNotes();
    } catch (e) {
      toast.push({ type:"error", title:"Delete failed", description: e.message || "" });
    }
  };

  const runServiceFromNote = (note, options = {}) => {
    if (!selectedHost) return;
    const matched = findServiceByNote(selectedHost, note);
    if (!matched) {
      toast.push({ type:"warning", title:"Service not found", description:"Could not map note to a current service." });
      return;
    }
    openFollowupDialog("Run ffuf on selected service", [serviceTargetPayload(selectedHost, matched)]);
    if (options.deep) {
      setFollowupDialog(prev=>prev ? {...prev, recursive:true, maxDepth:2, force:true} : prev);
    }
  };

  const openBrowserFromNote = note => {
    if (!selectedHost) return;
    const url = noteBrowserUrl(selectedHost.label, note);
    if (!url) {
      toast.push({ type:"warning", title:"Not a web service", description:"Browser shortcut is available only for common web ports." });
      return;
    }
    window.open(url, "_blank", "noopener,noreferrer");
  };

  const openDirectoryUrl = item => {
    const parsed = safeUrl(findingUrl(item));
    if (!parsed || !["http:", "https:"].includes(parsed.protocol)) {
      toast.push({ type:"warning", title:"Invalid URL", description:"Only http/https URLs can be opened." });
      return;
    }
    window.open(parsed.toString(), "_blank", "noopener,noreferrer");
  };

  const runDirectoryFfufFollowup = item => {
    if (!selectedHost) return;
    const rowService = selectedService || item?.__service;
    if (!serviceIsWeb(rowService)) {
      toast.push({ type:"warning", title:"Not a web service", description:"Directory follow-up is available only for web services." });
      return;
    }
    openFollowupDialog("Run recursive ffuf from directory finding", [serviceTargetPayload(selectedHost, rowService)]);
    setFollowupDialog(prev=>prev ? {...prev, recursive:true, maxDepth:2} : prev);
  };

  const addDirectoryNote = item => {
    if (!selectedHost) return;
    const rowService = selectedService || item?.__service;
    if (!rowService) return;
    const ev = findingEvidence(item);
    const path = String(firstDefined(ev.path, safeUrl(findingUrl(item))?.pathname, "/") || "/");
    const status = Number(firstDefined(ev.status_code, ev.status, 0) || 0);
    const hint = path.toLowerCase().includes("/admin")
      ? "Possible admin interface."
      : "Review access controls and exposure.";
    const suggestion = `Discovered ${path} (status ${status || "unknown"}). ${hint}`;
    setNoteModal({
      kind:"create",
      hostLabel:selectedHost.label,
      service:rowService,
      initialText:suggestion,
    });
  };

  const runRecommendation = item => {
    const kind = String(item?.type || "");
    if (kind === "review_cve") {
      navigate(`/runs/${encodeURIComponent(runId)}/findings?tab=cve`);
      return;
    }
    if (kind === "run_recursive_sensitive") {
      openFollowupDialog("Run recursive ffuf from sensitive paths", arrayOrEmpty(item.targets));
      setFollowupDialog(prev=>prev ? {...prev, recursive:true, maxDepth:2, pathHints:arrayOrEmpty(item.sensitivePaths)} : prev);
      return;
    }
    if (kind === "rerun_force") {
      openFollowupDialog("Re-run ffuf with force", arrayOrEmpty(item.targets));
      setFollowupDialog(prev=>prev ? {...prev, force:true} : prev);
      return;
    }
    if (kind === "run_ffuf_web" || kind === "run_ffuf_diff_web") {
      openFollowupDialog(item.title || "Run ffuf", arrayOrEmpty(item.targets));
      return;
    }
  };

  const dismissRecommendation = id => {
    setDismissedRecommendations(prev=>({...prev, [id]: true}));
  };
  const onChangeAlertBaseline = nextId => {
    updateQuery({compare:nextId || ""});
  };

  const updateQuery = next => {
    const params = new URLSearchParams();
    const host = next.host !== undefined ? next.host : hostParam;
    const service = next.service !== undefined ? next.service : serviceParam;
    const tab = next.tab !== undefined ? next.tab : activeTab;
    const compare = next.compare !== undefined ? next.compare : compareParam;
    if (host) params.set("host", host);
    if (service) params.set("service", service);
    if (tab && tab !== "overview") params.set("tab", tab);
    if (compare) params.set("compare", compare);
    const suffix = params.toString();
    navigate(`/runs/${encodeURIComponent(runId)}/findings${suffix ? `?${suffix}` : ""}`);
  };

  const openFollowupDialog = (title, targets) => {
    if (!Array.isArray(targets) || targets.length === 0) return;
    setFollowupError("");
    setFollowupDialog({
      title,
      targets,
      wordlist: runView?.run?.config?.ffuf_wordlist_path || "",
      recursive: false,
      maxDepth: 1,
      force: false,
    });
  };

  const submitFollowup = async () => {
    if (!followupDialog || followupBusy) return;
    setFollowupBusy(true);
    setFollowupError("");
    try {
      const payload = {
        targets: followupDialog.targets,
        wordlist: followupDialog.wordlist || undefined,
        recursive: !!followupDialog.recursive,
        max_depth: Number(followupDialog.maxDepth || 1),
        force: !!followupDialog.force,
      };
      const queued = await apiJson(`/api/runs/${encodeURIComponent(runId)}/dir-enum`, {
        method:"POST",
        body:JSON.stringify(payload),
      });
      setLastFfufSkipped(arrayOrEmpty(queued.skipped_targets));
      const skippedCount = Number(queued.skipped || 0);
      const queuedCount = Number(queued.queued || 0);
      const skippedReasonText = summarizeSkippedReasonsFriendly(queued.skipped_targets || []);
      toast.push({
        type: skippedCount > 0 ? "warning" : "success",
        title: `ffuf queued for ${queuedCount} services`,
        description: skippedCount > 0
          ? `${skippedCount} skipped (${skippedReasonText || "Unknown reason"})`
          : null,
        details: arrayOrEmpty(queued.skipped_targets),
        actionLabel: "View execution",
        onAction: () => navigate(`/runs/${encodeURIComponent(runId)}/execution`),
      });
      if (Number(queued.queued || 0) > 0) {
        await apiJson(`/api/runs/${encodeURIComponent(runId)}/execute`, {method:"POST", body:JSON.stringify({})});
      }
      setFollowupDialog(null);
      navigate(`/runs/${encodeURIComponent(runId)}/execution`);
    } catch (err) {
      setFollowupError(err.message || "Failed to queue ffuf follow-up");
    } finally {
      setFollowupBusy(false);
    }
  };

  return (
    <div data-findings-page="vantage" style={{height:"100%",display:"flex",flexDirection:"column",overflow:"hidden"}}>
      <FindingsPageHeader runView={runView} runId={runId} compare={compareParam}/>
      {error&&<div style={{margin:16}}><ErrorState msg={`Failed to load run data: ${error}`}/></div>}
      {loading ? (
        <div style={{padding:24}}><LoadingState msg="Loading findings..."/></div>
      ) : (
        selectedHost ? (
          <div style={{flex:1,minHeight:0,display:"grid",gridTemplateColumns:"260px 220px minmax(0,1fr)",overflow:"hidden"}}>
            <FindingsHostNavigator hosts={model.hosts} query={query} onQuery={setQuery} visMode={visMode} onVisMode={setVisMode}
              selectedHostId={selectedHost.id} onSelect={host=>updateQuery(host ? {host:host.id, service:"", tab:"overview"} : {host:"", service:"", tab:"global"})}/>
            <FindingsServicePanel host={selectedHost} selectedServiceId={selectedService?.id}
              serviceNotes={serviceNotes}
              onSelect={service=>updateQuery({host:selectedHost.id, service:selectedService?.id === service.id ? "" : service.id, tab:"overview"})}
              onRunServiceFfuf={service=>openFollowupDialog("Run ffuf on selected service", [serviceTargetPayload(selectedHost, service)])}
              onRunHostFfuf={()=>{
                const targets = selectedHost.services.filter(serviceIsWeb).map(svc=>serviceTargetPayload(selectedHost, svc));
                openFollowupDialog("Run ffuf on selected web services", targets);
              }}/>
            <FindingsResultPanel host={selectedHost} service={selectedService} activeTab={activeTab} tabs={availableTabs}
              onActiveTab={tab=>updateQuery({tab})} onArtifact={setArtifact}
              recommendations={recommendations.filter(item=>!item.hostId || item.hostId === selectedHost.id)}
              onRunRecommendation={runRecommendation}
              onDismissRecommendation={dismissRecommendation}
              serviceNotes={serviceNotes}
              onAddServiceNote={()=>{
                if (!selectedHost || !selectedService) return;
                setNoteModal({ kind:"create", hostLabel: selectedHost.label, service: selectedService });
              }}
              onEditServiceNote={note=>setNoteModal({ kind:"edit", note })}
              onDeleteServiceNote={deleteServiceNote}
              onRunFfufForNote={note=>runServiceFromNote(note)}
              onOpenBrowserForNote={openBrowserFromNote}
              onRescanDeeperForNote={note=>runServiceFromNote(note, { deep:true })}
              onDirectoryOpen={openDirectoryUrl}
              onDirectoryRunFfuf={runDirectoryFfufFollowup}
              onDirectoryAddNote={addDirectoryNote}/>
          </div>
        ) : (
          <div style={{flex:1,minHeight:0,display:"grid",gridTemplateColumns:"260px minmax(0,1fr)",overflow:"hidden"}}>
            <FindingsHostNavigator hosts={model.hosts} query={query} onQuery={setQuery} visMode={visMode} onVisMode={setVisMode}
              selectedHostId={null} onSelect={host=>updateQuery(host ? {host:host.id, service:"", tab:"overview"} : {host:"", service:"", tab:"global"})}/>
            <div style={{padding:16,overflow:"auto"}}>
              <ChangeAlertsPanel
                alerts={changeAlerts}
                baselineRunId={compareParam}
                compareOptions={compareOptions}
                onChangeBaseline={onChangeAlertBaseline}
              />
              <div style={{height:12}}/>
              <GlobalNotesSummaryPanel runId={runId} notes={serviceNotes}/>
              <div style={{height:12}}/>
              <RecommendedActionsPanel items={recommendations} onRun={runRecommendation} onDismiss={dismissRecommendation}/>
              <div style={{height:12}}/>
              <PriorityQueueSection runId={runId} rows={priorityQueue}/>
              <div style={{height:12}}/>
              <GlobalSummaryPanel runId={runId} aggregate={aggregate}
                onRunGlobalFfuf={()=>{
                  const targets = model.hosts.flatMap(host=>arrayOrEmpty(host.services).filter(serviceIsWeb).map(svc=>serviceTargetPayload(host, svc)));
                  openFollowupDialog("Run ffuf on discovered web ports", targets);
                }}/>
            </div>
          </div>
        )
      )}
      {artifact&&<FindingsArtifactSidePanel artifact={artifact} onClose={()=>setArtifact(null)}/>}
      {followupDialog&&(
        <FfufFollowupDialog
          dialog={followupDialog}
          busy={followupBusy}
          error={followupError}
          onChange={next=>setFollowupDialog({...followupDialog, ...next})}
          onClose={()=>!followupBusy&&setFollowupDialog(null)}
          onConfirm={submitFollowup}
        />
      )}
      {noteModal?.kind === "create" && noteModal.service && (
        <ServiceNoteModal
          key={`create-${noteModal.service.id}`}
          runId={runId}
          variant="create"
          hostLabel={noteModal.hostLabel}
          service={noteModal.service}
          initialText={noteModal.initialText}
          onClose={()=>setNoteModal(null)}
          onComplete={refreshServiceNotes}
          toast={toast}
        />
      )}
      {noteModal?.kind === "edit" && noteModal.note && (
        <ServiceNoteModal
          key={noteModal.note.id}
          runId={runId}
          variant="edit"
          existingNote={noteModal.note}
          onClose={()=>setNoteModal(null)}
          onComplete={refreshServiceNotes}
          toast={toast}
        />
      )}
    </div>
  );
}

function FindingsPageHeader({ runView, runId, compare }) {
  const run = runView?.run || {};
  const autoRec = runView?.run?.config?.auto_recommendation_enabled !== false;
  return (
    <div style={{padding:"18px 24px",borderBottom:`1px solid ${C.slateMid}`,display:"flex",alignItems:"center",gap:14,flexShrink:0}}>
      <div>
        <div style={{fontFamily:"'Orbitron',sans-serif",fontSize:18,letterSpacing:"0.08em",color:C.inkBright}}>Findings</div>
        <div style={{marginTop:5,fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>{run.target_display || run.target || run.run_id || runId}</div>
      </div>
      <RunStatusPill run={{...run, execution:runView?.execution}}/>
      <Tag color={autoRec ? C.blueDim : "rgba(100,116,139,0.25)"}>Auto Recommendation: {autoRec ? "ON" : "OFF"}</Tag>
      <Tag color="rgba(59,130,246,0.20)">Config changes apply to upcoming tasks only</Tag>
      {compare&&<Tag color={C.sky}>Compare: {compare}</Tag>}
    </div>
  );
}

function FfufFollowupDialog({ dialog, busy, error, onChange, onClose, onConfirm }) {
  return (
    <div style={{position:"fixed",inset:0,background:"rgba(2,6,23,0.66)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:70}}>
      <div style={{width:560,maxWidth:"90vw",background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:10,padding:14}}>
        <div style={{fontSize:14,color:C.inkBright,fontWeight:700}}>{dialog.title || "Run ffuf follow-up"}</div>
        <div style={{marginTop:8,fontSize:12,color:C.slate}}>
          Selected targets: <b style={{color:C.sky}}>{arrayOrEmpty(dialog.targets).length}</b>
        </div>
        {arrayOrEmpty(dialog.pathHints).length>0 && (
          <div style={{marginTop:6,fontSize:11,color:C.slate}}>
            Recommended path hints: {arrayOrEmpty(dialog.pathHints).slice(0, 4).join(", ")}
          </div>
        )}
        <div style={{marginTop:10,display:"grid",gridTemplateColumns:"1fr 120px",gap:10}}>
          <div>
            <div style={{fontSize:11,color:C.slate,marginBottom:5}}>Wordlist (optional)</div>
            <input value={dialog.wordlist || ""} onChange={event=>onChange({wordlist:event.target.value})} style={inputStyle} placeholder="wordlists/test.txt"/>
          </div>
          <div>
            <div style={{fontSize:11,color:C.slate,marginBottom:5}}>Max Depth</div>
            <input type="number" min={1} max={10} value={dialog.maxDepth || 1}
              onChange={event=>onChange({maxDepth:Number(event.target.value) || 1})} style={inputStyle}/>
          </div>
        </div>
        <label style={{marginTop:10,display:"inline-flex",gap:8,alignItems:"center",fontSize:12,color:C.ink}}>
          <input type="checkbox" checked={!!dialog.recursive} onChange={event=>onChange({recursive:event.target.checked})}/>
          Recursive
        </label>
        <label style={{marginTop:8,display:"inline-flex",gap:8,alignItems:"center",fontSize:12,color:C.ink}}>
          <input type="checkbox" checked={!!dialog.force} onChange={event=>onChange({force:event.target.checked})}/>
          Re-run even if already scanned
        </label>
        {error&&<div style={{marginTop:8,fontSize:12,color:"#FCA5A5"}}>{error}</div>}
        <div style={{marginTop:12,display:"flex",justifyContent:"flex-end",gap:8}}>
          <button type="button" onClick={onClose} disabled={busy} style={actionButtonStyle}>Cancel</button>
          <button type="button" onClick={onConfirm} disabled={busy} style={{...actionButtonStyle,borderColor:C.blueBorder,color:C.sky}}>
            {busy ? "Queueing..." : "Run ffuf"}
          </button>
        </div>
      </div>
    </div>
  );
}

function FindingsHostNavigator({ hosts, query, onQuery, visMode, onVisMode, selectedHostId, onSelect }) {
  const filtered = arrayOrEmpty(hosts).filter(host=>{
    const matchesMode = visMode === "all" || host.type === "web";
    const matchesQuery = host.label.toLowerCase().includes(query.toLowerCase());
    return matchesMode && matchesQuery;
  });
  return (
    <div style={{borderRight:`1px solid ${C.slateMid}`,background:"#0B1220",padding:14,overflow:"auto"}}>
      <SectionLabel>Hosts</SectionLabel>
      <input value={query} onChange={event=>onQuery(event.target.value)} placeholder="Filter host/IP/domain" style={{...inputStyle,marginBottom:10}}/>
      <div style={{display:"flex",gap:6,marginBottom:12}}>
        {["all","web"].map(mode=>(
          <button key={mode} onClick={()=>onVisMode(mode)} style={{...actionButtonStyle,color:visMode===mode?C.sky:C.slate,borderColor:visMode===mode?C.blueBorder:C.slateMid}}>
            {mode === "all" ? "All" : "Web only"}
          </button>
        ))}
      </div>
      <button onClick={()=>onSelect(null)} style={{textAlign:"left",border:`1px solid ${!selectedHostId?C.blueBorder:C.slateMid}`,borderRadius:6,padding:10,
        background:!selectedHostId?C.blueDim:C.slateDark,color:C.ink,cursor:"pointer",marginBottom:10}}>
        <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>Global</div>
        <div style={{marginTop:7,display:"flex",gap:6,alignItems:"center",fontSize:10,color:C.slate}}>
          <span style={{color:C.sky,fontWeight:700}}>SUMMARY</span>
          <span>all hosts</span>
        </div>
      </button>
      {filtered.length===0 ? <EmptyState msg={query ? `No hosts matching "${query}"` : "No hosts yet."}/> : (
        <div style={{display:"grid",gap:8}}>
          {filtered.map(host=><FindingsHostItem key={host.id} host={host} selected={selectedHostId===host.id} onClick={()=>onSelect(host)}/>)}
        </div>
      )}
    </div>
  );
}

function FindingsHostItem({ host, selected, onClick }) {
  const badge = host.type === "web" ? "WEB" : (host.type === "non-web" ? "NON-WEB" : "UNKNOWN");
  const color = host.type === "web" ? C.sky : (host.type === "non-web" ? C.slate : C.muted);
  return (
    <button onClick={onClick} style={{textAlign:"left",border:`1px solid ${selected?C.blueBorder:C.slateMid}`,borderRadius:6,padding:10,
      background:selected?C.blueDim:C.slateDark,color:C.ink,cursor:"pointer"}}>
      <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{host.label}</div>
      <div style={{marginTop:7,display:"flex",gap:6,alignItems:"center",fontSize:10,color:C.slate}}>
        <span style={{color,fontWeight:700}}>{badge}</span>
        <span>{host.portsCount} ports</span>
        <span>{host.findingsCount} findings</span>
      </div>
    </button>
  );
}

function FindingsServicePanel({ host, selectedServiceId, serviceNotes, onSelect, onRunServiceFfuf, onRunHostFfuf }) {
  if (!host) {
    return <div style={{borderRight:`1px solid ${C.slateMid}`,padding:14,background:C.slateDark}}><EmptyState msg="Select a host to view services."/></div>;
  }
  const webCount = arrayOrEmpty(host.services).filter(serviceIsWeb).length;
  return (
    <div style={{borderRight:`1px solid ${C.slateMid}`,padding:14,background:C.slateDark,overflow:"auto"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8,gap:8}}>
        <SectionLabel>Services</SectionLabel>
        <button type="button" onClick={onRunHostFfuf} disabled={webCount===0}
          style={{...actionButtonStyle,padding:"6px 8px",fontSize:11}}>
          Run ffuf on selected web services
        </button>
      </div>
      {host.services.length===0 ? <EmptyState msg="No services for selected host."/> : (
        <div style={{display:"grid",gap:8}}>
          {host.services.map(service=>(
            <FindingsServiceItem key={service.id} service={service} selected={selectedServiceId===service.id}
              noteCount={serviceNotesForService(serviceNotes, host.label, service).length}
              onClick={()=>onSelect(service)} onRunFfuf={()=>onRunServiceFfuf(service)}/>
          ))}
        </div>
      )}
    </div>
  );
}

function FindingsServiceItem({ service, selected, noteCount, onClick, onRunFfuf }) {
  const web = serviceIsWeb(service);
  const n = Number(noteCount || 0);
  const techBadges = serviceTechnologies(service);
  return (
    <div className={n > 0 ? "service-has-notes" : ""} style={{
      border:`1px solid ${selected?C.blueBorder:(n > 0 ? "rgba(167,139,250,0.45)" : C.slateMid)}`,
      borderLeft: n > 0 ? "3px solid rgba(167,139,250,0.8)" : "1px solid transparent",
      borderRadius:6,
      padding:10,
      background:selected ? C.blueDim : (n > 0 ? "rgba(167,139,250,0.08)" : "#0B1220"),
    }}>
      <button onClick={onClick} style={{textAlign:"left",border:"none",padding:0,background:"transparent",color:C.ink,cursor:"pointer",width:"100%"}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:6}}>
          <span style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.sky}}>{service.port}/{service.protocol}</span>
          {n > 0 && <span style={{fontSize:10,fontWeight:700,color:"#A78BFA",border:`1px solid rgba(167,139,250,0.4)`,borderRadius:10,padding:"0 6px"}}>📝 {n}</span>}
        </div>
        <div style={{marginTop:4,fontSize:12,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{service.serviceName}</div>
        {techBadges.length > 0 && (
          <div style={{marginTop:6,display:"flex",gap:5,flexWrap:"wrap"}}>
            {techBadges.map(tech=>(
              <Tag key={`${service.id}-${tech}`} color={C.blueDim}>{tech}</Tag>
            ))}
          </div>
        )}
        <div style={{marginTop:6,fontSize:10,color:web?C.sky:C.slate,fontWeight:700}}>{web ? "WEB" : "NON-WEB"}</div>
      </button>
      <div style={{marginTop:8,display:"flex",justifyContent:"flex-end"}}>
        <button
          type="button"
          onClick={event=>{ event.stopPropagation(); if (web) onRunFfuf(); }}
          disabled={!web}
          title={web ? "Run ffuf" : "Directory scan is only available for web services."}
          style={{...actionButtonStyle,padding:"5px 8px",fontSize:11,opacity:web?1:0.65}}
        >
          Run ffuf
        </button>
      </div>
    </div>
  );
}

function FindingsResultPanel({ host, service, activeTab, tabs, onActiveTab, onArtifact, recommendations, onRunRecommendation, onDismissRecommendation, serviceNotes, onAddServiceNote, onEditServiceNote, onDeleteServiceNote, onRunFfufForNote, onOpenBrowserForNote, onRescanDeeperForNote, onDirectoryOpen, onDirectoryRunFfuf, onDirectoryAddNote }) {
  return (
    <div style={{display:"flex",flexDirection:"column",minWidth:0,overflow:"hidden"}}>
      <FindingsContextHeader host={host} service={service} onAddServiceNote={onAddServiceNote}/>
      <FindingsTabsBar tabs={tabs} active={activeTab} onChange={onActiveTab}/>
      <div style={{flex:1,overflow:"auto",padding:16}}>
        {activeTab === "overview"&&(
          <FindingsOverviewTab
            host={host}
            service={service}
            recommendations={recommendations}
            onRunRecommendation={onRunRecommendation}
            onDismissRecommendation={onDismissRecommendation}
            serviceNotes={serviceNotes}
            onEditServiceNote={onEditServiceNote}
            onDeleteServiceNote={onDeleteServiceNote}
            onRunFfufForNote={onRunFfufForNote}
            onOpenBrowserForNote={onOpenBrowserForNote}
            onRescanDeeperForNote={onRescanDeeperForNote}
          />
        )}
        {activeTab === "http"&&<FindingsHTTPTable rows={findingsForContext(host, service, "http")} showPort={!service}/>}
        {activeTab === "directories"&&<FindingsDirectoryCards
          rows={findingsForContext(host, service, "directories")}
          showLocation={!service}
          onOpen={onDirectoryOpen}
          onRunFfuf={onDirectoryRunFfuf}
          onAddNote={onDirectoryAddNote}
        />}
        {activeTab === "cve"&&<FindingsCVECards rows={findingsForContext(host, service, "cve")} service={service}/>}
        {activeTab === "artifacts"&&<FindingsArtifactList rows={findingsForContext(host, service, "artifacts")} onSelect={onArtifact}/>}
      </div>
    </div>
  );
}

function GlobalSummaryPanel({ runId, aggregate, onRunGlobalFfuf }) {
  const cards = [
    ["Hosts", aggregate.hosts],
    ["Web Hosts", aggregate.webHosts],
    ["Open Ports", aggregate.ports],
    ["HTTP Findings", aggregate.http],
    ["Directories", aggregate.directories],
    ["CVE Candidates", aggregate.cve],
    ["Artifacts", aggregate.artifacts],
  ];

  return (
    <div style={{border:`1px solid ${C.slateMid}`,borderRadius:8,padding:14,background:C.slateDark}}>
      <SectionLabel>Global Findings Summary</SectionLabel>
      <div style={{display:"grid",gap:12}}>
        <div style={{display:"flex",justifyContent:"flex-end"}}>
          <button type="button" onClick={onRunGlobalFfuf} disabled={!arrayOrEmpty(aggregate.allOpenPorts).some(item=>serviceIsWeb(item))}
            style={{...actionButtonStyle,padding:"7px 10px",fontSize:12}}>
            Run ffuf on discovered web ports
          </button>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(7,minmax(110px,1fr))",gap:8}}>
          {cards.map(([label, value])=>(
            <div key={label} style={{border:`1px solid ${C.slateMid}`,borderRadius:6,padding:"9px 10px",background:"#0B1220"}}>
              <div style={{fontSize:10,color:C.slate,textTransform:"uppercase",letterSpacing:"0.08em"}}>{label}</div>
              <div style={{marginTop:6,fontFamily:"JetBrains Mono, monospace",fontSize:16,color:C.inkBright}}>{value}</div>
            </div>
          ))}
        </div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
          <div style={{border:`1px solid ${C.slateMid}`,borderRadius:6,padding:10,background:"#0B1220"}}>
            <div style={{fontSize:10,color:C.slate,textTransform:"uppercase",letterSpacing:"0.08em",marginBottom:7}}>All Open Ports</div>
            {arrayOrEmpty(aggregate.allOpenPorts).length===0 ? <div style={{fontSize:11,color:C.slate}}>No open ports discovered.</div> : (
              <div style={{maxHeight:300,overflowY:"auto",display:"grid",gap:6}}>
                {arrayOrEmpty(aggregate.allOpenPorts).map((item,index)=>(
                  <button key={`${item.host}-${item.serviceId || index}`} onClick={()=>navigate(`/runs/${encodeURIComponent(runId)}/findings?host=${encodeURIComponent(item.host)}${item.serviceId ? `&service=${encodeURIComponent(item.serviceId)}` : ""}`)}
                    style={{textAlign:"left",border:`1px solid ${C.slateMid}`,borderRadius:5,padding:"7px 8px",background:C.slateDark,cursor:"pointer"}}>
                    <div style={{display:"grid",gridTemplateColumns:"1fr auto auto",gap:8,alignItems:"center"}}>
                      <span style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.ink,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{item.host}</span>
                      <span style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.sky}}>{item.port}/{item.protocol}</span>
                      <span style={{fontSize:10,color:C.slate}}>{item.serviceName}</span>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
          <div style={{border:`1px solid ${C.slateMid}`,borderRadius:6,padding:10,background:"#0B1220"}}>
            <div style={{fontSize:10,color:C.slate,textTransform:"uppercase",letterSpacing:"0.08em",marginBottom:7}}>All Directories</div>
            {arrayOrEmpty(aggregate.allDirectories).length===0 ? <div style={{fontSize:11,color:C.slate}}>No directory findings discovered.</div> : (
              <div style={{maxHeight:300,overflowY:"auto",display:"grid",gap:6}}>
                {arrayOrEmpty(aggregate.allDirectories).map((item,index)=>(
                  <button key={`${item.host}-${item.path}-${index}`} onClick={()=>navigate(`/runs/${encodeURIComponent(runId)}/findings?host=${encodeURIComponent(item.host)}&tab=directories${item.serviceId ? `&service=${encodeURIComponent(item.serviceId)}` : ""}`)}
                    style={{textAlign:"left",border:`1px solid ${C.slateMid}`,borderRadius:5,padding:"7px 8px",background:C.slateDark,cursor:"pointer"}}>
                    <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.ink,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{item.path}</div>
                    <div style={{marginTop:4,display:"flex",gap:8,flexWrap:"wrap",fontSize:10,color:C.slate}}>
                      <span style={{fontFamily:"JetBrains Mono, monospace"}}>{item.hostContext}</span>
                      {(item.status !== null && item.status !== undefined) && <span>{item.status}</span>}
                      {(item.size !== null && item.size !== undefined) && <span>{formatBytes(item.size)}</span>}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
        <div style={{border:`1px solid ${C.slateMid}`,borderRadius:6,padding:12,background:"#0B1220"}}>
          <SectionLabel>Global Discovered URLs</SectionLabel>
          {arrayOrEmpty(aggregate.globalUrls).length===0 ? <EmptyState msg="No discovered URLs in this run."/> : (
            <div style={{display:"grid",gap:8}}>
              {arrayOrEmpty(aggregate.globalUrls).map((row,index)=>{
                const parsed = safeUrl(row.url);
                const clickable = Boolean(parsed && ["http:","https:"].includes(parsed.protocol));
                return (
                  <div key={`${row.url}-${index}`} style={{border:`1px solid ${C.slateMid}`,borderRadius:6,padding:"9px 10px",background:C.slateDark}}>
                    <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
                      {clickable ? (
                        <a href={row.url} target="_blank" rel="noreferrer" style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.sky,textDecoration:"none"}}>
                          {row.url}
                        </a>
                      ) : (
                        <span style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.ink}}>{row.url}</span>
                      )}
                    </div>
                    <div style={{marginTop:6,display:"flex",gap:10,flexWrap:"wrap",fontSize:11,color:C.slate}}>
                      <span>{row.source}</span>
                      <span style={{fontFamily:"JetBrains Mono, monospace"}}>{row.hostContext}</span>
                      {(row.status !== null && row.status !== undefined) && <span>{row.status}</span>}
                      {(row.size !== null && row.size !== undefined) && <span>{formatBytes(row.size)}</span>}
                      {(row.time !== null && row.time !== undefined) && <span style={{fontFamily:"JetBrains Mono, monospace"}}>{row.time}</span>}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function GlobalNotesSummaryPanel({ runId, notes }) {
  const rows = arrayOrEmpty(notes).slice().sort((a, b)=>(
    String(a.host).localeCompare(String(b.host))
    || Number(a.port || 0) - Number(b.port || 0)
    || String(a.protocol || "tcp").localeCompare(String(b.protocol || "tcp"))
    || String(a.updated_at || "").localeCompare(String(b.updated_at || ""))
  ));
  return (
    <div data-global-notes-summary="vantage" style={{border:`1px solid ${C.slateMid}`,borderRadius:8,padding:14,background:C.slateDark}}>
      <SectionLabel>Notes Summary</SectionLabel>
      {rows.length === 0 ? (
        <EmptyState msg="No service notes in this run."/>
      ) : (
        <div style={{display:"grid",gap:8}}>
          {rows.map((n, index)=>{
            const host = String(n.host || "unknown");
            const protocol = String(n.protocol || "tcp");
            const service = String(n.service_name || "");
            const port = Number(n.port || 0);
            const hostParam = encodeURIComponent(host);
            const serviceParam = encodeURIComponent(`${protocol}/${port || "unknown"}`);
            const href = `/runs/${encodeURIComponent(runId)}/findings?host=${hostParam}&service=${serviceParam}&tab=overview`;
            return (
              <button key={n.id || `${host}-${port}-${protocol}-${index}`} type="button" onClick={()=>navigate(href)}
                style={{textAlign:"left",border:`1px solid ${C.slateMid}`,borderRadius:6,padding:"10px 12px",background:"#0B1220",cursor:"pointer"}}>
                <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
                  <span style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.sky}}>{host}</span>
                  <span style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>{port}/{protocol}</span>
                  {service ? <Tag color="#A78BFA">{service}</Tag> : null}
                </div>
                <div style={{marginTop:6,fontSize:12,color:C.ink,whiteSpace:"pre-wrap",wordBreak:"break-word"}}>{String(n.note || "")}</div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function FindingsContextHeader({ host, service, onAddServiceNote }) {
  return (
    <div style={{padding:"14px 16px",borderBottom:`1px solid ${C.slateMid}`,display:"flex",gap:10,alignItems:"center",flexWrap:"wrap",justifyContent:"space-between"}}>
      <div style={{display:"flex",gap:10,alignItems:"center",flexWrap:"wrap"}}>
        <Tag color={C.sky}>Host: {host.label}</Tag>
        <Tag color={service ? C.ink : C.slate}>Service: {serviceLabel(service)}</Tag>
      </div>
      {service && onAddServiceNote && (
        <button type="button" data-add-service-note="vantage" onClick={onAddServiceNote}
          style={{...actionButtonStyle,padding:"6px 10px",fontSize:11}}>
          Add note
        </button>
      )}
    </div>
  );
}

function domainMappingHref(ev) {
  const d = String(ev?.domain || "").trim();
  if (!d) return null;
  return ev?.source === "http" ? `http://${d}/` : `https://${d}/`;
}

function FindingsTabsBar({ tabs, active, onChange }) {
  const labels = {global:"Global", overview:"Overview", http:"HTTP", directories:"Directories", cve:"CVE", artifacts:"Artifacts"};
  return (
    <div style={{display:"flex",gap:4,borderBottom:`1px solid ${C.slateMid}`,padding:"0 16px",background:"#0B1220"}}>
      {tabs.map(tab=>(
        <button key={tab} onClick={()=>onChange(tab)} style={{padding:"9px 10px",border:"none",borderBottom:`2px solid ${active===tab?C.blue:"transparent"}`,
          background:"transparent",color:active===tab?C.sky:C.slate,cursor:"pointer",fontSize:12}}>
          {labels[tab]}
        </button>
      ))}
    </div>
  );
}

function FindingsOverviewTab({ host, service, recommendations, onRunRecommendation, onDismissRecommendation, serviceNotes, onEditServiceNote, onDeleteServiceNote, onRunFfufForNote, onOpenBrowserForNote, onRescanDeeperForNote }) {
  const web = !service || serviceIsWeb(service);
  const valueFor = (key, count) => host.moduleAvailable?.[key] === false ? "Not run" : (count ? count : "No findings");
  const discoveredUrls = buildDiscoveredUrls(host, service);
  const hostNotes = serviceNotesForHostLabel(serviceNotes, host.label);
  const svcNotes = service ? serviceNotesForService(serviceNotes, host.label, service) : [];
  const cards = [
    web&&["HTTP Summary", valueFor("http", findingsForContext(host, service, "http").length), "HTTP probe results"],
    web&&["Discovery Summary", valueFor("directories", findingsForContext(host, service, "directories").length), "Directory findings"],
    ["Security Summary", valueFor("cve", findingsForContext(host, service, "cve").length), "Candidate CVEs"],
    ["Artifacts Summary", valueFor("artifacts", findingsForContext(host, service, "artifacts").length), "Raw artifacts"],
    ["Mapped domains", valueFor("domainMappings", findingsForContext(host, service, "domainMappings").length), "rDNS / TLS / HTTP"],
    ["Banners", valueFor("banners", findingsForContext(host, service, "banners").length), "Unknown service ports"],
  ].filter(Boolean);
  return (
    <div style={{display:"grid",gap:12}}>
      <RecommendedActionsPanel items={recommendations} onRun={onRunRecommendation} onDismiss={onDismissRecommendation}/>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(150px,1fr))",gap:12}}>
        {cards.map(([label,value,hint])=>(
          <div key={label} style={{border:`1px solid ${C.slateMid}`,borderRadius:7,padding:13,background:C.slateDark}}>
            <div style={{fontSize:10,color:C.slate,textTransform:"uppercase",letterSpacing:"0.08em"}}>{label}</div>
            <div style={{marginTop:8,fontFamily:"JetBrains Mono, monospace",fontSize:22,color:C.inkBright}}>{value}</div>
            <div style={{marginTop:4,fontSize:11,color:C.slate}}>{hint}</div>
          </div>
        ))}
      </div>
      <div data-service-notes-section="vantage" style={{border:`1px solid ${C.slateMid}`,borderRadius:7,padding:14,background:C.slateDark}}>
        <SectionLabel>Notes</SectionLabel>
        {!service ? (
          hostNotes.length === 0 ? (
            <EmptyState msg="Select a service to add notes"/>
          ) : (
            <div style={{display:"grid",gap:10}}>
              {hostNotes.map(n=>(
                <div key={n.id} style={{border:`1px solid ${C.slateMid}`,borderRadius:6,padding:"10px 12px",background:"#0B1220"}}>
                  <div style={{fontSize:10,color:C.slate,marginBottom:4,fontFamily:"JetBrains Mono, monospace"}}>{n.port}/{n.protocol || "tcp"}{n.service_name ? ` · ${n.service_name}` : ""}</div>
                  <div style={{fontSize:12,color:C.ink,whiteSpace:"pre-wrap",wordBreak:"break-word"}}>{n.note}</div>
                  <div style={{marginTop:8,display:"flex",gap:8,justifyContent:"flex-end"}}>
                    <button type="button" onClick={()=>onRunFfufForNote(n)} style={{...actionButtonStyle,padding:"4px 8px",fontSize:11}}>Run ffuf</button>
                    <button type="button" onClick={()=>onOpenBrowserForNote(n)} style={{...actionButtonStyle,padding:"4px 8px",fontSize:11}}>Open browser</button>
                    <button type="button" onClick={()=>onRescanDeeperForNote(n)} style={{...actionButtonStyle,padding:"4px 8px",fontSize:11}}>Re-scan deeper</button>
                    <button type="button" onClick={()=>onEditServiceNote(n)} style={{...actionButtonStyle,padding:"4px 8px",fontSize:11}}>Edit</button>
                    <button type="button" onClick={()=>onDeleteServiceNote(n.id)} style={{...actionButtonStyle,padding:"4px 8px",fontSize:11,color:"#FCA5A5",borderColor:"rgba(248,113,113,0.4)"}}>Delete</button>
                  </div>
                </div>
              ))}
            </div>
          )
        ) : svcNotes.length === 0 ? (
          <EmptyState msg="No notes for this service"/>
        ) : (
          <div style={{display:"grid",gap:8}}>
            {svcNotes.map(n=>(
              <div key={n.id} style={{border:`1px solid ${C.slateMid}`,borderRadius:6,padding:"10px 12px",background:"#0B1220"}}>
                <div style={{fontSize:12,color:C.ink,whiteSpace:"pre-wrap",wordBreak:"break-word"}}>{n.note}</div>
                <div style={{marginTop:8,display:"flex",gap:8,justifyContent:"flex-end"}}>
                  <button type="button" onClick={()=>onRunFfufForNote(n)} style={{...actionButtonStyle,padding:"4px 8px",fontSize:11}}>Run ffuf</button>
                  <button type="button" onClick={()=>onOpenBrowserForNote(n)} style={{...actionButtonStyle,padding:"4px 8px",fontSize:11}}>Open browser</button>
                  <button type="button" onClick={()=>onRescanDeeperForNote(n)} style={{...actionButtonStyle,padding:"4px 8px",fontSize:11}}>Re-scan deeper</button>
                  <button type="button" onClick={()=>onEditServiceNote(n)} style={{...actionButtonStyle,padding:"4px 8px",fontSize:11}}>Edit</button>
                  <button type="button" onClick={()=>onDeleteServiceNote(n.id)} style={{...actionButtonStyle,padding:"4px 8px",fontSize:11,color:"#FCA5A5",borderColor:"rgba(248,113,113,0.4)"}}>Delete</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      <div style={{border:`1px solid ${C.slateMid}`,borderRadius:7,padding:14,background:C.slateDark}}>
        <SectionLabel>Discovered URLs</SectionLabel>
        {!web ? (
          <EmptyState msg="No web URLs for this service."/>
        ) : discoveredUrls.length===0 ? (
          <EmptyState msg="No discovered URLs for this context."/>
        ) : (
          <div style={{display:"grid",gap:8}}>
            {discoveredUrls.map((row,index)=>{
              const parsed = safeUrl(row.url);
              const clickable = Boolean(parsed && ["http:","https:"].includes(parsed.protocol));
              return (
                <div key={`${row.url}-${index}`} style={{border:`1px solid ${C.slateMid}`,borderRadius:6,padding:"9px 10px",background:"#0B1220"}}>
                  <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
                    {clickable ? (
                      <a href={row.url} target="_blank" rel="noreferrer" style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.sky,textDecoration:"none"}}>
                        {row.url}
                      </a>
                    ) : (
                      <span style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.ink}}>{row.url}</span>
                    )}
                    <Tag color={row.source === "HTTP" ? C.blue : "#1d4ed8"}>{row.source}</Tag>
                    {row.status !== null && row.status !== undefined && <Tag color="#0f766e">Status {row.status}</Tag>}
                  </div>
                  <div style={{marginTop:6,display:"flex",gap:12,flexWrap:"wrap",fontSize:11,color:C.slate}}>
                    {!service && row.serviceInfo && <span style={{fontFamily:"JetBrains Mono, monospace"}}>{row.serviceInfo}</span>}
                    {(row.size !== null && row.size !== undefined) && <span>size {formatBytes(row.size)}</span>}
                    {(row.time !== null && row.time !== undefined) && <span style={{fontFamily:"JetBrains Mono, monospace"}}>time {row.time}</span>}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
      <div style={{border:`1px solid ${C.slateMid}`,borderRadius:7,padding:14,background:C.slateDark}}>
        <SectionLabel>Mapped domains</SectionLabel>
        {findingsForContext(host, service, "domainMappings").length===0 ? (
          <EmptyState msg="No domain mappings for this host."/>
        ) : (
          <div style={{display:"grid",gap:8}}>
            {findingsForContext(host, service, "domainMappings").map((item,index)=>{
              const ev = findingEvidence(item);
              const href = domainMappingHref(ev);
              const label = String(ev.domain || item.target || "—");
              return (
                <div key={item.finding_id || `${label}-${index}`} style={{border:`1px solid ${C.slateMid}`,borderRadius:6,padding:"9px 10px",background:"#0B1220",display:"flex",gap:10,alignItems:"center",flexWrap:"wrap"}}>
                  {href ? (
                    <a href={href} target="_blank" rel="noreferrer" style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.sky,textDecoration:"none"}}>{label}</a>
                  ) : (
                    <span style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.ink}}>{label}</span>
                  )}
                  <Tag color="#334155">{String(ev.source || "—")}</Tag>
                  {ev.ip ? <span style={{fontSize:11,color:C.slate}}>IP {ev.ip}</span> : null}
                </div>
              );
            })}
          </div>
        )}
      </div>
      <div style={{border:`1px solid ${C.slateMid}`,borderRadius:7,padding:14,background:C.slateDark}}>
        <SectionLabel>TCP banners</SectionLabel>
        {findingsForContext(host, service, "banners").length===0 ? (
          <EmptyState msg="No banner probes in this context."/>
        ) : (
          <div style={{display:"grid",gap:8}}>
            {findingsForContext(host, service, "banners").map((item,index)=>{
              const ev = findingEvidence(item);
              const rowService = service || item.__service;
              return (
                <div key={item.finding_id || `${item.target}-${index}`} style={{border:`1px solid ${C.slateMid}`,borderRadius:6,padding:"9px 10px",background:"#0B1220"}}>
                  <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
                    <span style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.sky}}>{ev.port}/{ev.protocol || "tcp"}</span>
                    <Tag color="#7c3aed">{String(ev.guessed_service || "unknown")}</Tag>
                    {!service && rowService ? <span style={{fontSize:10,color:C.slate}}>{serviceLabel(rowService)}</span> : null}
                  </div>
                  <div style={{marginTop:6,fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.ink,whiteSpace:"pre-wrap",wordBreak:"break-word"}}>{ev.banner_preview || "—"}</div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function FindingsHTTPTable({ rows, showPort }) {
  const data = arrayOrEmpty(rows);
  if (data.length===0) return <EmptyState msg="No HTTP findings for this context."/>;
  const headers = showPort ? ["Port","URL","Status","Title","Tech","Response Time"] : ["URL","Status","Title","Tech","Response Time"];
  return (
    <table style={{width:"100%",borderCollapse:"collapse",background:C.slateDark,border:`1px solid ${C.slateMid}`,borderRadius:7,overflow:"hidden"}}>
      <thead><tr>{headers.map(header=><th key={header} style={{textAlign:"left",padding:"9px",fontSize:10,color:C.slate,textTransform:"uppercase"}}>{header}</th>)}</tr></thead>
      <tbody>
        {data.map((item,index)=>{
          const evidence = findingEvidence(item);
          return (
            <tr key={item.finding_id || `${item.target}-${index}`} style={{borderTop:`1px solid ${C.slateMid}`}}
              onMouseEnter={event=>event.currentTarget.style.background=C.rowHover}
              onMouseLeave={event=>event.currentTarget.style.background="transparent"}>
              {showPort&&<td style={{padding:"9px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.sky}}>{findingPortLabel(item)}</td>}
              <td style={{padding:"9px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.ink}}>{findingUrl(item) || "—"}</td>
              <td style={{padding:"9px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.sky}}>{evidence.status_code ?? "—"}</td>
              <td style={{padding:"9px",fontSize:11,color:C.ink}}>{evidence.title || item.summary || "—"}</td>
              <td style={{padding:"9px",fontSize:11,color:C.slate}}>{arrayOrEmpty(evidence.technologies).join(", ") || "—"}</td>
              <td style={{padding:"9px",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>{firstDefined(evidence.response_time_ms, evidence.time_ms, "—")}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function FindingsDirectoryCards({ rows, showLocation, onOpen, onRunFfuf, onAddNote }) {
  const data = arrayOrEmpty(rows);
  if (data.length===0) return <EmptyState msg="No directory findings for this context."/>;
  const sensitiveHints = ["/admin", "/.git", "/backup", "/config"];
  const groups = new Map();
  data.forEach(item=>{
    const key = showLocation ? findingPortLabel(item) : "Current service";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  });
  const groupedRows = Array.from(groups.entries());
  return (
    <div style={{display:"grid",gap:12}}>
      <div style={{display:"flex",alignItems:"center",gap:8}}>
        <SectionLabel>Directory Findings</SectionLabel>
        <Tag color={C.blueDim}>Count {data.length}</Tag>
      </div>
      {groupedRows.map(([group, items])=>(
        <div key={group} style={{display:"grid",gap:8}}>
          <div style={{display:"flex",alignItems:"center",gap:8}}>
            <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>Service {group}</div>
            <Tag color={C.blueDim}>{items.length}</Tag>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(240px,1fr))",gap:10}}>
            {items.map((item,index)=>{
              const evidence = findingEvidence(item);
              const url = safeUrl(findingUrl(item));
              const status = Number(firstDefined(evidence.status_code, evidence.status, 0) || 0);
              const path = String(firstDefined(evidence.path, url?.pathname, item.target, "/") || "/");
              const lowerPath = path.toLowerCase();
              const sensitive = sensitiveHints.some(hint=>lowerPath.includes(hint));
              const isServerError = status >= 500 && status < 600;
              const canOpen = Boolean(url && ["http:","https:"].includes(url.protocol));
              const showOpen = status === 200 && canOpen;
              const inspectAndRun = status === 401 || status === 403;
              const runLabel = inspectAndRun ? "Inspect + Run ffuf" : "Run ffuf";
              const rowService = item?.__service;
              const canRunFfuf = rowService ? serviceIsWeb(rowService) : true;
              return (
                <div key={item.finding_id || `${item.target}-${index}`} style={{
                  border:`1px solid ${isServerError ? "rgba(248,113,113,0.6)" : (sensitive ? "rgba(239,68,68,0.55)" : C.slateMid)}`,
                  borderRadius:7,padding:12,background:C.slateDark,transition:"border-color 0.12s"
                }}
                  onMouseEnter={event=>event.currentTarget.style.borderColor=isServerError ? "rgba(248,113,113,0.8)" : C.blueBorder}
                  onMouseLeave={event=>event.currentTarget.style.borderColor=isServerError ? "rgba(248,113,113,0.6)" : (sensitive ? "rgba(239,68,68,0.55)" : C.slateMid)}>
                  <div style={{display:"flex",alignItems:"center",gap:8,justifyContent:"space-between"}}>
                    <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.ink,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{path}</div>
                    {sensitive ? <Tag color="rgba(239,68,68,0.25)">Sensitive</Tag> : null}
                  </div>
                  <div style={{marginTop:8,display:"flex",gap:8,fontSize:11,color:C.slate}}>
                    <span>Status <b style={{color:isServerError ? "#FCA5A5" : C.sky}}>{firstDefined(evidence.status_code, evidence.status, "—")}</b></span>
                    <span>Size <b style={{color:C.sky}}>{formatBytes(firstDefined(evidence.content_length, evidence.size, 0))}</b></span>
                  </div>
                  {(evidence.recursion_depth != null && evidence.recursion_depth !== undefined) && (
                    <div style={{marginTop:6,fontSize:11,color:C.slate}}>Recursion depth <b style={{color:C.sky}}>{evidence.recursion_depth}</b></div>
                  )}
                  {(evidence.parent_base_url || evidence.parent_path) && (
                    <div style={{marginTop:4,fontFamily:"JetBrains Mono, monospace",fontSize:10,color:"#94A3B8"}}>Parent: {String(evidence.parent_path || evidence.parent_base_url || "—")}</div>
                  )}
                  <div data-directory-actions="vantage" style={{marginTop:8,display:"flex",justifyContent:"flex-end",gap:6,flexWrap:"wrap"}}>
                    {showOpen ? (
                      <button type="button" onClick={()=>onOpen&&onOpen(item)} style={{...actionButtonStyle,padding:"4px 8px",fontSize:11}}>
                        Open
                      </button>
                    ) : null}
                    <button type="button" disabled={!canRunFfuf} onClick={()=>onRunFfuf&&onRunFfuf(item)} style={{...actionButtonStyle,padding:"4px 8px",fontSize:11,opacity:canRunFfuf?1:0.65}}>
                      {runLabel}
                    </button>
                    <button type="button" onClick={()=>onAddNote&&onAddNote(item)} style={{...actionButtonStyle,padding:"4px 8px",fontSize:11}}>
                      Add note
                    </button>
                  </div>
                  {showLocation&&<div style={{marginTop:8,fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>Found on: {findingPortLabel(item)}</div>}
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

function FindingsCVECards({ rows, service }) {
  const data = arrayOrEmpty(rows);
  if (data.length===0) return <EmptyState msg="No CVE candidates for this context."/>;
  return (
    <div style={{display:"grid",gap:10}}>
      {data.map((item,index)=>{
        const evidence = findingEvidence(item);
        return (
          <div key={item.finding_id || `${item.target}-${index}`} style={{border:"1px solid rgba(234,179,8,0.35)",borderRadius:7,padding:12,background:"rgba(234,179,8,0.06)",transition:"border-color 0.12s"}}
            onMouseEnter={event=>event.currentTarget.style.borderColor="#FDE68A"}
            onMouseLeave={event=>event.currentTarget.style.borderColor="rgba(234,179,8,0.35)"}>
            <div style={{display:"flex",gap:8,alignItems:"center"}}>
              <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:13,color:"#FDE68A"}}>{evidence.cve_id || item.summary || "CVE candidate"}</div>
              <Tag color="#FDE68A">{firstDefined(evidence.severity, evidence.confidence, "candidate")}</Tag>
            </div>
            <div style={{marginTop:7,fontSize:12,color:C.ink}}>{evidence.title || evidence.description || item.summary || "—"}</div>
            <div style={{marginTop:7,fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.slate}}>Affected service: {serviceLabel(service || item.__service)}</div>
            <div style={{marginTop:7,fontSize:11,color:"#FDE68A"}}>Candidate only — not confirmed vulnerability</div>
          </div>
        );
      })}
    </div>
  );
}

function FindingsArtifactList({ rows, onSelect }) {
  const data = arrayOrEmpty(rows);
  if (data.length===0) return <EmptyState msg="No artifacts for this context."/>;
  return (
    <div style={{display:"grid",gap:8}}>
      {data.map((item,index)=>(
        <button key={item.artifact_id || item.path || index} onClick={()=>onSelect(item)} style={{textAlign:"left",border:`1px solid ${C.slateMid}`,borderRadius:7,padding:11,background:C.slateDark,color:C.ink,cursor:"pointer"}}>
          <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:12}}>{String(item.path || item.artifact_id || "artifact").split(/[\\/]/).pop()}</div>
          <div style={{marginTop:6,fontSize:11,color:C.slate}}>{item.module || "—"} / {item.tool || "—"} / {formatBytes(item.size_bytes)} / {item.content_type || "unknown"}</div>
        </button>
      ))}
    </div>
  );
}

function FindingsArtifactSidePanel({ artifact, onClose }) {
  const [tab, setTab] = useState("raw");
  const [rawState, setRawState] = useState({loading:false, content:"", error:""});
  useEffect(()=>{
    const handler = event => { if (event.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  },[onClose]);
  useEffect(()=>{
    if (!artifact.path) {
      setRawState({loading:false, content:"", error:"Unable to load artifact content"});
      return;
    }
    setRawState({loading:true, content:"", error:""});
    apiText(`/api/dashboard/artifact?path=${encodeURIComponent(artifact.path)}`)
      .then(content=>setRawState({loading:false, content, error:""}))
      .catch(()=>setRawState({loading:false, content:"", error:"Unable to load artifact content"}));
  },[artifact.path]);
  const metadata = objectOrEmpty(artifact.metadata);
  const hasParsed = Object.keys(metadata).length > 0;
  return (
    <div style={{position:"fixed",top:0,right:0,bottom:0,width:460,background:C.slateDark,borderLeft:`1px solid ${C.blueBorder}`,zIndex:60,boxShadow:"-20px 0 60px rgba(0,0,0,0.35)",display:"flex",flexDirection:"column"}}>
      <div style={{padding:16,borderBottom:`1px solid ${C.slateMid}`,display:"flex",alignItems:"center",gap:10}}>
        <div style={{fontFamily:"JetBrains Mono, monospace",fontSize:12,color:C.ink,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{artifact.path || artifact.artifact_id || "artifact"}</div>
        <div style={{flex:1}}/>
        <button onClick={onClose} style={actionButtonStyle}>X</button>
      </div>
      <div style={{display:"flex",gap:6,padding:"10px 16px",borderBottom:`1px solid ${C.slateMid}`}}>
        {["raw", ...(hasParsed ? ["parsed"] : [])].map(name=>(
          <button key={name} onClick={()=>setTab(name)} style={{...actionButtonStyle,color:tab===name?C.sky:C.slate,borderColor:tab===name?C.blueBorder:C.slateMid}}>{name}</button>
        ))}
      </div>
      <div style={{padding:16,overflow:"auto",flex:1}}>
        {tab === "raw" ? (
          rawState.loading ? <LoadingState msg="Loading artifact content..."/> : (
            rawState.error ? <ErrorState msg={rawState.error}/> : (
              <pre style={{margin:0,whiteSpace:"pre-wrap",wordBreak:"break-word",fontFamily:"JetBrains Mono, monospace",fontSize:11,lineHeight:1.55,color:C.ink,
                border:`1px solid ${C.slateMid}`,borderRadius:6,padding:12,background:"#0B1220"}}>{rawState.content || "No data"}</pre>
            )
          )
        ) : (
          <pre style={{margin:0,whiteSpace:"pre-wrap",fontFamily:"JetBrains Mono, monospace",fontSize:11,color:C.ink}}>{JSON.stringify(metadata, null, 2)}</pre>
        )}
      </div>
    </div>
  );
}

function FindingsPagePlaceholder({ runId }) {
  return <PlaceholderPage title="Findings" runId={runId}/>;
}

// ── App Root ───────────────────────────────────────────────────────────────────
function App() {
  const route = useRoute();
  const matched = matchRoute(route.pathname);
  const openNewScan = route.search.has("newScan") || route.pathname === "/runs/new";
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  if (matched.page === "execution") {
    if (!matched.runId) {
      return <AppShell active="execution" sidebarCollapsed={sidebarCollapsed} onToggleSidebar={()=>setSidebarCollapsed(v=>!v)}><RunPickerPage page="execution" title="Execution" subtitle="Select a run to start, resume, cancel, or watch progress."/></AppShell>;
    }
    return <AppShell active="execution" runId={matched.runId} sidebarCollapsed={sidebarCollapsed} onToggleSidebar={()=>setSidebarCollapsed(v=>!v)}><ExecutionPage runId={matched.runId}/></AppShell>;
  }
  if (matched.page === "summary") {
    if (!matched.runId) {
      return <AppShell active="summary" sidebarCollapsed={sidebarCollapsed} onToggleSidebar={()=>setSidebarCollapsed(v=>!v)}><RunPickerPage page="summary" title="Run Summary" subtitle="Select a run to inspect normalized results and scan quality."/></AppShell>;
    }
    return <AppShell active="summary" runId={matched.runId} sidebarCollapsed={sidebarCollapsed} onToggleSidebar={()=>setSidebarCollapsed(v=>!v)}><RunSummaryPage runId={matched.runId}/></AppShell>;
  }
  if (matched.page === "findings") {
    if (!matched.runId) {
      return <AppShell active="findings" sidebarCollapsed={sidebarCollapsed} onToggleSidebar={()=>setSidebarCollapsed(v=>!v)}><RunPickerPage page="findings" title="Findings" subtitle="Select a run to open host, service, directory, artifact, and CVE findings."/></AppShell>;
    }
    return <AppShell active="findings" runId={matched.runId} sidebarCollapsed={sidebarCollapsed} onToggleSidebar={()=>setSidebarCollapsed(v=>!v)}><FindingsPage runId={matched.runId}/></AppShell>;
  }
  if (matched.page === "artifacts") {
    return <AppShell active="artifacts" runId={matched.runId} sidebarCollapsed={sidebarCollapsed} onToggleSidebar={()=>setSidebarCollapsed(v=>!v)}><ArtifactsPage runId={matched.runId}/></AppShell>;
  }
  if (matched.page === "reports") {
    return <AppShell active="reports" runId={matched.runId} sidebarCollapsed={sidebarCollapsed} onToggleSidebar={()=>setSidebarCollapsed(v=>!v)}><ReportsPage runId={matched.runId}/></AppShell>;
  }
  if (["settings","tools","profiles","wordlists"].includes(matched.page)) {
    return <AppShell active="settings" runId={matched.runId} sidebarCollapsed={sidebarCollapsed} onToggleSidebar={()=>setSidebarCollapsed(v=>!v)}><SettingsPage runId={matched.runId}/></AppShell>;
  }
  return <AppShell active={openNewScan ? "new" : "runs"} sidebarCollapsed={sidebarCollapsed} onToggleSidebar={()=>setSidebarCollapsed(v=>!v)}><RunsDashboard initialNewScanOpen={openNewScan}/></AppShell>;
}

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <ToastProvider>
    <App/>
  </ToastProvider>
);
""",

    # ── closing tags ──
    "</script>\n</body>\n</html>\n",
]
DASHBOARD_HTML = "".join(_DASHBOARD_HTML_PARTS)
