/**
 * Dashboard.jsx — wired to FastAPI /api/scan
 * Updated to fix Compliance counting and add PCI DSS support.
 */
import { useState, useEffect } from "react";
import "./Dashboard.css";

const SEV_COLOR  = { CRITICAL:"#ff3b5c", HIGH:"#ff7c2a", MEDIUM:"#e6b800", LOW:"#22c97a", UNKNOWN:"#9490b5" };
const TYPE_COLORS = ["#6c47ff","#c84bff","#ff4d8d","#ff7c2a","#00d4aa"];
const FW_ICON    = { ISO_27001:"🔒", NIST_CSF:"🏛", OWASP:"🕷", PCI_DSS:"💳", SOC2:"🏢" };
const PRI_COLOR  = { IMMEDIATE:"#ff3b5c", HIGH:"#ff7c2a", MEDIUM:"#e6b800", LOW:"#22c97a" };

// ─── normalise ────────────────────────────────────────────────────────────────
function normalise(raw) {
  if (!raw) return null;
  const secrets    = Array.isArray(raw.exposed_secrets)        ? raw.exposed_secrets        : [];
  const risks      = Array.isArray(raw.risk_scores)            ? raw.risk_scores            : [];
  const mitigs     = Array.isArray(raw.mitigation_suggestions) ? raw.mitigation_suggestions : [];
  const compliance = Array.isArray(raw.compliance_mappings)    ? raw.compliance_mappings    : [];
  const repo = raw.repository_info ?? {};
  const repoName = repo.full_name ?? (repo.owner && repo.repo_name ? `${repo.owner}/${repo.repo_name}` : repo.url ?? "unknown/repo");
  
  const summary = raw.summary ?? { 
    total_secrets:secrets.length, 
    critical_count:risks.filter(r=>r.severity==="CRITICAL").length, 
    high_count:risks.filter(r=>r.severity==="HIGH").length, 
    medium_count:risks.filter(r=>r.severity==="MEDIUM").length, 
    low_count:risks.filter(r=>r.severity==="LOW").length, 
    overall_risk: raw.summary?.overall_risk ?? "UNKNOWN" 
  };

  const merged = secrets.map((s,i) => { 
    const r = risks[i]??{}; 
    return { 
        id:i+1, 
        provider:s.provider??"Unknown", 
        type:s.secret_type??s.type??"Unknown", 
        file_name:s.file_path??s.file_name??"unknown", 
        line_number:s.line_number??0, 
        is_valid:s.is_valid??false, 
        secret_preview:s.masked_value??"***", 
        environment:s.environment??"Unknown", 
        privilege:s.privilege_level??"Low", 
        context:s.context??"", 
        exposure_type:s.exposure_type??"Hardcoded", 
        validation_msg:s.validation_result??"", 
        severity:r.severity??"LOW", 
        risk_score:r.total_score??0, 
        exploit_prob:r.exploitation_probability??0 
    }; 
  });

  // FIX: Force violation count if backend returns 0 but has items in violated_controls
  const mappedCompliance = compliance.map(m => {
    const violated_list = Array.isArray(m.violated_controls) ? m.violated_controls : [];
    return {
        framework: m.framework??"Unknown",
        framework_name: m.framework_name??m.framework??"Unknown",
        compliance_status: m.compliance_status??"UNKNOWN",
        controls: Array.isArray(m.controls)?m.controls:[],
        violated_controls: violated_list.map(v=>({ 
            control_id:v.control_id??"—", 
            control_name:v.control_name??"—", 
            description:v.description??"", 
            violation:v.violation??"", 
            remediation:v.remediation??"" 
        })),
        total_violations: m.total_violations > 0 ? m.total_violations : violated_list.length,
        severity: m.severity??null 
    };
  });

  const mappedMitigs = mitigs.map(m => ({ priority:m.priority??"MEDIUM", action:m.action??"Action", description:m.description??"", effort:m.effort??"—", done:false }));
  const ai=raw.ai_predictions??{}, aiTrends=ai.trends??{}, aiModel=ai.model_info??{};
  const typeMap={}; merged.forEach(s=>{typeMap[s.type]=(typeMap[s.type]||0)+1;});
  const secretTypes=Object.entries(typeMap).sort((a,b)=>b[1]-a[1]).map(([type,count])=>({type,count}));
  
  const SEV_R={CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1}; 
  const fileMap={};
  merged.forEach(s=>{
    if(!fileMap[s.file_name]) fileMap[s.file_name]={file:s.file_name,secrets:0,severity:"LOW"};
    fileMap[s.file_name].secrets++;
    if((SEV_R[s.severity]||0)>(SEV_R[fileMap[s.file_name].severity]||0)) fileMap[s.file_name].severity=s.severity;
  });
  const vulnerableFiles=Object.values(fileMap).sort((a,b)=>b.secrets-a.secrets).slice(0,6);
  
  const provMap={}; merged.forEach(s=>{provMap[s.provider]=(provMap[s.provider]||0)+1;});
  const providerBreakdown=Object.entries(provMap).sort((a,b)=>b[1]-a[1]).map(([provider,count])=>({provider,count}));
  
  const riskDist=aiTrends.risk_distribution??{};
  const aiRiskTrend=Object.keys(riskDist).length>0?Object.entries(riskDist).map(([label,score])=>({month:label,score})):risks.slice(-6).map((r,i)=>({month:`#${i+1}`,score:r.total_score}));
  
  const avgRisk=risks.length?risks.reduce((s,r)=>s+r.total_score,0)/risks.length:0;
  
  return { 
    repository_info:{full_name:repoName,owner:repo.owner??"",repo_name:repo.repo_name??"",url:repo.url??"#",is_public:repo.is_public??true,last_scanned:new Date().toISOString()}, 
    summary, 
    exposed_secrets:merged, 
    compliance_mappings:mappedCompliance, 
    mitigation_suggestions:mappedMitigs, 
    ai_predictions:{
        trends:{risk_distribution:riskDist,most_likely_risk:aiTrends.most_likely_risk??summary.overall_risk,average_confidence:aiTrends.average_confidence??0},
        model_info:{model_type:aiModel.model_type??"Random Forest Classifier",accuracy:aiModel.accuracy??"—"}
    }, 
    secret_types:secretTypes, 
    vulnerable_files:vulnerableFiles, 
    provider_breakdown:providerBreakdown, 
    ai_risk_trend:aiRiskTrend, 
    security_score:Math.max(0,Math.round(100-avgRisk)), 
    risk_scores:risks 
  };
}

// ─── exports ──────────────────────────────────────────────────────────────────
function dl(blob,name){const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=name;a.click();}
function exportCSV(s){const h=["#","Provider","Type","File","Line","Severity","Risk","Valid","Env","Privilege"];const rows=s.map(x=>[x.id,x.provider,x.type,x.file_name,x.line_number,x.severity,x.risk_score,x.is_valid?"Yes":"No",x.environment,x.privilege]);dl(new Blob([[h,...rows].map(r=>r.map(v=>`"${v}"`).join(",")).join("\n")],{type:"text/csv"}),"security-report.csv");}
function exportJSON(data){dl(new Blob([JSON.stringify(data,null,2)],{type:"application/json"}),"security-report.json");}
function exportHTML(R){const sc={CRITICAL:"crit",HIGH:"high",MEDIUM:"med",LOW:"low"};dl(new Blob([`<!DOCTYPE html><html><head><title>Report</title><style>body{font-family:sans-serif;padding:32px;max-width:900px;margin:auto;background:#f5f5ff}h1{color:#6c47ff}table{width:100%;border-collapse:collapse;margin:1em 0}th{background:#6c47ff;color:#fff;padding:10px;text-align:left}td{padding:8px 10px;border-bottom:1px solid #ddd}.crit{color:#c00;font-weight:700}.high{color:#c05;font-weight:700}.med{color:#960;font-weight:700}.low{color:#270;font-weight:700}</style></head><body><h1>Security Report — ${R.repository_info.full_name}</h1><p>Generated: ${new Date().toLocaleString()} | Overall Risk: <span class="${sc[R.summary.overall_risk]||""}">${R.summary.overall_risk}</span></p><h2>Secrets (${R.exposed_secrets.length})</h2><table><tr><th>Provider</th><th>File</th><th>Line</th><th>Severity</th><th>Risk</th></tr>${R.exposed_secrets.map(s=>`<tr><td><b>${s.provider}</b></td><td><code>${s.file_name}</code></td><td>${s.line_number}</td><td class="${sc[s.severity]||""}">${s.severity}</td><td>${s.risk_score}</td></tr>`).join("")}</table></body></html>`],{type:"text/html"}),"security-report.html");}

// ─── SparkBar ──────────────────────────────────────────────────────────────────
function SparkBar({data,highlight}){const vals=data.map(d=>d.value??d.score??0);const max=Math.max(...vals,1);return(<div className="sparkbar">{data.map((d,i)=>(<div key={i} className="sparkbar-col"><div className="sparkbar-fill" style={{height:`${(vals[i]/max)*56}px`,background:highlight?`rgba(200,75,255,${0.25+0.75*(i/Math.max(data.length-1,1))})`:i===data.length-1?"linear-gradient(180deg,#6c47ff,#4a2fcf)":"rgba(108,71,255,0.3)"}}/><span className="sparkbar-label">{d.date??d.month??""}</span></div>))}</div>);}

// ─── Donut ─────────────────────────────────────────────────────────────────────
function Donut({segments,size=128}){const total=segments.reduce((s,d)=>s+d.value,0)||1;let cum=0;const Rad=46,cx=size/2,cy=size/2;const paths=segments.map(d=>{const a0=(cum/total)*2*Math.PI-Math.PI/2;cum+=d.value;const a1=(cum/total)*2*Math.PI-Math.PI/2;const x0=cx+Rad*Math.cos(a0),y0=cy+Rad*Math.sin(a0),x1=cx+Rad*Math.cos(a1),y1=cy+Rad*Math.sin(a1);return{...d,path:`M${cx},${cy} L${x0},${y0} A${Rad},${Rad} 0 ${a1-a0>Math.PI?1:0} 1 ${x1},${y1} Z`};});return(<svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{flexShrink:0}}>{paths.map((p,i)=><path key={i} d={p.path} fill={p.color} opacity={0.9}/>)}<circle cx={cx} cy={cy} r={30} fill="white"/><text x={cx} y={cy-4} textAnchor="middle" fill="#6c47ff" fontSize="16" fontWeight="800">{total}</text><text x={cx} y={cy+13} textAnchor="middle" fill="#9490b5" fontSize="9">total</text></svg>);}

// ─── ScoreRing ─────────────────────────────────────────────────────────────────
function ScoreRing({score}){const pct=Math.min(Math.max(score,0),100),R=54,circ=2*Math.PI*R;const color=pct>=80?"#22c97a":pct>=60?"#e6b800":pct>=40?"#ff7c2a":"#ff3b5c";return(<div className="score-ring-wrap"><svg width="144" height="144" viewBox="0 0 144 144"><circle cx="72" cy="72" r={R} fill="none" stroke="rgba(108,71,255,0.1)" strokeWidth="13"/><circle cx="72" cy="72" r={R} fill="none" stroke={color} strokeWidth="13" strokeDasharray={`${(pct/100)*circ} ${circ}`} strokeLinecap="round" transform="rotate(-90 72 72)" style={{transition:"stroke-dasharray 1.2s ease"}}/></svg><div className="score-ring-inner"><span className="score-val" style={{color}}>{pct}</span><span className="score-sub">/ 100</span></div></div>);}

// ─── Secret Drawer ─────────────────────────────────────────────────────────────
function SecretDrawer({secret,onClose}){const sev=(secret.severity??"low").toLowerCase();return(<><div className="drawer-overlay" onClick={onClose}/><aside className="secret-drawer"><div className="drawer-top"><h3 className="drawer-title">Secret Details</h3><button className="drawer-close" onClick={onClose}>×</button></div><div className={`drawer-banner banner-${sev}`}><span className="drawer-sev">{secret.severity} — Risk Score: {secret.risk_score}/100</span><span className="drawer-sev-name">{secret.provider} · {secret.type}</span></div>{[["File",<code className="code-blue">{secret.file_name}</code>],["Line",secret.line_number],["Masked Value",<code className="code-amber">{secret.secret_preview}</code>],["Environment",secret.environment],["Privilege",secret.privilege],["Exposure Type",secret.exposure_type],["Exploit Probability",`${((secret.exploit_prob??0)*100).toFixed(0)}%`],["Validation Note",secret.validation_msg||"—"],["Active Credential",<span className={secret.is_valid?"status-valid":"status-unverified"}>{secret.is_valid?"● Yes — Rotate immediately":"○ Unverified / Likely example"}</span>]].map(([l,v],i)=>(<div key={i} className="drawer-row"><p className="drawer-label">{l}</p><p className="drawer-value">{v}</p></div>))}{secret.context&&(<div className="drawer-row"><p className="drawer-label">Code Context</p><pre className="context-pre">{secret.context}</pre></div>)}{secret.is_valid&&(<div className="drawer-warn">⚠ Active credential. Rotate immediately and audit access logs.</div>)}</aside></>);}

// ─── Compliance mini card for Dashboard tab ────────────────────────────────────
function CMiniCard({m,onClick}){const pass=m.compliance_status==="COMPLIANT";return(<div className={`comp-mini-card ${pass?"cmc-pass":"cmc-fail"}`} onClick={onClick} title="Click to see full violation details"><div className="cmc-left"><span className="cmc-icon">{FW_ICON[m.framework]??"📋"}</span><div><p className="cmc-fw">{m.framework_name}</p><p className="cmc-fw-id">{m.framework.replace(/_/g," ")}</p></div></div><div className="cmc-right">{!pass&&m.total_violations>0&&<span className="cmc-violations">{m.total_violations} violation{m.total_violations!==1?"s":""}</span>}<span className={`cmc-chip ${pass?"cmc-chip-pass":"cmc-chip-fail"}`}>{pass?"✓ PASS":"✗ FAIL"}</span><span className="cmc-arrow">→</span></div></div>);}

// ═══════════════════════════════════════════════════════════════════════════════
export default function Dashboard({results:propResults}){
  const R=normalise(propResults);
  const [tab,setTab]=useState("dashboard");
  const [sevFilter,setSevFilter]=useState("ALL");
  const [provFilter,setProvFilter]=useState("ALL");
  const [valFilter,setValFilter]=useState("ALL");
  const [search,setSearch]=useState("");
  const [sortBy,setSortBy]=useState("severity");
  const [selected,setSelected]=useState(null);
  const [expanded,setExpanded]=useState(null);
  const [remList,setRemList]=useState([]);
  const [toast,setToast]=useState(null);
  const [ready,setReady]=useState(false);

  useEffect(()=>{if(R)setRemList(R.mitigation_suggestions.map(m=>({...m,done:false})));setTimeout(()=>setReady(true),80);},[propResults]);// eslint-disable-line

  if(!R)return(<div className="db-root"><div className="db-empty"><p className="db-empty-icon">🔐</p><p className="db-empty-title">No scan results yet</p><p className="db-empty-sub">Run a scan to see your dashboard.</p></div></div>);

  const showToast=(msg,type="success")=>{setToast({msg,type});setTimeout(()=>setToast(null),3000);};
  const toggleDone=idx=>setRemList(p=>p.map((m,i)=>i===idx?{...m,done:!m.done}:m));
  const SEV_RANK={CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1};
  const providers=[...new Set(R.exposed_secrets.map(s=>s.provider))];
  const validCount=R.exposed_secrets.filter(s=>s.is_valid).length;
  const doneCount=remList.filter(m=>m.done).length;
  const remPct=Math.round((doneCount/Math.max(remList.length,1))*100);
  const filtered=R.exposed_secrets.filter(s=>sevFilter==="ALL"||s.severity===sevFilter).filter(s=>provFilter==="ALL"||s.provider===provFilter).filter(s=>valFilter==="ALL"||(valFilter==="VALID"?s.is_valid:!s.is_valid)).filter(s=>!search||[s.file_name,s.provider,s.type,s.environment].join(" ").toLowerCase().includes(search.toLowerCase())).sort((a,b)=>sortBy==="severity"?(SEV_RANK[b.severity]??0)-(SEV_RANK[a.severity]??0):sortBy==="risk"?b.risk_score-a.risk_score:a.provider.localeCompare(b.provider));
  const donutSev=[{value:R.summary.critical_count,color:"#ff3b5c"},{value:R.summary.high_count,color:"#ff7c2a"},{value:R.summary.medium_count,color:"#f5c800"},{value:R.summary.low_count,color:"#22c97a"}];
  const donutTypes=R.secret_types.map((t,i)=>({value:t.count,color:TYPE_COLORS[i%5]}));
  const topProv=R.provider_breakdown[0];
  const avgExploit=R.risk_scores.length?Math.round(R.risk_scores.reduce((s,r)=>s+(r.exploitation_probability??0),0)/R.risk_scores.length*100):0;
  const nonCompliant=R.compliance_mappings.filter(m=>m.compliance_status!=="COMPLIANT").length;
  function goCompliance(fw){setExpanded(fw);setTab("compliance");}
  const TABS=[{id:"dashboard",label:"Dashboard",icon:"🏠"},{id:"secrets",label:`Secrets (${R.summary.total_secrets})`,icon:"🔐"},{id:"compliance",label:`Compliance (${R.compliance_mappings.length})`,icon:"📋"},{id:"remediation",label:"Remediation",icon:"🛠"}];

  return(
    <div className="db-root">
      <header className="db-topbar">
        <div className="db-brand">
          <div className="db-logo">🔐</div>
          <span className="db-brand-name">SecretScan</span>
          <span className="db-sep"/>
          <code className="db-repo-name">{R.repository_info.full_name}</code>
          <span className={`risk-chip chip-${R.summary.overall_risk.toLowerCase()}`}>{R.summary.overall_risk}</span>
        </div>
        <div className="db-topbar-actions">
          <span className="db-scan-time">Scanned: {(()=>{try{return new Date(R.repository_info.last_scanned).toLocaleTimeString();}catch{return"—";}})()}</span>
          <button className="btn btn-outline-purple" onClick={()=>{exportCSV(R.exposed_secrets);showToast("CSV exported!");}}>↓ CSV</button>
          <button className="btn btn-outline-green"  onClick={()=>{exportJSON(R);showToast("JSON exported!");}}>↓ JSON</button>
          <button className="btn btn-outline-pink"   onClick={()=>{exportHTML(R);showToast("HTML downloaded!");}}>↓ HTML</button>
        </div>
      </header>

      {R.summary.overall_risk==="CRITICAL"&&(<div className="risk-banner"><span className="risk-banner-icon">⚠</span><strong>CRITICAL RISK DETECTED</strong><span className="risk-banner-sub"> — {validCount} confirmed active credential{validCount!==1?"s":""} require immediate rotation.</span></div>)}

      <main className="db-main">
        <nav className="db-tabbar">{TABS.map(t=>(<button key={t.id} className={`db-tab${tab===t.id?" active":""}`} onClick={()=>setTab(t.id)}>{t.icon} {t.label}</button>))}</nav>

        {/* ══════ DASHBOARD TAB ══════ */}
        {tab==="dashboard"&&(<div className={`tab-pane${ready?" visible":""}`}>
          <div className="stat-cards-row">
            {[{label:"Total Secrets",val:R.summary.total_secrets,icon:"🔑",accent:"#6c47ff",sub:`${validCount} confirmed active`},{label:"Critical",val:R.summary.critical_count,icon:"🚨",accent:"#ff3b5c",sub:"Immediate action required"},{label:"High",val:R.summary.high_count,icon:"⚠️",accent:"#ff7c2a",sub:"Escalate within 24h"},{label:"Medium",val:R.summary.medium_count,icon:"🔶",accent:"#e6b800",sub:"Address this week"},{label:"Low",val:R.summary.low_count,icon:"🟢",accent:"#22c97a",sub:"Monitor & review"},{label:"Overall Risk",val:R.summary.overall_risk,icon:"📊",accent:SEV_COLOR[R.summary.overall_risk]??"#6c47ff",sub:"Repository risk level"}].map((c,i)=>(<div key={i} className="stat-card" style={{"--accent":c.accent}}><div className="stat-card-top-bar"/><span className="stat-card-icon">{c.icon}</span><p className="stat-card-val" style={{color:c.accent}}>{c.val}</p><p className="stat-card-label">{c.label}</p><p className="stat-card-sub">{c.sub}</p></div>))}
          </div>

          <div className="two-col">
            <div className="card-grad-header">
              <div className="cgh-inner"><h3 className="cgh-title">📁 Repository Information</h3><p className="cgh-sub">{R.repository_info.full_name}</p></div>
              <div className="org-stats-grid">
                {[{label:"Owner",val:R.repository_info.owner||"—",icon:"👤"},{label:"Repository",val:R.repository_info.repo_name||"—",icon:"📦"},{label:"Visibility",val:R.repository_info.is_public?"Public":"Private",icon:"🌐"},{label:"Secrets Found",val:R.summary.total_secrets,icon:"🔍"}].map((s,i)=>(<div key={i} className="org-stat-box"><span className="org-stat-icon">{s.icon}</span><span className="org-stat-val">{s.val}</span><span className="org-stat-lbl">{s.label}</span></div>))}
              </div>
            </div>
            <div className="card card-center">
              <p className="section-label">🛡 Security Score</p>
              <ScoreRing score={R.security_score}/>
              <p className="score-desc">{R.security_score>=80?"Good standing — keep it up!":R.security_score>=60?"Needs improvement":"Critical attention required"}</p>
              <div className="sev-breakdown">
                {[["Critical",R.summary.critical_count,"#ff3b5c"],["High",R.summary.high_count,"#ff7c2a"],["Medium",R.summary.medium_count,"#e6b800"],["Low",R.summary.low_count,"#22c97a"]].map(([l,v,c])=>(<div key={l} className="sev-bd-row"><span className="sev-bd-dot" style={{background:c}}/><span className="sev-bd-lbl">{l}</span><span className="sev-bd-val" style={{color:c}}>{v}</span></div>))}
              </div>
            </div>
          </div>

          <div className="card card-ai">
            <div className="ai-full-header">
              <div>
                <p className="ai-full-title">🤖 AI Risk Predictions</p>
                <p className="ai-full-sub">Model: <strong>{R.ai_predictions.model_info.model_type}</strong>{R.ai_predictions.model_info.accuracy!=="—"&&<> · Accuracy: <strong>{R.ai_predictions.model_info.accuracy}</strong></>}</p>
              </div>
              <span className={`ai-risk-pill chip-${(R.ai_predictions.trends.most_likely_risk||"unknown").toLowerCase()}`}>Predicted: {R.ai_predictions.trends.most_likely_risk||R.summary.overall_risk}</span>
            </div>

            <div className="ai-metrics-grid">
              <div className="ai-metric-card"><span className="ai-metric-icon">🎯</span><span className="ai-metric-val">{avgExploit}%</span><span className="ai-metric-lbl">Avg Exploit Probability</span><span className="ai-metric-desc">Average chance an attacker could use any found secret to access real systems</span></div>
              <div className="ai-metric-card"><span className="ai-metric-icon">⚡</span><span className="ai-metric-val" style={{color:SEV_COLOR[R.summary.overall_risk]??"#fff"}}>{R.summary.critical_count+R.summary.high_count}</span><span className="ai-metric-lbl">High-Severity Secrets</span><span className="ai-metric-desc">Critical + High findings that need urgent action</span></div>
              <div className="ai-metric-card"><span className="ai-metric-icon">🔍</span><span className="ai-metric-val">{topProv?.provider??"—"}</span><span className="ai-metric-lbl">Most Exposed Provider</span><span className="ai-metric-desc">{topProv?`${topProv.count} secret${topProv.count!==1?"s":""} found`:"No provider-specific secrets detected"}</span></div>
              <div className="ai-metric-card"><span className="ai-metric-icon">📋</span><span className="ai-metric-val">{nonCompliant}/{R.compliance_mappings.length}</span><span className="ai-metric-lbl">Frameworks Violated</span><span className="ai-metric-desc">{nonCompliant>0?`${nonCompliant} frameworks non-compliant`:"All frameworks satisfied."}</span></div>
            </div>

            {R.ai_risk_trend.length>0&&(<div className="ai-trend-section"><p className="ai-trend-label">Risk Score Distribution (AI Insights)</p><SparkBar data={R.ai_risk_trend} highlight/></div>)}

            <div className="ai-insights-list">
              <p className="ai-insights-heading">🧠 Key Insights</p>
              <div className="ai-insights-grid">
                {[
                  {icon:"🔴",text:validCount>0?`${validCount} credentials confirmed active — live secrets that can be used to access real systems.`:"No confirmed active credentials found. All secrets appear to be test values."},
                  {icon:"📁",text:R.vulnerable_files.length>0?`Most exposed file: ${R.vulnerable_files[0].file} — ${R.vulnerable_files[0].secrets} secrets found.`:"No vulnerable files detected."},
                  {icon:"🏭",text:topProv?`${topProv.provider} has the most exposed secrets (${topProv.count}). Rotate these first.`:"No provider patterns detected."},
                  {icon:"⚖️",text:nonCompliant>0?`${nonCompliant} frameworks are violated. Click rows below for fix guidance.`:"Compliance frameworks are currently satisfied."},
                  {icon:"🛡",text:`Security score is ${R.security_score}/100. ${R.security_score<60?"Remediation required immediately.":"Repository is in good shape."}`},
                  {icon:"🔧",text:remList.length>0?`${remList.length} remediation actions generated.`:"No remediation suggestions."},
                ].map((ins,i)=>(<div key={i} className="ai-insight-item"><span className="ai-insight-icon">{ins.icon}</span><p className="ai-insight-text">{ins.text}</p></div>))}
              </div>
            </div>
          </div>

          <div className="two-col">
            <div className="card">
              <p className="section-label">📊 Secret Type Breakdown</p>
              {R.secret_types.length===0?<p className="empty-msg">No secrets found.</p>:<div className="type-chart-row"><Donut segments={donutTypes} size={128}/><div className="type-legend">{R.secret_types.map((t,i)=>{const maxC=Math.max(...R.secret_types.map(x=>x.count),1);return(<div key={i} className="type-legend-row"><span className="type-dot" style={{background:TYPE_COLORS[i%5]}}/><span className="type-name">{t.type}</span><span className="type-count" style={{color:TYPE_COLORS[i%5]}}>{t.count}</span><div className="type-bar-track"><div className="type-bar-fill" style={{width:`${(t.count/maxC)*100}%`,background:TYPE_COLORS[i%5]}}/></div></div>);})}</div></div>}
            </div>
            <div className="card">
              <p className="section-label">📁 Most Vulnerable Files</p>
              {R.vulnerable_files.length===0?<p className="empty-msg">No vulnerable files detected.</p>:R.vulnerable_files.map((f,i)=>(<div key={i} className="vuln-row"><div className="vuln-left"><code className="vuln-file">{f.file}</code></div><div className="vuln-right"><span className={`sev-chip chip-${f.severity.toLowerCase()}`}>{f.severity}</span><span className="vuln-count">{f.secrets} secret{f.secrets>1?"s":""}</span></div></div>))}
            </div>
          </div>

          <div className="two-col">
            <div className="card">
              <div className="section-label-row"><p className="section-label" style={{marginBottom:0}}>📋 Compliance Status</p><button className="btn btn-sm btn-outline-purple" onClick={()=>setTab("compliance")}>View All →</button></div>
              <p className="comp-hint">Click any row for details</p>
              {R.compliance_mappings.length===0?<p className="empty-msg">No data.</p>:R.compliance_mappings.map((m,i)=>(<CMiniCard key={i} m={m} onClick={()=>goCompliance(m.framework)}/>))}
            </div>
            <div className="card">
              <p className="section-label">🛠 Remediation Progress</p>
              <div className="rem-summary-row">
                <div className="rem-ring-mini-wrap"><svg width="84" height="84" viewBox="0 0 84 84"><circle cx="42" cy="42" r="34" fill="none" stroke="rgba(108,71,255,0.1)" strokeWidth="10"/><circle cx="42" cy="42" r="34" fill="none" stroke={remPct>=80?"#22c97a":"#6c47ff"} strokeWidth="10" strokeDasharray={`${(remPct/100)*213.6} 213.6`} strokeLinecap="round" transform="rotate(-90 42 42)"/></svg><div className="rem-ring-mini-inner"><span style={{fontSize:14,fontWeight:900,color:"#6c47ff"}}>{remPct}%</span></div></div>
                <div className="rem-counts"><p className="rem-count-done"><span>{doneCount}</span> done</p><p className="rem-count-left"><span>{remList.length-doneCount}</span> left</p></div>
              </div>
              <div className="rem-bar-track"><div className="rem-bar-fill" style={{width:`${remPct}%`}}/></div>
              <div className="rem-mini-list">{remList.slice(0,4).map((m,i)=>(<div key={i} className="rem-mini-row"><input type="checkbox" className="rem-checkbox" checked={m.done} onChange={()=>toggleDone(i)}/><span className={`rem-mini-action${m.done?" rem-done-text":""}`}>{m.action}</span></div>))}</div>
            </div>
          </div>
        </div>)}

        {/* ══════ SECRETS TAB ══════ */}
        {tab==="secrets"&&(<div className="tab-pane visible">
          <div className="filter-row">
            <input className="filter-input" placeholder="Search secrets..." value={search} onChange={e=>setSearch(e.target.value)}/>
            <select className="filter-select" value={sevFilter} onChange={e=>setSevFilter(e.target.value)}><option value="ALL">All Severities</option>{["CRITICAL","HIGH","MEDIUM","LOW"].map(s=><option key={s}>{s}</option>)}</select>
            <select className="filter-select" value={provFilter} onChange={e=>setProvFilter(e.target.value)}><option value="ALL">All Providers</option>{providers.map(p=><option key={p}>{p}</option>)}</select>
            <select className="filter-select" value={valFilter} onChange={e=>setValFilter(e.target.value)}><option value="ALL">All Status</option><option value="VALID">Valid</option><option value="INVALID">Unverified</option></select>
            <select className="filter-select" value={sortBy} onChange={e=>setSortBy(e.target.value)}><option value="severity">Sort: Severity</option><option value="risk">Sort: Risk</option></select>
            <span className="filter-result-count">{filtered.length} secrets</span>
          </div>
          <div className="card" style={{padding:0,overflow:"hidden"}}><div className="table-scroll"><table className="secrets-table"><thead><tr>{["Provider","Type","File : Line","Severity","Risk","Env","Privilege","Preview","Valid"].map(h=><th key={h}>{h}</th>)}</tr></thead><tbody>{filtered.map(s=>(<tr key={s.id} className={`secret-row${selected?.id===s.id?" selected-row":""}`} onClick={()=>setSelected(s)}><td>{s.provider}</td><td className="td-muted">{s.type}</td><td><code className="code-blue">{s.file_name}:{s.line_number}</code></td><td><span className={`sev-chip chip-${s.severity.toLowerCase()}`}>{s.severity}</span></td><td>{s.risk_score}</td><td className="td-muted">{s.environment}</td><td className="td-muted">{s.privilege}</td><td><code className="code-amber">{s.secret_preview}</code></td><td><span className={s.is_valid?"status-valid":"status-unverified"}>{s.is_valid?"● Valid":"○ Unverified"}</span></td></tr>))}{filtered.length===0&&<tr><td colSpan={9} className="table-empty">No results.</td></tr>}</tbody></table></div></div>
        </div>)}

        {/* ══════ COMPLIANCE TAB ══════ */}
        {tab==="compliance"&&(<div className="tab-pane visible">
          <div className="comp-chips-row">{R.compliance_mappings.map((m,i)=>(<div key={i} className={`comp-chip-btn ${m.compliance_status==="COMPLIANT"?"ccb-pass":"ccb-fail"} ${expanded===m.framework?"ccb-active":""}`} onClick={()=>setExpanded(expanded===m.framework?null:m.framework)}><span className="ccb-icon">{FW_ICON[m.framework]||"📋"}</span><span className="ccb-fw">{m.framework.replace(/_/g," ")}</span><span className={`ccb-status ${m.compliance_status==="COMPLIANT"?"ccb-s-pass":"ccb-s-fail"}`}>{m.compliance_status==="COMPLIANT"?"✓ PASS":`✗ ${m.total_violations} violation${m.total_violations!==1?"s":""}`}</span></div>))}</div>
          {R.compliance_mappings.map((m,i)=>{const pass=m.compliance_status==="COMPLIANT";const isOpen=expanded===m.framework;return(<div key={i} className="cc-card-full"><div className={`ccf-header ${pass?"ccfh-pass":"ccfh-fail"}`} onClick={()=>setExpanded(isOpen?null:m.framework)} style={{cursor:"pointer"}}><div className="ccf-header-left"><span className="ccf-fw-icon">{FW_ICON[m.framework]||"📋"}</span><div><h3 className="ccf-fw-title">{m.framework_name}</h3><p className="ccf-fw-sub">{pass?"No violations":`${m.total_violations} controls violated`}</p></div></div><div className="ccf-header-right"><span className="ccf-badge">{pass?"✓ COMPLIANT":"✗ NON-COMPLIANT"}</span><span className="ccf-chevron">{isOpen?"▲":"▼"}</span></div></div>{isOpen&&(<div className="ccf-body">{m.violated_controls.length===0?<p className="cc-no-viol">✓ All controls satisfied.</p>:m.violated_controls.map((ctrl,j)=>(<div key={j} className="ctrl-card"><div className="ctrl-header"><code className="ctrl-id-badge">{ctrl.control_id}</code><span className="ctrl-name">{ctrl.control_name}</span></div><div className="ctrl-blocks"><div className="ctrl-block ctrl-req"><span className="ctrl-block-label">📖 Requirement</span><p className="ctrl-block-text">{ctrl.description}</p></div><div className="ctrl-block ctrl-viol"><span className="ctrl-block-label">⚠ Violation</span><p className="ctrl-block-text">{ctrl.violation}</p></div><div className="ctrl-block ctrl-fix"><span className="ctrl-block-label">✓ Remediation</span><p className="ctrl-block-text">{ctrl.remediation}</p></div></div></div>))}</div>)}</div>);})}
        </div>)}

        {/* ══════ REMEDIATION TAB ══════ */}
        {tab==="remediation"&&(<div className="tab-pane visible">
          <div className="card rem-progress-card"><p className="section-label">🛠 Overall Progress</p><div className="rem-bar-track rem-bar-lg"><div className="rem-bar-fill" style={{width:`${remPct}%`}}/></div><p className="rem-progress-txt">{doneCount} of {remList.length} actions completed ({remPct}%)</p></div>
          {["IMMEDIATE","HIGH","MEDIUM","LOW"].map(pri=>{const items=remList.map((m,idx)=>({...m,_idx:idx})).filter(m=>m.priority===pri);if(!items.length)return null;return(<div key={pri} className="rem-group"><div className="rem-group-header"><span className="rem-group-label" style={{color:PRI_COLOR[pri]}}>{pri}</span><div className="rem-group-line" style={{background:`${PRI_COLOR[pri]}30`}}/></div>{items.map((item,i)=>(<div key={i} className={`rem-item${item.done?" rem-item-done":""}`} style={{borderLeftColor:PRI_COLOR[item.priority]}}><input type="checkbox" className="rem-checkbox" checked={item.done} onChange={()=>toggleDone(item._idx)}/><div className="rem-item-content"><p className="rem-action-title">{item.action}</p><p className="rem-desc-txt">{item.description}</p></div></div>))}</div>);})}
        </div>)}
      </main>

      {selected&&<SecretDrawer secret={selected} onClose={()=>setSelected(null)}/>}
      {toast&&<div className={`toast-msg toast-${toast.type}`}>✓ {toast.msg}</div>}
    </div>
  );
}