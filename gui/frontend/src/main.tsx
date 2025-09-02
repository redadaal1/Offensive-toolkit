import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import './styles.css'

const API = import.meta.env.VITE_API || 'http://127.0.0.1:8000'
const q = new QueryClient()

function Layout({ children, theme }: { children: React.ReactNode, theme: string }){
  return (
    <div data-theme={theme} className="min-h-screen bg-base-100 text-slate-100 relative overflow-hidden">
      <motion.div
        className="pointer-events-none absolute inset-0 opacity-25 bg-[radial-gradient(ellipse_at_top_right,theme(colors.primary/20),transparent_40%),radial-gradient(ellipse_at_bottom_left,theme(colors.accent/15),transparent_40%)]"
        initial={{ opacity: 0.15 }}
        animate={{ opacity: [0.15, 0.3, 0.15] }}
        transition={{ duration: 10, repeat: Infinity }}
      />
      <main className="container mx-auto px-4 md:px-6 py-5 relative z-10">{children}</main>
    </div>
  )
}

function useSSE(sessionId: string|undefined, setter: React.Dispatch<React.SetStateAction<string>>){
  React.useEffect(()=>{
    if(!sessionId) return;
    const es = new EventSource(`${API}/api/logs/${sessionId}`)
    es.onmessage = (ev)=> setter((prev: string)=> prev + ev.data + '\n')
    return ()=> es.close()
  },[sessionId])
}

function Dashboard(){
  const [log, setLog] = React.useState('')
  const [sessionId,setSessionId]=React.useState<string>('')
  useSSE(sessionId, setLog)
  const [theme,setTheme]=React.useState<string>('hacker')
  const [target,setTarget]=React.useState('')
  const [services,setServices]=React.useState('')
  const [attackerIp,setAttackerIp]=React.useState('')
  const [attackerPort,setAttackerPort]=React.useState('4444')
  const [useRockyou,setUseRockyou]=React.useState(false)
  const [noConfirm,setNoConfirm]=React.useState(true)
  const [mode,setMode]=React.useState<'recon'|'exploit'|'post-exploit'|'report'|'walkthrough-full'|'vuln-assess'|'evasion'|'walkthrough'|'list-services'>('recon')
  const [status,setStatus]=React.useState<{state:string,action:string}>({state:'idle',action:'none'})
  const [files,setFiles]=React.useState<string[]>([])
  const [withVulnAssess,setWithVulnAssess]=React.useState(false)
  const [allServices,setAllServices]=React.useState<boolean>(false)
  const [tab,setTab]=React.useState<'logs'|'outputs'>('logs')
  const [selectedFile,setSelectedFile]=React.useState<string>('')
  const [fileText,setFileText]=React.useState<string>('')
  const [isEmbed,setIsEmbed]=React.useState<boolean>(false)
  const [loadingFile,setLoadingFile]=React.useState<boolean>(false)
  const [autoScroll,setAutoScroll]=React.useState<boolean>(true)
  const [wrapLogs,setWrapLogs]=React.useState<boolean>(true)
  const [logFont,setLogFont]=React.useState<number>(12)
  const [fileFilter,setFileFilter]=React.useState<string>('')
  const [logFilter,setLogFilter]=React.useState<string>('')
  const [splitView,setSplitView]=React.useState<boolean>(false)
  const logBoxRef = React.useRef<HTMLPreElement|null>(null)
  const [completedPhases,setCompletedPhases]=React.useState<string[]>([])
  const [currentPhase,setCurrentPhase]=React.useState<string>('none')
  const [logSlice,setLogSlice]=React.useState<{start:number,end:number|null}|null>(null)
  const [runStartedAt,setRunStartedAt]=React.useState<number|null>(null)
  const [showEdit,setShowEdit]=React.useState<boolean>(false)
  const [regexFilter,setRegexFilter]=React.useState<boolean>(false)
  const [chipFilters,setChipFilters]=React.useState<string[]>([])
  const [hideNoise,setHideNoise]=React.useState<boolean>(false)
  const [bookmarks,setBookmarks]=React.useState<number[]>([])
  const [outputsItems,setOutputsItems]=React.useState<any[]>([])
  const [phaseFilter,setPhaseFilter]=React.useState<string>('')
  const [toolFilter,setToolFilter]=React.useState<string>('')
  const [extFilter,setExtFilter]=React.useState<string>('')
  const [diffLeft,setDiffLeft]=React.useState<string>('')
  const [showPalette,setShowPalette]=React.useState<boolean>(false)
  const [paletteQuery,setPaletteQuery]=React.useState<string>('')
  const [queueText,setQueueText]=React.useState<string>('')
  const [queueRunning,setQueueRunning]=React.useState<boolean>(false)
  const [notes,setNotes]=React.useState<string>('')
  const [preflight,setPreflight]=React.useState<any>(null)
  const [webhookUrl,setWebhookUrl]=React.useState<string>('')
  const [webhookToken,setWebhookToken]=React.useState<string>('')
  const [presets,setPresets]=React.useState<any[]>([])
  const [sessionsHistory,setSessionsHistory]=React.useState<any[]>([])
  const modeMeta: Record<string, {label: string, icon: string, hint?: string}> = {
    'recon': { label: 'Recon', icon: '', hint: 'Map the surface' },
    'vuln-assess': { label: 'VA Only', icon: '', hint: 'Vulnerability assessment' },
    'exploit': { label: 'Exploit', icon: '', hint: 'Attempt exploitation' },
    'post-exploit': { label: 'Post‑Exploit', icon: '', hint: 'Loot & persistence' },
    'report': { label: 'Report', icon: '', hint: 'Build docs' },
    'walkthrough-full': { label: 'Full Pipeline', icon: '', hint: 'End‑to‑end' },
    'walkthrough': { label: 'Walkthrough', icon: '', hint: 'Narrative report' },
    'evasion': { label: 'Evasion', icon: '', hint: 'Firewall/IDS bypass' },
    'list-services': { label: 'List Services', icon: '',hint: 'Available modules' },
  }

  // Persist UI state across reloads (non-sensitive)
  React.useEffect(()=>{
    try{
      const raw = localStorage.getItem('offsec_ui_settings')
      if(raw){
        const s = JSON.parse(raw)
        setTheme(s.theme ?? 'hacker')
        setTarget(s.target ?? '')
        setServices(s.services ?? '')
        setAttackerIp(s.attackerIp ?? '')
        setAttackerPort(s.attackerPort ?? '4444')
        setMode(s.mode ?? 'recon')
        setUseRockyou(Boolean(s.useRockyou))
        setNoConfirm(s.noConfirm ?? true)
        setWithVulnAssess(Boolean(s.withVulnAssess))
      }
      const ph = localStorage.getItem('offsec_presets')
      if(ph){ try{ setPresets(JSON.parse(ph)) }catch{} }
      const sh = localStorage.getItem('offsec_sessions')
      if(sh){ try{ setSessionsHistory(JSON.parse(sh)) }catch{} }
    }catch{}
  },[])
  React.useEffect(()=>{
    const s = { theme, target, services, attackerIp, attackerPort, mode, useRockyou, noConfirm, withVulnAssess }
    try{ localStorage.setItem('offsec_ui_settings', JSON.stringify(s)) }catch{}
  },[theme, target, services, attackerIp, attackerPort, mode, useRockyou, noConfirm, withVulnAssess])
  // Ensure theme applies globally to DaisyUI components
  React.useEffect(()=>{
    try{ document.documentElement.setAttribute('data-theme', theme) }catch{}
  },[theme])
  React.useEffect(()=>{
    const t = setInterval(async()=>{
      try{
        const r = await fetch(`${API}/api/status?session_id=${encodeURIComponent(sessionId||'')}`)
        const s = await r.json()
        setStatus(s)
        if(s && s.state){
          if(s.state==='running' && !runStartedAt){ setRunStartedAt(Date.now()) }
          if(s.action){ setCurrentPhase(s.action) }
        }
      }catch{}
    }, 1000)
    return ()=> clearInterval(t)
  },[sessionId, runStartedAt])
  const refreshOutputs = async()=>{
    try{ const r = await fetch(`${API}/api/outputs`); const d = await r.json(); setFiles(d.files||[]); setOutputsItems(d.items||[]) }catch{}
  }
  React.useEffect(()=>{ refreshOutputs() },[])
  const requiresAtk = mode==='exploit' || mode==='post-exploit' || mode==='walkthrough-full'
  const requiresServices = mode==='recon' || mode==='walkthrough-full' || mode==='exploit' || mode==='post-exploit'
  const requiresTarget = mode!=='list-services'
  const showWithVA = mode==='recon' || mode==='walkthrough-full'
  const showRockyou = mode==='exploit' || mode==='walkthrough-full'
  // CLI now auto-detects attacker IP; only require target when needed
  const canStart = (!requiresTarget || Boolean(target))

  // Auto-detect attacker IP from backend helper when relevant
  const detectAttacker = async()=>{
    try{
      const url = target ? `${API}/api/attacker-ip?target=${encodeURIComponent(target)}` : `${API}/api/attacker-ip`
      const r = await fetch(url)
      if(r.ok){ const d = await r.json(); if(d.ip && !attackerIp){ setAttackerIp(d.ip) } }
    }catch{}
  }
  React.useEffect(()=>{
    if(requiresAtk && !attackerIp){ detectAttacker() }
  },[requiresAtk, target])

  // Global hotkeys for power users
  React.useEffect(()=>{
    const onKey = (e: KeyboardEvent)=>{
      if((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==='enter'){ e.preventDefault(); if(canStart) run() }
      if((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==='p'){ e.preventDefault(); pause() }
      if((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==='.' ){ e.preventDefault(); stop() }
      if((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==='l'){ e.preventDefault(); copyLogs() }
      if((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==='k'){ e.preventDefault(); setShowPalette(true) }
    }
    window.addEventListener('keydown', onKey)
    return ()=> window.removeEventListener('keydown', onKey)
  },[canStart, sessionId, log])

  const run = async()=>{
    setLog('')
    // add to session history
    try{
      const entry = { ts: Date.now(), target, mode, services, attackerIp, attackerPort }
      const raw = localStorage.getItem('offsec_sessions')
      const arr = raw ? JSON.parse(raw) : []
      const next = [entry, ...arr].slice(0,20)
      localStorage.setItem('offsec_sessions', JSON.stringify(next))
      setSessionsHistory(next)
    }catch{}
    const selectedServices = allServices ? [] : services.split(',').map(s=>s.trim()).filter(Boolean)
    const body:any = {session_id:sessionId||undefined,action:mode,target,no_confirm:noConfirm,attacker_ip:attackerIp,attacker_port:attackerPort,use_rockyou:useRockyou,with_vuln_assess:withVulnAssess}
    if(requiresServices){ body.services = selectedServices }
    const res = await fetch(`${API}/api/run`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    try{ const j = await res.json(); if(j.session_id) setSessionId(j.session_id) }catch{}
  }
  const pause = ()=> fetch(`${API}/api/pause`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:sessionId||undefined})})
  const resume = ()=> fetch(`${API}/api/resume`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:sessionId||undefined})})
  const stop = ()=> fetch(`${API}/api/stop`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:sessionId||undefined})})
  const clearOutputs = async()=>{ await fetch(`${API}/api/clear-outputs`,{method:'POST'}); await refreshOutputs() }
  const copyLogs = async()=>{ try{ await navigator.clipboard.writeText(log) }catch{} }
  const clearLogs = ()=> setLog('')
  React.useEffect(()=>{
    if(autoScroll && logBoxRef.current){
      logBoxRef.current.scrollTop = logBoxRef.current.scrollHeight
    }
  },[log,autoScroll])
  const displayLog = React.useMemo(()=>{
    const base = (()=>{
      if(!logSlice) return log
      const lines = log.split('\n')
      const start = Math.max(0, logSlice.start)
      const end = (logSlice.end==null)? lines.length : Math.max(start, logSlice.end)
      return lines.slice(start, end).join('\n')
    })()
    // chips filtering
    const applyChips = (txt:string)=>{
      if(chipFilters.length===0) return txt
      const ls = txt.split('\n')
      const fs = chipFilters.map(c=> c.toLowerCase())
      return ls.filter(l=> fs.some(f=> l.toLowerCase().includes(f))).join('\n')
    }
    // hide noise
    const applyNoise = (txt:string)=>{
      if(!hideNoise) return txt
      const ls = txt.split('\n')
      return ls.filter(l=> !l.startsWith('[SERVER]') && !/\bdebug\b/i.test(l)).join('\n')
    }
    let working = base
    working = applyChips(working)
    working = applyNoise(working)
    if(!logFilter) return working
    try{
      const lines = working.split('\n')
      if(regexFilter){
        const re = new RegExp(logFilter, 'i')
        return lines.filter(l=> re.test(l)).join('\n')
      }
      const f = logFilter.toLowerCase()
      return lines.filter(l=> l.toLowerCase().includes(f)).join('\n')
    }catch{ return working }
  },[log, logFilter, logSlice, chipFilters, hideNoise, regexFilter])
  const clearLogSlice = ()=> setLogSlice(null)
  const phaseList = React.useMemo(()=> (mode==='evasion' ? ['evasion'] : ['recon','exploit','post','report']), [mode])
  const phasePercent = (p:string)=> completedPhases.includes(p) ? 100 : (currentPhase===p ? 50 : 0)
  const sliceToPhase = (p:string)=>{
    try{
      const lines = log.split('\n')
      const starts:number[] = []
      const phases:string[] = []
      for(let i=0;i<lines.length;i++){
        const l = lines[i]
        if(l.startsWith('[PHASE] ')){
          const rest = l.substring(8)
          const key = rest.split(':',1)[0]?.trim()
          if(key){ phases.push(key); starts.push(i) }
        }
      }
      const idx = phases.findIndex(x=>x===p)
      if(idx===-1){ setTab('logs'); return }
      const start = starts[idx]
      const end = (idx+1<starts.length) ? starts[idx+1] : null
      setLogSlice({start, end})
      setTab('logs')
    }catch{ setTab('logs') }
  }
  const etaText = React.useMemo(()=>{
    if(!runStartedAt) return 'ETA: —'
    const elapsedMs = Date.now() - runStartedAt
    const m = Math.floor(elapsedMs/60000)
    const s = Math.floor((elapsedMs%60000)/1000)
    const pad=(n:number)=> (n<10?`0${n}`:`${n}`)
    return `Elapsed ${pad(m)}:${pad(s)}`
  },[runStartedAt, status.state])

  // Detect phases from log and mark completion (phase completes when next phase starts)
  React.useEffect(()=>{
    try{
      const lines = log.split('\n')
      const markers: {phase:string, line:number}[] = []
      for(let i=0;i<lines.length;i++){
        const l = lines[i]
        if(l.startsWith('[PHASE] ')){
          const rest = l.substring(8)
          const parts = rest.split(':',1)
          const key = parts[0]?.trim()
          if(key){ markers.push({phase:key, line:i}) }
        }
      }
      if(markers.length){
        const uniq: string[] = []
        for(const m of markers){ if(!uniq.includes(m.phase)) uniq.push(m.phase) }
        const done: string[] = []
        for(let i=0;i<markers.length-1;i++){ const p = markers[i].phase; if(!done.includes(p)) done.push(p) }
        setCompletedPhases(done)
      }
    }catch{}
  },[log])
  const viewFile = async(f:string)=>{
    setSelectedFile(f)
    setTab('outputs')
    const lower = f.toLowerCase()
    const isPdf = lower.endsWith('.pdf')
    const isHtml = lower.endsWith('.html') || lower.endsWith('.htm')
    if(isPdf || isHtml){
      setIsEmbed(true)
      setFileText('')
      return
    }
    setIsEmbed(false)
    setLoadingFile(true)
    try{
      const r = await fetch(`${API}/outputs/${encodeURIComponent(f)}`)
      const t = await r.text()
      setFileText(t)
    }catch{
      setFileText('Failed to load file.')
    }finally{
      setLoadingFile(false)
    }
  }
  return (
    <Layout theme={theme}>
      {/* Operator HUD (always visible) */}
      <div className="sticky top-2 z-20 mb-2">
        <div className="rounded-lg border border-base-300 bg-base-200/60 backdrop-blur px-3 py-2 text-xs flex items-center gap-3">
          <div><span className="opacity-60">Target</span>: <span className="font-mono">{target||'—'}</span></div>
          <div className="hidden sm:block"><span className="opacity-60">Services</span>: <span className="font-mono">{allServices?'ALL':(services||'—')}</span></div>
          <div><span className="opacity-60">Attacker</span>: <span className="font-mono">{attackerIp||'auto'}:{attackerPort}</span></div>
          <div><span className="opacity-60">Mode</span>: <span className="font-mono">{modeMeta[mode].label}</span></div>
          <div className="ml-auto opacity-80">{etaText}</div>
          <button className="btn btn-ghost btn-xs" onClick={()=>setShowEdit(true)}>Edit</button>
        </div>
      </div>
      {showEdit && (
        <div className="fixed inset-0 z-30 grid place-items-center bg-black/50" onClick={()=>setShowEdit(false)}>
          <div className="card w-[92vw] max-w-2xl bg-base-100 p-4 border border-base-300" onClick={e=>e.stopPropagation()}>
            <div className="flex items-center justify-between mb-2">
              <div className="font-semibold">Quick Edit</div>
              <button className="btn btn-ghost btn-xs" onClick={()=>setShowEdit(false)}>✕</button>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <input className="input input-bordered input-sm" placeholder="Target" value={target} onChange={e=>setTarget(e.target.value)} />
              <input className="input input-bordered input-sm" placeholder="Services (csv)" value={services} onChange={e=>{setServices(e.target.value); setAllServices(false)}} />
              <input className="input input-bordered input-sm" placeholder="Attacker IP" value={attackerIp} onChange={e=>setAttackerIp(e.target.value)} />
              <input className="input input-bordered input-sm" placeholder="Attacker Port" value={attackerPort} onChange={e=>setAttackerPort(e.target.value)} />
              <select className="select select-bordered select-sm" value={mode} onChange={e=>setMode(e.target.value as any)}>
                {(Object.keys(modeMeta) as (keyof typeof modeMeta)[]).map(m=> <option key={m} value={m}>{modeMeta[m].label}</option>)}
              </select>
              <div className="flex items-center gap-2 text-xs">
                <label className="label cursor-pointer"><span className="label-text">All services</span><input type="checkbox" className="toggle toggle-xs" checked={allServices} onChange={()=>{ setAllServices(!allServices); if(!allServices) setServices('') }} /></label>
                <label className="label cursor-pointer"><span className="label-text">Skip confirms</span><input type="checkbox" className="toggle toggle-xs" checked={noConfirm} onChange={()=>setNoConfirm(!noConfirm)} /></label>
              </div>
            </div>
            <div className="mt-3 flex items-center justify-end gap-2">
              <button className="btn btn-sm" onClick={()=>{ setShowEdit(false) }}>Close</button>
              <button className="btn btn-primary btn-sm" onClick={()=>{ setShowEdit(false); run() }}>Save & Start</button>
            </div>
          </div>
        </div>
      )}
      {/* Top Bar */}
      <div className="mb-4 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-md bg-primary/20 border border-primary/40 grid place-content-center text-primary">⚔️</div>
          <div>
            <div className="text-lg font-semibold tracking-wide">Offsec Control Center</div>
            <div className="text-xs opacity-70">Modern offensive ops dashboard</div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <select className="select select-bordered select-sm" value={theme} onChange={e=>setTheme(e.target.value)} title="Theme">
            {['hacker','night','synthwave','dracula','cyberpunk','dark','business'].map(t=> (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <button className="btn btn-sm btn-ghost" title="Keyboard shortcuts" onClick={()=>alert('Shortcuts:\n• Start: Ctrl/Cmd+Enter\n• Pause: Ctrl/Cmd+P\n• Stop: Ctrl/Cmd+.\n• Copy logs: Ctrl/Cmd+L')}>⌨️</button>
        </div>
      </div>
      {/* Phase timeline (compact row) */}
      <div className="mb-2 flex items-center gap-3">
        <div className="text-xs opacity-70">Phase Timeline</div>
        <div className="flex flex-wrap gap-2">
          {phaseList.map(p=>{
            const pct = phasePercent(p)
            const stateClass = pct===100 ? 'badge-success' : (pct>0 ? 'badge-warning' : 'badge-ghost')
            const label = `${p} ${pct}%`
            return (
              <button key={p} className={`badge gap-2 ${stateClass}`} onClick={()=>{ sliceToPhase(p); setFileFilter(p) }} title="Click to view logs & outputs for this phase">
                <span className="font-mono text-[10px] uppercase">{label}</span>
              </button>
            )
          })}
        </div>
      </div>
      <div className="grid grid-cols-12 gap-6">
        <motion.div className="card p-5 space-y-4 col-span-12 xl:col-span-4 relative overflow-hidden"
          initial={{opacity:0, y:10}} animate={{opacity:1, y:0}} transition={{duration:0.5}}>
          <motion.div className="absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r from-transparent via-primary to-transparent"
            animate={{opacity:[0.2,1,0.2]}} transition={{repeat:Infinity, duration:3}} />
          <div className="flex items-center justify-between gap-2">
            <div className="font-semibold tracking-wide">Controls</div>
            <div className="flex items-center gap-2">
              <div className={`badge ${status.state==='running'?'badge-success':status.state==='paused'?'badge-warning':'badge-ghost'}`}>{status.state} / {status.action}</div>
              <div className="join">
                <button className="btn btn-xs join-item btn-success" onClick={resume} title="Resume">▶</button>
                <button className="btn btn-xs join-item btn-warning" onClick={pause} title="Pause (Ctrl/Cmd+P)">⏸</button>
                <button className="btn btn-xs join-item btn-error" onClick={stop} title="Stop (Ctrl/Cmd+.)">■</button>
                <button className="btn btn-xs join-item btn-accent" onClick={clearOutputs} title="Clear outputs">🧹</button>
              </div>
            </div>
          </div>
          <div className="flex items-center justify-between">
            <div className="text-sm opacity-80">Mode</div>
            <div className="text-xs opacity-70">Session: <span className="font-mono">{sessionId || 'new'}</span></div>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {(Object.keys(modeMeta) as (keyof typeof modeMeta)[]).map((m)=> (
              <button
                key={m}
                className={`btn btn-sm justify-start ${mode===m?'btn-primary ring-1 ring-primary/50 shadow-[0_0_20px_theme(colors.primary/20)]':'btn-outline'} group`}
                onClick={()=>setMode(m as any)}
                title={modeMeta[m].hint || modeMeta[m].label}
              >
                <span className="opacity-90 mr-1">{modeMeta[m].icon}</span>
                <span className="truncate">{modeMeta[m].label}</span>
              </button>
            ))}
          </div>
          <div className="mt-2 flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs">
              <span className="relative flex h-3 w-3">
                <span className={`absolute inline-flex h-full w-full rounded-full ${status.state==='running'?'bg-success':'bg-base-300'} opacity-75 animate-ping`}></span>
                <span className={`relative inline-flex rounded-full h-3 w-3 ${status.state==='running'?'bg-success':'bg-base-300'}`}></span>
              </span>
              <span className="opacity-80">Current:</span>
              <span className="font-mono">{modeMeta[mode].label}</span>
              <span className="opacity-60">({status.state})</span>
            </div>
            <div className="text-[10px] opacity-60">Tip: Ctrl/Cmd+Enter to start</div>
          </div>

          {requiresTarget && (
            <div className="form-control w-full">
              <label className="label"><span className="label-text">Target host/IP or domain</span></label>
              <input className="input input-bordered w-full" placeholder="e.g. 10.10.10.10 or app.local" value={target} onChange={e=>setTarget(e.target.value)} />
              <div className="mt-2 flex items-center gap-2 text-xs opacity-80">
                <button className="btn btn-xs" onClick={()=>{
                  try{
                    const raw = localStorage.getItem('offsec_recent_targets')
                    const arr = raw ? JSON.parse(raw) : []
                    const next = [target, ...arr.filter((x:string)=>x!==target)].slice(0,8)
                    localStorage.setItem('offsec_recent_targets', JSON.stringify(next))
                    alert('Saved to recent targets')
                  }catch{}
                }}>Save Target</button>
                <button className="btn btn-xs btn-ghost" onClick={()=>{
                  try{
                    const raw = localStorage.getItem('offsec_recent_targets')
                    const arr = raw ? JSON.parse(raw) : []
                    const pick = prompt('Pick index from recent:\n' + arr.map((t:string,i:number)=>`${i+1}. ${t}`).join('\n'))
                    const idx = pick ? (parseInt(pick)-1) : -1
                    if(idx>=0 && arr[idx]) setTarget(arr[idx])
                  }catch{}
                }}>Recent…</button>
              </div>
            </div>
          )}
          {requiresServices && (
            <div className="form-control w-full">
              <label className="label"><span className="label-text">Services (comma‑separated)</span></label>
              <div className="join w-full">
                <input className="input input-bordered join-item w-full" placeholder="http,ssh,ftp" value={services} onChange={e=>{setServices(e.target.value); setAllServices(false)}} disabled={allServices} />
                <button
                  type="button"
                  className={`btn join-item ${allServices?'btn-primary':'btn-ghost'}`}
                  onClick={()=>{
                    if(allServices){
                      setAllServices(false)
                    }else{
                      setAllServices(true); setServices('')
                    }
                  }}
                  title="Use all available services"
                >Full</button>
              </div>
              {allServices && <div className="text-xs opacity-70 mt-1">Using all available services.</div>}
            </div>
          )}
          {requiresAtk && (
            <div className="grid grid-cols-2 gap-2">
              <div className="form-control">
                <label className="label"><span className="label-text">Attacker IP</span></label>
                <div className="join w-full">
                  <input className="input input-bordered join-item w-full" placeholder="auto-detect or set manually" value={attackerIp} onChange={e=>setAttackerIp(e.target.value)} />
                  <button type="button" className="btn join-item btn-ghost" title="Auto-detect" onClick={detectAttacker}>Auto</button>
                </div>
              </div>
              <div className="form-control">
                <label className="label"><span className="label-text">Attacker Port</span></label>
                <input className="input input-bordered w-full" placeholder="4444" value={attackerPort} onChange={e=>setAttackerPort(e.target.value)} />
              </div>
            </div>
          )}
          <details className="collapse collapse-arrow bg-base-200/40 border border-base-300 rounded-lg">
            <summary className="collapse-title text-sm">Advanced Options</summary>
            <div className="collapse-content space-y-2">
              {showRockyou && (
                <label className="label cursor-pointer"><span className="label-text">Use rockyou</span><input type="checkbox" className="toggle" checked={useRockyou} onChange={()=>setUseRockyou(!useRockyou)} /></label>
              )}
              <label className="label cursor-pointer"><span className="label-text">Skip confirmations</span><input type="checkbox" className="toggle" checked={noConfirm} onChange={()=>setNoConfirm(!noConfirm)} /></label>
              {showWithVA && (
                <label className="label cursor-pointer"><span className="label-text">Run VA with Recon/Full Workflow</span><input type="checkbox" className="toggle" checked={withVulnAssess} onChange={()=>setWithVulnAssess(!withVulnAssess)} /></label>
              )}
            </div>
          </details>
          {/* Evasion options (frontend only flags) */}
          {mode==='evasion' && (
            <div className="grid grid-cols-2 gap-2">
              <label className="label cursor-pointer" title="Skip slower steps and sudo-heavy scans"><span className="label-text">Fast mode</span><input type="checkbox" className="toggle" onChange={e=> (window as any).__evasion_fast = e.currentTarget.checked} /></label>
              <label className="label cursor-pointer" title="Scan all TCP ports with baseline scans when applicable"><span className="label-text">All TCP ports</span><input type="checkbox" className="toggle" onChange={e=> (window as any).__evasion_all_ports = e.currentTarget.checked} /></label>
              <div className="form-control">
                <label className="label"><span className="label-text">Per-step timeout (s)</span></label>
                <input className="input input-bordered" placeholder="e.g. 60" title="Max seconds to allow each evasion step before skipping" onChange={e=> (window as any).__evasion_timeout = e.target.value} />
              </div>
              <div className="form-control">
                <label className="label"><span className="label-text">Test high port</span></label>
                <input className="input input-bordered" placeholder="50000" defaultValue={"50000"} title="High port to verify source-port 53 bypass" onChange={e=> (window as any).__evasion_test_port = e.target.value} />
              </div>
              <div className="form-control">
                <label className="label"><span className="label-text">Decoys (RND:n)</span></label>
                <input className="input input-bordered" placeholder="5" defaultValue={"5"} title="Number of random decoy IPs for -D RND:n" onChange={e=> (window as any).__evasion_decoys = e.target.value} />
              </div>
              <div className="col-span-2 text-xs opacity-70">Dry‑run: shows the exact payload that will be sent to the backend.</div>
              <button className="btn btn-xs" onClick={()=>{
                const selectedServices = allServices ? [] : services.split(',').map(s=>s.trim()).filter(Boolean)
                const body:any = {action:mode,target,no_confirm:noConfirm,attacker_ip:attackerIp,attacker_port:attackerPort,with_vuln_assess:withVulnAssess}
                if(requiresServices){ body.services = selectedServices }
                if((window as any).__evasion_fast) body.fast = true
                if((window as any).__evasion_all_ports) body.all_ports = true
                if((window as any).__evasion_timeout) body.timeout = parseInt((window as any).__evasion_timeout)
                if((window as any).__evasion_test_port) body.test_port = parseInt((window as any).__evasion_test_port)
                if((window as any).__evasion_decoys) body.decoys = parseInt((window as any).__evasion_decoys)
                alert('Payload to /api/run:\n'+JSON.stringify(body,null,2)+"\n\nETA: typically 2-6 minutes depending on flags")
              }}>Dry‑run preview</button>
            </div>
          )}

          <div className="grid grid-cols-4 gap-2 items-start">
            <button className="btn btn-primary col-span-3 shadow-[0_0_30px_theme(colors.primary/25)]" onClick={run} disabled={!canStart}>🚀 Start</button>
            <button className="btn" onClick={refreshOutputs}>Refresh</button>
            {!canStart && (
              <div className="col-span-4 text-xs opacity-70 mt-1">
                {(!requiresTarget || target) ? null : <div>Target is required.</div>}
              </div>
            )}
            <div className="col-span-4">
              <button className="btn btn-ghost btn-xs" onClick={()=>{
                const selectedServices = allServices ? [] : services.split(',').map(s=>s.trim()).filter(Boolean)
                const body:any = {action:mode,target,no_confirm:noConfirm,attacker_ip:attackerIp,attacker_port:attackerPort,use_rockyou:useRockyou,with_vuln_assess:withVulnAssess}
                if(requiresServices){ body.services = selectedServices }
                if(mode==='evasion'){
                  if((window as any).__evasion_fast) body.fast = true
                  if((window as any).__evasion_all_ports) body.all_ports = true
                  if((window as any).__evasion_timeout) body.timeout = parseInt((window as any).__evasion_timeout)
                  if((window as any).__evasion_test_port) body.test_port = parseInt((window as any).__evasion_test_port)
                  if((window as any).__evasion_decoys) body.decoys = parseInt((window as any).__evasion_decoys)
                }
                const payload = JSON.stringify(body)
                const cmd = `curl -sS -X POST '${API}/api/run' -H 'Content-Type: application/json' --data '${payload.replace(/'/g,"'\''")}'`
                navigator.clipboard.writeText(cmd).then(()=> alert('cURL copied to clipboard'))
              }}>Copy cURL</button>
            </div>
          </div>
        </motion.div>

        <motion.div className="card col-span-12 xl:col-span-8 p-0 overflow-hidden" initial={{opacity:0}} animate={{opacity:1}} transition={{delay:0.1}}>
          <div role="tablist" className="tabs tabs-bordered px-4 pt-3">
            <a role="tab" className={`tab ${tab==='logs'?'tab-active':''}`} onClick={()=>setTab('logs')}>Logs</a>
            <a role="tab" className={`tab ${tab==='outputs'?'tab-active':''}`} onClick={()=>setTab('outputs')}>Outputs</a>
            <div className="ml-auto flex items-center gap-2 pr-2">
              <label className="label cursor-pointer gap-2"><span className="label-text text-xs">Split view</span><input type="checkbox" className="toggle toggle-xs" checked={splitView} onChange={()=>setSplitView(!splitView)} /></label>
            </div>
          </div>
          {tab==='logs' && (
            <div className="p-4">
              <div className="flex items-center justify-between">
                <div className="text-xs opacity-70">Live Log</div>
                <div className="flex items-center gap-2">
                  <input className="input input-bordered input-xs w-48" placeholder="Filter (e.g., ERROR, nmap)" value={logFilter} onChange={e=>setLogFilter(e.target.value)} />
                  <div className="join">
                    {['ERROR','WARN','nmap'].map(ch=> (
                      <button key={ch} className={`btn btn-xs join-item ${chipFilters.includes(ch.toLowerCase())?'btn-primary':'btn-ghost'}`} onClick={()=>{
                        const low = ch.toLowerCase(); setChipFilters(prev=> prev.includes(low)? prev.filter(x=>x!==low): [...prev, low])
                      }}>{ch}</button>
                    ))}
                  </div>
                  <label className="label cursor-pointer gap-2"><span className="label-text text-xs">Regex</span><input type="checkbox" className="toggle toggle-xs" checked={regexFilter} onChange={()=>setRegexFilter(!regexFilter)} /></label>
                  <label className="label cursor-pointer gap-2"><span className="label-text text-xs">Hide noise</span><input type="checkbox" className="toggle toggle-xs" checked={hideNoise} onChange={()=>setHideNoise(!hideNoise)} /></label>
                  {logSlice && <button className="btn btn-ghost btn-xs" onClick={clearLogSlice} title="Clear phase slice">Slice✕</button>}
                  <label className="label cursor-pointer gap-2"><span className="label-text text-xs">Auto‑scroll</span><input type="checkbox" className="toggle toggle-xs" checked={autoScroll} onChange={()=>setAutoScroll(!autoScroll)} /></label>
                  <label className="label cursor-pointer gap-2"><span className="label-text text-xs">Wrap</span><input type="checkbox" className="toggle toggle-xs" checked={wrapLogs} onChange={()=>setWrapLogs(!wrapLogs)} /></label>
                  <div className="flex items-center gap-1 text-xs">
                    <span className="opacity-70">Font</span>
                    <input type="range" min={10} max={16} value={logFont} onChange={e=>setLogFont(parseInt(e.target.value))} className="range range-xs w-28" />
                  </div>
                  <button className="btn btn-xs" onClick={copyLogs}>Copy</button>
                  <button className="btn btn-xs" onClick={()=>{
                    const blob = new Blob([log], {type: 'text/plain'}); const url = URL.createObjectURL(blob);
                    const a = document.createElement('a'); a.href = url; a.download = `offsec_logs_${Date.now()}.txt`; a.click(); URL.revokeObjectURL(url);
                  }}>Download</button>
                  <button className="btn btn-xs" onClick={()=>{
                    const blob = new Blob([displayLog], {type: 'text/plain'}); const url = URL.createObjectURL(blob);
                    const a = document.createElement('a'); a.href = url; a.download = `offsec_logs_filtered_${Date.now()}.txt`; a.click(); URL.revokeObjectURL(url);
                  }}>Export filtered</button>
                  <button className="btn btn-xs" onClick={()=>{
                    try{ const lines = log.split('\n'); const idx = lines.findIndex(l=> /error|exception|fail/i.test(l)); if(idx>=0){ setLogSlice({start: Math.max(0, idx-3), end: Math.min(lines.length, idx+50)}) ; setTab('logs') } else { alert('No errors found') } }catch{}
                  }}>Jump error</button>
                  <button className="btn btn-xs" onClick={()=>{ try{ const cur = log.split('\n').length; setBookmarks(b=>[...b, cur]) }catch{} }}>Bookmark</button>
                  <button className="btn btn-xs" onClick={clearLogs}>Clear</button>
                </div>
              </div>
              <pre ref={logBoxRef} className={`mt-2 h-[68vh] overflow-auto ${wrapLogs?'whitespace-pre-wrap':'whitespace-pre'} bg-base-200 rounded-lg p-3`}
                   style={{fontSize: `${logFont}px`}}>{displayLog}</pre>
              {bookmarks.length>0 && (
                <div className="mt-2 text-xs flex items-center gap-2 flex-wrap">
                  <span className="opacity-70">Bookmarks:</span>
                  {bookmarks.map((b,i)=> (
                    <button key={i} className="btn btn-ghost btn-xs" onClick={()=> setLogSlice({start: Math.max(0, b-1), end: null}) } title={`Jump to line ${b}`}>#{i+1}</button>
                  ))}
                  <button className="btn btn-ghost btn-xs" onClick={()=> setBookmarks([])}>Clear</button>
                </div>
              )}
            </div>
          )}
          {tab==='outputs' && (
            <div className="grid grid-cols-12 gap-0">
              <div className="col-span-5 border-r border-base-300 p-4">
                <div className="flex items-center justify-between">
                  <div className="text-sm opacity-70">Files</div>
                  <div className="flex items-center gap-2">
                    <button className="btn btn-xs btn-ghost" onClick={async()=>{
                      try{
                        const r = await fetch(`${API}/api/outputs`); const d = await r.json();
                        const all = (d.files||[]) as string[]
                        if(all.length===0){ alert('No files'); return }
                        const last = all[all.length-1]
                        setSelectedFile(last); setTab('outputs')
                      }catch{ alert('Failed to get latest file') }
                    }}>Open latest</button>
                    <div className="text-xs opacity-60">{files.length}</div>
                  </div>
                </div>
                <div className="mt-2">
                  <input className="input input-bordered input-sm w-full" placeholder="Filter files (e.g., evasion, report, json)" value={fileFilter} onChange={e=>setFileFilter(e.target.value)} />
                  <div className="mt-2 grid grid-cols-3 gap-2 text-xs">
                    <select className="select select-bordered select-xs" value={phaseFilter} onChange={e=>{ setPhaseFilter(e.target.value); (async()=>{ try{ const params=new URLSearchParams(); if(e.target.value) params.set('phase', e.target.value); if(toolFilter) params.set('tool', toolFilter); if(extFilter) params.set('ext', extFilter); const r=await fetch(`${API}/api/outputs${params.toString()?`?${params.toString()}`:''}`); const d=await r.json(); setFiles(d.files||[]); setOutputsItems(d.items||[]) }catch{} })() }}>
                      <option value="">phase:any</option>
                      {['recon','exploit','post','report','evasion'].map(p=> <option key={p} value={p}>{p}</option>)}
                    </select>
                    <select className="select select-bordered select-xs" value={toolFilter} onChange={e=>{ setToolFilter(e.target.value); (async()=>{ try{ const params=new URLSearchParams(); if(phaseFilter) params.set('phase', phaseFilter); if(e.target.value) params.set('tool', e.target.value); if(extFilter) params.set('ext', extFilter); const r=await fetch(`${API}/api/outputs${params.toString()?`?${params.toString()}`:''}`); const d=await r.json(); setFiles(d.files||[]); setOutputsItems(d.items||[]) }catch{} })() }}>
                      <option value="">tool:any</option>
                      {['nmap','dns','ncat','report'].map(t=> <option key={t} value={t}>{t}</option>)}
                    </select>
                    <select className="select select-bordered select-xs" value={extFilter} onChange={e=>{ setExtFilter(e.target.value); (async()=>{ try{ const params=new URLSearchParams(); if(phaseFilter) params.set('phase', phaseFilter); if(toolFilter) params.set('tool', toolFilter); if(e.target.value) params.set('ext', e.target.value); const r=await fetch(`${API}/api/outputs${params.toString()?`?${params.toString()}`:''}`); const d=await r.json(); setFiles(d.files||[]); setOutputsItems(d.items||[]) }catch{} })() }}>
                      <option value="">ext:any</option>
                      {['json','md','txt','pdf','html','csv'].map(x=> <option key={x} value={x}>{x}</option>)}
                    </select>
                  </div>
                </div>
                <ul className="mt-2 max-h-[70vh] overflow-auto pr-1">
                  {files.filter(f=> f.toLowerCase().includes(fileFilter.toLowerCase())).map(f=> (
                    <li key={f} className="truncate">
                      <div className="flex items-center justify-between gap-2">
                        <button className="link link-primary text-left truncate" onClick={()=>viewFile(f)} title={f}>{f}</button>
                        <a className="btn btn-ghost btn-xs" href={`${API}/outputs/${encodeURIComponent(f)}`} target="_blank" rel="noreferrer">Open</a>
                        <button className="btn btn-ghost btn-xs" onClick={()=> setDiffLeft(f)} title="Select as left file for diff">Diff◀</button>
                      </div>
                      {(()=>{ const item = outputsItems.find((it:any)=> it.name===f); if(!item) return null; const t = item.tags||{}; return <div className="text-[10px] opacity-60">{t.phase||'‑'} · {t.tool||'‑'} · .{t.ext||''}</div> })()}
                    </li>
                  ))}
                  {files.length===0 && <div className="opacity-70">No files yet.</div>}
                </ul>
              </div>
              <div className="col-span-7 p-4">
                {!selectedFile && <div className="opacity-60">Select a file to preview.</div>}
                {selectedFile && isEmbed && (
                  <iframe title={selectedFile} className="w-full h-[70vh] rounded border border-base-300" src={`${API}/outputs/${encodeURIComponent(selectedFile)}`}></iframe>
                )}
                {selectedFile && !isEmbed && (
                  <div>
                    <div className="text-xs opacity-70 truncate mb-2">{selectedFile}</div>
                    {loadingFile ? (
                      <div className="loading loading-dots loading-sm"></div>
                    ) : (
                      <>
                        <div className="mb-2 flex items-center gap-2">
                          <button className="btn btn-xs" onClick={()=>{ try{ navigator.clipboard.writeText(fileText) }catch{} }}>Copy</button>
                          <button className="btn btn-xs" onClick={()=>{
                            const blob = new Blob([fileText], {type: 'text/plain'}); const url = URL.createObjectURL(blob);
                            const a = document.createElement('a'); a.href = url; a.download = selectedFile; a.click(); URL.revokeObjectURL(url);
                          }}>Download</button>
                          {diffLeft && diffLeft!==selectedFile && <button className="btn btn-xs" onClick={async()=>{
                            try{
                              const r = await fetch(`${API}/outputs/${encodeURIComponent(diffLeft)}`); const leftText = await r.text()
                              const linesA = leftText.split('\n'); const linesB = fileText.split('\n')
                              let diff: string[] = []
                              const max = Math.max(linesA.length, linesB.length)
                              for(let i=0;i<max;i++){
                                const a = linesA[i]||''; const b = linesB[i]||''
                                if(a!==b){ diff.push(`- ${a}`); diff.push(`+ ${b}`) }
                              }
                              setFileText(diff.join('\n'))
                            }catch{ alert('Diff failed') }
                          }}>Compare with ◀ {diffLeft}</button>}
                        </div>
                        {selectedFile.toLowerCase().endsWith('.json') ? (
                          <div className="h-[66vh] overflow-auto bg-base-200 rounded-lg p-3 text-xs">
                            {(()=>{ try{ const obj = JSON.parse(fileText); const Render=(v:any,k?:string)=>{
                              if(v && typeof v==='object'){
                                const entries = Array.isArray(v)? v.map((vv,i)=>[i as any, vv]) : Object.entries(v)
                                return <ul className="pl-3">{entries.map(([kk,vv]:any)=> <li key={kk}><span className="opacity-70">{String(kk)}:</span> {typeof vv==='object'? Render(vv): <span className="font-mono">{String(vv)}</span>}</li>)}</ul>
                              }
                              return <span className="font-mono">{String(v)}</span>
                            }; return Render(obj) }catch{return <pre className="whitespace-pre-wrap">{fileText}</pre>} })()}
                          </div>
                        ) : (
                          <pre className="h-[66vh] overflow-auto whitespace-pre-wrap text-xs bg-base-200 rounded-lg p-3">{fileText}</pre>
                        )}
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}
        </motion.div>

        <motion.div className="card p-5 space-y-3 col-span-12" initial={{opacity:0,y:10}} animate={{opacity:1,y:0}} transition={{delay:0.25}}>
          <div className="text-lg font-semibold">About</div>
          <p className="text-sm opacity-80">Unified offensive security toolkit: Reconnaissance, Vulnerability Assessment, Exploitation, Post‑Exploitation, and Reporting. Integrates Burp Suite Pro and other scanners. All artifacts are saved in <code>outputs/</code> and included in the final report.</p>
          <div className="grid sm:grid-cols-2 gap-2 text-sm">
            <div>
              <div className="font-semibold">Phases</div>
              <ul className="list-disc pl-4 opacity-80">
                <li>Recon: Nmap + per‑service footprint</li>
                <li>VA: Burp/Nessus/Nuclei/SSLyze/ssh‑audit/Nmap vulns</li>
                <li>Exploit: service‑specific exploits</li>
                <li>Post‑Exploit: loot, persistence, intel</li>
                <li>Report: Markdown/PDF walkthrough</li>
              </ul>
            </div>
            <div>
              <div className="font-semibold">How to use</div>
              <ul className="list-disc pl-4 opacity-80">
                <li>Choose Mode (buttons above)</li>
                <li>Provide required fields (target, services, attacker)</li>
                <li>Start and watch logs live</li>
                <li>Preview or download results in Outputs</li>
              </ul>
            </div>
          </div>
          <div className="opacity-70 text-xs">Note: Some modes hide irrelevant inputs. For example, Walkthrough (report) only generates documentation; Exploit/Post‑Exploit require attacker details.</div>
        </motion.div>

        <div className="col-span-full text-center opacity-60 text-xs pt-2">
          © Offsec Toolkit — Authorized testing only. Handle data responsibly.
        </div>
      </div>
    </Layout>
  )
}
ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={q}>
      <Dashboard />
    </QueryClientProvider>
  </React.StrictMode>
)

