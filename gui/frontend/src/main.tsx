import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import './styles.css'

const API = import.meta.env.VITE_API || 'http://127.0.0.1:8000'
const q = new QueryClient()

function Layout({ children }: { children: React.ReactNode }){
  return (
    <div data-theme="hacker" className="min-h-screen bg-base-100 text-slate-100 relative overflow-hidden">
      <motion.div
        className="pointer-events-none absolute inset-0 opacity-20 bg-gradient-to-b from-primary/20 via-transparent to-primary/20"
        initial={{ backgroundPosition: '0% 0%' }}
        animate={{ backgroundPosition: ['0% 0%','0% 100%','0% 0%'] }}
        transition={{ duration: 12, repeat: Infinity }}
      />
      <main className="container mx-auto p-6 relative z-10">{children}</main>
    </div>
  )
}

function useSSE(setter: React.Dispatch<React.SetStateAction<string>>){
  React.useEffect(()=>{
    const es = new EventSource(`${API}/api/logs`)
    es.onmessage = (ev)=> setter((prev: string)=> prev + ev.data + '\n')
    return ()=> es.close()
  },[])
}

function Dashboard(){
  const [log, setLog] = React.useState('')
  useSSE(setLog)
  const [target,setTarget]=React.useState('')
  const [services,setServices]=React.useState('')
  const [attackerIp,setAttackerIp]=React.useState('')
  const [attackerPort,setAttackerPort]=React.useState('4444')
  const [useRockyou,setUseRockyou]=React.useState(false)
  const [mode,setMode]=React.useState<'recon'|'exploit'|'post-exploit'|'report'|'walkthrough'|'walkthrough-full'>('recon')
  const [status,setStatus]=React.useState<{state:string,action:string}>({state:'idle',action:'none'})
  const [files,setFiles]=React.useState<string[]>([])
  React.useEffect(()=>{
    const t = setInterval(async()=>{
      try{ const r = await fetch(`${API}/api/status`); setStatus(await r.json()) }catch{}
    }, 1000)
    return ()=> clearInterval(t)
  },[])
  const refreshOutputs = async()=>{
    try{ const r = await fetch(`${API}/api/outputs`); const d = await r.json(); setFiles(d.files||[]) }catch{}
  }
  React.useEffect(()=>{ refreshOutputs() },[])
  const run = async()=>{
    setLog('')
    await fetch(`${API}/api/run`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:mode,target,services:services.split(',').map(s=>s.trim()).filter(Boolean),no_confirm:true,attacker_ip:attackerIp,attacker_port:attackerPort,use_rockyou:useRockyou})})
  }
  const pause = ()=> fetch(`${API}/api/pause`,{method:'POST'})
  const resume = ()=> fetch(`${API}/api/resume`,{method:'POST'})
  const stop = ()=> fetch(`${API}/api/stop`,{method:'POST'})
  const clearOutputs = async()=>{ await fetch(`${API}/api/clear-outputs`,{method:'POST'}); await refreshOutputs() }
  return (
    <Layout>
      <div className="grid xl:grid-cols-3 gap-6">
        <motion.div className="card p-5 space-y-4 xl:col-span-1 relative overflow-hidden"
          initial={{opacity:0, y:10}} animate={{opacity:1, y:0}} transition={{duration:0.5}}>
          <motion.div className="absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r from-transparent via-primary to-transparent"
            animate={{opacity:[0.2,1,0.2]}} transition={{repeat:Infinity, duration:3}} />
          <div className="flex items-center justify-between gap-2">
            <div className="font-semibold tracking-wide">Offsec Control Center</div>
            <div className="flex items-center gap-2">
              <div className={`badge ${status.state==='running'?'badge-success':status.state==='paused'?'badge-warning':'badge-ghost'}`}>{status.state} / {status.action}</div>
              <div className="join">
                <button className="btn btn-xs btn-warning join-item" onClick={pause}>Pause</button>
                <button className="btn btn-xs btn-success join-item" onClick={resume}>Continue</button>
                <button className="btn btn-xs btn-error join-item" onClick={stop}>Stop</button>
                <button className="btn btn-xs btn-accent join-item" onClick={clearOutputs}>Clear</button>
              </div>
            </div>
          </div>
          <select className="select select-bordered w-full" value={mode} onChange={e=>setMode(e.target.value as any)}>
            <option value="recon">Recon</option>
            <option value="exploit">Exploit</option>
            <option value="post-exploit">Post-Exploit</option>
            <option value="report">Report</option>
            <option value="walkthrough">Walkthrough (only)</option>
            <option value="walkthrough-full">Walkthrough (full pipeline)</option>
          </select>
          <input className="input input-bordered w-full" placeholder="Target" value={target} onChange={e=>setTarget(e.target.value)} />
          <input className="input input-bordered w-full" placeholder="Services (http,ssh)" value={services} onChange={e=>setServices(e.target.value)} />
          <div className="grid grid-cols-2 gap-2">
            <input className="input input-bordered w-full" placeholder="Attacker IP" value={attackerIp} onChange={e=>setAttackerIp(e.target.value)} />
            <input className="input input-bordered w-full" placeholder="Attacker Port" value={attackerPort} onChange={e=>setAttackerPort(e.target.value)} />
          </div>
          <label className="label cursor-pointer"><span className="label-text">Use rockyou</span><input type="checkbox" className="toggle" checked={useRockyou} onChange={()=>setUseRockyou(!useRockyou)} /></label>
          <div className="grid grid-cols-4 gap-2">
            <button className="btn btn-primary col-span-3" onClick={run}>Start</button>
            <button className="btn" onClick={refreshOutputs}>Refresh</button>
          </div>
        </motion.div>

        <motion.div className="card p-5 xl:col-span-2" initial={{opacity:0}} animate={{opacity:1}} transition={{delay:0.15}}>
          <div className="text-xs opacity-70">Live Log</div>
          <pre className="mt-2 h-[46vh] overflow-auto whitespace-pre-wrap text-xs">{log}</pre>
        </motion.div>

        <motion.div className="card p-5 xl:col-span-2" initial={{opacity:0,y:10}} animate={{opacity:1,y:0}} transition={{delay:0.2}}>
          <div className="flex items-center justify-between">
            <div className="text-sm opacity-70">Outputs</div>
            <div className="text-xs opacity-60">{files.length} files</div>
          </div>
          <ul className="mt-2 grid md:grid-cols-2 gap-2">
            {files.map(f=> (
              <li key={f} className="truncate">
                <a className="link link-primary" href={`${API}/outputs/${encodeURIComponent(f)}`} target="_blank" rel="noreferrer">{f}</a>
              </li>
            ))}
            {files.length===0 && <div className="opacity-70">No files yet.</div>}
          </ul>
        </motion.div>

        <motion.div className="card p-5 space-y-3" initial={{opacity:0,y:10}} animate={{opacity:1,y:0}} transition={{delay:0.25}}>
          <div className="text-lg font-semibold">About the Toolkit</div>
          <p className="text-sm opacity-80">Automated reconnaissance, exploitation, post‑exploitation, and reporting with integrated Burp Suite Pro. Outputs are written into the <code>outputs/</code> folder and summarized into comprehensive PDF/Markdown reports.</p>
          <div className="grid sm:grid-cols-2 gap-2 text-sm">
            <div>
              <div className="font-semibold">Phases</div>
              <ul className="list-disc pl-4 opacity-80">
                <li>Recon: Nmap + service footprint</li>
                <li>Exploit: per‑service exploits</li>
                <li>Post‑Exploit: loot + intel</li>
                <li>Report: Markdown/PDF</li>
                <li>Walkthrough: step‑by‑step</li>
              </ul>
            </div>
            <div>
              <div className="font-semibold">How to use</div>
              <ul className="list-disc pl-4 opacity-80">
                <li>Set Target and Services</li>
                <li>Select Mode and press Start</li>
                <li>Watch logs in real‑time</li>
                <li>Download results from Outputs</li>
              </ul>
            </div>
          </div>
          <div className="opacity-70 text-xs">Tip: Burp scanning is triggered during HTTP recon when enabled in <code>config/settings.json</code>.</div>
        </motion.div>

        <div className="col-span-full text-center opacity-60 text-xs pt-2">
          © Offsec Toolkit — For authorized testing only.
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

