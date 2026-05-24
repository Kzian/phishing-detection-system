import React, { useState, useEffect } from 'react'
import { useAuth } from '../App'
import { analyzeUrl, analyzeEmail, analyzeSms, getStats, getHealth } from '../api'
import ThreatResult from '../components/ThreatResult'
import SeverityBadge from '../components/SeverityBadge'

const TABS = ['url','email','sms']

export default function Dashboard() {
  const { user } = useAuth()
  const [tab,     setTab]     = useState('url')
  const [result,  setResult]  = useState(null)
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState('')
  const [stats,   setStats]   = useState(null)
  const [health,  setHealth]  = useState(null)

  // URL state
  const [url, setUrl] = useState('')
  // Email state
  const [subject,  setSubject]  = useState('')
  const [body,     setBody]     = useState('')
  const [sender,   setSender]   = useState('')
  // SMS state
  const [message,  setMessage]  = useState('')
  const [senderNo, setSenderNo] = useState('')

  useEffect(() => {
    Promise.all([getStats(), getHealth()])
      .then(([s, h]) => { setStats(s); setHealth(h) })
      .catch(() => {})
  }, [result])

  async function analyze() {
    setError(''); setResult(null); setLoading(true)
    try {
      let data
      if (tab === 'url')   data = await analyzeUrl(url)
      if (tab === 'email') data = await analyzeEmail(subject, body, sender, user?.email)
      if (tab === 'sms')   data = await analyzeSms(message, senderNo, user?.email)
      setResult(data)
    } catch(e) { setError(e.message) }
    finally    { setLoading(false) }
  }

  const canSubmit = () => {
    if (tab === 'url')   return url.trim()
    if (tab === 'email') return subject.trim() && body.trim()
    if (tab === 'sms')   return message.trim()
  }

  return (
    <div className="max-w-5xl mx-auto p-6 space-y-6">

      {/* Welcome bar */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">
            Good {new Date().getHours() < 12 ? 'morning' : 'afternoon'}, {user?.name?.split(' ')[0]} 👋
          </h1>
          <p className="text-gray-400 text-sm mt-0.5">
            {user?.role?.charAt(0).toUpperCase()+user?.role?.slice(1)}
            {user?.department ? ` · ${user.department}` : ''}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${
            health?.status === 'healthy' ? 'bg-green-400' : 'bg-yellow-400'
          }`} />
          <span className="text-xs text-gray-400">
            {health?.status === 'healthy' ? 'All systems operational' : 'Degraded'}
          </span>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-4 gap-4">
          {[
            { label:'Total incidents', val: stats.total,         color:'text-white' },
            { label:'Critical',        val: stats.critical_count, color:'text-red-400' },
            { label:'Avg threat score',
              val: stats.avg_threat_score ? (stats.avg_threat_score*100).toFixed(1)+'%' : '0%',
              color:'text-yellow-400' },
            { label:'Models active', val: '3 / 3', color:'text-green-400' },
          ].map(({ label, val, color }) => (
            <div key={label} className="card text-center py-4">
              <div className={`text-2xl font-bold ${color}`}>{val}</div>
              <div className="text-xs text-gray-500 mt-1">{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Analysis panel */}
      <div className="card">
        <h2 className="font-semibold mb-4">Threat Analysis</h2>

        {/* Tabs */}
        <div className="flex gap-1 bg-gray-800 p-1 rounded-lg mb-5 w-fit">
          {TABS.map(t => (
            <button key={t} onClick={() => { setTab(t); setResult(null); setError('') }}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition capitalize ${
                tab === t ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'
              }`}>
              {t === 'url' ? '🔗 URL' : t === 'email' ? '📧 Email' : '📱 SMS'}
            </button>
          ))}
        </div>

        {/* URL input */}
        {tab === 'url' && (
          <div className="space-y-3">
            <div>
              <label className="text-xs text-gray-400 block mb-1">URL to analyze</label>
              <input value={url} onChange={e => setUrl(e.target.value)}
                placeholder="https://suspicious-link.xyz/verify"
                onKeyDown={e => e.key === 'Enter' && canSubmit() && analyze()} />
            </div>
            <p className="text-xs text-gray-600">
              Network features (domain age, ASN, SPF) resolved automatically.
              Allow 3–6s for new domains.
            </p>
          </div>
        )}

        {/* Email input */}
        {tab === 'email' && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-gray-400 block mb-1">Subject line</label>
                <input value={subject} onChange={e => setSubject(e.target.value)}
                  placeholder="URGENT: Verify your account" />
              </div>
              <div>
                <label className="text-xs text-gray-400 block mb-1">
                  Sender email <span className="text-gray-600">(optional but recommended)</span>
                </label>
                <input value={sender} onChange={e => setSender(e.target.value)}
                  placeholder="admin@nhis.gov.ng" />
              </div>
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Email body</label>
              <textarea value={body} onChange={e => setBody(e.target.value)}
                rows={5} placeholder="Paste the full email body here..." />
            </div>
            <p className="text-xs text-gray-600">
              Sender domain analysis: .gov.ng / .edu.ng / .org.ng receive trust adjustment.
              Incident will be attributed to your account ({user?.email}).
            </p>
          </div>
        )}

        {/* SMS input */}
        {tab === 'sms' && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2">
                <label className="text-xs text-gray-400 block mb-1">SMS message</label>
                <textarea value={message} onChange={e => setMessage(e.target.value)}
                  rows={3} placeholder="Your account has been suspended. Click here to verify: http://..." />
              </div>
              <div>
                <label className="text-xs text-gray-400 block mb-1">Sender number <span className="text-gray-600">(optional)</span></label>
                <input value={senderNo} onChange={e => setSenderNo(e.target.value)}
                  placeholder="+2348012345678" />
              </div>
            </div>
          </div>
        )}

        {error && (
          <div className="mt-3 bg-red-950 border border-red-800 rounded-lg p-3
            text-red-400 text-sm">{error}</div>
        )}

        <button onClick={analyze} disabled={loading || !canSubmit()}
          className="btn-primary mt-4 px-6 py-2.5">
          {loading
            ? <><span className="animate-spin inline-block w-4 h-4 border-2
                border-white border-t-transparent rounded-full" /> Analyzing...</>
            : '⚡ Analyze'}
        </button>

        <ThreatResult data={result} />
      </div>
    </div>
  )
}
