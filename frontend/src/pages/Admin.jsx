import React, { useState, useEffect } from 'react'
import { useAuth } from '../App'
import { useNavigate } from 'react-router-dom'
import SeverityBadge from '../components/SeverityBadge'

const API = '/api'

function authHeaders() {
  const token = localStorage.getItem('pg_token')
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function apiFetch(path, opts = {}) {
  const res  = await fetch(API + path, {
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    ...opts,
  })
  const data = await res.json()
  if (!res.ok) throw new Error(data.detail || 'Request failed')
  return data
}

const TYPE_ICON = { url: '🔗', email: '📧', sms: '📱' }
const SEV_RANK  = { CLEAN: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }

export default function Admin() {
  const { user }   = useAuth()
  const navigate   = useNavigate()

  const [incidents,  setIncidents]  = useState([])
  const [stats,      setStats]      = useState(null)
  const [selected,   setSelected]   = useState(null)
  const [loading,    setLoading]    = useState(true)
  const [actionNote, setActionNote] = useState('')
  const [filter,     setFilter]     = useState({ severity: '', type: '' })

  // Redirect non-admin roles
  useEffect(() => {
    if (user && !['it','admin'].includes(user.role)) {
      navigate('/dashboard')
    }
  }, [user])

  useEffect(() => { loadAll() }, [])

  async function loadAll() {
    setLoading(true)
    try {
      const [inc, st] = await Promise.all([
        apiFetch('/incidents?limit=100'),
        apiFetch('/admin/stats'),
      ])
      setIncidents(inc.incidents || [])
      setStats(st)
    } catch(e) { console.error(e) }
    finally { setLoading(false) }
  }

  async function takeAction(action) {
    if (!selected) return
    try {
      await apiFetch(`/incidents/${selected.incident_id}/action`, {
        method: 'PATCH',
        body: JSON.stringify({ action, note: actionNote }),
      })
      // Update locally
      setIncidents(prev => prev.map(i =>
        i.incident_id === selected.incident_id
          ? { ...i, admin_action: action, admin_note: actionNote,
              actioned_by: user.email,
              actioned_at: new Date().toISOString() }
          : i
      ))
      setSelected(prev => ({ ...prev, admin_action: action,
        admin_note: actionNote, actioned_by: user.email }))
      setActionNote('')
    } catch(e) { alert(e.message) }
  }

  function downloadReport(id) {
    const token = localStorage.getItem('pg_token')
    window.open(`${API}/incidents/${id}/report?token=${token}`, '_blank')
  }

  const filtered = incidents.filter(i => {
    if (filter.severity && i.severity !== filter.severity) return false
    if (filter.type     && i.input_type !== filter.type)   return false
    return true
  })

  const pct = (score) => Math.round((score || 0) * 100)

  const barColor = (score) => {
    if (score < 0.3)  return 'bg-green-500'
    if (score < 0.5)  return 'bg-blue-500'
    if (score < 0.7)  return 'bg-yellow-500'
    if (score < 0.85) return 'bg-orange-500'
    return 'bg-red-500'
  }

  return (
    <div className="max-w-7xl mx-auto p-6 space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Admin Dashboard</h1>
          <p className="text-gray-400 text-sm mt-0.5">
            {user?.name} · {user?.role?.toUpperCase()} · Full incident access
          </p>
        </div>
        <button onClick={loadAll} className="btn-ghost text-xs px-3 py-1.5">
          🔄 Refresh
        </button>
      </div>

      {/* Staff breakdown */}
      {stats && (
        <div>
          <h2 className="text-sm font-medium text-gray-400 mb-3">
            Staff Threat Overview
          </h2>
          <div className="grid grid-cols-4 gap-3">
            {stats.staff_breakdown.map((s, i) => (
              <div key={i} className="card py-3 px-4">
                <div className="text-sm font-medium truncate">{s.name}</div>
                <div className="text-xs text-gray-500 capitalize mb-2">
                  {s.role} {s.department ? `· ${s.department}` : ''}
                </div>
                <div className="flex items-center justify-between">
                  <div className="text-xs text-gray-400">
                    {s.count} incident{s.count !== 1 ? 's' : ''}
                  </div>
                  {s.count > 0 && <SeverityBadge severity={s.highest} />}
                </div>
                {s.critical > 0 && (
                  <div className="text-xs text-red-400 mt-1">
                    ⚠️ {s.critical} critical
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-3 items-center">
        <div className="text-sm text-gray-400">
          {filtered.length} incidents
        </div>
        <select
          value={filter.severity}
          onChange={e => setFilter(f => ({ ...f, severity: e.target.value }))}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5
                     text-sm w-40 focus:outline-none focus:border-blue-500">
          <option value="">All severities</option>
          {['CRITICAL','HIGH','MEDIUM','LOW','CLEAN'].map(s => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select
          value={filter.type}
          onChange={e => setFilter(f => ({ ...f, type: e.target.value }))}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5
                     text-sm w-40 focus:outline-none focus:border-blue-500">
          <option value="">All channels</option>
          {['url','email','sms'].map(t => (
            <option key={t} value={t}>{t.toUpperCase()}</option>
          ))}
        </select>
        {(filter.severity || filter.type) && (
          <button onClick={() => setFilter({ severity: '', type: '' })}
            className="text-xs text-gray-400 hover:text-white">
            Clear filters
          </button>
        )}
      </div>

      {/* Main content */}
      <div className="flex gap-4">

        {/* Incidents table */}
        <div className="flex-1 card p-0 overflow-hidden">
          {loading ? (
            <div className="p-8 text-center text-gray-500">Loading...</div>
          ) : filtered.length === 0 ? (
            <div className="p-8 text-center text-gray-500 text-sm">
              No incidents match the current filters.
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-xs text-gray-500
                               uppercase tracking-wide">
                  <th className="px-4 py-3 text-left">Ch</th>
                  <th className="px-4 py-3 text-left">Severity</th>
                  <th className="px-4 py-3 text-left">Score</th>
                  <th className="px-4 py-3 text-left">Staff</th>
                  <th className="px-4 py-3 text-left">Status</th>
                  <th className="px-4 py-3 text-left">Time</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(inc => (
                  <tr key={inc.incident_id}
                    onClick={() => { setSelected(inc); setActionNote('') }}
                    className={`cursor-pointer border-b border-gray-800 transition ${
                      selected?.incident_id === inc.incident_id
                        ? 'bg-blue-950/40'
                        : 'hover:bg-gray-800/50'
                    }`}>
                    <td className="px-4 py-3">
                      {TYPE_ICON[inc.input_type] || '?'}
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                          <div className={`h-full rounded-full ${barColor(inc.threat_score)}`}
                            style={{ width: `${pct(inc.threat_score)}%` }} />
                        </div>
                        <span className="text-xs">{pct(inc.threat_score)}%</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400 max-w-32 truncate">
                      {inc.user_email
                        ? (stats?.staff_breakdown?.find(s =>
                            s.email === inc.user_email)?.name || inc.user_email)
                        : inc.metadata?.recipient || '—'}
                    </td>
                    <td className="px-4 py-3">
                      {inc.admin_action ? (
                        <span className={`text-xs px-2 py-0.5 rounded-full border ${
                          inc.admin_action === 'cleared'
                            ? 'bg-green-950 text-green-400 border-green-800'
                            : inc.admin_action === 'blocked'
                            ? 'bg-red-950 text-red-400 border-red-800'
                            : 'bg-yellow-950 text-yellow-400 border-yellow-800'
                        }`}>
                      {inc.admin_action}
                        </span>
                      ) : (
                        <span className={`text-xs px-2 py-0.5 rounded-full border ${
                          ['HIGH','CRITICAL'].includes(inc.severity)
                            ? 'bg-orange-950 text-orange-400 border-orange-800'
                            : 'bg-gray-800 text-gray-500 border-gray-700'
                        }`}>
                          {['HIGH','CRITICAL'].includes(inc.severity)
                            ? '🔒 auto-suspended'
                            : 'pending review'}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {inc.timestamp?.slice(0,16).replace('T',' ')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Action panel */}
        {selected && (
          <div className="w-80 space-y-4 self-start sticky top-6">

            {/* Incident detail */}
            <div className="card space-y-3">
              <div className="flex items-center justify-between">
                <div className="font-mono text-sm font-semibold">
                  {selected.incident_id}
                </div>
                <button onClick={() => setSelected(null)}
                  className="text-gray-600 hover:text-white text-lg leading-none">×
                </button>
              </div>
              <SeverityBadge severity={selected.severity} />

              <div className="space-y-2 text-sm">
                {[
                  ['Channel',    selected.input_type],
                  ['Prediction', selected.prediction],
                  ['Score',      `${pct(selected.threat_score)}%`],
                  ['Staff',      selected.user_email ||
                                 selected.metadata?.recipient || '—'],
                  ['Sender',     selected.metadata?.sender ||
                                 selected.metadata?.sender_number || '—'],
                  ['Subject',    selected.metadata?.subject || '—'],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-2">
                    <span className="text-gray-500 shrink-0">{k}</span>
                    <span className="text-right text-xs break-all">{v}</span>
                  </div>
                ))}
              </div>

              {/* Current admin status */}
              {selected.admin_action && (
                <div className="border-t border-gray-800 pt-3 text-xs space-y-1">
                  <div className="text-gray-500">Admin review</div>
                  <div>Action: <span className="text-white capitalize">
                    {selected.admin_action}</span></div>
                  <div className="text-gray-400">
                    by {selected.actioned_by}</div>
                  {selected.admin_note && (
                    <div className="text-gray-400 italic">
                      "{selected.admin_note}"</div>
                  )}
                </div>
              )}
            </div>

            {/* Action buttons */}
            <div className="card space-y-3">
              <div className="text-sm font-medium">Take Action</div>
              <textarea
                value={actionNote}
                onChange={e => setActionNote(e.target.value)}
                placeholder="Optional note..."
                rows={2}
                className="text-xs" />
              <div className="grid grid-cols-3 gap-2">
                <button onClick={() => takeAction('blocked')}
                  className="bg-red-950 hover:bg-red-900 border border-red-800
                             text-red-400 text-xs py-2 rounded-lg transition">
                  🚫 Block
                </button>
                <button onClick={() => takeAction('cleared')}
                  className="bg-green-950 hover:bg-green-900 border border-green-800
                             text-green-400 text-xs py-2 rounded-lg transition">
                  ✅ Clear
                </button>
                <button onClick={() => takeAction('escalated')}
                  className="bg-yellow-950 hover:bg-yellow-900 border border-yellow-800
                             text-yellow-400 text-xs py-2 rounded-lg transition">
                  ⬆️ Escalate
                </button>
              </div>
              <button
                onClick={() => downloadReport(selected.incident_id)}
                className="btn-ghost w-full text-xs py-2">
                📄 Download Report
              </button>
            </div>

          </div>
        )}
      </div>
    </div>
  )
}
