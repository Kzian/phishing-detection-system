import React, { useState, useEffect } from 'react'
import { useAuth } from '../App'
import { getMyIncidents, getIncidents } from '../api'
import SeverityBadge from '../components/SeverityBadge'

const TYPE_ICON = { url: '🔗', email: '📧', sms: '📱' }

function IncidentRow({ inc, onClick, selected }) {
  const pct = Math.round((inc.threat_score || 0) * 100)
  const ts  = inc.timestamp?.slice(0,19).replace('T',' ') + ' UTC'

  return (
    <tr onClick={() => onClick(inc)}
      className={`cursor-pointer transition border-b border-gray-800
        ${selected ? 'bg-blue-950/40' : 'hover:bg-gray-800/50'}`}>
      <td className="px-4 py-3 text-lg">{TYPE_ICON[inc.input_type] || '?'}</td>
      <td className="px-4 py-3">
        <SeverityBadge severity={inc.severity} />
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <div className="w-20 h-1.5 bg-gray-700 rounded-full overflow-hidden">
            <div className={`h-full rounded-full ${
              pct >= 85 ? 'bg-red-500' : pct >= 70 ? 'bg-orange-500' :
              pct >= 50 ? 'bg-yellow-500' : pct >= 30 ? 'bg-blue-500' : 'bg-green-500'
            }`} style={{ width: `${pct}%` }} />
          </div>
          <span className="text-sm">{pct}%</span>
        </div>
      </td>
      <td className="px-4 py-3 font-mono text-xs text-gray-400">{inc.incident_id}</td>
      <td className="px-4 py-3 text-xs text-gray-500">{ts}</td>
    </tr>
  )
}

export default function MyIncidents() {
  const { user } = useAuth()
  const [incidents, setIncidents] = useState([])
  const [selected,  setSelected]  = useState(null)
  const [loading,   setLoading]   = useState(true)
  const [view,      setView]      = useState('mine') // mine | all

  useEffect(() => {
    setLoading(true)
    const fetch = view === 'mine' ? getMyIncidents() : getIncidents()
    fetch.then(d => setIncidents(d.incidents || []))
         .catch(() => setIncidents([]))
         .finally(() => setLoading(false))
  }, [view])

  return (
    <div className="max-w-5xl mx-auto p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold">Incident History</h1>
          <p className="text-gray-400 text-sm mt-0.5">{user?.email}</p>
        </div>
        {/* View toggle */}
        <div className="flex gap-1 bg-gray-800 p-1 rounded-lg">
          {[['mine','My Incidents'],['all','All Incidents']].map(([v, label]) => (
            <button key={v} onClick={() => { setView(v); setSelected(null) }}
              className={`px-3 py-1.5 rounded-md text-sm transition ${
                view === v ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'
              }`}>{label}</button>
          ))}
        </div>
      </div>

      <div className="flex gap-4">
        {/* Table */}
        <div className="flex-1 card p-0 overflow-hidden">
          {loading ? (
            <div className="p-8 text-center text-gray-500 text-sm">Loading...</div>
          ) : incidents.length === 0 ? (
            <div className="p-8 text-center">
              <div className="text-3xl mb-2">🛡</div>
              <div className="text-gray-400 text-sm">No incidents yet.</div>
              <div className="text-gray-600 text-xs mt-1">
                Analyze a URL, email, or SMS from the dashboard.
              </div>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wide">
                  <th className="px-4 py-3 text-left">Type</th>
                  <th className="px-4 py-3 text-left">Severity</th>
                  <th className="px-4 py-3 text-left">Score</th>
                  <th className="px-4 py-3 text-left">ID</th>
                  <th className="px-4 py-3 text-left">Time</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map(inc => (
                  <IncidentRow key={inc.incident_id} inc={inc}
                    onClick={setSelected}
                    selected={selected?.incident_id === inc.incident_id} />
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Detail panel */}
        {selected && (
          <div className="w-80 card space-y-4 self-start sticky top-6">
            <div className="flex items-center justify-between">
              <div className="font-mono text-sm font-semibold">{selected.incident_id}</div>
              <button onClick={() => setSelected(null)}
                className="text-gray-600 hover:text-white text-lg leading-none">×</button>
            </div>
            <SeverityBadge severity={selected.severity} />

            <div className="space-y-2 text-sm">
              {[
                ['Channel',    selected.input_type],
                ['Prediction', selected.prediction],
                ['Confidence', selected.confidence],
                ['Score',      `${Math.round((selected.threat_score||0)*100)}%`],
              ].map(([k,v]) => (
                <div key={k} className="flex justify-between">
                  <span className="text-gray-500">{k}</span>
                  <span className="capitalize">{v}</span>
                </div>
              ))}
            </div>

            {/* Metadata */}
            {selected.metadata && Object.keys(selected.metadata).length > 0 && (
              <div className="border-t border-gray-800 pt-3">
                <div className="text-xs text-gray-500 mb-2">Metadata</div>
                {Object.entries(selected.metadata).map(([k, v]) => (
                  <div key={k} className="text-xs mb-1">
                    <span className="text-gray-600">{k}: </span>
                    <span className="text-gray-300 break-all">{String(v)}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Actions */}
            <div className="border-t border-gray-800 pt-3">
              <div className="text-xs text-gray-500 mb-2">Actions taken</div>
              <div className="flex flex-wrap gap-1.5">
                {(selected.actions||[]).map(a => (
                  <span key={a} className="text-xs bg-gray-800 border border-gray-700
                    px-2 py-0.5 rounded-full text-gray-400 capitalize">
                    {a.replace(/_/g,' ')}
                  </span>
                ))}
              </div>
            </div>

            <div className="text-xs text-gray-600">
              {selected.timestamp?.replace('T',' ').replace('Z',' UTC')}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
