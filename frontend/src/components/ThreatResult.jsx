import React from 'react'
import SeverityBadge from './SeverityBadge'

const BAR_COLOR = (score) => {
  if (score < 0.3)  return 'bg-green-500'
  if (score < 0.5)  return 'bg-blue-500'
  if (score < 0.7)  return 'bg-yellow-500'
  if (score < 0.85) return 'bg-orange-500'
  return 'bg-red-500'
}

export default function ThreatResult({ data }) {
  if (!data) return null
  const pct = Math.round((data.threat_score || 0) * 100)

  return (
    <div className="card mt-4 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs text-gray-500 mb-1">Incident ID</div>
          <div className="font-mono text-sm font-semibold">{data.incident_id}</div>
        </div>
        <SeverityBadge severity={data.severity} />
      </div>

      {/* Score bar */}
      <div>
        <div className="flex justify-between text-xs text-gray-400 mb-1">
          <span>Threat Score</span>
          <span className="font-medium text-white">{pct}%</span>
        </div>
        <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
          <div className={`h-full rounded-full transition-all duration-700 ${BAR_COLOR(data.threat_score)}`}
            style={{ width: `${pct}%` }} />
        </div>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-3 gap-3">
        {[
          ['Prediction', data.prediction],
          ['Confidence', data.confidence],
          ['Channel',    data.input_type],
        ].map(([label, val]) => (
          <div key={label} className="bg-gray-800 rounded-lg p-3">
            <div className="text-xs text-gray-500 mb-1">{label}</div>
            <div className="text-sm font-medium capitalize">{val}</div>
          </div>
        ))}
      </div>

      {/* Actions */}
      <div>
        <div className="text-xs text-gray-500 mb-2">Response Actions Triggered</div>
        <div className="flex flex-wrap gap-2">
          {(data.actions || []).map(a => (
            <span key={a} className="text-xs bg-gray-800 border border-gray-700
              px-2.5 py-1 rounded-full text-gray-300 capitalize">
              {a.replace(/_/g,' ')}
            </span>
          ))}
        </div>
      </div>

      {/* Sender analysis (email only) */}
      {data.sender_analysis && (
        <div className="border-t border-gray-800 pt-3">
          <div className="text-xs text-gray-500 mb-2">Sender Domain Analysis</div>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="bg-gray-800 rounded p-2">
              <span className="text-gray-500">Domain signal: </span>
              <span className="text-gray-200">{data.sender_analysis.domain_reason}</span>
            </div>
            <div className="bg-gray-800 rounded p-2">
              <span className="text-gray-500">SPF: </span>
              <span className="text-gray-200">{data.sender_analysis.spf_reason}</span>
            </div>
            <div className="bg-gray-800 rounded p-2">
              <span className="text-gray-500">Content score: </span>
              <span className="text-gray-200">
                {Math.round((data.sender_analysis.base_content_score || 0)*100)}%
              </span>
            </div>
            <div className="bg-gray-800 rounded p-2">
              <span className="text-gray-500">Adjustment: </span>
              <span className={data.sender_analysis.domain_adjustment < 0
                ? 'text-green-400' : data.sender_analysis.domain_adjustment > 0
                ? 'text-red-400' : 'text-gray-200'}>
                {data.sender_analysis.domain_adjustment > 0 ? '+' : ''}
                {Math.round((data.sender_analysis.domain_adjustment +
                  data.sender_analysis.spf_adjustment)*100)}%
              </span>
            </div>
          </div>
        </div>
      )}

      <div className="text-xs text-gray-600">{data.timestamp?.replace('T',' ').replace('Z',' UTC')}</div>
    </div>
  )
}
