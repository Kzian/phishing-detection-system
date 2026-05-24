import React from 'react'

const MAP = {
  CRITICAL: 'badge-critical', HIGH: 'badge-high',
  MEDIUM:   'badge-medium',   LOW:  'badge-low', CLEAN: 'badge-clean',
}

export default function SeverityBadge({ severity }) {
  return (
    <span className={`text-xs font-medium px-2.5 py-0.5 rounded-full border ${MAP[severity] || 'badge-low'}`}>
      {severity}
    </span>
  )
}
