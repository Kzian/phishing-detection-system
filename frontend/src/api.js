/**
 * PhishGuard AI — API client
 * All requests go to FastAPI on localhost:8000 (proxied via Vite)
 */

const BASE = '/api'

function authHeaders() {
  const token = localStorage.getItem('pg_token')
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function request(method, path, body = null) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
  }
  if (body) opts.body = JSON.stringify(body)
  const res  = await fetch(BASE + path, opts)
  const data = await res.json()
  if (!res.ok) throw new Error(data.detail || 'Request failed')
  return data
}

// Auth
export const register = (payload) =>
  request('POST', '/auth/register', payload)

export const login = (email, password) =>
  fetch(BASE + '/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: email, password }),
  }).then(async r => {
    const d = await r.json()
    if (!r.ok) throw new Error(d.detail || 'Login failed')
    return d
  })

export const getMe = () => request('GET', '/auth/me')

// Analysis
export const analyzeUrl   = (url)                    => request('POST', '/analyze/url',   { url })
export const analyzeEmail = (subject, body, sender, recipient) =>
  request('POST', '/analyze/email', { subject, body, sender, recipient })
export const analyzeSms   = (message, sender_number, recipient) =>
  request('POST', '/analyze/sms',   { message, sender_number, recipient })

// Incidents
export const getIncidents    = (params = '') => request('GET', `/incidents?limit=50${params}`)
export const getMyIncidents  = ()            => request('GET', '/my/incidents')
export const getStats        = ()            => request('GET', '/incidents/stats/summary')
export const getHealth       = ()            => request('GET', '/health')
