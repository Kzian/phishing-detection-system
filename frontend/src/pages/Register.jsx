import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { register } from '../api'
import { useAuth } from '../App'

const ROLES = ['doctor','nurse','admin','it']
const DEPTS = ['Emergency','Cardiology','Paediatrics','Surgery','Radiology',
               'Pharmacy','Administration','IT & Systems','Laboratory','Nursing']

export default function Register() {
  const { signIn } = useAuth()
  const navigate   = useNavigate()
  const [form, setForm]     = useState({ name:'', email:'', password:'', role:'', department:'' })
  const [error, setError]   = useState('')
  const [loading, setLoading] = useState(false)

  function handle(e) { setForm(f => ({ ...f, [e.target.name]: e.target.value })) }

  async function submit(e) {
    e.preventDefault()
    setError(''); setLoading(true)
    try {
      const data = await register(form)
      signIn(data.access_token, data.user)
      navigate('/dashboard')
    } catch(err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-[calc(100vh-57px)] flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="w-14 h-14 bg-blue-600 rounded-2xl flex items-center
            justify-center text-3xl mx-auto mb-4">🛡</div>
          <h1 className="text-2xl font-bold">Create staff account</h1>
          <p className="text-gray-400 text-sm mt-1">
            PhishGuard AI — Healthcare Security Portal
          </p>
        </div>

        <form onSubmit={submit} className="card space-y-4">
          <div>
            <label className="text-xs text-gray-400 block mb-1">Full name</label>
            <input name="name" value={form.name} onChange={handle}
              placeholder="Dr. Amina Bello" required />
          </div>

          <div>
            <label className="text-xs text-gray-400 block mb-1">Work email</label>
            <input name="email" type="email" value={form.email} onChange={handle}
              placeholder="amina.bello@hospital.gov.ng" required />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-gray-400 block mb-1">Role</label>
              <select name="role" value={form.role} onChange={handle} required
                className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2
                           text-sm w-full focus:outline-none focus:border-blue-500">
                <option value="">Select role</option>
                {ROLES.map(r => <option key={r} value={r} className="capitalize">{r.charAt(0).toUpperCase()+r.slice(1)}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Department</label>
              <select name="department" value={form.department} onChange={handle}
                className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2
                           text-sm w-full focus:outline-none focus:border-blue-500">
                <option value="">Select dept.</option>
                {DEPTS.map(d => <option key={d} value={d}>{d}</option>)}
              </select>
            </div>
          </div>

          <div>
            <label className="text-xs text-gray-400 block mb-1">Password</label>
            <input name="password" type="password" value={form.password}
              onChange={handle} placeholder="Min. 8 characters" required minLength={8} />
          </div>

          {error && (
            <div className="bg-red-950 border border-red-800 rounded-lg p-3
              text-red-400 text-sm">{error}</div>
          )}

          <button type="submit" disabled={loading} className="btn-primary w-full py-2.5">
            {loading ? 'Creating account...' : 'Create account'}
          </button>

          <p className="text-center text-sm text-gray-500">
            Already registered?{' '}
            <Link to="/login" className="text-blue-400 hover:underline">Sign in</Link>
          </p>
        </form>
      </div>
    </div>
  )
}
