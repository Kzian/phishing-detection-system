import React from 'react'
import { Link, useNavigate, useLocation } from 'react-router-dom'
import { useAuth } from '../App'

const ROLE_COLORS = {
  doctor: 'text-blue-400', nurse: 'text-green-400',
  admin: 'text-purple-400', it: 'text-orange-400',
}

export default function NavBar() {
  const { user, isAuth, signOut } = useAuth()
  const navigate = useNavigate()
  const { pathname } = useLocation()

  const navLink = (to, label) => (
    <Link to={to} className={`text-sm px-3 py-1.5 rounded-lg transition ${
      pathname === to ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white hover:bg-gray-800'
    }`}>{label}</Link>
  )

  return (
    <nav className="border-b border-gray-800 bg-gray-950 px-6 py-3 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center text-lg">🛡</div>
        <div>
          <div className="text-sm font-semibold leading-tight">PhishGuard AI</div>
          <div className="text-xs text-gray-500 leading-tight">Healthcare Security</div>
        </div>
      </div>
      {isAuth && (
        <div className="flex items-center gap-1">
          {navLink('/dashboard',    '⚡ Analyze')}
          {navLink('/my-incidents', '📋 My Incidents')}
        </div>
      )}
      <div className="flex items-center gap-3">
        {isAuth ? (
          <>
            <div className="text-right hidden sm:block">
              <div className="text-sm font-medium">{user?.name}</div>
              <div className={`text-xs capitalize ${ROLE_COLORS[user?.role] || 'text-gray-400'}`}>
                {user?.role}{user?.department ? ` · ${user.department}` : ''}
              </div>
            </div>
            <button onClick={() => { signOut(); navigate('/login') }}
              className="btn-ghost text-xs px-3 py-1.5">Sign out</button>
          </>
        ) : (
          <div className="flex gap-2">
            <Link to="/login"    className="btn-ghost text-xs px-3 py-1.5">Sign in</Link>
            <Link to="/register" className="btn-primary text-xs px-3 py-1.5">Register</Link>
          </div>
        )}
      </div>
    </nav>
  )
}
