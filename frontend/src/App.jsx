import React, { createContext, useContext, useState, useEffect } from 'react'
import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom'
import Register  from './pages/Register'
import Login     from './pages/Login'
import Dashboard from './pages/Dashboard'
import MyIncidents from './pages/MyIncidents'
import NavBar    from './components/NavBar'

// ── Auth context ──────────────────────────────────────────────────────────────
export const AuthCtx = createContext(null)

export function useAuth() { return useContext(AuthCtx) }

function AuthProvider({ children }) {
  const [user,  setUser]  = useState(() => {
    try { return JSON.parse(localStorage.getItem('pg_user')) } catch { return null }
  })
  const [token, setToken] = useState(() => localStorage.getItem('pg_token') || null)

  function signIn(tokenStr, userObj) {
    setToken(tokenStr);  localStorage.setItem('pg_token', tokenStr)
    setUser(userObj);    localStorage.setItem('pg_user',  JSON.stringify(userObj))
  }

  function signOut() {
    setToken(null); setUser(null)
    localStorage.removeItem('pg_token')
    localStorage.removeItem('pg_user')
  }

  return (
    <AuthCtx.Provider value={{ user, token, signIn, signOut, isAuth: !!token }}>
      {children}
    </AuthCtx.Provider>
  )
}

function Protected({ children }) {
  const { isAuth } = useAuth()
  const loc = useLocation()
  if (!isAuth) return <Navigate to="/login" state={{ from: loc }} replace />
  return children
}

export default function App() {
  return (
    <AuthProvider>
      <div className="min-h-screen flex flex-col">
        <NavBar />
        <main className="flex-1">
          <Routes>
            <Route path="/"         element={<Navigate to="/dashboard" replace />} />
            <Route path="/register" element={<Register />} />
            <Route path="/login"    element={<Login />} />
            <Route path="/dashboard" element={
              <Protected><Dashboard /></Protected>
            } />
            <Route path="/my-incidents" element={
              <Protected><MyIncidents /></Protected>
            } />
          </Routes>
        </main>
      </div>
    </AuthProvider>
  )
}
