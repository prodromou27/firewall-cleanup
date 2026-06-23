import { useState } from 'react'
import { Eye, Lock, AlertCircle, Loader2 } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import logoImg from '../assets/logo-onlight.png'

export function Login() {
  const { login } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await login(email.trim(), password)
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status
      setError(
        status === 401
          ? 'Invalid email or password.'
          : 'Unable to sign in. Please try again.'
      )
      setSubmitting(false)
    }
  }

  return (
    <div className="auth-shell flex items-center justify-center">
      <div className="w-full max-w-sm">
        {/* Brand */}
        <div className="flex flex-col items-center mb-8">
          <div className="auth-brand">
            <img src={logoImg} alt="PolicyInsight" className="h-9 w-auto object-contain" />
          </div>
          <div className="security-mode-pill">
            <Eye className="w-3.5 h-3.5 text-emerald-400" />
            <span>Read-only firewall audit</span>
          </div>
        </div>

        {/* Card */}
        <form
          onSubmit={onSubmit}
          className="auth-card space-y-4"
        >
          <div>
            <h1 className="text-lg font-bold text-white">Sign in</h1>
            <p className="text-xs text-slate-400 mt-0.5">Enter your credentials to continue.</p>
          </div>

          {error && (
            <div className="flex items-start gap-2 bg-red-500/10 border border-red-500/25 rounded-lg px-3 py-2">
              <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
              <span className="text-xs text-red-300">{error}</span>
            </div>
          )}

          <div className="space-y-1.5">
            <label htmlFor="email" className="text-xs font-medium text-slate-300">Email</label>
            <input
              id="email"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={e => setEmail(e.target.value)}
              className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400"
              placeholder="you@example.com"
            />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="password" className="text-xs font-medium text-slate-300">Password</label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={e => setPassword(e.target.value)}
              className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400"
              placeholder="Password"
            />
          </div>

          <button
            type="submit"
            disabled={submitting || !email || !password}
            className="w-full flex items-center justify-center gap-2 bg-brand-gradient hover:brightness-110 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-lg py-2.5 transition"
          >
            {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />}
            {submitting ? 'Signing in...' : 'Sign in'}
          </button>
        </form>

        <p className="text-center text-[11px] text-slate-600 mt-6">
          PolicyInsight v2.1.0 - Sessions expire automatically for security.
        </p>
      </div>
    </div>
  )
}
