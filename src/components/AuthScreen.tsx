import React, { useEffect, useState } from 'react';
import { ShieldCheck, Lock, ArrowRight } from 'lucide-react';
import { apiRequest, setAuthToken } from '../api/client';
import type { UserSession } from '../types/sentinel';

interface AuthScreenProps {
  onAuthenticated: (user: UserSession) => void;
}

export const AuthScreen: React.FC<AuthScreenProps> = ({ onAuthenticated }) => {
  const [mode, setMode] = useState<'login' | 'register'>('register');
  const [initialized, setInitialized] = useState<boolean | null>(null);
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [organizationName, setOrganizationName] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiRequest<{ initialized: boolean }>('/auth/status')
      .then((res) => {
        setInitialized(res.initialized);
        if (res.initialized) setMode('login');
      })
      .catch(() => {
        setInitialized(false);
      });
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      if (mode === 'register') {
        const res = await apiRequest<{ token: string; user: UserSession }>('/auth/register', {
          method: 'POST',
          body: JSON.stringify({ email, fullName, organizationName, password }),
        });
        setAuthToken(res.token);
        onAuthenticated(res.user);
      } else {
        const res = await apiRequest<{ token: string; user: UserSession }>('/auth/login', {
          method: 'POST',
          body: JSON.stringify({ email, password }),
        });
        setAuthToken(res.token);
        onAuthenticated(res.user);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#090D16] flex items-center justify-center p-6">
      <div className="w-full max-w-4xl grid grid-cols-1 lg:grid-cols-12 border border-slate-800 bg-[#0F172A] rounded-lg overflow-hidden">
        {/* Left Briefing Panel */}
        <div className="lg:col-span-5 p-8 border-b lg:border-b-0 lg:border-r border-slate-800 bg-[#0B1220] flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2.5 text-slate-100 font-semibold text-lg tracking-tight">
              <ShieldCheck className="w-5 h-5 text-blue-500" aria-hidden="true" />
              <span>SentinelScan</span>
            </div>
            <h1 className="mt-6 text-2xl font-semibold text-slate-100 leading-snug text-balance">
              Web Application Security Assessment Platform
            </h1>
            <p className="mt-3 text-sm text-slate-400 leading-relaxed">
              Authorize target ownership, run modular TLS, header, API, SCA, and SAST assessments, and generate evidence-backed reports.
            </p>
          </div>

          <div className="mt-8 pt-6 border-t border-slate-800/80 space-y-3 text-xs text-slate-400">
            <div className="flex items-start gap-2.5">
              <Lock className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" aria-hidden="true" />
              <span>SSRF-isolated outbound verification with mandatory ownership checks before active testing.</span>
            </div>
            <div className="flex items-start gap-2.5">
              <ShieldCheck className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" aria-hidden="true" />
              <span>Tenant-isolated SQLite workspace with scrypt password hashing and AES-256-GCM credential vault.</span>
            </div>
          </div>
        </div>

        {/* Right Auth Form */}
        <div className="lg:col-span-7 p-8">
          <div className="flex items-center gap-1 p-1 bg-[#090D16] border border-slate-800 rounded-md w-fit">
            <button
              type="button"
              onClick={() => { setMode('register'); setError(null); }}
              className={`px-3.5 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap ${
                mode === 'register' ? 'bg-slate-800 text-slate-100' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {initialized === false ? 'Initialize Workspace Admin' : 'Create Organization'}
            </button>
            <button
              type="button"
              onClick={() => { setMode('login'); setError(null); }}
              className={`px-3.5 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap ${
                mode === 'login' ? 'bg-slate-800 text-slate-100' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Sign In
            </button>
          </div>

          <h2 className="mt-6 text-lg font-semibold text-slate-100">
            {mode === 'register'
              ? initialized === false
                ? 'Set Up First Administrator & Organization'
                : 'Create a New Organization Workspace'
              : 'Sign In to SentinelScan'}
          </h2>
          <p className="mt-1 text-xs text-slate-400">
            {mode === 'register'
              ? 'First user becomes the organization administrator with full assessment and RBAC permissions.'
              : 'Enter your organization credentials to access security assessments and reports.'}
          </p>

          {error && (
            <div role="alert" className="mt-4 px-3.5 py-2.5 text-xs text-red-300 bg-red-950/50 border border-red-800/60 rounded">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="mt-5 space-y-4">
            {mode === 'register' && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="auth-fullname" className="block text-xs font-medium text-slate-300 mb-1.5">
                    Full Name
                  </label>
                  <input
                    id="auth-fullname"
                    type="text"
                    required
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Alex Mercer"
                    className="w-full px-3 py-2 text-sm bg-[#090D16] border border-slate-700 rounded text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label htmlFor="auth-org" className="block text-xs font-medium text-slate-300 mb-1.5">
                    Organization Name
                  </label>
                  <input
                    id="auth-org"
                    type="text"
                    required
                    value={organizationName}
                    onChange={(e) => setOrganizationName(e.target.value)}
                    placeholder="Acme Security Group"
                    className="w-full px-3 py-2 text-sm bg-[#090D16] border border-slate-700 rounded text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>
            )}

            <div>
              <label htmlFor="auth-email" className="block text-xs font-medium text-slate-300 mb-1.5">
                Work Email
              </label>
              <input
                id="auth-email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="security@organization.com"
                className="w-full px-3 py-2 text-sm bg-[#090D16] border border-slate-700 rounded text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label htmlFor="auth-password" className="block text-xs font-medium text-slate-300 mb-1.5">
                Password
              </label>
              <input
                id="auth-password"
                type="password"
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Minimum 8 characters"
                className="w-full px-3 py-2 text-sm bg-[#090D16] border border-slate-700 rounded text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-2 flex items-center justify-center gap-2 px-4 py-2.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded transition-colors"
            >
              <span>{loading ? 'Authenticating...' : mode === 'register' ? 'Create Workspace & Continue' : 'Sign In'}</span>
              <ArrowRight className="w-4 h-4" aria-hidden="true" />
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
