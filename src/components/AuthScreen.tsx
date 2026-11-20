import React, { useEffect, useState } from 'react';
import { ShieldCheck, Lock, ArrowRight, CheckCircle2 } from 'lucide-react';
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
    <div className="min-h-screen bg-[#F8FAFC] flex items-center justify-center p-4 sm:p-6">
      <div className="w-full max-w-4xl grid grid-cols-1 lg:grid-cols-12 border border-[#E2E8F0] bg-[#FFFFFF] rounded-xl shadow-sm overflow-hidden">
        {/* Left Enterprise Briefing Panel */}
        <div className="lg:col-span-5 p-8 bg-[#1E40AF] text-white flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2.5 font-semibold text-lg tracking-tight">
              <div className="w-8 h-8 rounded-lg bg-white/15 border border-white/25 flex items-center justify-center">
                <ShieldCheck className="w-4 h-4 text-white" aria-hidden="true" />
              </div>
              <span>SentinelScan</span>
            </div>

            <h1 className="mt-7 text-2xl font-semibold leading-snug tracking-tight text-balance">
              Web Application Security Assessment &amp; Vulnerability Intelligence
            </h1>
            <p className="mt-3 text-sm text-blue-100/90 leading-relaxed">
              Authorize target scope, execute evidence-based OWASP, API, SCA, and SAST assessments, and deliver verifiable security reports.
            </p>

            <ul className="mt-7 space-y-3 text-xs text-blue-50">
              <li className="flex items-start gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-blue-200 shrink-0 mt-0.5" aria-hidden="true" />
                <span>Controlled recursive attack-surface discovery &amp; non-destructive OWASP probes.</span>
              </li>
              <li className="flex items-start gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-blue-200 shrink-0 mt-0.5" aria-hidden="true" />
                <span>Multi-role authenticated testing, OpenAPI validation, OSV SCA &amp; SAST analysis.</span>
              </li>
              <li className="flex items-start gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-blue-200 shrink-0 mt-0.5" aria-hidden="true" />
                <span>Executive PDF, scoped CSV, and SIEM-ready JSON assessment exports.</span>
              </li>
            </ul>
          </div>

          <div className="mt-8 pt-6 border-t border-white/15 space-y-2.5 text-xs text-blue-100/85">
            <div className="flex items-start gap-2.5">
              <Lock className="w-4 h-4 text-blue-200 shrink-0 mt-0.5" aria-hidden="true" />
              <span>SSRF-isolated outbound verification with AES-256-GCM credential vault and tenant isolation.</span>
            </div>
          </div>
        </div>

        {/* Right Auth Form */}
        <div className="lg:col-span-7 p-6 sm:p-9 flex flex-col justify-center">
          <div className="inline-flex items-center gap-1 p-1 bg-[#F1F5F9] border border-[#E2E8F0] rounded-lg w-fit">
            <button
              type="button"
              onClick={() => {
                setMode('register');
                setError(null);
              }}
              className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                mode === 'register'
                  ? 'bg-[#FFFFFF] text-[#0F172A] shadow-xs border border-[#E2E8F0]'
                  : 'text-[#64748B] hover:text-[#0F172A]'
              }`}
            >
              {initialized === false ? 'Initialize Workspace Admin' : 'Create Organization'}
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('login');
                setError(null);
              }}
              className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                mode === 'login'
                  ? 'bg-[#FFFFFF] text-[#0F172A] shadow-xs border border-[#E2E8F0]'
                  : 'text-[#64748B] hover:text-[#0F172A]'
              }`}
            >
              Sign In
            </button>
          </div>

          <h2 className="mt-6 text-xl font-semibold text-[#0F172A] tracking-tight">
            {mode === 'register'
              ? initialized === false
                ? 'Set Up First Administrator & Organization'
                : 'Create a New Organization Workspace'
              : 'Sign In to SentinelScan'}
          </h2>
          <p className="mt-1 text-xs text-[#64748B] leading-relaxed">
            {mode === 'register'
              ? 'First user becomes the organization administrator with full assessment and RBAC permissions.'
              : 'Enter your organization credentials to access security assessments and reports.'}
          </p>

          {error && (
            <div
              role="alert"
              className="mt-4 px-3.5 py-2.5 text-xs text-[#B91C1C] bg-[#FEF2F2] border border-[#FECACA] rounded-md"
            >
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="mt-5 space-y-4">
            {mode === 'register' && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="auth-fullname" className="block text-xs font-medium text-[#334155] mb-1.5">
                    Full Name
                  </label>
                  <input
                    id="auth-fullname"
                    type="text"
                    required
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Alex Mercer"
                    className="w-full px-3 py-2 text-sm bg-[#FFFFFF] border border-[#CBD5E1] rounded-md text-[#0F172A] placeholder-[#94A3B8] focus:outline-none focus:border-[#2563EB] focus:ring-2 focus:ring-[#2563EB]/15"
                  />
                </div>
                <div>
                  <label htmlFor="auth-org" className="block text-xs font-medium text-[#334155] mb-1.5">
                    Organization Name
                  </label>
                  <input
                    id="auth-org"
                    type="text"
                    required
                    value={organizationName}
                    onChange={(e) => setOrganizationName(e.target.value)}
                    placeholder="Acme Security Group"
                    className="w-full px-3 py-2 text-sm bg-[#FFFFFF] border border-[#CBD5E1] rounded-md text-[#0F172A] placeholder-[#94A3B8] focus:outline-none focus:border-[#2563EB] focus:ring-2 focus:ring-[#2563EB]/15"
                  />
                </div>
              </div>
            )}

            <div>
              <label htmlFor="auth-email" className="block text-xs font-medium text-[#334155] mb-1.5">
                Work Email
              </label>
              <input
                id="auth-email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="security@organization.com"
                className="w-full px-3 py-2 text-sm bg-[#FFFFFF] border border-[#CBD5E1] rounded-md text-[#0F172A] placeholder-[#94A3B8] focus:outline-none focus:border-[#2563EB] focus:ring-2 focus:ring-[#2563EB]/15"
              />
            </div>

            <div>
              <label htmlFor="auth-password" className="block text-xs font-medium text-[#334155] mb-1.5">
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
                className="w-full px-3 py-2 text-sm bg-[#FFFFFF] border border-[#CBD5E1] rounded-md text-[#0F172A] placeholder-[#94A3B8] focus:outline-none focus:border-[#2563EB] focus:ring-2 focus:ring-[#2563EB]/15"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-2 flex items-center justify-center gap-2 px-4 py-2.5 text-sm font-medium text-white bg-[#2563EB] hover:bg-[#1D4ED8] disabled:opacity-50 rounded-md transition-colors shadow-xs"
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
