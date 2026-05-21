import { useState, useEffect, useRef } from 'react';
import { api } from '../api';

const POLL_MS = 3000;

// ── Shared ────────────────────────────────────────────────────────────────────

function Badge({ status }) {
  return <span className={`badge ${status}`}>{status}</span>;
}

function usePoll(jobs, setJobs) {
  useEffect(() => {
    const pending = jobs.filter(j => j.status === 'pending' || j.status === 'processing');
    if (!pending.length) return;
    const t = setTimeout(async () => {
      const settled = await Promise.allSettled(
        pending.map(j => api.getJob(j.id).then(r => ({ ...r, _localId: j.id })))
      );
      setJobs(prev =>
        prev.map(j => {
          const hit = settled.find(s => s.status === 'fulfilled' && s.value._localId === j.id);
          if (!hit) return j;
          const v = hit.value;
          return { ...j, status: v.status, result: v.result, error: v.error };
        })
      );
    }, POLL_MS);
    return () => clearTimeout(t);
  }, [jobs, setJobs]);
}

// ── Usecase 1 ─────────────────────────────────────────────────────────────────

function Usecase1Panel() {
  const [ipInput, setIpInput] = useState('');
  const [jobs, setJobs] = useState([]);
  const [expanded, setExpanded] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  usePoll(jobs, setJobs);

  const submit = async () => {
    const ips = ipInput.split('\n').map(s => s.trim()).filter(Boolean);
    if (!ips.length) return setError('Enter at least one IP address');
    if (ips.length > 256) return setError('Maximum 256 IPs per request');
    setError('');
    setLoading(true);
    try {
      const res = await api.submitUsecase1(ips);
      setJobs(prev => [{ id: res.job_id, status: 'pending', result: null, ips }, ...prev]);
      setIpInput('');
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div>
      <p className="hint">Submit up to 256 IPv4 addresses. Each bit in the Uint256 result indicates a match.</p>
      <textarea rows={6} placeholder={'1.2.3.4\n5.6.7.8\n...'} value={ipInput} onChange={e => setIpInput(e.target.value)} />
      <button onClick={submit} disabled={loading}>{loading ? 'encrypting & submitting...' : 'submit'}</button>
      {error && <div className="error">{error}</div>}
      {jobs.length > 0 && (
        <table className="jobs-table">
          <thead><tr><th>job id</th><th>ips</th><th>status</th><th></th></tr></thead>
          <tbody>
            {jobs.map(j => (
              <>
                <tr key={j.id}>
                  <td style={{ color: '#444', fontSize: 11 }}>{j.id.slice(0, 8)}…</td>
                  <td>{j.ips.length}</td>
                  <td><Badge status={j.status} /></td>
                  <td>
                    {j.status === 'done' && (
                      <button className="result-toggle" onClick={() => setExpanded(expanded === j.id ? null : j.id)}>
                        {expanded === j.id ? 'hide' : 'results'}
                      </button>
                    )}
                    {j.status === 'error' && <span style={{ color: '#8a4a4a', fontSize: 11 }}>{j.error}</span>}
                  </td>
                </tr>
                {expanded === j.id && j.result && (
                  <tr key={`${j.id}-d`}>
                    <td colSpan={4} style={{ padding: 0 }}>
                      <div className="result-detail">
                        {j.result.data.map(r => (
                          <div key={r.ip} className="ip-row">
                            <span>{r.ip}</span>
                            <span className={r.matched ? 'matched' : 'unmatched'}>{r.matched ? 'match' : 'no match'}</span>
                          </div>
                        ))}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ── Shared hash-lookup panel (usecase2 + usecase3) ────────────────────────────

function HashLookupPanel({ submitFn, hint, placeholder }) {
  const [input, setInput] = useState('');
  const [jobs, setJobs] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  usePoll(jobs, setJobs);

  const submit = async () => {
    const val = input.trim();
    if (!val) return setError('Enter a value');
    setError('');
    setLoading(true);
    try {
      const res = await submitFn(val);
      setJobs(prev => [{ id: res.job_id, status: 'pending', result: null, label: val }, ...prev]);
      setInput('');
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div>
      <p className="hint">{hint}</p>
      <input type="text" placeholder={placeholder} value={input}
        onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && submit()} />
      <button onClick={submit} disabled={loading}>{loading ? 'encrypting & submitting...' : 'submit'}</button>
      {error && <div className="error">{error}</div>}
      {jobs.length > 0 && (
        <table className="jobs-table">
          <thead><tr><th>job id</th><th>input</th><th>status</th><th>result</th></tr></thead>
          <tbody>
            {jobs.map(j => (
              <tr key={j.id}>
                <td style={{ color: '#444', fontSize: 11 }}>{j.id.slice(0, 8)}…</td>
                <td style={{ color: '#666', fontSize: 11, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{j.label}</td>
                <td><Badge status={j.status} /></td>
                <td>
                  {j.status === 'done' && j.result != null && (
                    <span className={j.result.data ? 'matched' : 'unmatched'}>{j.result.data ? 'found' : 'not found'}</span>
                  )}
                  {j.status === 'error' && <span style={{ color: '#8a4a4a', fontSize: 11 }}>{j.error}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

async function sha256hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Usecase 4 ─────────────────────────────────────────────────────────────────

function Usecase4Panel() {
  const [input, setInput] = useState('');
  const [jobs, setJobs] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  usePoll(jobs, setJobs);

  const submit = async () => {
    const parts = input.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
    if (!parts.length) return setError('Enter at least one number');

    const values = [];
    for (const p of parts) {
      const n = BigInt(p);
      if (n < 0n || n > 18446744073709551615n) return setError(`Out of u64 range: ${p}`);
      values.push(Number(n)); // JSON doesn't support BigInt; safe for values < 2^53
    }

    setError('');
    setLoading(true);
    try {
      const res = await api.submitUsecase4(values);
      setJobs(prev => [{ id: res.job_id, status: 'pending', result: null, label: parts.join(', ') }, ...prev]);
      setInput('');
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div>
      <p className="hint">Space or comma-separated u64 integers. Result is a single u64 displayed as a float (4 decimal places).</p>
      <input type="text" placeholder="100 200 300  or  100,200,300" value={input}
        onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && submit()} />
      <button onClick={submit} disabled={loading}>{loading ? 'encrypting & submitting...' : 'submit'}</button>
      {error && <div className="error">{error}</div>}
      {jobs.length > 0 && (
        <table className="jobs-table">
          <thead><tr><th>job id</th><th>inputs</th><th>status</th><th>result</th></tr></thead>
          <tbody>
            {jobs.map(j => (
              <tr key={j.id}>
                <td style={{ color: '#444', fontSize: 11 }}>{j.id.slice(0, 8)}…</td>
                <td style={{ color: '#666', fontSize: 11, maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{j.label}</td>
                <td><Badge status={j.status} /></td>
                <td>
                  {j.status === 'done' && j.result != null && (
                    <span className="matched" style={{ fontVariantNumeric: 'tabular-nums' }}>
                      {(Number(j.result.data) / 10000).toFixed(4)}
                    </span>
                  )}
                  {j.status === 'error' && <span style={{ color: '#8a4a4a', fontSize: 11 }}>{j.error}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

const TABS = [
  { id: 'usecase1', label: 'usecase1 — ip lookup' },
  { id: 'usecase2', label: 'usecase2 — file hash' },
  { id: 'usecase3', label: 'usecase3 — string lookup' },
  { id: 'usecase4', label: 'usecase4 — u64 list' },
];

export default function Dashboard({ onLogout }) {
  const [tab, setTab] = useState('usecase1');

  return (
    <div className="page">
      <div className="nav">
        <span className="nav-title">KMS Gateway</span>
        <button onClick={onLogout}>logout</button>
      </div>

      <div className="tabs">
        {TABS.map(t => (
          <button key={t.id} className={`tab${tab === t.id ? ' active' : ''}`} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      <div className="tab-body">
        {tab === 'usecase1' && <Usecase1Panel />}
        {tab === 'usecase2' && (
          <HashLookupPanel
            submitFn={hash => api.submitUsecase2(hash)}
            hint="Submit a 32-byte file hash (64 hex chars, 0x prefix optional). Returns found / not found."
            placeholder="0xdeadbeef… (64 hex chars)"
          />
        )}
        {tab === 'usecase3' && (
          <HashLookupPanel
            submitFn={async str => { const hash = await sha256hex(str); return api.submitUsecase3(hash); }}
            hint="Submit any string. The browser hashes it with SHA-256 before sending. Returns found / not found."
            placeholder="any string…"
          />
        )}
        {tab === 'usecase4' && <Usecase4Panel />}
      </div>
    </div>
  );
}
