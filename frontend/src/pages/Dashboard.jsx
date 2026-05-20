import { useState, useEffect, useRef } from 'react';
import { api } from '../api';

const POLL_MS = 3000;

// ── Shared ────────────────────────────────────────────────────────────────────

function Badge({ status }) {
  return <span className={`badge ${status}`}>{status}</span>;
}

/** Poll a list of jobs, updating state when results arrive. */
function usePoll(jobs, setJobs) {
  const jobsRef = useRef(jobs);
  jobsRef.current = jobs;

  useEffect(() => {
    const pending = jobs.filter(j => j.status === 'pending' || j.status === 'processing');
    if (!pending.length) return;

    const t = setTimeout(async () => {
      const settled = await Promise.allSettled(
        pending.map(j => api.getJob(j.id).then(r => ({ ...r, _localId: j.id })))
      );
      setJobs(prev =>
        prev.map(j => {
          const hit = settled.find(
            s => s.status === 'fulfilled' && s.value._localId === j.id
          );
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
  const [ipInput, setIpInput]     = useState('');
  const [jobs, setJobs]           = useState([]);
  const [expanded, setExpanded]   = useState(null);
  const [error, setError]         = useState('');
  const [loading, setLoading]     = useState(false);

  usePoll(jobs, setJobs);

  const submit = async () => {
    const ips = ipInput.split('\n').map(s => s.trim()).filter(Boolean);
    if (!ips.length)   return setError('Enter at least one IP address');
    if (ips.length > 256) return setError('Maximum 256 IPs per request');
    setError('');
    setLoading(true);
    try {
      const res = await api.submitUsecase1(ips);
      setJobs(prev => [{ id: res.job_id, status: 'pending', result: null, ips }, ...prev]);
      setIpInput('');
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <p className="hint">Submit up to 256 IPv4 addresses. Each bit in the Uint256 result indicates a match.</p>

      <textarea
        rows={6}
        placeholder={'1.2.3.4\n5.6.7.8\n...'}
        value={ipInput}
        onChange={e => setIpInput(e.target.value)}
      />
      <button onClick={submit} disabled={loading}>
        {loading ? 'encrypting & submitting...' : 'submit'}
      </button>
      {error && <div className="error">{error}</div>}

      {jobs.length > 0 && (
        <table className="jobs-table">
          <thead>
            <tr>
              <th>job id</th>
              <th>ips</th>
              <th>status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {jobs.map(j => (
              <>
                <tr key={j.id}>
                  <td style={{ color: '#444', fontSize: 11 }}>{j.id.slice(0, 8)}…</td>
                  <td>{j.ips.length}</td>
                  <td><Badge status={j.status} /></td>
                  <td>
                    {j.status === 'done' && (
                      <button
                        className="result-toggle"
                        onClick={() => setExpanded(expanded === j.id ? null : j.id)}
                      >
                        {expanded === j.id ? 'hide' : 'results'}
                      </button>
                    )}
                    {j.status === 'error' && (
                      <span style={{ color: '#8a4a4a', fontSize: 11 }}>{j.error}</span>
                    )}
                  </td>
                </tr>
                {expanded === j.id && j.result && (
                  <tr key={`${j.id}-detail`}>
                    <td colSpan={4} style={{ padding: 0 }}>
                      <div className="result-detail">
                        {j.result.data.map(r => (
                          <div key={r.ip} className="ip-row">
                            <span>{r.ip}</span>
                            <span className={r.matched ? 'matched' : 'unmatched'}>
                              {r.matched ? 'match' : 'no match'}
                            </span>
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

// ── Usecase 2 ─────────────────────────────────────────────────────────────────

function Usecase2Panel() {
  const [hash, setHash]       = useState('');
  const [jobs, setJobs]       = useState([]);
  const [error, setError]     = useState('');
  const [loading, setLoading] = useState(false);

  usePoll(jobs, setJobs);

  const submit = async () => {
    const h = hash.trim();
    if (!h) return setError('Enter a file hash');
    setError('');
    setLoading(true);
    try {
      const res = await api.submitUsecase2(h);
      setJobs(prev => [{ id: res.job_id, status: 'pending', result: null, hash: h }, ...prev]);
      setHash('');
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <p className="hint">Submit a 32-byte file hash (64 hex chars, 0x prefix optional). Returns found / not found.</p>

      <input
        type="text"
        placeholder="0xdeadbeef… (64 hex chars)"
        value={hash}
        onChange={e => setHash(e.target.value)}
        onKeyDown={e => e.key === 'Enter' && submit()}
      />
      <button onClick={submit} disabled={loading}>
        {loading ? 'encrypting & submitting...' : 'submit'}
      </button>
      {error && <div className="error">{error}</div>}

      {jobs.length > 0 && (
        <table className="jobs-table">
          <thead>
            <tr>
              <th>job id</th>
              <th>hash</th>
              <th>status</th>
              <th>result</th>
            </tr>
          </thead>
          <tbody>
            {jobs.map(j => (
              <tr key={j.id}>
                <td style={{ color: '#444', fontSize: 11 }}>{j.id.slice(0, 8)}…</td>
                <td style={{ color: '#444', fontSize: 11 }}>{j.hash.replace(/^0x/, '').slice(0, 12)}…</td>
                <td><Badge status={j.status} /></td>
                <td>
                  {j.status === 'done' && j.result != null && (
                    <span className={j.result.data ? 'matched' : 'unmatched'}>
                      {j.result.data ? 'found' : 'not found'}
                    </span>
                  )}
                  {j.status === 'error' && (
                    <span style={{ color: '#8a4a4a', fontSize: 11 }}>{j.error}</span>
                  )}
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

export default function Dashboard({ onLogout }) {
  const [tab, setTab] = useState('usecase1');

  return (
    <div className="page">
      <div className="nav">
        <span className="nav-title">KMS Gateway</span>
        <button onClick={onLogout}>logout</button>
      </div>

      <div className="tabs">
        <button
          className={`tab${tab === 'usecase1' ? ' active' : ''}`}
          onClick={() => setTab('usecase1')}
        >
          usecase1 — ip lookup
        </button>
        <button
          className={`tab${tab === 'usecase2' ? ' active' : ''}`}
          onClick={() => setTab('usecase2')}
        >
          usecase2 — file hash
        </button>
      </div>

      <div className="tab-body">
        {tab === 'usecase1' ? <Usecase1Panel /> : <Usecase2Panel />}
      </div>
    </div>
  );
}
