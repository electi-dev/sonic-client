const BASE = '/api';
let sessionId = localStorage.getItem('session_id');

async function req(method, path, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (sessionId) headers['X-Session-Id'] = sessionId;

  const res = await fetch(BASE + path, {
    method,
    headers,
    body: body != null ? JSON.stringify(body) : undefined,
  });

  let data = null;
  try { data = await res.json(); } catch (_) { }

  if (!res.ok) {
    throw new Error(data?.error ?? `HTTP ${res.status}`);
  }
  return data;
}

export const api = {
  register: (u, p) => req('POST', '/auth/register', { username: u, password: p }),
  login: (u, p) => req('POST', '/auth/login', { username: u, password: p }),
  logout: () => req('POST', '/auth/logout'),
  submitUsecase1: (ips) => req('POST', '/jobs/usecase1', { ips }),
  submitUsecase2: (hash) => req('POST', '/jobs/usecase2', { hash }),
  submitUsecase3: (hash) => req('POST', '/jobs/usecase3', { hash }),
  submitUsecase4: (values) => req('POST', '/jobs/usecase4', { values }),
  getJob: (id) => req('GET', `/jobs/${id}`),

  setSession: (id) => { sessionId = id; localStorage.setItem('session_id', id); },
  clearSession: () => { sessionId = null; localStorage.removeItem('session_id'); },
  hasSession: () => Boolean(sessionId),
};
