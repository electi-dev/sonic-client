import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]     = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    setError('');
    setLoading(true);
    try {
      const res = await api.login(username.trim(), password);
      onLogin(res.session_id);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="box">
        <h2>Login</h2>
        <input
          type="text"
          placeholder="username"
          value={username}
          onChange={e => setUsername(e.target.value)}
          autoFocus
        />
        <input
          type="password"
          placeholder="password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && submit()}
        />
        <button onClick={submit} disabled={loading}>
          {loading ? 'logging in...' : 'login'}
        </button>
        {error && <div className="error">{error}</div>}
      </div>
      <div className="auth-footer">
        <Link to="/register">register</Link>
      </div>
    </div>
  );
}
