import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';

export default function Register({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]     = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    setError('');
    setLoading(true);
    try {
      const res = await api.register(username.trim(), password);
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
        <h2>Register</h2>
        <p className="hint" style={{ marginBottom: 14 }}>
          FHE key generation runs on the server and takes 30–120s with default params.
        </p>
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
          {loading ? 'generating FHE keys & registering...' : 'register'}
        </button>
        {error && <div className="error">{error}</div>}
      </div>
      <div className="auth-footer">
        <Link to="/login">login</Link>
      </div>
    </div>
  );
}
