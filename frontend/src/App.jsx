import { useState } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import { api } from './api';

export default function App() {
  const [authed, setAuthed] = useState(api.hasSession());

  const onLogin = (sessionId) => {
    api.setSession(sessionId);
    setAuthed(true);
  };

  const onLogout = () => {
    api.logout().catch(() => {});
    api.clearSession();
    setAuthed(false);
  };

  return (
    <Routes>
      <Route path="/login"    element={authed ? <Navigate to="/" replace /> : <Login    onLogin={onLogin} />} />
      <Route path="/register" element={authed ? <Navigate to="/" replace /> : <Register onLogin={onLogin} />} />
      <Route path="/"         element={authed ? <Dashboard onLogout={onLogout} /> : <Navigate to="/login" replace />} />
    </Routes>
  );
}
