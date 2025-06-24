import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import LoginPage from './LoginPage';
import Dashboard from './Dashboard';
import AdminAudit from './AdminAudit';
import UserProfile from './UserProfile';
import Register from './Register'; // ✅ Add this import
import './i18n';

function App() {
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'light');

  useEffect(() => {
    document.body.className = theme;
    localStorage.setItem('theme', theme);
  }, [theme]);

  return (
    <Router>
      <Routes>
        <Route path="/" element={<LoginPage setTheme={setTheme} theme={theme} />} />
        <Route path="/register" element={<Register />} /> {/* ✅ Add this route */}
        <Route path="/dashboard" element={<Dashboard setTheme={setTheme} theme={theme} />} />
        <Route path="/admin/audit" element={<AdminAudit />} />
        <Route path="/profile" element={<UserProfile />} />
      </Routes>
    </Router>
  );
}

export default App;
