import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate, Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [darkMode, setDarkMode] = useState(() => localStorage.getItem('theme') === 'dark');

  const navigate = useNavigate();
  const { t, i18n } = useTranslation();

  useEffect(() => {
    document.body.className = darkMode ? 'dark' : 'light';
    localStorage.setItem('theme', darkMode ? 'dark' : 'light');
  }, [darkMode]);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');

    try {
      const response = await axios.post('http://127.0.0.1:8000/login', new URLSearchParams({
        username: email,
        password: password
      }));

      const token = response.data.access_token;
      localStorage.setItem('token', token);
      navigate('/dashboard');
    } catch (err) {
      setError(t('Invalid credentials or server error.'));
    }
  };

  return (
    <div style={{ padding: '2rem' }}>
      <div style={{ float: 'right' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <select onChange={(e) => i18n.changeLanguage(e.target.value)} defaultValue={i18n.language}>
            <option value="en">EN</option>
            <option value="ro">RO</option>
          </select>
          <button onClick={() => setDarkMode(!darkMode)}>
            {darkMode ? '☀ Light' : '🌙 Dark'}
          </button>
        </div>
      </div>

      <h2>{t('Login to Secure File Vault')}</h2>
      <form onSubmit={handleLogin}>
        <div>
          <label>{t('Email')}:</label>{' '}
          <input type="text" value={email} onChange={e => setEmail(e.target.value)} required />
        </div>
        <div>
          <label>{t('Password')}:</label>{' '}
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} required />
        </div>
        <button type="submit">{t('Login')}</button>
        {error && <p style={{ color: 'red' }}>{error}</p>}
      </form>

      <p style={{ marginTop: '1rem' }}>
        {t("Don't have an account?")}{' '}
        <Link to="/register">{t('Register here')}</Link>
      </p>
    </div>
  );
}

export default LoginPage;
