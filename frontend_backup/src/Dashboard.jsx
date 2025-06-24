import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { jwtDecode } from 'jwt-decode';
import { useTranslation } from 'react-i18next';

function Dashboard() {
  const [files, setFiles] = useState([]);
  const [error, setError] = useState('');
  const [uploadFile, setUploadFile] = useState(null);
  const [message, setMessage] = useState('');
  const [darkMode, setDarkMode] = useState(() => localStorage.getItem('theme') === 'dark');

  const { i18n, t } = useTranslation();
  const changeLanguage = (lng) => i18n.changeLanguage(lng);

  const navigate = useNavigate();
  const token = localStorage.getItem('token');
  const decoded = token ? jwtDecode(token) : {};
  const userEmail = decoded?.sub || 'Unknown';
  const isAdmin = decoded?.role === 'admin';

  useEffect(() => {
    document.body.className = darkMode ? 'dark' : 'light';
    localStorage.setItem('theme', darkMode ? 'dark' : 'light');
  }, [darkMode]);

  useEffect(() => {
    fetchFiles();
  }, []);

  const fetchFiles = async () => {
    try {
      const { data } = await axios.get('http://127.0.0.1:8000/files', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setFiles(data);
    } catch {
      setError(t('Download failed'));
    }
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!uploadFile) return;

    const form = new FormData();
    form.append('upload_file', uploadFile);

    try {
      await axios.post('http://127.0.0.1:8000/upload', form, {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'multipart/form-data'
        }
      });
      setMessage(t('Upload successful!'));
      setUploadFile(null);
      fetchFiles();
    } catch {
      setMessage(t('Upload failed.'));
    }
  };

  const handleDownload = async (id, name) => {
    try {
      const res = await axios.get(`http://127.0.0.1:8000/download/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'blob'
      });
      const blob = new Blob([res.data], {
        type: name.endsWith('.txt') ? 'text/plain' : 'application/octet-stream'
      });
      const url = URL.createObjectURL(blob);
      const link = Object.assign(document.createElement('a'), {
        href: url,
        download: name
      });
      document.body.appendChild(link).click();
      link.remove();
    } catch {
      alert(t('Download failed'));
    }
  };

  const handleDelete = async (id) => {
    try {
      await axios.delete(`http://127.0.0.1:8000/files/${id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setMessage(t('File deleted.'));
      fetchFiles();
    } catch {
      setMessage(t('Delete failed.'));
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/');
  };

  return (
    <div style={{ padding: '2rem' }}>
      <div style={{ marginBottom: '1rem' }}>
        <strong>{t('Logged in as:')}</strong> {userEmail}{' '}
        | <a href="/profile">{t('Profile')}</a>{' '}
        {isAdmin && (
          <>| <a href="/admin/audit">{t('Admin audit')}</a>{' '}</>
        )}
        | <button onClick={handleLogout}>{t('Logout')}</button>

        <div style={{ float: 'right' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <select onChange={e => changeLanguage(e.target.value)} defaultValue={i18n.language}>
              <option value="en">EN</option>
              <option value="ro">RO</option>
            </select>
            <button onClick={() => setDarkMode(!darkMode)}>
              {darkMode ? '☀ Light' : '🌙 Dark'}
            </button>
          </div>
        </div>
      </div>

      <h2>{t('Secure File Dashboard')}</h2>

      <form onSubmit={handleUpload} style={{ marginBottom: '1rem' }}>
        <label style={{ display: 'inline-block', marginRight: '8px' }}>
          <input
            type="file"
            style={{ display: 'none' }}
            onChange={e => setUploadFile(e.target.files[0])}
          />
          <button type="button">{t("Choose File")}</button>
        </label>
        <span>{uploadFile ? uploadFile.name : t("No file chosen")}</span>
        <button type="submit">{t('Upload')}</button>
      </form>

      {message && <p>{message}</p>}
      {error && <p style={{ color: 'red' }}>{error}</p>}

      <h3>{t('Your Files')}</h3>
      {files.length === 0 ? (
        <p>{t('No files uploaded yet.')}</p>
      ) : (
        <ul>
          {files.map(f => (
            <li key={f.id}>
              {f.filename}{' '}
              <button onClick={() => handleDownload(f.id, f.filename)}>{t('Download')}</button>{' '}
              <button onClick={() => handleDelete(f.id)}>{t('Delete')}</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default Dashboard;
