import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { jwtDecode } from 'jwt-decode';
import { saveAs } from 'file-saver';
import { useTranslation } from 'react-i18next';

function AdminAudit() {
  const [logs, setLogs] = useState([]);
  const [msg, setMsg] = useState('');

  const token = localStorage.getItem('token');
  const decoded = token ? jwtDecode(token) : {};
  const navigate = useNavigate();
  const { t } = useTranslation();

  useEffect(() => {
    if (decoded.role !== 'admin') navigate('/dashboard');
  }, [decoded, navigate]);

  useEffect(() => {
    fetchLogs();
  }, []);

  const fetchLogs = async () => {
    try {
      const { data } = await axios.get('http://127.0.0.1:8000/admin/audit', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setLogs(data);
    } catch {
      setMsg(t('Failed to fetch audit logs'));
    }
  };

  const adminDelete = async (action) => {
    const match = action.match(/Uploaded file:\s(.+)/i);
    if (!match) return;
    const filename = match[1];

    try {
      const { data: files } = await axios.get('http://127.0.0.1:8000/files', {
        headers: { Authorization: `Bearer ${token}` }
      });
      const file = files.find(f => f.filename === filename);
      if (!file) return alert(t('File not found'));

      await axios.delete(`http://127.0.0.1:8000/admin/files/${file.id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      setMsg(t('File deleted.'));
      fetchLogs();
    } catch {
      alert(t('Admin delete failed'));
    }
  };

  const exportCSV = async () => {
    try {
      const res = await axios.get('http://127.0.0.1:8000/admin/audit/export', {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'blob'
      });
      const fname = `audit-${new Date().toISOString().slice(0, 10)}.csv`;
      saveAs(res.data, fname);
    } catch {
      alert(t('CSV export failed (auth?)'));
    }
  };

  return (
    <div style={{ padding: '2rem' }}>
      <button onClick={() => navigate('/dashboard')} style={{ marginBottom: '1rem' }}>
  ← {t('Back to Dashboard')}
</button>
      <h2>{t('Audit Log (Admin)')}</h2>

      <button onClick={exportCSV} style={{ marginBottom: '8px' }}>
        {t('Export CSV')}
      </button>
      {msg && <p>{msg}</p>}

      <table border="1" cellPadding="6">
        <thead>
          <tr>
            <th>{t('Time')}</th>
            <th>{t('User')}</th>
            <th>{t('Action')}</th>
            <th>{t('Delete')}</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((l, idx) => (
            <tr key={idx}>
              <td>{new Date(l.timestamp).toLocaleString()}</td>
              <td>{l.user}</td>
              <td>{l.action}</td>
              <td>
                {l.action.startsWith('Uploaded file:') && (
                  <button onClick={() => adminDelete(l.action)}>
                    {t('Delete file')}
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default AdminAudit;
