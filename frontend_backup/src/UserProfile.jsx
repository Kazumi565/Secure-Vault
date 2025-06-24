import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { jwtDecode } from 'jwt-decode';
import { useTranslation } from 'react-i18next';
import axios from 'axios';
import defaultAvatar from './assets/default-avatar.png';
import Cropper from 'react-easy-crop';
import Modal from '@mui/material/Modal';
import Slider from '@mui/material/Slider';
import { getCroppedImg } from './utils/cropImage';

function UserProfile() {
  const token = localStorage.getItem('token');
  const decoded = token ? jwtDecode(token) : {};
  const email = decoded?.sub || 'Unknown';
  const role = decoded?.role || 'user';
  const navigate = useNavigate();
  const { t } = useTranslation();

  const [fullName, setFullName] = useState('');
  const [newName, setNewName] = useState('');
  const [editingName, setEditingName] = useState(false);
  const [createdAt, setCreatedAt] = useState(null);
  const [changingPassword, setChangingPassword] = useState(false);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');

  const [avatar, setAvatar] = useState(null);
  const [profileUrl, setProfileUrl] = useState(null);
  const [imageSrc, setImageSrc] = useState(null);
  const [crop, setCrop] = useState({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(1);
  const [croppedAreaPixels, setCroppedAreaPixels] = useState(null);
  const [open, setOpen] = useState(false);
  const fileInputRef = useRef(null);

  useEffect(() => {
    axios.get('http://127.0.0.1:8000/me', {
      headers: { Authorization: `Bearer ${token}` }
    })
    .then(res => {
      const user = res.data;
      if (user.profile_picture) {
        setProfileUrl(`http://127.0.0.1:8000${user.profile_picture}`);
      }
      if (user.full_name) {
        setFullName(user.full_name);
      }
      if (user.created_at) {
        setCreatedAt(new Date(user.created_at).toLocaleString());
      }
    })
    .catch(err => console.error("Error fetching user info:", err));
  }, [token]);

  const handleAvatarClick = () => fileInputRef.current.click();

  const handleAvatarChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      const imageUrl = URL.createObjectURL(file);
      setImageSrc(imageUrl);
      setOpen(true);
    }
  };

  const handleCropComplete = (_, croppedPixels) => {
    setCroppedAreaPixels(croppedPixels);
  };

  const handleCropSave = async () => {
    try {
      const croppedImg = await getCroppedImg(imageSrc, croppedAreaPixels);
      const blob = await fetch(croppedImg).then(res => res.blob());
      const form = new FormData();
      form.append('file', blob, 'avatar.png');

      const res = await axios.patch('http://127.0.0.1:8000/me/profile-picture', form, {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'multipart/form-data'
        }
      });

      setProfileUrl(`http://127.0.0.1:8000${res.data.profile_picture}`);
      setAvatar(null);
      setOpen(false);
    } catch (err) {
      console.error('Failed to upload avatar:', err);
      alert('Upload failed.');
    }
  };

  const handleNameUpdate = async () => {
    if (!newName.trim()) return;

    try {
      await axios.patch('http://127.0.0.1:8000/me/full-name', {
        full_name: newName
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });

      alert('Name updated successfully!');
      setFullName(newName);
      setEditingName(false);
      setNewName('');
    } catch (err) {
      alert('Failed to update name');
      console.error(err);
    }
  };

  const handleDeleteAccount = async () => {
    const password = prompt("Enter your password to confirm account deletion:");
    if (!password) return;

    try {
      await axios.delete('http://127.0.0.1:8000/me', {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        data: { password }
      });

      alert("Your account has been deleted.");
      localStorage.removeItem('token');
      navigate('/');
    } catch (err) {
      console.error(err);
      alert(err.response?.data?.detail || "Account deletion failed.");
    }
  };

  const handlePasswordChange = async () => {
    if (!currentPassword || !newPassword) {
      alert("Please enter both current and new passwords.");
      return;
    }

    try {
      await axios.patch('http://127.0.0.1:8000/me/password', {
        current_password: currentPassword,
        new_password: newPassword
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });

      alert("Password changed successfully!");
      setChangingPassword(false);
      setCurrentPassword('');
      setNewPassword('');
    } catch (err) {
      alert(err.response?.data?.detail || "Password change failed.");
    }
  };

  return (
    <div style={{
      padding: '2rem',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center'
    }}>
      <h2>User Profile</h2>

      <div
        onClick={handleAvatarClick}
        style={{
          width: '120px',
          height: '120px',
          borderRadius: '50%',
          backgroundColor: '#ccc',
          backgroundImage: `url(${avatar || profileUrl || defaultAvatar})`,
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          cursor: 'pointer',
          marginBottom: '1rem'
        }}
        title="Click to change profile picture"
      />

      <input
        type="file"
        accept="image/*"
        ref={fileInputRef}
        onChange={handleAvatarChange}
        style={{ display: 'none' }}
      />

      <div style={{
        border: '1px solid gray',
        padding: '1rem 2rem',
        borderRadius: '8px',
        minWidth: '300px',
        marginBottom: '1rem'
      }}>
        <p><strong>Email:</strong> {email}</p>
        <p><strong>Role:</strong> {role}</p>
        <p><strong>Full Name:</strong> {fullName || 'N/A'}</p>
        <p><strong>Account Created:</strong> {createdAt || 'N/A'}</p>

        {!editingName ? (
          <button onClick={() => {
            setNewName(fullName || '');
            setEditingName(true);
          }} style={{ marginTop: '10px' }}>
            Change Name
          </button>
        ) : (
          <div style={{ marginTop: '1rem', textAlign: 'center' }}>
            <input
              type="text"
              value={newName}
              onChange={e => setNewName(e.target.value)}
              placeholder="Enter new full name"
              style={{ padding: '5px', marginRight: '10px' }}
            />
            <button onClick={handleNameUpdate} style={{ marginRight: '5px' }}>Save</button>
            <button onClick={() => setEditingName(false)}>Cancel</button>
          </div>
        )}
      </div>

      {!changingPassword ? (
        <button onClick={() => setChangingPassword(true)} style={{ marginBottom: '10px' }}>
          Change Password
        </button>
      ) : (
        <div style={{ marginBottom: '1rem', textAlign: 'center' }}>
          <input
            type="password"
            placeholder="Current Password"
            value={currentPassword}
            onChange={e => setCurrentPassword(e.target.value)}
            style={{ padding: '5px', marginBottom: '5px', display: 'block', width: '100%' }}
          />
          <input
            type="password"
            placeholder="New Password"
            value={newPassword}
            onChange={e => setNewPassword(e.target.value)}
            style={{ padding: '5px', marginBottom: '5px', display: 'block', width: '100%' }}
          />
          <button onClick={handlePasswordChange} style={{ marginRight: '5px' }}>Save</button>
          <button onClick={() => {
            setChangingPassword(false);
            setCurrentPassword('');
            setNewPassword('');
          }}>Cancel</button>
        </div>
      )}

      <button
        onClick={handleDeleteAccount}
        style={{ marginBottom: '10px', backgroundColor: 'red', color: 'white' }}
      >
        Delete Account
      </button>

      <button onClick={() => navigate('/dashboard')}>
        Back to Dashboard
      </button>

      <Modal open={open} onClose={() => setOpen(false)}>
        <div style={{
          position: 'absolute',
          top: '50%', left: '50%',
          transform: 'translate(-50%, -50%)',
          width: '90%', maxWidth: '400px',
          backgroundColor: '#fff',
          padding: '1rem',
          borderRadius: '10px',
          outline: 'none'
        }}>
          <h3>Crop Image</h3>
          <div style={{ position: 'relative', width: '100%', height: 300 }}>
            <Cropper
              image={imageSrc}
              crop={crop}
              zoom={zoom}
              aspect={1}
              onCropChange={setCrop}
              onZoomChange={setZoom}
              onCropComplete={handleCropComplete}
            />
          </div>
          <Slider
            value={zoom}
            min={1}
            max={3}
            step={0.1}
            onChange={(e, z) => setZoom(z)}
            style={{ margin: '1rem 0' }}
          />
          <button onClick={handleCropSave} style={{ marginRight: '10px' }}>Save</button>
          <button onClick={() => setOpen(false)}>Cancel</button>
        </div>
      </Modal>
    </div>
  );
}

export default UserProfile;
