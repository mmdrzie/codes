'use client';

import React, { useState, useEffect } from 'react';
import { useFormState, useFormStatus } from 'react-dom';
import { useRouter } from 'next/navigation';
import { z } from 'zod';
import FormInput from '@/components/profile/FormInput';
import FormSelect from '@/components/profile/FormSelect';
import CheckboxField from '@/components/profile/CheckboxField';
import ConfirmModal from '@/components/profile/ConfirmModal';
import { 
  updateProfile, 
  changePassword, 
  updateNotificationPreferences, 
  updateAccountPreferences, 
  uploadProfileImage, 
  requestAccountDeletion, 
  getUserSessions, 
  revokeSession, 
  getApiKeys, 
  revokeApiKey 
} from '@/actions/profile-actions';
import { 
  UserProfile, 
  SessionInfo, 
  ApiKey,
  notificationPreferencesSchema,
  accountPreferencesSchema
} from '@/types/profile';
import { useAuth } from '@/hooks/useAuth';

// Define initial states
const initialUserProfile: UserProfile = {
  id: '',
  displayName: '',
  username: '',
  email: '',
  emailVerified: false,
  avatarUrl: '',
  createdAt: new Date(),
  lastLoginAt: undefined,
  lastLoginIp: '',
  lastLoginDevice: '',
};

const initialNotificationPrefs = {
  systemNotifications: true,
  securityAlerts: true,
  productUpdates: false,
  tradingSignals: true,
  emailNotifications: true,
  pushNotifications: true,
  smsNotifications: false,
};

const initialAccountPrefs = {
  language: 'en',
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  dateFormat: 'MM/DD/YYYY' as const,
  timeFormat: '24h' as const,
  currency: 'USD',
  numberFormat: 'comma' as const,
  theme: 'dark' as const,
};

// Loading button component for form submissions
const LoadingButton: React.FC<{ children: React.ReactNode; pendingText?: string }> = ({ 
  children, 
  pendingText = 'Submitting...' 
}) => {
  const { pending } = useFormStatus();
  
  return (
    <button
      type="submit"
      disabled={pending}
      className={`px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${
        pending ? 'opacity-75 cursor-not-allowed' : ''
      }`}
    >
      {pending ? pendingText : children}
    </button>
  );
};

// Password change form component
const PasswordChangeForm: React.FC = () => {
  const [state, formAction] = useFormState(changePassword, {});
  const [showSuccess, setShowSuccess] = useState(false);

  useEffect(() => {
    if (state.success) {
      setShowSuccess(true);
      setTimeout(() => setShowSuccess(false), 3000); // Hide after 3 seconds
    }
  }, [state.success]);

  return (
    <form action={formAction} className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <FormInput
          label="Current Password"
          id="currentPassword"
          name="currentPassword"
          type="password"
          required
          error={state?.fieldErrors?.currentPassword?.[0] || state?.error}
        />
        <div></div> {/* Empty div for grid alignment */}
        <FormInput
          label="New Password"
          id="newPassword"
          name="newPassword"
          type="password"
          required
          placeholder="At least 12 characters with uppercase, lowercase, number, and special character"
          error={state?.fieldErrors?.newPassword?.[0]}
        />
        <FormInput
          label="Confirm New Password"
          id="confirmPassword"
          name="confirmPassword"
          type="password"
          required
          error={state?.fieldErrors?.confirmPassword?.[0]}
        />
      </div>
      <div className="flex items-center">
        <LoadingButton pendingText="Changing Password...">
          Change Password
        </LoadingButton>
        {showSuccess && (
          <span className="ml-4 text-green-500 text-sm">Password changed successfully!</span>
        )}
      </div>
    </form>
  );
};

// Notification preferences form component
const NotificationPreferencesForm: React.FC = () => {
  const [state, formAction] = useFormState(updateNotificationPreferences, {});
  const [showSuccess, setShowSuccess] = useState(false);
  const [prefs, setPrefs] = useState(initialNotificationPrefs);

  useEffect(() => {
    if (state.success) {
      setShowSuccess(true);
      setTimeout(() => setShowSuccess(false), 3000); // Hide after 3 seconds
    }
  }, [state.success]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, checked } = e.target;
    setPrefs(prev => ({
      ...prev,
      [name]: checked
    }));
  };

  return (
    <form action={formAction} className="space-y-4">
      <input type="hidden" name="systemNotifications" value={prefs.systemNotifications ? 'on' : 'off'} />
      <input type="hidden" name="securityAlerts" value={prefs.securityAlerts ? 'on' : 'off'} />
      <input type="hidden" name="productUpdates" value={prefs.productUpdates ? 'on' : 'off'} />
      <input type="hidden" name="tradingSignals" value={prefs.tradingSignals ? 'on' : 'off'} />
      <input type="hidden" name="emailNotifications" value={prefs.emailNotifications ? 'on' : 'off'} />
      <input type="hidden" name="pushNotifications" value={prefs.pushNotifications ? 'on' : 'off'} />
      <input type="hidden" name="smsNotifications" value={prefs.smsNotifications ? 'on' : 'off'} />

      <div className="space-y-2">
        <CheckboxField
          label="System Notifications"
          id="systemNotifications"
          name="systemNotifications"
          checked={prefs.systemNotifications}
          onChange={handleChange}
        />
        <CheckboxField
          label="Security Alerts"
          id="securityAlerts"
          name="securityAlerts"
          checked={prefs.securityAlerts}
          onChange={handleChange}
        />
        <CheckboxField
          label="Product Updates"
          id="productUpdates"
          name="productUpdates"
          checked={prefs.productUpdates}
          onChange={handleChange}
        />
        <CheckboxField
          label="Trading Signals"
          id="tradingSignals"
          name="tradingSignals"
          checked={prefs.tradingSignals}
          onChange={handleChange}
        />
        <CheckboxField
          label="Email Notifications"
          id="emailNotifications"
          name="emailNotifications"
          checked={prefs.emailNotifications}
          onChange={handleChange}
        />
        <CheckboxField
          label="Push Notifications"
          id="pushNotifications"
          name="pushNotifications"
          checked={prefs.pushNotifications}
          onChange={handleChange}
        />
        <CheckboxField
          label="SMS Notifications"
          id="smsNotifications"
          name="smsNotifications"
          checked={prefs.smsNotifications}
          onChange={handleChange}
        />
      </div>

      <div className="flex items-center">
        <LoadingButton pendingText="Saving Preferences...">
          Save Preferences
        </LoadingButton>
        {showSuccess && (
          <span className="ml-4 text-green-500 text-sm">Preferences saved!</span>
        )}
      </div>
    </form>
  );
};

// Account preferences form component
const AccountPreferencesForm: React.FC = () => {
  const [state, formAction] = useFormState(updateAccountPreferences, {});
  const [showSuccess, setShowSuccess] = useState(false);
  const [prefs, setPrefs] = useState(initialAccountPrefs);

  useEffect(() => {
    if (state.success) {
      setShowSuccess(true);
      setTimeout(() => setShowSuccess(false), 3000); // Hide after 3 seconds
    }
  }, [state.success]);

  const handleChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const { name, value } = e.target;
    setPrefs(prev => ({
      ...prev,
      [name]: value
    }));
  };

  return (
    <form action={formAction} className="space-y-4">
      <input type="hidden" name="language" value={prefs.language} />
      <input type="hidden" name="timezone" value={prefs.timezone} />
      <input type="hidden" name="dateFormat" value={prefs.dateFormat} />
      <input type="hidden" name="timeFormat" value={prefs.timeFormat} />
      <input type="hidden" name="currency" value={prefs.currency} />
      <input type="hidden" name="numberFormat" value={prefs.numberFormat} />
      <input type="hidden" name="theme" value={prefs.theme} />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <FormSelect
          label="Language"
          id="language"
          name="language"
          value={prefs.language}
          onChange={handleChange}
          options={[
            { value: 'en', label: 'English' },
            { value: 'fa', label: 'Persian' },
            { value: 'ar', label: 'Arabic' },
            { value: 'de', label: 'German' },
            { value: 'fr', label: 'French' },
            { value: 'es', label: 'Spanish' },
            { value: 'zh', label: 'Chinese' },
            { value: 'ja', label: 'Japanese' },
          ]}
        />
        <FormInput
          label="Timezone"
          id="timezone"
          name="timezone"
          value={prefs.timezone}
          onChange={(e) => setPrefs(prev => ({ ...prev, timezone: e.target.value }))}
        />
        <FormSelect
          label="Date Format"
          id="dateFormat"
          name="dateFormat"
          value={prefs.dateFormat}
          onChange={handleChange}
          options={[
            { value: 'MM/DD/YYYY', label: 'MM/DD/YYYY' },
            { value: 'DD/MM/YYYY', label: 'DD/MM/YYYY' },
            { value: 'YYYY-MM-DD', label: 'YYYY-MM-DD' },
          ]}
        />
        <FormSelect
          label="Time Format"
          id="timeFormat"
          name="timeFormat"
          value={prefs.timeFormat}
          onChange={handleChange}
          options={[
            { value: '12h', label: '12-hour (AM/PM)' },
            { value: '24h', label: '24-hour' },
          ]}
        />
        <FormInput
          label="Currency Display"
          id="currency"
          name="currency"
          value={prefs.currency}
          onChange={(e) => setPrefs(prev => ({ ...prev, currency: e.target.value }))}
        />
        <FormSelect
          label="Number Format"
          id="numberFormat"
          name="numberFormat"
          value={prefs.numberFormat}
          onChange={handleChange}
          options={[
            { value: 'comma', label: 'Comma (1,000,000)' },
            { value: 'space', label: 'Space (1 000 000)' },
            { value: 'period', label: 'Period (1.000.000)' },
          ]}
        />
      </div>

      <div className="flex items-center">
        <LoadingButton pendingText="Saving Preferences...">
          Save Preferences
        </LoadingButton>
        {showSuccess && (
          <span className="ml-4 text-green-500 text-sm">Preferences saved!</span>
        )}
      </div>
    </form>
  );
};

// Profile image upload component
const ProfileImageUpload: React.FC = () => {
  const [preview, setPreview] = useState<string | null>(null);
  const [fileName, setFileName] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    
    try {
      const result = await uploadProfileImage(formData);
      if (result.error) {
        setError(result.error);
      } else {
        setError('');
        alert('Profile image updated successfully!');
      }
    } catch (err) {
      setError('Failed to upload image');
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      // Validate file type and size
      if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type)) {
        setError('File must be a JPEG, PNG, or WEBP image');
        return;
      }
      
      if (file.size > 5 * 1024 * 1024) { // 5MB
        setError('File size must be less than 5MB');
        return;
      }
      
      setError('');
      setFileName(file.name);
      
      // Create a preview URL
      const reader = new FileReader();
      reader.onloadend = () => {
        setPreview(reader.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="flex flex-col items-center">
        <div className="relative">
          <img
            src={preview || '/placeholder-avatar.jpg'}
            alt="Profile Preview"
            className="w-24 h-24 rounded-full object-cover border-2 border-gray-600"
          />
          {preview && (
            <div className="absolute -bottom-2 left-1/2 transform -translate-x-1/2 bg-blue-600 text-white text-xs px-2 py-1 rounded">
              Preview
            </div>
          )}
        </div>
        
        <div className="mt-4 w-full max-w-xs">
          <label className="block text-sm font-medium text-gray-300 mb-1">
            Profile Image
          </label>
          <input
            type="file"
            name="avatar"
            accept="image/jpeg,image/png,image/webp"
            onChange={handleFileChange}
            className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-md text-white file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-blue-600 file:text-white hover:file:bg-blue-700"
          />
          {fileName && <p className="mt-1 text-sm text-gray-400">Selected: {fileName}</p>}
          {error && <p className="mt-1 text-sm text-red-500">{error}</p>}
        </div>
      </div>
      
      <div className="flex justify-center">
        <LoadingButton pendingText="Uploading...">
          Upload Image
        </LoadingButton>
      </div>
    </form>
  );
};

// Sessions management component
const SessionsManagement: React.FC = () => {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [revokeModalOpen, setRevokeModalOpen] = useState(false);
  const [sessionToRevoke, setSessionToRevoke] = useState<string | null>(null);
  const router = useRouter();

  useEffect(() => {
    const fetchSessions = async () => {
      try {
        const data = await getUserSessions();
        setSessions(data);
      } catch (error) {
        console.error('Error fetching sessions:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchSessions();
  }, []);

  const handleRevokeSession = async () => {
    if (!sessionToRevoke) return;

    try {
      const result = await revokeSession(sessionToRevoke);
      if (result.success) {
        setSessions(sessions.filter(s => s.id !== sessionToRevoke));
        setRevokeModalOpen(false);
        setSessionToRevoke(null);
        
        // If we're revoking the current session, redirect to logout
        const currentSession = sessions.find(s => s.isCurrent);
        if (currentSession && currentSession.id === sessionToRevoke) {
          router.push('/auth/logout');
        }
      }
    } catch (error) {
      console.error('Error revoking session:', error);
    }
  };

  if (loading) {
    return <div className="text-gray-400">Loading sessions...</div>;
  }

  return (
    <div>
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-700">
          <thead>
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Device</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Location</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Last Active</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Status</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {sessions.map((session) => (
              <tr key={session.id} className={session.isCurrent ? 'bg-gray-800' : ''}>
                <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-300">
                  <div>{session.device}</div>
                  <div className="text-xs text-gray-500">{session.ip}</div>
                </td>
                <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-300">
                  {session.location}
                </td>
                <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-300">
                  {new Date(session.lastActive).toLocaleString()}
                </td>
                <td className="px-4 py-3 whitespace-nowrap">
                  <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                    session.isActive 
                      ? session.isCurrent 
                        ? 'bg-green-900 text-green-200' 
                        : 'bg-blue-900 text-blue-200'
                      : 'bg-gray-700 text-gray-300'
                  }`}>
                    {session.isCurrent ? 'Current' : session.isActive ? 'Active' : 'Inactive'}
                  </span>
                </td>
                <td className="px-4 py-3 whitespace-nowrap text-sm">
                  {!session.isCurrent && (
                    <button
                      onClick={() => {
                        setSessionToRevoke(session.id);
                        setRevokeModalOpen(true);
                      }}
                      className="text-red-500 hover:text-red-400"
                    >
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ConfirmModal
        isOpen={revokeModalOpen}
        onClose={() => setRevokeModalOpen(false)}
        title="Revoke Session"
        message="Are you sure you want to revoke this session? The user will be logged out on that device."
        onConfirm={handleRevokeSession}
        confirmText="Revoke Session"
        cancelText="Cancel"
        variant="danger"
      />
    </div>
  );
};

// API Keys management component
const ApiKeysManagement: React.FC = () => {
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [revokeModalOpen, setRevokeModalOpen] = useState(false);
  const [keyToRevoke, setKeyToRevoke] = useState<string | null>(null);

  useEffect(() => {
    const fetchApiKeys = async () => {
      try {
        const data = await getApiKeys();
        setApiKeys(data);
      } catch (error) {
        console.error('Error fetching API keys:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchApiKeys();
  }, []);

  const handleRevokeApiKey = async () => {
    if (!keyToRevoke) return;

    try {
      const result = await revokeApiKey(keyToRevoke);
      if (result.success) {
        setApiKeys(apiKeys.filter(k => k.id !== keyToRevoke));
        setRevokeModalOpen(false);
        setKeyToRevoke(null);
      }
    } catch (error) {
      console.error('Error revoking API key:', error);
    }
  };

  if (loading) {
    return <div className="text-gray-400">Loading API keys...</div>;
  }

  return (
    <div>
      <div className="mb-4 flex justify-between items-center">
        <h3 className="text-lg font-medium text-white">API Keys</h3>
        <button className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 text-sm">
          Generate New Key
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-700">
          <thead>
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Name</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Key</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Created</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Last Used</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Status</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {apiKeys.map((key) => (
              <tr key={key.id}>
                <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-300">
                  {key.name}
                </td>
                <td className="px-4 py-3 text-sm text-gray-300 font-mono">
                  {key.keyPrefix}
                </td>
                <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-300">
                  {new Date(key.createdAt).toLocaleDateString()}
                </td>
                <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-300">
                  {key.lastUsedAt ? new Date(key.lastUsedAt).toLocaleString() : 'Never'}
                </td>
                <td className="px-4 py-3 whitespace-nowrap">
                  <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                    key.isActive ? 'bg-green-900 text-green-200' : 'bg-gray-700 text-gray-300'
                  }`}>
                    {key.isActive ? 'Active' : 'Inactive'}
                  </span>
                </td>
                <td className="px-4 py-3 whitespace-nowrap text-sm">
                  <button
                    onClick={() => {
                      setKeyToRevoke(key.id);
                      setRevokeModalOpen(true);
                    }}
                    className="text-red-500 hover:text-red-400"
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ConfirmModal
        isOpen={revokeModalOpen}
        onClose={() => setRevokeModalOpen(false)}
        title="Revoke API Key"
        message="Are you sure you want to revoke this API key? Any applications using this key will lose access."
        onConfirm={handleRevokeApiKey}
        confirmText="Revoke Key"
        cancelText="Cancel"
        variant="danger"
      />
    </div>
  );
};

// Account deletion component
const AccountDeletionSection: React.FC = () => {
  const [state, formAction] = useFormState(requestAccountDeletion, {});
  const [showSuccess, setShowSuccess] = useState(false);
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);

  useEffect(() => {
    if (state.success) {
      setShowSuccess(true);
      setDeleteModalOpen(false);
    }
  }, [state.success]);

  return (
    <div>
      <div className="bg-red-900/20 border border-red-800 rounded-lg p-6">
        <h3 className="text-lg font-medium text-red-400 mb-2">Danger Zone</h3>
        <p className="text-gray-300 mb-4">
          Permanently delete your account and all associated data. This action cannot be undone.
        </p>
        
        <button
          onClick={() => setDeleteModalOpen(true)}
          className="px-4 py-2 bg-red-700 text-white rounded-md hover:bg-red-600 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2"
        >
          Delete Account
        </button>
      </div>

      <ConfirmModal
        isOpen={deleteModalOpen}
        onClose={() => setDeleteModalOpen(false)}
        title="Delete Account"
        message={
          <div className="space-y-4">
            <p className="text-red-400">
              This action is irreversible. Your account and all associated data will be permanently deleted after a 14-day grace period.
            </p>
            
            <form action={formAction} className="space-y-4">
              <div>
                <label htmlFor="confirmationText" className="block text-sm font-medium text-gray-300 mb-1">
                  Type "DELETE MY ACCOUNT" to confirm
                </label>
                <input
                  type="text"
                  id="confirmationText"
                  name="confirmationText"
                  required
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                />
              </div>
              
              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-300 mb-1">
                  Enter your password to confirm
                </label>
                <input
                  type="password"
                  id="password"
                  name="password"
                  required
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                />
              </div>
              
              <div className="flex justify-end space-x-3 pt-4">
                <button
                  type="button"
                  onClick={() => setDeleteModalOpen(false)}
                  className="px-4 py-2 text-sm font-medium text-gray-300 bg-gray-700 rounded-md hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-sm font-medium text-white bg-red-700 rounded-md hover:bg-red-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
                >
                  Delete My Account
                </button>
              </div>
            </form>
            
            {state?.error && (
              <div className="mt-4 p-3 bg-red-900/30 border border-red-700 rounded text-red-300 text-sm">
                {state.error}
              </div>
            )}
          </div>
        }
        onConfirm={() => {}} // Confirmation happens in the form submission
        confirmText=""
        cancelText=""
        variant="danger"
      />
      
      {showSuccess && (
        <div className="mt-4 p-3 bg-green-900/30 border border-green-700 rounded text-green-300">
          {state.message}
        </div>
      )}
    </div>
  );
};

// Main Profile Page Component
export default function ProfilePage() {
  const [state, formAction] = useFormState(updateProfile, {});
  const [showSuccess, setShowSuccess] = useState(false);
  const [user, setUser] = useState<UserProfile>(initialUserProfile);
  const [isLoading, setIsLoading] = useState(true);
  const { user: authUser, isLoading: authLoading } = useAuth();

  useEffect(() => {
    // Simulate loading user data
    if (authUser) {
      setUser({
        id: authUser.id,
        displayName: authUser.firebaseUser?.displayName || 'John Doe',
        username: 'johndoe',
        email: authUser.firebaseUser?.email || 'john@example.com',
        emailVerified: authUser.isVerified,
        avatarUrl: authUser.firebaseUser?.photoURL || '',
        createdAt: new Date(authUser.createdAt),
        lastLoginAt: new Date(),
        lastLoginIp: '192.168.1.100',
        lastLoginDevice: 'Chrome on Windows',
      });
      setIsLoading(false);
    }
  }, [authUser]);

  useEffect(() => {
    if (state.success) {
      setShowSuccess(true);
      setTimeout(() => setShowSuccess(false), 3000); // Hide after 3 seconds
    }
  }, [state.success]);

  if (isLoading || authLoading) {
    return (
      <div className="max-w-7xl mx-auto p-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-700 rounded w-1/4 mb-8"></div>
          <div className="space-y-6">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="bg-gray-800 p-6 rounded-lg">
                <div className="h-6 bg-gray-700 rounded w-1/3 mb-4"></div>
                <div className="space-y-3">
                  <div className="h-4 bg-gray-700 rounded w-full"></div>
                  <div className="h-4 bg-gray-700 rounded w-5/6"></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Account Profile</h1>
        <p className="text-gray-400 mt-2">Manage your account information, security settings, and preferences</p>
      </div>

      {/* Success Message */}
      {showSuccess && (
        <div className="mb-6 p-4 bg-green-900/30 border border-green-700 rounded text-green-300">
          Profile updated successfully!
        </div>
      )}

      {/* Identity Information Section */}
      <section className="mb-8 bg-gray-800 p-6 rounded-lg border border-gray-700">
        <h2 className="text-xl font-semibold text-white mb-4">Identity Information</h2>
        
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-1">
            <ProfileImageUpload />
          </div>
          
          <div className="lg:col-span-2">
            <form action={formAction} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <FormInput
                  label="Display Name"
                  id="displayName"
                  name="displayName"
                  defaultValue={user.displayName}
                  required
                  error={state?.fieldErrors?.displayName?.[0] || state?.error}
                />
                <FormInput
                  label="Username"
                  id="username"
                  name="username"
                  defaultValue={user.username}
                  error={state?.fieldErrors?.username?.[0]}
                />
                <FormInput
                  label="Email Address"
                  id="email"
                  name="email"
                  type="email"
                  defaultValue={user.email}
                  required
                  error={state?.fieldErrors?.email?.[0]}
                />
                <div className="flex items-end">
                  {!user.emailVerified ? (
                    <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-yellow-900/30 text-yellow-300 border border-yellow-800">
                      Email not verified
                    </span>
                  ) : (
                    <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-900/30 text-green-300 border border-green-800">
                      Verified
                    </span>
                  )}
                </div>
              </div>
              
              <div className="pt-4">
                <LoadingButton pendingText="Saving Profile...">
                  Save Changes
                </LoadingButton>
              </div>
            </form>
          </div>
        </div>
      </section>

      {/* Security Settings Section */}
      <section className="mb-8 bg-gray-800 p-6 rounded-lg border border-gray-700">
        <h2 className="text-xl font-semibold text-white mb-4">Security Settings</h2>
        
        <div className="space-y-8">
          <div>
            <h3 className="text-lg font-medium text-white mb-3">Change Password</h3>
            <PasswordChangeForm />
          </div>
          
          <div>
            <h3 className="text-lg font-medium text-white mb-3">Two-Factor Authentication</h3>
            <div className="flex items-center">
              <span className="mr-4 px-3 py-1 bg-gray-700 text-gray-300 rounded-md text-sm">Disabled</span>
              <button className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 text-sm">
                Enable 2FA
              </button>
            </div>
          </div>
          
          <div>
            <h3 className="text-lg font-medium text-white mb-3">Active Sessions</h3>
            <SessionsManagement />
          </div>
          
          <div>
            <h3 className="text-lg font-medium text-white mb-3">API Keys</h3>
            <ApiKeysManagement />
          </div>
        </div>
      </section>

      {/* Account Preferences Section */}
      <section className="mb-8 bg-gray-800 p-6 rounded-lg border border-gray-700">
        <h2 className="text-xl font-semibold text-white mb-4">Account Preferences</h2>
        
        <div className="space-y-8">
          <div>
            <h3 className="text-lg font-medium text-white mb-3">Notification Preferences</h3>
            <NotificationPreferencesForm />
          </div>
          
          <div>
            <h3 className="text-lg font-medium text-white mb-3">General Preferences</h3>
            <AccountPreferencesForm />
          </div>
        </div>
      </section>

      {/* Data & Privacy Controls Section */}
      <section className="mb-8 bg-gray-800 p-6 rounded-lg border border-gray-700">
        <h2 className="text-xl font-semibold text-white mb-4">Data & Privacy Controls</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div>
            <h3 className="text-lg font-medium text-white mb-3">Data Export</h3>
            <div className="space-y-3">
              <button className="w-full text-left px-4 py-3 bg-gray-700 hover:bg-gray-600 rounded-md text-gray-300">
                Download Personal Data (JSON)
              </button>
              <button className="w-full text-left px-4 py-3 bg-gray-700 hover:bg-gray-600 rounded-md text-gray-300">
                Download Personal Data (CSV)
              </button>
            </div>
          </div>
          
          <div>
            <h3 className="text-lg font-medium text-white mb-3">Privacy Settings</h3>
            <div className="space-y-3">
              <a href="#" className="block px-4 py-3 bg-gray-700 hover:bg-gray-600 rounded-md text-gray-300">
                View Privacy Policy
              </a>
              <a href="#" className="block px-4 py-3 bg-gray-700 hover:bg-gray-600 rounded-md text-gray-300">
                View Terms of Service
              </a>
              <a href="#" className="block px-4 py-3 bg-gray-700 hover:bg-gray-600 rounded-md text-gray-300">
                View Data Retention Policy
              </a>
            </div>
          </div>
        </div>
        
        <div className="mt-8 pt-6 border-t border-gray-700">
          <AccountDeletionSection />
        </div>
      </section>
    </div>
  );
}
