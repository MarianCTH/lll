"use client";
import React, { useEffect, useState } from 'react';

interface MonitoredUser {
  user_id: number;
  reason: string;
  detected_at: string;
}

export default function MonitoredUsersTable() {
  const [users, setUsers] = useState<MonitoredUser[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('http://localhost:5000/monitored-users')
      .then(res => {
        if (!res.ok) throw new Error('Not authorized or server error');
        return res.json();
      })
      .then(data => setUsers(data))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div>Loading...</div>;
  if (error) return <div className="text-red-500">{error}</div>;

  return (
    <div className="overflow-x-auto">
      <h2 className="text-lg font-semibold mb-4">Monitored Users</h2>
      <table className="min-w-full border border-gray-200">
        <thead>
          <tr>
            <th className="border px-4 py-2">User ID</th>
            <th className="border px-4 py-2">Reason</th>
            <th className="border px-4 py-2">Detected At</th>
          </tr>
        </thead>
        <tbody>
          {users.map(user => (
            <tr key={user.user_id + user.detected_at}>
              <td className="border px-4 py-2">{user.user_id}</td>
              <td className="border px-4 py-2">{user.reason}</td>
              <td className="border px-4 py-2">{user.detected_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
} 