import React, { useEffect, useState } from 'react';
import BarChartOne from './bar/BarChartOne';
import LineChartOne from './line/LineChartOne';

interface User {
  id: number;
  name: string;
  email: string;
  image: string;
  type: string;
}

interface UserChartsProps {
  users: User[];
}

export default function UserCharts({ users }: UserChartsProps) {
  const [typeData, setTypeData] = useState<{ name: string; value: number }[]>([]);
  const [emailDomainData, setEmailDomainData] = useState<{ name: string; value: number }[]>([]);
  const [userTrendData, setUserTrendData] = useState<{ name: string; value: number }[]>([]);

  useEffect(() => {
    // Process user type distribution
    const typeDistribution = users.reduce((acc: { [key: string]: number }, user) => {
      acc[user.type] = (acc[user.type] || 0) + 1;
      return acc;
    }, {});

    setTypeData(
      Object.entries(typeDistribution).map(([name, value]) => ({
        name,
        value,
      }))
    );

    // Process email domain distribution
    const domainDistribution = users.reduce((acc: { [key: string]: number }, user) => {
      const domain = user.email.split('@')[1];
      acc[domain] = (acc[domain] || 0) + 1;
      return acc;
    }, {});

    setEmailDomainData(
      Object.entries(domainDistribution).map(([name, value]) => ({
        name,
        value,
      }))
    );

    // Process user trend data (using IDs as time points)
    const sortedUsers = [...users].sort((a, b) => a.id - b.id);
    setUserTrendData(
      sortedUsers.map((user, index) => ({
        name: `User ${index + 1}`,
        value: index + 1,
      }))
    );
  }, [users]);

  return (
    <div className="flex flex-col gap-8 p-4">
      <div className="bg-white p-6 rounded-lg shadow">
        <h3 className="text-xl font-semibold mb-6">User Type Distribution</h3>
        <BarChartOne data={typeData} title="Number of Users" />
      </div>
      <div className="bg-white p-6 rounded-lg shadow">
        <h3 className="text-xl font-semibold mb-6">Email Domain Distribution</h3>
        <BarChartOne data={emailDomainData} title="Number of Users" />
      </div>
      <div className="bg-white p-6 rounded-lg shadow">
        <h3 className="text-xl font-semibold mb-6">User Registration Trend</h3>
        <LineChartOne data={userTrendData} title="User Count" />
      </div>
    </div>
  );
} 