"use client";
import React, { useEffect, useState } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHeader,
  TableRow,
} from "../ui/table";
import Badge from "../ui/badge/Badge";
import Image from "next/image";
import Button from "../ui/button/Button";

interface User {
  id: number;
  name: string;
  email: string;
  image: string;
  type: string;
}

export default function UsersTable() {
  const [users, setUsers] = useState<User[]>([]);
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [editForm, setEditForm] = useState({ name: '', email: '', type: '' });
  const [showEditForm, setShowEditForm] = useState(false);
  const [deleteId, setDeleteId] = useState<number | null>(null);
  const [filterName, setFilterName] = useState('');
  const [filterEmail, setFilterEmail] = useState('');
  const [filterType, setFilterType] = useState('');
  const [sortBy, setSortBy] = useState<'name' | 'email' | 'type' | 'created_at'>('name');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

  const fetchUsers = async () => {
    const offset = (currentPage - 1) * itemsPerPage;
    const params = new URLSearchParams({
      limit: itemsPerPage.toString(),
      offset: offset.toString(),
      name: filterName,
      email: filterEmail,
      type: filterType,
      sort: sortBy,
      order: sortOrder,
    });
    try {
      const res = await fetch(`http://localhost:5000/users?${params.toString()}`);
      if (!res.ok) throw new Error('Failed to fetch users');
      const data = await res.json();
      setUsers(data);
    } catch (error) {
      console.error('Error fetching users:', error);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, [currentPage, filterName, filterEmail, filterType, sortBy, sortOrder]);

  const handleEditClick = (user: User) => {
    setEditingUser(user);
    setEditForm({ name: user.name, email: user.email, type: user.type });
    setShowEditForm(true);
  };

  const handleEditSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingUser) return;
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    try {
      const res = await fetch(`http://localhost:5000/users/${editingUser.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', 'X-User-Id': user.id },
        body: JSON.stringify(editForm),
      });
      if (!res.ok) throw new Error('Failed to update user');
      setShowEditForm(false);
      setEditingUser(null);
      fetchUsers();
    } catch (err) {
      alert('Failed to update user');
    }
  };

  const handleDeleteClick = (id: number) => {
    setDeleteId(id);
  };

  const confirmDelete = async () => {
    if (deleteId === null) return;
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    try {
      const res = await fetch(`http://localhost:5000/users/${deleteId}`, { method: 'DELETE', headers: { 'X-User-Id': user.id } });
      if (!res.ok) throw new Error('Failed to delete user');
      setDeleteId(null);
      fetchUsers();
    } catch (err) {
      alert('Failed to delete user');
    }
  };

  const cancelDelete = () => setDeleteId(null);

  return (
    <div className="overflow-hidden rounded-xl border border-gray-200 bg-white dark:border-white/[0.05] dark:bg-white/[0.03]">
      <div className="max-w-full overflow-x-auto">
        <div className="min-w-[1102px]">
          <Table>
            <TableHeader className="border-b border-gray-100 dark:border-white/[0.05]">
              <TableRow>
                <TableCell isHeader className="px-5 py-3 text-start">
                  <div className="cursor-pointer select-none" onClick={() => { setSortBy('name'); setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc'); }}>
                    Utilizator {sortBy === 'name' ? (sortOrder === 'asc' ? '▲' : '▼') : ''}
                  </div>
                </TableCell>
                <TableCell isHeader className="px-5 py-3 text-start">
                  <div className="cursor-pointer select-none" onClick={() => { setSortBy('email'); setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc'); }}>
                    Email {sortBy === 'email' ? (sortOrder === 'asc' ? '▲' : '▼') : ''}
                  </div>
                </TableCell>
                <TableCell isHeader className="px-5 py-3 text-start">
                  <div className="cursor-pointer select-none" onClick={() => { setSortBy('type'); setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc'); }}>
                    Tip utilizator {sortBy === 'type' ? (sortOrder === 'asc' ? '▲' : '▼') : ''}
                  </div>
                </TableCell>
                <TableCell isHeader className="px-5 py-3 text-start">
                  Actions
                </TableCell>
              </TableRow>
            </TableHeader>

            <TableBody className="divide-y divide-gray-100 dark:divide-white/[0.05]">
              {users.map((user) => (
                <TableRow key={user.id}>
                  <TableCell className="px-5 py-4 text-start">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 overflow-hidden rounded-full">
                        <Image
                          width={40}
                          height={40}
                          src={`/images/user/owner.jpg`}
                          alt={user.name}
                        />
                      </div>
                      <div>
                        <span className="block font-medium text-gray-800 dark:text-white/90">
                          {user.name}
                        </span>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell className="px-4 py-3 text-gray-500 text-start">
                    {user.email}
                  </TableCell>
                  <TableCell className="px-4 py-3 text-gray-500 text-start">
                    <Badge color={user.type === "Agent imobiliar" ? "success" : "info"}>
                      {user.type}
                    </Badge>
                  </TableCell>
                  <TableCell className="px-4 py-3 text-gray-500 text-start">
                    <Button onClick={() => handleEditClick(user)} className="mr-2 bg-blue-500 text-white">Edit</Button>
                    <Button onClick={() => handleDeleteClick(user.id)} className="bg-red-500 text-white">Delete</Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>
      <div className="flex justify-between items-center mt-4">
        <Button onClick={() => setCurrentPage((prev) => Math.max(prev - 1, 1))} disabled={currentPage === 1}>
          Previous
        </Button>
        <span>Page {currentPage}</span>
        <Button onClick={() => setCurrentPage((prev) => prev + 1)} disabled={users.length < itemsPerPage}>
          Next
        </Button>
      </div>
      {deleteId !== null && (
        <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50 z-50">
          <div className="bg-white p-6 rounded shadow">
            <p>Are you sure you want to delete this user?</p>
            <div className="mt-4 flex gap-2">
              <Button onClick={confirmDelete} className="bg-red-500 text-white">Yes, Delete</Button>
              <Button onClick={cancelDelete}>Cancel</Button>
            </div>
          </div>
        </div>
      )}
      {showEditForm && (
        <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50 z-50">
          <form onSubmit={handleEditSubmit} className="bg-white p-6 rounded shadow w-80">
            <h2 className="mb-4 text-lg font-semibold">Edit User</h2>
            <div className="mb-2">
              <label className="block mb-1">Name</label>
              <input
                type="text"
                value={editForm.name}
                onChange={e => setEditForm(f => ({ ...f, name: e.target.value }))}
                className="w-full border px-2 py-1 rounded"
                required
              />
            </div>
            <div className="mb-2">
              <label className="block mb-1">Email</label>
              <input
                type="email"
                value={editForm.email}
                onChange={e => setEditForm(f => ({ ...f, email: e.target.value }))}
                className="w-full border px-2 py-1 rounded"
                required
              />
            </div>
            <div className="mb-4">
              <label className="block mb-1">Type</label>
              <input
                type="text"
                value={editForm.type}
                onChange={e => setEditForm(f => ({ ...f, type: e.target.value }))}
                className="w-full border px-2 py-1 rounded"
                required
              />
            </div>
            <div className="flex gap-2">
              <Button type="submit" className="bg-blue-500 text-white">Save</Button>
              <Button onClick={() => setShowEditForm(false)} type="button">Cancel</Button>
            </div>
          </form>
        </div>
      )}
      <div className="flex gap-2 mb-4">
        <input
          type="text"
          placeholder="Filter by name"
          value={filterName}
          onChange={e => setFilterName(e.target.value)}
          className="border px-2 py-1 rounded"
        />
        <input
          type="text"
          placeholder="Filter by email"
          value={filterEmail}
          onChange={e => setFilterEmail(e.target.value)}
          className="border px-2 py-1 rounded"
        />
        <input
          type="text"
          placeholder="Filter by type"
          value={filterType}
          onChange={e => setFilterType(e.target.value)}
          className="border px-2 py-1 rounded"
        />
      </div>
    </div>
  );
}
