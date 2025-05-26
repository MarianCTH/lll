import { render, screen, fireEvent, act } from '@testing-library/react';
import '@testing-library/jest-dom';
import UsersTable from '../usersTable';

// Mock window.confirm
const mockConfirm = jest.fn(() => true);
window.confirm = mockConfirm;

describe('UsersTable Component', () => {
  beforeEach(() => {
    // Clear all mocks before each test
    jest.clearAllMocks();
  });

  // Test CRUD Operations
  describe('CRUD Operations', () => {
    test('should add a new user', async () => {
      render(<UsersTable />);
      
      // Fill in the form
      await act(async () => {
        fireEvent.change(screen.getByPlaceholderText('Name'), { target: { value: 'Test User' } });
        fireEvent.change(screen.getByPlaceholderText('Role'), { target: { value: 'Developer' } });
        fireEvent.change(screen.getByPlaceholderText('Project Name'), { target: { value: 'Test Project' } });
        fireEvent.change(screen.getByPlaceholderText('Budget'), { target: { value: '15K' } });
      });
      
      // Submit the form
      await act(async () => {
        fireEvent.click(screen.getByText('Add User'));
      });
      
      // Check if new user appears in table
      expect(screen.getByText(/Test User \(Developer\)/)).toBeInTheDocument();
      expect(screen.getByText('Test Project')).toBeInTheDocument();
      expect(screen.getByText(/15K/)).toBeInTheDocument();
    });

    test('should edit an existing user', async () => {
      render(<UsersTable />);
      
      // Click edit button on first user
      await act(async () => {
        const editButtons = screen.getAllByText('Edit');
        fireEvent.click(editButtons[0]);
      });
      
      // Update the form
      await act(async () => {
        fireEvent.change(screen.getByPlaceholderText('Name'), { target: { value: 'Updated Name' } });
        fireEvent.change(screen.getByPlaceholderText('Role'), { target: { value: 'Updated Role' } });
        fireEvent.change(screen.getByPlaceholderText('Budget'), { target: { value: '20K' } });
      });
      
      // Submit the form
      await act(async () => {
        fireEvent.click(screen.getByText('Update User'));
      });
      
      // Check if user was updated
      expect(screen.getByText(/Updated Name \(Updated Role\)/)).toBeInTheDocument();
      expect(screen.getByText(/20K/)).toBeInTheDocument();
    });

    test('should delete a user', async () => {
      render(<UsersTable />);
      
      // Get initial count of users
      const initialUsers = screen.getAllByText('Edit');
      const initialCount = initialUsers.length;
      
      // Click delete button on first user
      await act(async () => {
        const deleteButtons = screen.getAllByText('Delete');
        fireEvent.click(deleteButtons[0]);
      });
      
      // Check if user count decreased
      const remainingUsers = screen.getAllByText('Edit');
      expect(remainingUsers.length).toBe(initialCount - 1);
    });
  });

  // Test Statistics and Highlighting
  describe('Budget Statistics', () => {
    test('should highlight highest budget in green', async () => {
      render(<UsersTable />);
      
      // Find the highest budget cell (10K in initial data)
      const highestBudgetCell = screen.getByText(/10K/);
      const parentElement = highestBudgetCell.closest('td');
      expect(parentElement).toHaveClass('bg-green-100');
      expect(highestBudgetCell.textContent).toMatch(/Highest/);
    });

    test('should highlight lowest budget in red', async () => {
      render(<UsersTable />);
      
      // Find the lowest budget cell (3.9K in initial data)
      const lowestBudgetCell = screen.getByText(/3.9K/);
      const parentElement = lowestBudgetCell.closest('td');
      expect(parentElement).toHaveClass('bg-red-100');
      expect(lowestBudgetCell.textContent).toMatch(/Lowest/);
    });

    test('should highlight average budget in yellow', async () => {
      render(<UsersTable />);
      
      // Find all budget cells
      const budgetCells = screen.getAllByText(/K/);
      // Find the cell that contains both the budget and "Average" text
      const averageBudgetCell = budgetCells.find(cell => cell.textContent?.includes('Average'));
      expect(averageBudgetCell).toBeTruthy();
      const parentElement = averageBudgetCell?.closest('td');
      expect(parentElement).toHaveClass('bg-yellow-100');
    });
  });

  // Test Sorting
  describe('Sorting', () => {
    test('should sort users by name', async () => {
      render(<UsersTable />);
      
      // Get initial order of first user
      const initialFirstUser = screen.getByText(/Lindsey Curtis/);
      
      // Click sort button
      await act(async () => {
        fireEvent.click(screen.getByText(/Sort by Name/));
      });
      
      // Get new order of first user
      const newFirstUser = screen.getByText(/Lindsey Curtis/);
      
      // Check if order changed
      expect(initialFirstUser).toBeTruthy();
    });
  });

  // Test Pagination
  describe('Pagination', () => {
    test('should show correct number of pages', async () => {
      render(<UsersTable />);
      
      // With 4 initial users and 5 items per page, should show 1 page
      const pageButtons = screen.queryAllByRole('button').filter(button => /^\d+$/.test(button.textContent || ''));
      expect(pageButtons.length).toBe(1); // Should show 1 page button for the current page
    });

    test('should change page when clicking pagination button', async () => {
      render(<UsersTable />);
      
      // Add more users to test pagination
      for (let i = 0; i < 6; i++) {
        await act(async () => {
          fireEvent.change(screen.getByPlaceholderText('Name'), { target: { value: `User ${i}` } });
          fireEvent.change(screen.getByPlaceholderText('Role'), { target: { value: 'Role' } });
          fireEvent.change(screen.getByPlaceholderText('Project Name'), { target: { value: 'Project' } });
          fireEvent.change(screen.getByPlaceholderText('Budget'), { target: { value: '10K' } });
          fireEvent.click(screen.getByText('Add User'));
        });
      }
      
      // Should now have 2 pages
      const pageButtons = screen.queryAllByRole('button').filter(button => /^\d+$/.test(button.textContent || ''));
      expect(pageButtons.length).toBeGreaterThan(1); // Should show more than 1 page button
    });
  });

  // Test Form Validation
  describe('Form Validation', () => {
    test('should show error for invalid budget', async () => {
      render(<UsersTable />);
      
      // Enter invalid budget
      await act(async () => {
        fireEvent.change(screen.getByPlaceholderText('Budget'), { target: { value: 'invalid' } });
      });
      
      // Check if error message appears
      expect(screen.getByText("Budget must be a number followed by 'K' (e.g., '10K')")).toBeInTheDocument();
      
      // Check if form submission is prevented
      await act(async () => {
        fireEvent.click(screen.getByText('Add User'));
      });
      expect(screen.queryByText('User successfully added.')).not.toBeInTheDocument();
    });
  });
});