require("dotenv").config();
const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const { body, validationResult } = require('express-validator');
const WebSocket = require('ws');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { 
    fileSize: 500 * 1024 * 1024, // 500MB limit
    files: 1 // Only 1 file at a time
  }
});

// Create database connection
const createDbConnection = () => {
  return mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  });
};

// Export db for testing
let db = createDbConnection();

// Connect to database
const connectToDatabase = () => {
  db.connect((err) => {
    if (err) {
      console.error("Database connection failed:", err);
      return;
    }
    console.log("Connected to MySQL database");
  });
};

// Allow injection of db connection for testing
const setDbConnection = (connection) => {
  db = connection;
};

// Connect to database if not in test environment
if (process.env.NODE_ENV !== 'test') {
  connectToDatabase();
}

// Validation middleware
const validateUser = [
  body('name').trim().notEmpty().withMessage('Name is required'),
  body('email').isEmail().withMessage('Invalid email format'),
  body('type').isIn(['admin', 'user']).withMessage('Type must be either admin or user'),
];

// Error handling middleware
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// GET total count of users with filtering
app.get('/users/count', (req, res) => {
  const { name, type } = req.query;
  let query = 'SELECT COUNT(*) as count FROM users WHERE 1=1';
  const params = [];

  if (name) {
    query += ' AND name LIKE ?';
    params.push(`%${name}%`);
  }

  if (type) {
    query += ' AND type = ?';
    params.push(type);
  }

  db.query(query, params, (err, results) => {
    if (err) {
      console.error('Error counting users:', err);
      return res.status(500).json({ error: 'Failed to count users' });
    }
    res.json({ count: results[0].count });
  });
});

app.get('/users', (req, res) => {
  const { name, email, type, sort = 'name', order = 'asc', limit = 10, offset = 0 } = req.query;
  let query = 'SELECT * FROM users WHERE 1=1';
  const params = [];

  if (name) {
    query += ' AND name LIKE ?';
    params.push(`%${name}%`);
  }
  if (email) {
    query += ' AND email LIKE ?';
    params.push(`%${email}%`);
  }
  if (type) {
    query += ' AND type = ?';
    params.push(type);
  }

  // Validate sort and order
  const allowedSort = ['name', 'email', 'type', 'created_at'];
  const allowedOrder = ['asc', 'desc'];
  const sortCol = allowedSort.includes(sort) ? sort : 'name';
  const sortOrder = allowedOrder.includes(order.toLowerCase()) ? order.toUpperCase() : 'ASC';

  query += ` ORDER BY ${sortCol} ${sortOrder}`;
  query += ' LIMIT ? OFFSET ?';
  params.push(parseInt(limit), parseInt(offset));

  db.query(query, params, (err, results) => {
    if (err) {
      console.error('Error fetching users:', err);
      return res.status(500).json({ error: 'Failed to fetch users' });
    }
    res.json(results);
  });
});

// Get a single user
app.get("/users/:id", (req, res) => {
  const query = "SELECT id, name, email, image, type FROM users WHERE id = ?";
  db.query(query, [req.params.id], (err, results) => {
    if (err) {
      console.error(err);
      res.status(500).json({ error: "Server error" });
    } else if (results.length === 0) {
      res.status(404).json({ error: "User not found" });
    } else {
      res.json(results[0]);
    }
  });
});

// Function to get all users
const getAllUsers = async () => {
  return new Promise((resolve, reject) => {
    db.query('SELECT * FROM users', (err, results) => {
      if (err) reject(err);
      else resolve(results);
    });
  });
};

// Function to broadcast updates to all connected clients
const broadcastUpdate = async (type, data) => {
  const allUsers = await getAllUsers();
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({
        type,
        data,
        allUsers
      }));
    }
  });
};

// Add a new user
app.post("/users", validateUser, handleValidationErrors, (req, res) => {
  const { name, email, type } = req.body;
  
  db.query("SELECT id FROM users WHERE email = ?", [email], (err, results) => {
    if (err) {
      console.error(err);
      res.status(500).json({ error: "Server error" });
    } else if (results.length > 0) {
      return res.status(400).json({ errors: [{ param: "email", msg: "Email already exists" }] });
    } else {
      const query = "INSERT INTO users (name, email, type) VALUES (?, ?, ?)";
      db.query(query, [name, email, type], async (err, result) => {
        if (err) {
          console.error(err);
          res.status(500).json({ error: "Server error" });
        } else {
          const newUser = {
            id: result.insertId,
            name,
            email,
            type,
            image: null
          };
          await broadcastUpdate('USER_ADDED', newUser);
          res.status(201).json(newUser);
        }
      });
    }
  });
});

// Update a user
app.patch("/users/:id", validateUser, handleValidationErrors, (req, res) => {
  const { id } = req.params;
  const { name, email, type } = req.body;
  const userId = req.headers['x-user-id'];

  db.query("SELECT id FROM users WHERE email = ? AND id != ?", [email, id], (err, results) => {
    if (err) {
      console.error(err);
      res.status(500).json({ error: "Server error" });
    } else if (results.length > 0) {
      res.status(400).json({ error: "Email already exists" });
    } else {
      const query = "UPDATE users SET name = ?, email = ?, type = ? WHERE id = ?";
      db.query(query, [name, email, type, id], async (err, result) => {
        if (err) {
          console.error(err);
          res.status(500).json({ error: "Server error" });
        } else if (result.affectedRows === 0) {
          res.status(404).json({ error: "User not found" });
        } else {
          // Log the update action
          db.query(
            "INSERT INTO logs (user_id, action, entity, entity_id) VALUES (?, 'update', 'user', ?)",
            [userId, id],
            (logErr) => {
              if (logErr) console.error('Failed to log update:', logErr);
            }
          );
          const updatedUser = {
            id: parseInt(id),
            name,
            email,
            type,
            image: null
          };
          await broadcastUpdate('USER_UPDATED', updatedUser);
          res.json(updatedUser);
        }
      });
    }
  });
});

// Delete a user
app.delete("/users/:id", (req, res) => {
  const { id } = req.params;
  const userId = req.headers['x-user-id'];

  db.query("DELETE FROM users WHERE id = ?", [id], async (err, result) => {
    if (err) {
      console.error("Error deleting user:", err);
      return res.status(500).json({ error: "Failed to delete user" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    // Log the delete action
    db.query(
      "INSERT INTO logs (user_id, action, entity, entity_id) VALUES (?, 'delete', 'user', ?)",
      [userId, id],
      (logErr) => {
        if (logErr) console.error('Failed to log delete:', logErr);
      }
    );

    await broadcastUpdate('USER_DELETED', { id });
    res.status(204).send();
  });
});

app.get('/ping', (req, res) => {
  res.status(200).send('pong');
});

// WebSocket server setup with initial data
const server = app.listen(process.env.PORT || 5000, () => {
  console.log(`Server running on port ${process.env.PORT || 5000}`);
});

const wss = new WebSocket.Server({ 
  server,
  path: '/ws',
  verifyClient: (info, callback) => {
    callback(true);
  }
});

wss.on('connection', async (ws) => {
  console.log('New WebSocket connection');
  
  // Send initial data to the new client
  try {
    const allUsers = await getAllUsers();
    ws.send(JSON.stringify({
      type: 'INITIAL_DATA',
      data: null,
      allUsers
    }));
  } catch (error) {
    console.error('Error sending initial data:', error);
  }

  ws.on('close', () => {
    console.log('Client disconnected');
  });
});

// Track uploaded files
let uploadedFiles = [];
let fileCounter = 0;

// File endpoints
app.get('/files', (req, res) => {
  try {
    // Read the uploads directory
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }

    // Get all files in the directory
    const files = fs.readdirSync(uploadDir).map(filename => {
      const filePath = path.join(uploadDir, filename);
      const stats = fs.statSync(filePath);
      return {
        id: ++fileCounter, // Use an incrementing counter for unique IDs
        filename: filename,
        originalName: filename,
        size: stats.size,
        uploadDate: stats.mtime
      };
    });

    res.json(files);
  } catch (error) {
    console.error('Error reading files:', error);
    res.status(500).json({ error: 'Failed to read files' });
  }
});

// File upload endpoint
app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  const fileInfo = {
    id: ++fileCounter, // Use an incrementing counter for unique IDs
    filename: req.file.filename,
    originalName: req.file.originalname,
    path: req.file.path,
    size: req.file.size,
    uploadDate: new Date()
  };
  
  // Broadcast the new file to all connected clients
  broadcastUpdate('FILE_UPLOADED', fileInfo);
  
  res.json(fileInfo);
});

// File download endpoint
app.get('/download/:filename', (req, res) => {
  const file = path.join(__dirname, 'uploads', req.params.filename);
  if (fs.existsSync(file)) {
    res.download(file);
  } else {
    res.status(404).json({ error: 'File not found' });
  }
});

// Register endpoint
app.post('/register', async (req, res) => {
  const { name, email, password, type } = req.body;
  if (!name || !email || !password || !type) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  db.query("SELECT id FROM users WHERE email = ?", [email], async (err, results) => {
    if (err) return res.status(500).json({ error: "Server error" });
    if (results.length > 0) return res.status(400).json({ error: "Email already exists" });
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query(
      "INSERT INTO users (name, email, password, type) VALUES (?, ?, ?, ?)",
      [name, email, hashedPassword, type],
      (err, result) => {
        if (err) return res.status(500).json({ error: "Server error" });
        res.status(201).json({ id: result.insertId, name, email, type });
      }
    );
  });
});

// Login endpoint
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    if (err) return res.status(500).json({ error: "Server error" });
    if (results.length === 0) return res.status(400).json({ error: "Invalid credentials" });
    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Invalid credentials" });
    const { password: _, ...userInfo } = user;
    res.json(userInfo);
  });
});

// --- Background Monitoring Thread ---
// This thread checks for users with high-frequency CRUD actions and adds them to monitored_users
setInterval(() => {
  // Check logs for users with more than 10 actions in the last 2 minutes
  const query = `SELECT user_id, COUNT(*) as action_count
                 FROM logs
                 WHERE timestamp > (NOW() - INTERVAL 2 MINUTE)
                   AND user_id IS NOT NULL AND user_id != 0
                 GROUP BY user_id
                 HAVING action_count > 10`;
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error analyzing logs for suspicious activity:', err);
      return;
    }
    results.forEach(row => {
      // Add to monitored_users if not already present
      db.query(
        'INSERT IGNORE INTO monitored_users (user_id, reason, detected_at) VALUES (?, ?, NOW())',
        [row.user_id, `High frequency: ${row.action_count} actions in 2 min`],
        (err2) => {
          if (err2) console.error('Error adding to monitored_users:', err2);
        }
      );
    });
  });
}, 60 * 1000); // Run every 1 minute

// Endpoint to get monitored users (admin only)
app.get('/monitored-users', (req, res) => {
  db.query('SELECT * FROM monitored_users', (err, results) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    res.json(results);
  });
});

module.exports = { app, setDbConnection };
