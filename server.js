
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ROOT_DIR = __dirname;

const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const sessions = new Map();
const loginAttempts = new Map();

const SESSION_MS = 8 * 60 * 60 * 1000;
const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
  '.ico': 'image/x-icon'
};

function safeEqual(a, b) {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');

  return x.length === y.length &&
    crypto.timingSafeEqual(x, y);
}

function getSession(req) {
  const cookie = req.headers.cookie || '';
  const item = cookie.split(';').map(s => s.trim())
    .find(s => s.startsWith('jr_admin_session='));

  if (!item) return false;

  const token = item.slice('jr_admin_session='.length);
  const expiry = sessions.get(token);

  if (!expiry || expiry < Date.now()) {
    sessions.delete(token);
    return false;
  }

  return token;
}

function loginPage(message = '') {
  return `<!doctype html>
<html lang="bn">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JR TOP-UP Admin Login</title>
<style>
body{font-family:Arial,sans-serif;background:#eef3ff;
margin:0;padding:22px;color:#14264a}
main{max-width:400px;margin:45px auto;background:white;
padding:25px;border-radius:18px}
input,button{box-sizing:border-box;width:100%;padding:13px;
margin:9px 0;border-radius:9px;font-size:16px}
input{border:1px solid #ccd5e8}
button{border:0;background:#2864e8;color:white}
.error{color:#b42318}
</style>
</head>
<body><main>
<h1>JR TOP-UP</h1><h2>Admin Login</h2>
<p class="error">${message}</p>
<form method="POST" action="/admin-login">
<label>Username</label>
<input name="username" autocomplete="username" required>
<label>Password</label>
<input name="password" type="password"
autocomplete="current-password" required>
<button type="submit">Login</button>
</form></main></body></html>`;
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    ...headers
  });
  res.end(body);
}

const server = http.createServer((req, res) => {
  let pathname;

  try {
    pathname = decodeURIComponent(
      new URL(req.url, 'http://localhost').pathname
    );
  } catch {
    return send(res, 400, 'Bad Request');
  }

  if (pathname === '/admin-login' && req.method === 'GET') {
    return send(res, 200, loginPage());
  }

  if (pathname === '/admin-login' && req.method === 'POST') {
    if (!ADMIN_USER || !ADMIN_PASSWORD) {
      return send(res, 503, 'Admin login is not configured.');
    }

    const ip = req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    let record = loginAttempts.get(ip);

    if (!record || now - record.start > WINDOW_MS) {
      record = { start: now, count: 0 };
      loginAttempts.set(ip, record);
    }

    if (record.count >= MAX_ATTEMPTS) {
      return send(res, 429, 'Too many attempts. Try again later.');
    }

    let body = '';

    req.on('data', chunk => {
      body += chunk.toString();
      if (body.length > 4096) req.destroy();
    });

    req.on('end', () => {
      let form;

      try {
        form = new URLSearchParams(body);
      } catch {
        return send(res, 400, 'Invalid form');
      }

      const username = form.get('username') || '';
      const password = form.get('password') || '';

      if (
        !safeEqual(username, ADMIN_USER) ||
        !safeEqual(password, ADMIN_PASSWORD)
      ) {
        record.count++;
        return send(res, 401, loginPage('ভুল Username বা Password'));
      }

      loginAttempts.delete(ip);

      const token = crypto.randomBytes(32).toString('hex');
      sessions.set(token, Date.now() + SESSION_MS);

      return send(res, 303, '', {
        'Location': '/admin.html',
        'Set-Cookie':
          `jr_admin_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`
      });
    });

    return;
  }

  if (pathname === '/admin-logout') {
    const token = getSession(req);
    if (token) sessions.delete(token);

    return send(res, 303, '', {
      'Location': '/admin-login',
      'Set-Cookie':
        'jr_admin_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'
    });
  }

  if (pathname === '/admin.html') {
    if (!getSession(req)) {
      return send(res, 303, '', {
        'Location': '/admin-login'
      });
    }
  }

  let safeUrl = pathname;

  if (
    safeUrl === '/' ||
    safeUrl === '/index.html'
  ) {
    safeUrl = '/FFX.html';
  }

  const filePath = path.resolve(
    ROOT_DIR,
    '.' + safeUrl
  );

  const relative = path.relative(ROOT_DIR, filePath);

  if (
    relative.startsWith('..') ||
    path.isAbsolute(relative)
  ) {
    return send(res, 403, '403 Forbidden');
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      if (pathname === '/admin.html') {
        return send(res, 404, 'Admin page not found');
      }

      const fallback = path.join(ROOT_DIR, 'FFX.html');

      return fs.stat(fallback, (fallbackErr, fallbackStats) => {
        if (fallbackErr || !fallbackStats.isFile()) {
          return send(res, 404, '404 Not Found');
        }
        serveFile(fallback, res);
      });
    }

    serveFile(filePath, res);
  });
});

function serveFile(filePath, res) {
  const ext = path.extname(filePath).toLowerCase();
  const contentType =
    MIME_TYPES[ext] || 'application/octet-stream';

  res.writeHead(200, {
    'Content-Type': contentType,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Cache-Control': path.basename(filePath) === 'admin.html'
      ? 'no-store'
      : 'public, max-age=3600'
  });

  const stream = fs.createReadStream(filePath);

  stream.on('error', () => {
    if (!res.headersSent) {
      send(res, 500, '500 Internal Server Error');
    } else {
      res.destroy();
    }
  });

  stream.pipe(res);
}

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
