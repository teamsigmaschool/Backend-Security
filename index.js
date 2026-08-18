let express = require('express');
let app = express();

const { Pool } = require('pg');
require('dotenv').config();
const cors = require('cors');
const { supabase } = require('./supabaseClient');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet')

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.use(helmet())
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || 'http://localhost:5173' }));
app.use(express.json({ limit: process.env.BODY_SIZE_LIMIT || '10kb' }));

// ---------- helper functions ----------
function sendSuccess(res, data, meta = {}, status = 200) {
  res.status(status).json({ success: true, data, meta });
}
class ApiError extends Error {
  constructor(status, title, detail) {
    super(detail || title);
    this.status = status;
    this.title = title;
    this.detail = detail;
  }
}
function validatePost(body, { requireAll = true } = {}) {
  const errors = [];
  const clean = {};

  if (body.title !== undefined) {
    clean.title = sanitizeText(body.title);
    if (!clean.title) errors.push('title cannot be empty');
    else if (clean.title.length > 200) errors.push('title must be 200 characters or fewer');
  } else if (requireAll) {
    errors.push('title is required');
  }

  if (body.content !== undefined) {
    clean.content = sanitizeText(body.content);
    if (!clean.content) errors.push('content cannot be empty');
    else if (clean.content.length > 5000) errors.push('content must be 5000 characters or fewer');
  } else if (requireAll) {
    errors.push('content is required');
  }

  return { errors, clean };
}
function sanitizeText(value) {
  if (typeof value !== 'string') return value;
  return value
    .trim()                    // drop leading/trailing whitespace
    .replace(/\s+/g, ' ')      // collapse repeated whitespace into one space
    .replace(/<[^>]*>/g, '');  // strip anything that looks like an HTML tag
}

// ---------- secure api ----------
const generalLimiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX) || 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 
    { status: 429, 
      title: 'Too Many Requests', 
      detail: 'Slow down and try again shortly.' 
    } },
});
app.use(generalLimiter);


// ---------- secure auth ----------
function validateSignup({ password }) {
  const errors = [];

  if (typeof password !== 'string' || password.length < 8) {
    errors.push('password must be at least 8 characters');

  } else if (!/[0-9]/.test(password)) {
    errors.push('password must contain at least one number');

  } else if (!/[^A-Za-z0-9]/.test(password)) {
    errors.push('password must contain at least one special character');
  }
  return errors;
}
const loginLimiter = rateLimit({
  windowMs: Number(process.env.LOGIN_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: Number(process.env.LOGIN_RATE_LIMIT_MAX) || 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: { 
    status: 429, 
    title: 'Too Many Requests', 
    detail: 'Too many login attempts. Try again shortly.' } },
});

// ---------- auth gate ----------
async function verifySupabaseSessionV1(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).end();
  const token = auth.split(' ')[1];
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data.user) return res.status(401).end();
  req.user = {
    userId: data.user.id,
    email: data.user.email,
    role: data.user.app_metadata?.role || 'user',
  };
  next();
}
async function verifySupabaseSessionV2(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return next(new ApiError(401, 'Unauthorized', 'Missing Authorization header'));
  const token = auth.split(' ')[1];
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data.user) return next(new ApiError(401, 'Unauthorized', 'Invalid or expired session'));
  req.user = {
    userId: data.user.id,
    email: data.user.email,
    role: data.user.app_metadata?.role || 'user',
  };
  next();
}

function requireRoleV1(role) {
  return (req, res, next) => {
    if (req.user.role !== role) return res.status(403).end();
    next();
  };
}
function requireRoleV2(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return next(new ApiError(403, 'Forbidden', `Requires the '${role}' role`));
    }
    next();
  };
}

// ---------- whoami ----------
async function whoamiV1(req, res) {
  res.json({ userId: req.user.userId, email: req.user.email, role: req.user.role });
}
async function whoamiV2(req, res) {
  sendSuccess(res, { userId: req.user.userId, email: req.user.email, role: req.user.role });
}

// ---------- auth ----------
async function signupV1(req, res) {
  const { email, password } = req.body;
  const { data, error } = await supabase.auth.signUp({ email, password });
  if (error) {
    if (error.message.includes('already registered')) {
      return res.status(409).json({ error: 'Email already in use' });
    }
    return res.status(400).json({ error: error.message });
  }
  res.status(201).json({ user: data.user });
}
async function signupV2(req, res, next) {
  const { email, password } = req.body;
  const errors = validateSignup({ email, password });
  if (errors.length) {
    return next(new ApiError(400, 'Bad Request', errors.join('; ')));
  }
  const { data, error } = await supabase.auth.signUp({ email, password });
  if (error) {
    if (error.message.includes('already registered')) {
      return next(new ApiError(409, 'Conflict', 'Email already in use'));
    }
    return next(new ApiError(400, 'Bad Request', error.message));
  }
  sendSuccess(res, { user: data.user }, {}, 201);
}

async function loginV1(req, res) {
  const { email, password } = req.body;
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return res.status(401).json({ error: error.message });
  res.json({ session: data.session });
}
async function loginV2(req, res, next) {
  const { email, password } = req.body;
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return next(new ApiError(401, 'Unauthorized', error.message));
  sendSuccess(res, { session: data.session });
}

// ---------- posts: list ----------
async function getAllPostsV1(req, res) {
  try {
    const result = await pool.query(
      `SELECT posts.id, posts.title, posts.content, posts.created_at, users.username AS author
       FROM posts JOIN users ON posts.user_id = users.id
       ORDER BY posts.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
}

const SORTABLE_FIELDS = { created_at: 'posts.created_at', title: 'posts.title' };

async function getAllPostsV2(req, res, next) {
  try {
    let page = parseInt(req.query.page, 10);
    let limit = parseInt(req.query.limit, 10);
    if (!Number.isInteger(page) || page < 1) page = 1;
    if (!Number.isInteger(limit) || limit < 1) limit = 10;
    if (limit > 50) limit = 50;

    const offset = (page - 1) * limit;

    const { author, sort, order, search } = req.query;
    const conditions = [];
    const values = [];
    if (author) {
      values.push(author);
      conditions.push(`users.username = $${values.length}`);
    }
    if (search) {
      values.push(`%${search}%`);
      conditions.push(`(posts.title ILIKE $${values.length} OR posts.content ILIKE $${values.length})`);
    }

    let ourFilter;
    if (conditions.length >= 1) {
      ourFilter = `WHERE ${conditions.join(' AND ')}`;
    }
    else {
      ourFilter = '';
    }

    const selectedColumn = SORTABLE_FIELDS[sort] ? sort : 'created_at';
    const sortColumn = SORTABLE_FIELDS[selectedColumn];
    const sortOrder = String(order).toLowerCase() === 'asc' ? 'ASC' : 'DESC';

    const countResult = await pool.query
    (`SELECT COUNT(*) FROM posts JOIN users ON posts.user_id = users.id ${ourFilter}`,
      values);

    const totalCount = parseInt(countResult.rows[0].count, 10);

    values.push(limit);
    const attachedLimit = `$${values.length}`;

    values.push(offset);
    const attachedOffset = `$${values.length}`;

    const result = await pool.query(
      `SELECT posts.id, posts.title, posts.content, posts.created_at,
              users.id AS author_id, users.username AS author_username
       FROM posts JOIN users ON posts.user_id = users.id
       ${ourFilter}
       ORDER BY ${sortColumn} ${sortOrder}
       LIMIT ${attachedLimit} OFFSET ${attachedOffset}`,
       values
    );
    sendSuccess(res, result.rows, {
      page,
      limit,
      totalCount,
      totalPages: Math.ceil(totalCount / limit),
      sort: selectedColumn,
      order: sortOrder.toLowerCase(),
    });
  } catch (err) {
    next(err);
  }
}

// ---------- posts: create ----------
async function createPostV1(req, res) {
  const { title, content } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO posts (title, content, user_id) VALUES ($1, $2, $3) RETURNING *',
      [title, content, req.user.userId]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
}
async function createPostV2(req, res, next) {
  //const { title, content } = req.body;
  const { errors, clean } = validatePost(req.body, { requireAll: true });
  if (errors.length) {
    return next(new ApiError(400, 'Bad Request', errors.join('; ')));
  }
  try {
    const result = await pool.query(
      'INSERT INTO posts (title, content, user_id) VALUES ($1, $2, $3) RETURNING *',
      [clean.title, clean.content, req.user.userId]
    );
    sendSuccess(res, result.rows[0], {}, 201);
  } catch (err) {
    next(err);
  }
}

// ---------- posts: update ----------
async function updatePostV1(req, res) {
  const { title, content } = req.body;
  try {
    const result = await pool.query(
      `UPDATE posts SET title = COALESCE($1, title), content = COALESCE($2, content)
       WHERE id = $3 AND user_id = $4 RETURNING *`,
      [title, content, req.params.id, req.user.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Post not found, or not yours to edit' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
}
async function updatePostV2(req, res, next) {
  //const { title, content } = req.body;
  const { errors, clean } = validatePost(req.body, { requireAll: false });
  if (errors.length) {
    return next(new ApiError(400, 'Bad Request', errors.join('; ')));
  }
  try {
    const result = await pool.query(
      `UPDATE posts SET title = COALESCE($1, title), content = COALESCE($2, content)
       WHERE id = $3 AND user_id = $4 RETURNING *`,
      [clean.title, clean.content, req.params.id, req.user.userId]
    );
    if (result.rows.length === 0) {
      return next(new ApiError(404, 'Not Found', 'Post not found, or not yours to edit'));
    }
    sendSuccess(res, result.rows[0]);
  } catch (err) {
    next(err);
  }
}

// ---------- posts: delete ----------
async function deletePostV1(req, res) {
  try {
    const result = await pool.query(
      'DELETE FROM posts WHERE id = $1 AND user_id = $2 RETURNING *',
      [req.params.id, req.user.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Post not found, or not yours to delete' });
    }
    res.json({ deleted: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
}
async function deletePostV2(req, res, next) {
  try {
    const result = await pool.query(
      'DELETE FROM posts WHERE id = $1 AND user_id = $2 RETURNING *',
      [req.params.id, req.user.userId]
    );
    if (result.rows.length === 0) {
      return next(new ApiError(404, 'Not Found', 'Post not found, or not yours to delete'));
    }
    sendSuccess(res, result.rows[0]);
  } catch (err) {
    next(err);
  }
}

// ---------- posts: force delete ----------
async function forceDeletePostV1(req, res) {
  try {
    const result = await pool.query(
      'DELETE FROM posts WHERE id = $1 RETURNING *',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }
    res.json({ deleted: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
}
async function forceDeletePostV2(req, res, next) {
  try {
    const result = await pool.query(
      'DELETE FROM posts WHERE id = $1 RETURNING *',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return next(new ApiError(404, 'Not Found', 'Post not found'));
    }
    sendSuccess(res, result.rows[0]);
  } catch (err) {
    next(err);
  }
}

// ---------- v1 (unchanged — frozen from Ch2 onward, see Chapter 3 README) ----------
const v1 = express.Router();
v1.post('/auth/signup', signupV1);
v1.post('/auth/login', loginV1);
v1.get('/whoami', verifySupabaseSessionV1, whoamiV1);
v1.get('/posts', getAllPostsV1);
v1.post('/posts', verifySupabaseSessionV1, createPostV1);
v1.patch('/posts/:id', verifySupabaseSessionV1, updatePostV1);
v1.delete('/posts/:id', verifySupabaseSessionV1, deletePostV1);
v1.delete('/posts/:id/force', verifySupabaseSessionV1, requireRoleV1('admin'), forceDeletePostV1);

// ---------- v2 (Chapter 3 builds on this — only getAllPostsV2 changes from here) ----------
const v2 = express.Router();
v2.post('/auth/signup', signupV2);
v2.post('/auth/login', loginV2, loginLimiter);
v2.get('/whoami', verifySupabaseSessionV2, whoamiV2);
v2.get('/posts', getAllPostsV2);
v2.post('/posts', verifySupabaseSessionV2, createPostV2);
v2.patch('/posts/:id', verifySupabaseSessionV2, updatePostV2);
v2.delete('/posts/:id', verifySupabaseSessionV2, deletePostV2);
v2.delete('/posts/:id/force', verifySupabaseSessionV2, requireRoleV2('admin'), forceDeletePostV2);

app.use('/api/v1', v1);
app.use('/api/v2', v2);

app.use((req, res, next) => {
  next(new ApiError(404, 'Not Found', 'Route not found'));
});

app.use((err, req, res, next) => {
  if (err instanceof ApiError) {
    return res.status(err.status).json({
      success: false,
      error: { status: err.status, title: err.title, detail: err.detail },
    });
  }
  
  if (err.type === 'entity.too.large' || err.status === 413) {
    return res.status(413).json({
      success: false,
      error: { status: 413, title: 'Payload Too Large', detail: 'Request body exceeds the size limit.' },
    });
  }

  console.error(err);
  res.status(500).json({
    success: false,
    error: { status: 500, title: 'Internal Server Error', detail: 'Something went wrong' },
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Mini Blog API listening on port ${PORT}`);
});