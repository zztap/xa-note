// Cloudflare Pages Functions 完整应用实现
import { Hono } from 'hono'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import { nanoid } from 'nanoid'

// Web Crypto based JWT helpers for Cloudflare Workers
async function generateToken(payload: any, secret?: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' }
  const jwtSecret = secret || 'default-secret'
  const encoder = new TextEncoder()
  const headerB64 = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  const payloadB64 = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  const data = headerB64 + '.' + payloadB64
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(jwtSecret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data))
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  return data + '.' + signatureB64
}

async function verifyToken(token: string, secret?: string): Promise<any> {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    const [headerB64, payloadB64, signatureB64] = parts
    const jwtSecret = secret || 'default-secret'
    const encoder = new TextEncoder()
    const data = headerB64 + '.' + payloadB64
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(jwtSecret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    )
    const signature = Uint8Array.from(atob(signatureB64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
    const isValid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data))
    if (!isValid) return null
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')))
    return payload
  } catch (error) {
    return null
  }
}

function generateSessionId(): string {
  return nanoid()
}

// Password hashing using Web Crypto with salt and iterations
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder()

  // Generate a random salt
  const salt = crypto.getRandomValues(new Uint8Array(16))

  // Import the password as a key
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  )

  // Derive a key using PBKDF2 with 100,000 iterations
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    passwordKey,
    256
  )

  // Combine salt and hash
  const hashArray = new Uint8Array(derivedBits)
  const combined = new Uint8Array(salt.length + hashArray.length)
  combined.set(salt)
  combined.set(hashArray, salt.length)

  // Convert to base64
  return btoa(String.fromCharCode(...combined))
}

async function comparePassword(password: string, stored: string): Promise<boolean> {
  try {
    const encoder = new TextEncoder()

    // Decode the stored hash
    const combined = Uint8Array.from(atob(stored), c => c.charCodeAt(0))
    const salt = combined.slice(0, 16)
    const storedHash = combined.slice(16)

    // Import the password as a key
    const passwordKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveBits']
    )

    // Derive the same key
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      passwordKey,
      256
    )

    const hashArray = new Uint8Array(derivedBits)

    // Compare hashes
    if (hashArray.length !== storedHash.length) return false

    let result = 0
    for (let i = 0; i < hashArray.length; i++) {
      result |= hashArray[i] ^ storedHash[i]
    }

    return result === 0
  } catch (error) {
    return false
  }
}

// Define the environment and variables types for Hono
type Bindings = {
  DB?: any
  JWT_SECRET?: string
}

type Variables = {
  db: any
  user?: any
}

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// D1 wrapper helpers
function dbPrepare(rawDb: any, sql: string) {
  return {
    async get(...params: any[]) {
      const stmt = rawDb.prepare(sql)
      if (params.length > 0) {
        const r = await stmt.bind(...params).first()
        return r || null
      }
      const r = await stmt.first()
      return r || null
    },
    async all(...params: any[]) {
      const stmt = rawDb.prepare(sql)
      const r = params.length > 0 ? await stmt.bind(...params).all() : await stmt.all()
      return r.results || []
    },
    async run(...params: any[]) {
      const stmt = rawDb.prepare(sql)
      const r = params.length > 0 ? await stmt.bind(...params).run() : await stmt.run()
      return { changes: r.changes || 0, lastInsertRowid: r.meta?.last_row_id ?? null }
    }
  }
}

function createDbWrapper(env: Bindings) {
  const raw = env?.DB
  if (!raw) throw new Error('D1 binding not found (env.DB)')
  return {
    prepare(sql: string) {
      return dbPrepare(raw, sql)
    },
    async isInstalled() {
      try {
        const r = await raw.prepare('SELECT value FROM settings WHERE key = ?').bind('system.installed').first()
        return r?.value === '1'
      } catch (error) {
        // If table doesn't exist, system is not installed
        return false
      }
    }
  }
}

// 数据库schema
const DATABASE_SCHEMA = `
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS categories (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY,
    title TEXT,
    content TEXT,
    tags TEXT,
    category_id TEXT,
    created_at INTEGER,
    updated_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS shares (
    id TEXT PRIMARY KEY,
    note_id TEXT,
    password TEXT,
    expires_at INTEGER,
    created_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS trash (
    id TEXT PRIMARY KEY,
    title TEXT,
    content TEXT,
    tags TEXT,
    category_id TEXT,
    created_at INTEGER,
    updated_at INTEGER,
    deleted_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS logs (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    details TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at INTEGER NOT NULL
  );

  -- Full Text Search Table
  CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(
    title, 
    content, 
    tags, 
    content='notes', 
    content_rowid='rowid'
  );

  -- FTS Synchronization Triggers
  CREATE TRIGGER IF NOT EXISTS notes_ai AFTER INSERT ON notes BEGIN
    INSERT INTO notes_fts(rowid, title, content, tags) VALUES (new.rowid, new.title, new.content, new.tags);
  END;
  CREATE TRIGGER IF NOT EXISTS notes_ad AFTER DELETE ON notes BEGIN
    INSERT INTO notes_fts(notes_fts, rowid, title, content, tags) VALUES('delete', old.rowid, old.title, old.content, old.tags);
  END;
  CREATE TRIGGER IF NOT EXISTS notes_au AFTER UPDATE ON notes BEGIN
    INSERT INTO notes_fts(notes_fts, rowid, title, content, tags) VALUES('delete', old.rowid, old.title, old.content, old.tags);
    INSERT INTO notes_fts(rowid, title, content, tags) VALUES (new.rowid, new.title, new.content, new.tags);
  END;
`;

// 获取当前环境的基础URL
function getBaseUrl(c: any): { apiUrl: string, frontendUrl: string } {
  const host = c.req.header('host') || 'localhost:9915'
  const protocol = c.req.header('x-forwarded-proto') ||
    c.req.header('cf-visitor') ? 'https' :
    (host.includes('localhost') ? 'http' : 'https')

  // Cloudflare Pages环境
  const baseUrl = `${protocol}://${host}`
  return {
    apiUrl: baseUrl,
    frontendUrl: baseUrl
  }
}

// 中间件：初始化数据库
app.use('*', async (c, next) => {
  try {
    const db = createDbWrapper(c.env)
    c.set('db', db)
    await next()
  } catch (err) {
    console.error('D1 binding not found:', err)
    return c.json({ error: 'D1 binding not found' }, 500)
  }
})

// 安全中间件
app.use('*', async (c, next) => {
  await next()
  c.header('X-Content-Type-Options', 'nosniff')
  c.header('X-Frame-Options', 'DENY')
  c.header('X-XSS-Protection', '1; mode=block')
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin')
  // Cloudflare Pages 默认提供 HSTS，这里作为双重保险
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload')
})

// 认证中间件
const requireAuth = async (c: any, next: any) => {
  const token = getCookie(c, 'auth_token')
  const sessionId = getCookie(c, 'session_id')

  if (!token || !sessionId) {
    return c.json({ error: 'UNAUTHORIZED', reason: 'missing_cookies' }, 401)
  }

  const payload = await verifyToken(token)
  if (!payload) {
    return c.json({ error: 'UNAUTHORIZED', reason: 'invalid_token' }, 401)
  }

  c.set('user', payload)
  await next()
}

// 安装检查中间件
const requireInstallation = async (c: any, next: any) => {
  // 跳过安装相关的API
  if (c.req.path.startsWith('/api/install') || c.req.path === '/api/settings/public') {
    await next()
    return
  }

  const db = c.get('db') as any
  const isInstalled = await db.isInstalled()
  if (!isInstalled) {
    return c.json({ error: 'NOT_INSTALLED', redirect: '/install' }, 503)
  }
  await next()
}

// 防止重复安装中间件
const preventReinstall = async (c: any, next: any) => {
  const db = c.get('db') as any
  const isInstalled = await db.isInstalled()
  if (isInstalled) {
    return c.json({ error: 'ALREADY_INSTALLED' }, 400)
  }
  await next()
}

// 健康检查
app.get('/api/health', (c) => {
  return c.json({
    status: 'ok',
    platform: 'cloudflare-pages',
    database: 'd1',
    timestamp: new Date().toISOString()
  })
})

// 安装状态检查
app.get('/api/install/status', async (c) => {
  const db = c.get('db') as any
  try {
    const isInstalled = await db.isInstalled()
    return c.json({ installed: isInstalled })
  } catch (error) {
    return c.json({ installed: false, error: 'Database check failed' })
  }
})

// 日志记录辅助函数
async function logAction(c: any, params: {
  user_id: string
  action: string
  target_type?: string
  target_id?: string
  details?: any
  ip_address?: string
  user_agent?: string
}): Promise<void> {
  const db = c.get('db') as any
  const executionCtx = c.executionCtx

  const id = nanoid()
  const created_at = Date.now()
  const logPromise = (async () => {
    try {
      await db.prepare(`
        INSERT INTO logs (id, user_id, action, target_type, target_id, details, ip_address, user_agent, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        params.user_id,
        params.action,
        params.target_type || null,
        params.target_id || null,
        params.details ? JSON.stringify(params.details) : null,
        params.ip_address || null,
        params.user_agent || null,
        created_at
      )
    } catch (error) {
      console.error('Failed to log action:', error)
    }
  })()

  // Use waitUntil to avoid blocking the response
  if (executionCtx) {
    executionCtx.waitUntil(logPromise)
  } else {
    await logPromise
  }
}

// 获取日志列表
app.get('/api/logs', requireAuth, async (c) => {
  const db = c.get('db') as any

  try {
    const page = parseInt(c.req.query('page') || '1')
    const limit = parseInt(c.req.query('limit') || '50')
    const action = c.req.query('action')
    const targetType = c.req.query('target_type')
    const startDate = c.req.query('start_date')
    const endDate = c.req.query('end_date')

    const offset = (page - 1) * limit

    let whereClause = 'WHERE 1=1'
    const queryParams: any[] = []

    if (action) {
      whereClause += ' AND action = ?'
      queryParams.push(action)
    }

    if (targetType) {
      whereClause += ' AND target_type = ?'
      queryParams.push(targetType)
    }

    if (startDate) {
      whereClause += ' AND created_at >= ?'
      queryParams.push(parseInt(startDate))
    }

    if (endDate) {
      whereClause += ' AND created_at <= ?'
      queryParams.push(parseInt(endDate))
    }

    // 获取总数
    const totalResult = await db.prepare(`SELECT COUNT(*) as count FROM logs ${whereClause}`).get(...queryParams) as any
    const total = totalResult?.count || 0

    // 获取日志列表
    const logs = await db.prepare(`
      SELECT * FROM logs ${whereClause} 
      ORDER BY created_at DESC 
      LIMIT ? OFFSET ?
    `).all(...queryParams, limit, offset)

    // 解析details字段
    const parsedLogs = logs.map((log: any) => ({
      ...log,
      details: log.details ? JSON.parse(log.details) : null
    }))

    // 为日志列表添加 Cache-Control: no-store，解决记录重置后的显示问题
    c.header('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
    return c.json({
      logs: parsedLogs,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit)
    })
  } catch (error) {
    console.error('Error fetching logs:', error)
    return c.json({ error: 'Failed to fetch logs' }, 500)
  }
})

// 清理旧日志
app.delete('/api/logs/cleanup', requireAuth, async (c) => {
  const db = c.get('db') as any

  try {
    const { days = 90 } = await c.req.json()
    let result;

    if (days === 0) {
      // 如果天数为0，彻底清空所有日志
      result = await db.prepare('DELETE FROM logs').run()
    } else {
      const cutoffTime = Date.now() - (days * 24 * 60 * 60 * 1000)
      result = await db.prepare('DELETE FROM logs WHERE created_at < ?').run(cutoffTime)
    }

    return c.json({
      ok: true,
      deletedCount: result.changes || 0,
      message: days === 0 ? 'All logs cleared' : `Deleted logs older than ${days} days`
    })
  } catch (error) {
    console.error('Error cleaning up logs:', error)
    return c.json({ error: 'Failed to cleanup logs' }, 500)
  }
})

// 安装接口
app.post('/api/install', preventReinstall, async (c) => {
  const db = c.get('db') as any

  try {
    const { siteTitle, adminEmail, adminPassword } = await c.req.json()

    // 验证输入
    if (!siteTitle?.trim()) {
      return c.json({ error: 'Site title is required' }, 400)
    }

    if (!adminEmail?.trim() || !adminEmail.includes('@')) {
      return c.json({ error: 'Valid admin email is required' }, 400)
    }

    if (!adminPassword || adminPassword.length < 6) {
      return c.json({ error: 'Admin password must be at least 6 characters' }, 400)
    }

    // 初始化数据库结构
    const statements = DATABASE_SCHEMA.split(';').filter(stmt => stmt.trim())
    for (const stmt of statements) {
      if (stmt.trim()) {
        await db.prepare(stmt).run()
      }
    }

    // 生成密码哈希
    const passwordHash = await hashPassword(adminPassword)

    // 设置基本配置
    const settings = [
      ['site.title', siteTitle.trim()],
      ['site.logo', '/logo.png'],
      ['site.favicon', '/favicon.png'],
      ['site.avatar_prefix', 'https://www.gravatar.com/avatar/'],
      ['admin.email', adminEmail.trim()],
      ['admin.password_hash', passwordHash],
      ['login.enable_captcha', '0'],
      ['login.enable_turnstile', '0'],
      ['login.turnstile_site_key', ''],
      ['login.turnstile_secret_key', ''],
      ['login.enable_github', '0'],
      ['github.client_id', ''],
      ['github.client_secret', ''],
      ['lockscreen.enabled', '0'],
      ['lockscreen.password', ''],
      ['webdav.url', ''],
      ['webdav.user', ''],
      ['webdav.password', ''],
      ['upload.max_file_size', '10'],
      ['language', 'zh'],
      ['system.installed', '1']
    ]

    const noteContent = `# XA Note

XA Note 是一款**轻量级、可完全自托管的个人笔记系统**，由您自行部署和管理，专为注重**隐私、安全与可控性**的用户设计。系统支持 Markdown 编辑、分类管理、标签系统和全文检索，提供流畅的写作体验与清晰的知识结构。

## 🌟 核心优势

### 🔐 完全的数据控制权
- **自托管部署**：所有数据仅存储在您自己的服务器中
- **无第三方依赖**：不依赖任何云服务，确保完全的数据所有权
- **隐私保护**：数据永远不会离开您的控制范围

### 📝 强大的笔记功能
- **Markdown 编辑**：实时预览的 Markdown 编辑器，支持丰富的语法
- **分类管理**：灵活的分类系统，构建清晰的知识结构
- **标签系统**：多维度标签管理，快速定位相关笔记
- **全文检索**：强大的搜索功能，快速找到所需内容
- **数据导出**：笔记可导出为 Markdown 文件，避免数据锁定

### 🛡️ 多层安全保护
- **多种登录方式**：账号密码登录、GitHub OAuth 登录
- **安全验证**：可选图片验证码或 Cloudflare Turnstile 防护
- **锁屏保护**：支持锁屏功能，防止未授权访问
- **访问控制**：适合在个人服务器或私有环境中长期使用
- **操作审计**：完整的日志系统记录所有用户操作，提供安全审计功能

### 🔗 安全分享与备份
- **只读分享**：支持笔记分享，可设置访问密码与过期时间控制
- **WebDAV 备份**：与云存储或私有 NAS 集成，实现数据自动同步
- **长期保存**：多种备份方式确保数据安全

### 🎨 优秀的用户体验
- **响应式设计**：在桌面和移动设备上均可获得良好体验
- **主题切换**：支持深色/浅色主题切换
- **多语言支持**：中英文界面无缝切换
- **键盘快捷键**：提高操作效率
- **系统监控**：内置日志管理系统，支持操作记录查看和过滤

## ⚙️ 配置说明

### 功能配置

系统提供了丰富的配置选项，包括：

- **站点设置**：站点标题、Logo、图标等
- **安全配置**：GitHub OAuth、验证码设置
- **备份配置**：WebDAV 自动备份
- **锁屏设置**：锁屏密码和超时时间
- **日志管理**：操作日志记录、查看和清理设置

所有配置都可以通过 Web 界面进行管理，无需修改配置文件。
`

    // D1 Batch 优化：使用 Promise.all 提升并发性能
    const setupTasks = settings.map(([key, value]) =>
      db.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)').run(key, value, Date.now())
    )

    setupTasks.push(db.prepare('INSERT OR REPLACE INTO categories (id, name, created_at) VALUES (?, ?, ?)').run('default', '默认', Date.now()))
    setupTasks.push(db.prepare('INSERT OR REPLACE INTO notes (id, title, content, tags, category_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
      'xa-note-welcome', 'XA Note', noteContent, '', 'default', Date.now(), Date.now()
    ))
    setupTasks.push(db.prepare('INSERT OR REPLACE INTO shares (id, note_id, password, expires_at, created_at) VALUES (?, ?, ?, ?, ?)').run(
      'xa-note', 'xa-note-welcome', null, null, Date.now()
    ))

    await Promise.all(setupTasks)

    return c.json({ success: true, message: 'Installation completed' })
  } catch (error) {
    console.error('Installation error:', error)
    return c.json({ error: 'Installation failed' }, 500)
  }
})

// 登录接口
app.post('/api/login', requireInstallation, async (c) => {
  const db = c.get('db') as any

  try {
    const { email, password, captcha, turnstileToken } = await c.req.json()

    if (!email || !password) {
      return c.json({ ok: false, reason: 'missing_credentials' }, 400)
    }

    const enableCaptcha = await db.prepare('SELECT value FROM settings WHERE key = ?').get('login.enable_captcha') as any
    const enableTurnstile = await db.prepare('SELECT value FROM settings WHERE key = ?').get('login.enable_turnstile') as any
    const turnstileSecretKey = await db.prepare('SELECT value FROM settings WHERE key = ?').get('login.turnstile_secret_key') as any

    if (enableCaptcha?.value === '1') {
      const savedCaptcha = getCookie(c, 'captcha')
      if (!captcha || !savedCaptcha || captcha.toLowerCase() !== savedCaptcha.toLowerCase()) {
        return c.json({ ok: false, error: 'captcha_invalid' }, 400)
      }
      deleteCookie(c, 'captcha', { path: '/' })
    }

    if (enableTurnstile?.value === '1' && turnstileSecretKey?.value) {
      if (!turnstileToken) {
        return c.json({ ok: false, error: 'turnstile_required' }, 400)
      }

      const turnstileResponse = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          secret: turnstileSecretKey.value,
          response: turnstileToken,
          remoteip: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown'
        })
      })

      const turnstileResult = await turnstileResponse.json() as any;
      if (!turnstileResult.success) {
        return c.json({ ok: false, error: 'turnstile_failed' }, 400)
      }
    }

    const adminEmail = await db.prepare('SELECT value FROM settings WHERE key = ?').get('admin.email') as any
    const adminPasswordHash = await db.prepare('SELECT value FROM settings WHERE key = ?').get('admin.password_hash') as any

    if (!adminEmail || !adminPasswordHash) {
      return c.json({ ok: false, reason: 'admin_not_configured' }, 500)
    }

    if (email !== adminEmail.value) {
      await logAction(c, {
        user_id: 'unknown',
        action: 'login',
        target_type: 'user',
        details: { success: false, reason: 'email_incorrect', email },
        ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
        user_agent: c.req.header('user-agent') || 'unknown'
      })
      return c.json({ ok: false, error: 'email_incorrect' }, 401)
    }

    const isValidPassword = await comparePassword(password, adminPasswordHash.value)
    if (!isValidPassword) {
      await logAction(c, {
        user_id: adminEmail.value,
        action: 'login',
        target_type: 'user',
        details: { success: false, reason: 'invalid_password' },
        ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
        user_agent: c.req.header('user-agent') || 'unknown'
      })
      return c.json({ ok: false, error: 'invalid_credentials' }, 401)
    }

    const token = await generateToken({ userId: 'admin', email: adminEmail.value, role: 'admin' })
    const sessionId = generateSessionId()

    setCookie(c, 'auth_token', token, { httpOnly: true, secure: true, sameSite: 'Lax', path: '/', maxAge: 60 * 60 * 24 * 7 })
    setCookie(c, 'session_id', sessionId, { httpOnly: true, secure: true, sameSite: 'Lax', path: '/', maxAge: 60 * 60 * 24 * 7 })

    await logAction(c, {
      user_id: adminEmail.value,
      action: 'login',
      target_type: 'user',
      details: { success: true, method: 'password' },
      ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
      user_agent: c.req.header('user-agent') || 'unknown'
    })

    return c.json({ ok: true, email: adminEmail.value })
  } catch (error) {
    console.error('Login error:', error)
    return c.json({ ok: false, reason: 'server_error' }, 500)
  }
})

// GitHub OAuth
app.get('/api/auth/github', requireInstallation, async (c) => {
  const db = c.get('db') as any
  try {
    const enableGithub = await db.prepare('SELECT value FROM settings WHERE key = ?').get('login.enable_github') as any
    if (!enableGithub || enableGithub.value !== '1') return c.json({ error: 'GitHub login not enabled' }, 400)

    const clientIdRow = await db.prepare('SELECT value FROM settings WHERE key = ?').get('github.client_id') as any
    if (!clientIdRow?.value) return c.json({ error: 'GitHub client ID not configured' }, 500)

    const { apiUrl, frontendUrl } = getBaseUrl(c)
    const redirectUri = `${apiUrl} /api/auth / github / callback`
    const state = nanoid(32)

    setCookie(c, 'github_oauth_state', state, { httpOnly: true, maxAge: 600, path: '/' })
    setCookie(c, 'github_oauth_frontend', frontendUrl, { httpOnly: true, maxAge: 600, path: '/' })

    const authUrl = new URL('https://github.com/login/oauth/authorize')
    authUrl.searchParams.set('client_id', clientIdRow.value)
    authUrl.searchParams.set('redirect_uri', redirectUri)
    authUrl.searchParams.set('scope', 'user:email')
    authUrl.searchParams.set('state', state)

    return c.redirect(authUrl.toString())
  } catch (error) {
    console.error('GitHub OAuth init error:', error)
    return c.json({ error: 'OAuth initialization failed' }, 500)
  }
})

app.get('/api/auth/github/callback', async (c) => {
  const db = c.get('db') as any
  try {
    const code = c.req.query('code')
    const state = c.req.query('state')
    const savedState = getCookie(c, 'github_oauth_state')
    const frontendUrl = getCookie(c, 'github_oauth_frontend') || getBaseUrl(c).frontendUrl

    if (!code || !state || state !== savedState) {
      return c.redirect(`${frontendUrl}/login?error=oauth_failed`)
    }

    deleteCookie(c, 'github_oauth_state')
    deleteCookie(c, 'github_oauth_frontend')

    const clientIdRow = await db.prepare('SELECT value FROM settings WHERE key = ?').get('github.client_id') as any
    const clientSecretRow = await db.prepare('SELECT value FROM settings WHERE key = ?').get('github.client_secret') as any

    if (!clientIdRow?.value || !clientSecretRow?.value) return c.redirect(`${frontendUrl}/login?error=oauth_config`)

    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: clientIdRow.value, client_secret: clientSecretRow.value, code })
    })

    const tokenData = await tokenResponse.json() as any;
    if (!tokenData.access_token) return c.redirect(`${frontendUrl}/login?error=oauth_token`)

    const userResponse = await fetch('https://api.github.com/user', {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}`, 'Accept': 'application/vnd.github.v3+json' }
    })
    const userData = await userResponse.json() as any;

    const emailResponse = await fetch('https://api.github.com/user/emails', {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}`, 'Accept': 'application/vnd.github.v3+json' }
    })
    const emailData = await emailResponse.json() as any[];
    const primaryEmail = emailData.find((email: any) => email.primary)?.email || userData.email

    const adminEmailRow = await db.prepare('SELECT value FROM settings WHERE key = ?').get('admin.email') as any
    if (!adminEmailRow || primaryEmail !== adminEmailRow.value) return c.redirect(`${frontendUrl}/login?error=email_incorrect`)

    const token = await generateToken({ userId: 'admin', email: adminEmailRow.value, role: 'admin' })
    const sessionId = generateSessionId()

    const cookieOptions = { httpOnly: true, secure: true, sameSite: 'Lax' as const, path: '/', maxAge: 60 * 60 * 24 * 7 }
    setCookie(c, 'auth_token', token, cookieOptions)
    setCookie(c, 'session_id', sessionId, cookieOptions)

    await logAction(c, {
      user_id: adminEmailRow.value,
      action: 'login',
      target_type: 'user',
      details: { success: true, method: 'github', github_user: userData.login },
      ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
      user_agent: c.req.header('user-agent') || 'unknown'
    })

    return c.redirect(`${frontendUrl}/`)
  } catch (error) {
    console.error('GitHub OAuth callback error:', error)
    const frontendUrl = getCookie(c, 'github_oauth_frontend') || getBaseUrl(c).frontendUrl
    return c.redirect(`${frontendUrl}/login?error=oauth_error`)
  }
})

// 认证检查
app.get('/api/me', requireInstallation, async (c) => {
  const token = getCookie(c, 'auth_token')
  const sessionId = getCookie(c, 'session_id')

  if (!token || !sessionId) {
    return c.json({ loggedIn: false, reason: 'missing_cookies' }, 401)
  }

  const payload = await verifyToken(token)
  if (!payload) {
    return c.json({ loggedIn: false, reason: 'invalid_token' }, 401)
  }

  return c.json({
    loggedIn: true,
    email: payload.email,
    role: payload.role
  })
})

// 退出登录
app.post('/api/logout', async (c) => {
  const db = c.get('db') as any

  // 获取当前用户信息用于日志记录
  const token = getCookie(c, 'auth_token')
  let userId = 'unknown'

  if (token) {
    const payload = await verifyToken(token)
    if (payload) {
      userId = payload.email || payload.userId || 'admin'
    }
  }

  // 记录登出操作
  await logAction(db, {
    user_id: userId,
    action: 'logout',
    target_type: 'user',
    details: { success: true },
    ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
    user_agent: c.req.header('user-agent') || 'unknown'
  })

  deleteCookie(c, 'auth_token', { path: '/' })
  deleteCookie(c, 'session_id', { path: '/' })
  return c.json({ ok: true })
})

// 获取系统信息
app.get('/api/system/info', async (c) => {
  const db = c.get('db') as any

  try {
    // 获取数据库统计信息
    const notesCount = await db.prepare('SELECT COUNT(*) as count FROM notes').get() as any
    const categoriesCount = await db.prepare('SELECT COUNT(*) as count FROM categories').get() as any

    return c.json({
      name: 'XA Note',
      version: '1.0.0',
      platform: 'cloudflare-pages', // 标识为Cloudflare Pages环境
      database: 'd1', // 标识使用D1数据库
      timestamp: new Date().toISOString(),
      notesCount: notesCount?.count || 0,
      categoriesCount: categoriesCount?.count || 0,
      databaseSize: 'N/A' // D1不提供文件大小信息
    })
  } catch (error) {
    return c.json({
      name: 'XA Note',
      version: '1.0.0',
      platform: 'cloudflare-pages',
      database: 'd1',
      timestamp: new Date().toISOString(),
      notesCount: 0,
      categoriesCount: 0,
      databaseSize: 'N/A'
    })
  }
})

// 获取公共设置
app.get('/api/settings/public', async (c) => {
  const db = c.get('db') as any

  try {
    const settings = [
      'login.enable_captcha',
      'login.enable_turnstile',
      'login.turnstile_site_key',
      'login.enable_github',
      'site.title',
      'site.logo',
      'site.favicon',
      'site.avatar_prefix',
      'upload.max_file_size'
    ]

    const result: any = {}
    for (const key of settings) {
      const row = await db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as any
      result[key] = row?.value || getDefaultValue(key)
    }

    return c.json(result)
  } catch (error) {
    return c.json({
      'login.enable_captcha': '0',
      'login.enable_turnstile': '0',
      'login.turnstile_site_key': '',
      'login.enable_github': '0',
      'site.title': 'XA Note',
      'site.logo': '/logo.png',
      'site.favicon': '/favicon.png',
      'site.avatar_prefix': 'https://www.gravatar.com/avatar/',
      'upload.max_file_size': '10'
    })
  }
})

function getDefaultValue(key: string): string {
  const defaults: { [key: string]: string } = {
    'login.enable_captcha': '0',
    'login.enable_turnstile': '0',
    'login.turnstile_site_key': '',
    'login.enable_github': '0',
    'site.title': 'XA Note',
    'site.logo': '/logo.png',
    'site.favicon': '/favicon.png',
    'site.avatar_prefix': 'https://www.gravatar.com/avatar/',
    'upload.max_file_size': '10'
  }
  return defaults[key] || ''
}

// 获取所有设置（需要认证）
app.get('/api/settings', requireAuth, async (c) => {
  const db = c.get('db') as any

  try {
    const rows = await db.prepare('SELECT key, value FROM settings').all()
    const result: any = {}

    for (const row of rows) {
      result[row.key] = row.value
    }

    return c.json(result)
  } catch (error) {
    console.error('Error fetching settings:', error)
    return c.json({ error: 'Failed to fetch settings' }, 500)
  }
})

// 更新设置（需要认证）
app.put('/api/settings', requireAuth, async (c) => {
  const db = c.get('db') as any
  const user = c.get('user')
  const updates = await c.req.json()

  const updatedKeys = Object.keys(updates)

  for (const [key, value] of Object.entries(updates)) {
    if (key === 'admin.password') {
      const hash = await hashPassword(String(value))
      await db.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)').run('admin.password_hash', hash, Date.now())
      continue
    }

    await db.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)').run(key, String(value), Date.now())
  }

  // 记录设置更新
  await logAction(db, {
    user_id: user.email || user.userId,
    action: 'update_settings',
    target_type: 'settings',
    details: { updated_keys: updatedKeys },
    ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
    user_agent: c.req.header('user-agent') || 'unknown'
  })

  return c.json({ ok: true })
})

// 更新设置（POST方法，与PUT相同）
app.post('/api/settings', requireAuth, async (c) => {
  const db = c.get('db') as any
  const user = c.get('user')
  const updates = await c.req.json()

  const updatedKeys = Object.keys(updates)

  for (const [key, value] of Object.entries(updates)) {
    if (key === 'admin.password') {
      const hash = await hashPassword(String(value))
      await db.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)').run('admin.password_hash', hash, Date.now())
      continue
    }

    await db.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)').run(key, String(value), Date.now())
  }

  // 记录设置更新
  await logAction(db, {
    user_id: user.email || user.userId,
    action: 'update_settings',
    target_type: 'settings',
    details: { updated_keys: updatedKeys },
    ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
    user_agent: c.req.header('user-agent') || 'unknown'
  })

  return c.json({ ok: true })
})

// Categories
app.get('/api/categories', async (c) => {
  const db = c.get('db') as any
  const rows = await db.prepare('SELECT * FROM categories ORDER BY created_at').all()
  return c.json(rows)
})

app.post('/api/categories', requireAuth, async (c) => {
  const db = c.get('db') as any
  const user = c.get('user')
  const { name } = await c.req.json()
  if (!name) return c.json({ error: 'BAD_REQUEST' }, 400)

  const id = nanoid()
  await db.prepare('INSERT INTO categories (id, name, created_at) VALUES (?, ?, ?)').run(id, name, Date.now())

  // 记录分类创建
  await logAction(db, {
    user_id: user.email || user.userId,
    action: 'create_category',
    target_type: 'category',
    target_id: id,
    details: { name },
    ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
    user_agent: c.req.header('user-agent') || 'unknown'
  })

  return c.json({ ok: true, id })
})

app.put('/api/categories/:id', requireAuth, async (c) => {
  const db = c.get('db') as any
  const user = c.get('user')
  const id = c.req.param('id')
  const { name } = await c.req.json()

  if (!id || !name) return c.json({ error: 'BAD_REQUEST' }, 400)
  if (id === 'default') return c.json({ error: 'CANNOT_EDIT_DEFAULT' }, 400)

  // 获取旧名称用于日志
  const oldCategory = await db.prepare('SELECT * FROM categories WHERE id=?').get(id) as any

  await db.prepare('UPDATE categories SET name = ? WHERE id = ?').run(name, id)

  // 记录分类更新
  await logAction(db, {
    user_id: user.email || user.userId,
    action: 'update_category',
    target_type: 'category',
    target_id: id,
    details: { old_name: oldCategory?.name, new_name: name },
    ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
    user_agent: c.req.header('user-agent') || 'unknown'
  })

  return c.json({ ok: true })
})

app.delete('/api/categories/:id', requireAuth, async (c) => {
  const db = c.get('db') as any
  const user = c.get('user')
  const id = c.req.param('id')
  if (!id) return c.json({ error: 'BAD_REQUEST' }, 400)
  if (id === 'default') return c.json({ error: 'CANNOT_DELETE_DEFAULT' }, 400)

  // 获取分类信息用于日志
  const category = await db.prepare('SELECT * FROM categories WHERE id=?').get(id) as any

  // 将该分类下的笔记转移到默认分类
  await db.prepare('UPDATE notes SET category_id = ? WHERE category_id = ?').run('default', id)

  // 删除分类
  await db.prepare('DELETE FROM categories WHERE id = ?').run(id)

  // 记录分类删除
  if (category) {
    await logAction(c, {
      user_id: user.email || user.userId,
      action: 'delete_category',
      target_type: 'category',
      target_id: id,
      details: { name: category.name },
      ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
      user_agent: c.req.header('user-agent') || 'unknown'
    })
  }

  return c.json({ ok: true })
})

// Notes
app.get('/api/notes', async (c) => {
  const db = c.get('db') as any
  const categoryId = c.req.query('category')

  const rows = categoryId
    ? await db.prepare('SELECT * FROM notes WHERE category_id=? ORDER BY updated_at DESC').all(categoryId)
    : await db.prepare('SELECT * FROM notes ORDER BY updated_at DESC').all()

  return c.json(rows)
})

app.post('/api/notes', requireAuth, async (c) => {
  const db = c.get('db') as any
  const user = c.get('user')
  const { categoryId } = await c.req.json()

  const noteId = nanoid()
  await db.prepare(`
    INSERT INTO notes
    (id, title, content, tags, category_id, created_at, updated_at)
    VALUES (?, '', '', '', ?, ?, ?)
  `).run(
    noteId,
    categoryId ?? 'default',
    Date.now(),
    Date.now()
  )

  // 记录笔记创建
  await logAction(db, {
    user_id: user.email || user.userId,
    action: 'create_note',
    target_type: 'note',
    target_id: noteId,
    details: { category_id: categoryId ?? 'default' },
    ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
    user_agent: c.req.header('user-agent') || 'unknown'
  })

  return c.json({ ok: true })
})

app.put('/api/notes/:id', requireAuth, async (c) => {
  const db = c.get('db') as any
  const id = c.req.param('id')
  if (!id) return c.json({ error: 'BAD_REQUEST' }, 400)

  const note = (await c.req.json()) as {
    title: string
    content: string
    tags: string[]
    category_id: string
  }

  await db.prepare(`
    UPDATE notes
    SET title=?, content=?, tags=?, category_id=?, updated_at=?
    WHERE id=?
  `).run(
    note.title,
    note.content,
    note.tags?.join(',') ?? '',
    note.category_id,
    Date.now(),
    id
  )

  return c.json({ ok: true })
})

app.delete('/api/notes/:id', requireAuth, async (c) => {
  const db = c.get('db') as any
  const user = c.get('user')
  const id = c.req.param('id')
  if (!id) return c.json({ error: 'BAD_REQUEST' }, 400)

  // 获取笔记信息
  const note = await db.prepare('SELECT * FROM notes WHERE id=?').get(id) as any
  if (!note) return c.json({ error: 'NOT_FOUND' }, 404)

  // 移动到回收站
  await db.prepare(`
    INSERT INTO trash (id, title, content, tags, category_id, created_at, updated_at, deleted_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    note.id,
    note.title,
    note.content,
    note.tags,
    note.category_id,
    note.created_at,
    note.updated_at,
    Date.now()
  )

  // 从笔记表中删除
  await db.prepare('DELETE FROM notes WHERE id=?').run(id)

  // 记录笔记删除
  await logAction(db, {
    user_id: user.email || user.userId,
    action: 'delete_note',
    target_type: 'note',
    target_id: id,
    details: { title: note.title, category_id: note.category_id },
    ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
    user_agent: c.req.header('user-agent') || 'unknown'
  })

  return c.json({ ok: true })
})

// Search (FTS5 优化版本)
app.get('/api/search', async (c) => {
  const db = c.get('db') as any
  const q = c.req.query('q')
  if (!q) return c.json([])

  try {
    // 优先尝试 FTS5 全文检索，性能更好且支持按相关度排序
    const rows = await db.prepare(`
      SELECT n.* FROM notes n
      JOIN notes_fts f ON n.rowid = f.rowid
      WHERE notes_fts MATCH ?
      ORDER BY rank
    `).all(q)

    if (rows && rows.length > 0) return c.json(rows)
  } catch (ftsError) {
    console.warn('FTS5 search failed, falling back to LIKE:', ftsError)
  }

  // Fallback to LIKE search
  const searchTerm = `%${q}%`
  const rows = await db.prepare(`
    SELECT * FROM notes 
    WHERE title LIKE ? OR content LIKE ? OR tags LIKE ?
    ORDER BY updated_at DESC
  `).all(searchTerm, searchTerm, searchTerm)

  return c.json(rows)
})

// Share
app.post('/api/share/:id', requireAuth, async (c) => {
  const db = c.get('db') as any
  const user = c.get('user')
  const id = c.req.param('id')
  if (!id) return c.json({ error: 'BAD_REQUEST' }, 400)

  const body = (await c.req.json()) as {
    password?: string
    expiresAt?: number
  }

  const code = nanoid(8)

  await db.prepare(`
    INSERT INTO shares (id, note_id, password, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    code,
    id,
    body.password ?? null,
    body.expiresAt ?? null,
    Date.now()
  )

  // 记录分享创建
  await logAction(c, {
    user_id: user.email || user.userId,
    action: 'create_share',
    target_type: 'share',
    target_id: code,
    details: {
      note_id: id,
      has_password: !!body.password,
      expires_at: body.expiresAt
    },
    ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
    user_agent: c.req.header('user-agent') || 'unknown'
  })

  return c.json({ code })
})

app.get('/api/shares', requireAuth, async (c) => {
  const db = c.get('db') as any
  const noteId = c.req.query('note_id')
  if (!noteId) return c.json({ error: 'BAD_REQUEST' }, 400)

  const shares = await db.prepare('SELECT * FROM shares WHERE note_id=? ORDER BY created_at DESC').all(noteId)

  return c.json(shares)
})

app.delete('/api/shares/:id', requireAuth, async (c) => {
  const db = c.get('db') as any
  const user = c.get('user')
  const id = c.req.param('id')
  if (!id) return c.json({ error: 'BAD_REQUEST' }, 400)

  // 获取分享信息用于日志
  const share = await db.prepare('SELECT * FROM shares WHERE id=?').get(id) as any

  await db.prepare('DELETE FROM shares WHERE id=?').run(id)

  // 记录分享删除
  if (share) {
    await logAction(c, {
      user_id: user.email || user.userId,
      action: 'delete_share',
      target_type: 'share',
      target_id: id,
      details: { note_id: share.note_id },
      ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
      user_agent: c.req.header('user-agent') || 'unknown'
    })
  }

  return c.json({ ok: true })
})

app.post('/api/share/:code/view', async (c) => {
  const db = c.get('db') as any
  const code = c.req.param('code')
  if (!code) return c.json({ error: 'BAD_REQUEST' }, 400)

  const body = (await c.req.json()) as { password?: string }

  const share = await db.prepare('SELECT * FROM shares WHERE id=?').get(code) as any

  if (!share) {
    return c.json({ error: 'NOT_FOUND' }, 404)
  }

  if (share.expires_at && Date.now() > share.expires_at) {
    return c.json({ error: 'EXPIRED' }, 403)
  }

  if (share.password && share.password !== body.password) {
    return c.json({ error: 'PASSWORD_REQUIRED' }, 401)
  }

  const note = await db.prepare('SELECT * FROM notes WHERE id=?').get(share.note_id) as any

  // 记录分享查看（匿名用户）
  await logAction(c, {
    user_id: 'anonymous',
    action: 'view_share',
    target_type: 'share',
    target_id: code,
    details: { note_id: share.note_id, success: true },
    ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
    user_agent: c.req.header('user-agent') || 'unknown'
  })

  return c.json(note)
})

// Captcha API
app.get('/api/captcha', (c) => {
  // Simple SVG captcha implementation for Cloudflare Pages
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  let captchaText = ''
  for (let i = 0; i < 4; i++) {
    captchaText += chars.charAt(Math.floor(Math.random() * chars.length))
  }

  const svg = `<svg width="120" height="40" xmlns="http://www.w3.org/2000/svg">
    <rect width="120" height="40" fill="#f4f4f5"/>
    <text x="60" y="25" font-family="Arial" font-size="18" text-anchor="middle" fill="#333">${captchaText}</text>
    <line x1="10" y1="15" x2="110" y2="25" stroke="#ccc" stroke-width="1"/>
    <line x1="20" y1="30" x2="100" y2="10" stroke="#ccc" stroke-width="1"/>
  </svg>`

  // Save to cookie (5 minutes)
  setCookie(c, 'captcha', captchaText.toLowerCase(), {
    httpOnly: true,
    maxAge: 300,
    path: '/'
  })

  return c.json({ svg })
})

// GitHub OAuth debug endpoint
app.get('/api/auth/github/debug', requireInstallation, async (c) => {
  const db = c.get('db') as any

  const enableGithub = await db.prepare('SELECT value FROM settings WHERE key = ?').get('login.enable_github') as any
  const clientId = await db.prepare('SELECT value FROM settings WHERE key = ?').get('github.client_id') as any
  const clientSecret = await db.prepare('SELECT value FROM settings WHERE key = ?').get('github.client_secret') as any
  const { apiUrl, frontendUrl } = getBaseUrl(c)
  const redirectUri = `${apiUrl}/api/auth/github/callback`

  return c.json({
    enabled: enableGithub?.value === '1',
    hasClientId: !!clientId?.value,
    hasClientSecret: !!clientSecret?.value,
    clientIdPreview: clientId?.value ? clientId.value.substring(0, 8) + '...' : 'not set',
    redirectUri,
    apiUrl,
    frontendUrl,
    environment: 'cloudflare-pages'
  })
})

// Auth cleanup endpoint
app.post('/api/auth/cleanup', (c) => {
  // Clear all possible auth cookies
  deleteCookie(c, 'auth_token', { path: '/' })
  deleteCookie(c, 'session_id', { path: '/' })
  deleteCookie(c, 'session', { path: '/' })
  return c.json({ ok: true, message: 'Tokens cleared' })
})

// Trash management APIs
app.get('/api/trash', requireAuth, async (c) => {
  const db = c.get('db') as any
  const rows = await db.prepare('SELECT * FROM trash ORDER BY deleted_at DESC').all()
  return c.json(rows)
})

app.post('/api/trash/:id/restore', requireAuth, async (c) => {
  const db = c.get('db') as any
  const user = c.get('user')
  const id = c.req.param('id')
  if (!id) return c.json({ error: 'BAD_REQUEST' }, 400)

  // Get note from trash
  const trashNote = await db.prepare('SELECT * FROM trash WHERE id=?').get(id) as any
  if (!trashNote) return c.json({ error: 'NOT_FOUND' }, 404)

  // Restore to notes table
  await db.prepare(`
    INSERT INTO notes (id, title, content, tags, category_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    trashNote.id,
    trashNote.title,
    trashNote.content,
    trashNote.tags,
    trashNote.category_id,
    trashNote.created_at,
    Date.now() // Update modification time
  )

  // Remove from trash
  await db.prepare('DELETE FROM trash WHERE id=?').run(id)

  // 记录笔记恢复
  await logAction(db, {
    user_id: user.email || user.userId,
    action: 'restore_note',
    target_type: 'note',
    target_id: id,
    details: { title: trashNote.title, category_id: trashNote.category_id },
    ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
    user_agent: c.req.header('user-agent') || 'unknown'
  })

  return c.json({ ok: true })
})

app.delete('/api/trash/:id', requireAuth, async (c) => {
  const db = c.get('db') as any
  const user = c.get('user')
  const id = c.req.param('id')
  if (!id) return c.json({ error: 'BAD_REQUEST' }, 400)

  // 获取笔记信息用于日志
  const trashNote = await db.prepare('SELECT * FROM trash WHERE id=?').get(id) as any

  // Permanently delete
  await db.prepare('DELETE FROM trash WHERE id=?').run(id)

  // 记录永久删除
  if (trashNote) {
    await logAction(c, {
      user_id: user.email || user.userId,
      action: 'permanent_delete_note',
      target_type: 'note',
      target_id: id,
      details: { title: trashNote.title, category_id: trashNote.category_id },
      ip_address: c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown',
      user_agent: c.req.header('user-agent') || 'unknown'
    })
  }

  return c.json({ ok: true })
})

app.delete('/api/trash', requireAuth, async (c) => {
  const db = c.get('db') as any
  // Empty trash
  await db.prepare('DELETE FROM trash').run()
  return c.json({ ok: true })
})

// SEO routes
app.get('/sitemap.xml', (c) => {
  // Get current request domain and protocol
  const host = c.req.header('host') || 'localhost:9915'
  const protocol = c.req.header('x-forwarded-proto') ||
    c.req.header('cf-visitor') ? 'https' :
    (host.includes('localhost') ? 'http' : 'https')
  const baseUrl = `${protocol}://${host}`

  // Get current date
  const currentDate = new Date().toISOString().split('T')[0]

  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml">
    
    <!-- Homepage -->
    <url>
        <loc>${baseUrl}/</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>daily</changefreq>
        <priority>1.0</priority>
        <xhtml:link rel="alternate" hreflang="zh-CN" href="${baseUrl}/" />
        <xhtml:link rel="alternate" hreflang="en" href="${baseUrl}/?lang=en" />
    </url>
    
    <!-- Login page -->
    <url>
        <loc>${baseUrl}/login</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
        <xhtml:link rel="alternate" hreflang="zh-CN" href="${baseUrl}/login" />
        <xhtml:link rel="alternate" hreflang="en" href="${baseUrl}/login?lang=en" />
    </url>
    
    <!-- Features page -->
    <url>
        <loc>${baseUrl}/features</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>weekly</changefreq>
        <priority>0.7</priority>
        <xhtml:link rel="alternate" hreflang="zh-CN" href="${baseUrl}/features" />
        <xhtml:link rel="alternate" hreflang="en" href="${baseUrl}/features?lang=en" />
    </url>
    
    <!-- Help page -->
    <url>
        <loc>${baseUrl}/help</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>weekly</changefreq>
        <priority>0.6</priority>
        <xhtml:link rel="alternate" hreflang="zh-CN" href="${baseUrl}/help" />
        <xhtml:link rel="alternate" hreflang="en" href="${baseUrl}/help?lang=en" />
    </url>
    
    <!-- Privacy page -->
    <url>
        <loc>${baseUrl}/privacy</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.5</priority>
        <xhtml:link rel="alternate" hreflang="zh-CN" href="${baseUrl}/privacy" />
        <xhtml:link rel="alternate" hreflang="en" href="${baseUrl}/privacy?lang=en" />
    </url>

    <!-- Copyright page -->
    <url>
        <loc>${baseUrl}/copyright</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.5</priority>
        <xhtml:link rel="alternate" hreflang="zh-CN" href="${baseUrl}/copyright" />
        <xhtml:link rel="alternate" hreflang="en" href="${baseUrl}/copyright?lang=en" />
    </url>
    
</urlset>`

  return new Response(sitemap, {
    headers: {
      'Content-Type': 'application/xml',
      'Cache-Control': 'public, max-age=3600' // Cache for 1 hour
    }
  })
})

app.get('/robots.txt', (c) => {
  // Get current request domain and protocol
  const host = c.req.header('host') || 'localhost:9915'
  const protocol = c.req.header('x-forwarded-proto') ||
    c.req.header('cf-visitor') ? 'https' :
    (host.includes('localhost') ? 'http' : 'https')
  const baseUrl = `${protocol}://${host}`

  const robots = `User-agent: *
Allow: /

# Static resources
Allow: /assets/
Allow: /favicon.png
Allow: /logo.png
Allow: /manifest.json

# Disallowed paths
Disallow: /api/
Disallow: /admin/
Disallow: /data/

# Sitemap
Sitemap: ${baseUrl}/sitemap.xml`

  return new Response(robots, {
    headers: {
      'Content-Type': 'text/plain',
      'Cache-Control': 'public, max-age=86400' // Cache for 24 hours
    }
  })
})

// Debug environment endpoint
app.get('/api/debug/env', (c) => {
  const db = c.get('db')
  return c.json({
    hasDB: !!db,
    dbType: 'D1',
    platform: 'cloudflare-pages',
    timestamp: new Date().toISOString(),
    env: {
      hasDB: !!c.env.DB,
      hasJWTSecret: !!c.env.JWT_SECRET
    }
  })
})

export default app