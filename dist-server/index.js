import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import db from './db/index.js';
import { nanoid } from 'nanoid';
import bcrypt from 'bcryptjs';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { getSetting, getSettings, setSetting } from './services/settings.js';
import { backupScheduler } from './services/backup-scheduler.js';
import { requireAuth } from './middleware/auth.js';
import svgCaptcha from 'svg-captcha';
import { generateToken, verifyToken, generateSessionId } from './utils/jwt.js';
import { LogService, LOG_ACTIONS } from './services/log-service.js';
const app = new Hono();
/* Installation */
// 检查是否已安装
function isInstalled() {
    const installed = getSetting('system.installed') === '1';
    return installed;
}
// 安装检查中间件
const requireInstallation = async (c, next) => {
    // 跳过安装相关的API
    if (c.req.path.startsWith('/api/install') || c.req.path === '/api/settings/public') {
        await next();
        return;
    }
    if (!isInstalled()) {
        return c.json({ error: 'NOT_INSTALLED', redirect: '/install' }, 503);
    }
    await next();
};
// 防止重复安装中间件
const preventReinstall = async (c, next) => {
    if (isInstalled()) {
        return c.json({ error: 'ALREADY_INSTALLED' }, 400);
    }
    await next();
};
app.post('/api/install', preventReinstall, async (c) => {
    const { siteTitle, adminEmail, adminPassword } = await c.req.json();
    // 验证输入
    if (!siteTitle?.trim()) {
        return c.json({ error: 'Site title is required' }, 400);
    }
    if (!adminEmail?.trim() || !adminEmail.includes('@')) {
        return c.json({ error: 'Valid admin email is required' }, 400);
    }
    if (!adminPassword || adminPassword.length < 6) {
        return c.json({ error: 'Admin password must be at least 6 characters' }, 400);
    }
    try {
        // 生成密码哈希
        const passwordHash = await bcrypt.hash(adminPassword, 10);
        // 设置基本配置
        setSetting('site.title', siteTitle.trim());
        setSetting('site.logo', '/logo.png');
        setSetting('site.favicon', '/favicon.png');
        setSetting('site.avatar_prefix', 'https://www.gravatar.com/avatar/');
        setSetting('admin.email', adminEmail.trim());
        setSetting('admin.password_hash', passwordHash);
        // 设置默认的登录配置
        setSetting('login.enable_captcha', '0');
        setSetting('login.enable_turnstile', '0');
        setSetting('login.turnstile_site_key', '');
        setSetting('login.turnstile_secret_key', '');
        setSetting('login.enable_github', '0');
        setSetting('github.client_id', '');
        setSetting('github.client_secret', '');
        // 设置默认的锁屏配置
        setSetting('lockscreen.enabled', '0');
        setSetting('lockscreen.password', '');
        // 设置默认的WebDAV配置
        setSetting('webdav.url', '');
        setSetting('webdav.user', '');
        setSetting('webdav.password', '');
        // 设置默认的上传配置
        setSetting('upload.max_file_size', '10'); // 默认10MB
        // 标记为已安装
        setSetting('system.installed', '1');
        return c.json({ success: true, message: 'Installation completed' });
    }
    catch (error) {
        return c.json({ error: 'Installation failed' }, 500);
    }
});
// 获取安装状态
app.get('/api/install/status', c => {
    const installed = isInstalled();
    return c.json({ installed });
});
/* Captcha */
app.get('/api/captcha', c => {
    const captcha = svgCaptcha.create({
        size: 4,
        noise: 2,
        background: '#f4f4f5'
    });
    // 保存到 Cookie（5 分钟）
    setCookie(c, 'captcha', captcha.text.toLowerCase(), {
        httpOnly: true,
        maxAge: 300,
        path: '/'
    });
    return c.json({
        svg: captcha.data
    });
});
/* Login */
app.post('/api/login', requireInstallation, async (c) => {
    const { email, password, captcha, turnstileToken } = await c.req.json();
    const adminEmail = getSetting('admin.email');
    const passwordHash = getSetting('admin.password_hash');
    if (email !== adminEmail) {
        return c.json({ ok: false, error: 'email_incorrect' }, 401);
    }
    if (!passwordHash) {
        return c.json({ ok: false, error: 'invalid_credentials' }, 401);
    }
    // 验证码检查
    const enableCaptcha = getSetting('login.enable_captcha') === '1';
    if (enableCaptcha) {
        const saved = getCookie(c, 'captcha');
        if (!saved || saved !== String(captcha).toLowerCase()) {
            return c.json({ ok: false, reason: 'captcha' }, 400);
        }
        deleteCookie(c, 'captcha');
    }
    // Turnstile 验证检查
    const enableTurnstile = getSetting('login.enable_turnstile') === '1';
    if (enableTurnstile) {
        const secretKey = getSetting('login.turnstile_secret_key');
        if (!secretKey) {
            return c.json({ ok: false, reason: 'turnstile_not_configured' }, 500);
        }
        if (!turnstileToken) {
            return c.json({ ok: false, reason: 'turnstile_required' }, 400);
        }
        // 验证 Turnstile token
        try {
            const remoteIp = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP') || '127.0.0.1';
            const verifyResponse = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    secret: secretKey,
                    response: turnstileToken,
                    remoteip: remoteIp
                })
            });
            const verifyResult = await verifyResponse.json();
            if (!verifyResult.success) {
                return c.json({ ok: false, reason: 'turnstile_failed', errors: verifyResult['error-codes'] }, 400);
            }
        }
        catch (error) {
            return c.json({ ok: false, reason: 'turnstile_error' }, 500);
        }
    }
    const ok = await bcrypt.compare(password, passwordHash);
    if (!ok) {
        return c.json({ ok: false, error: 'invalid_credentials' }, 401);
    }
    // 生成JWT token
    const token = generateToken({
        userId: 'admin',
        email: adminEmail || '',
        role: 'admin'
    });
    // 生成session ID
    const sessionId = generateSessionId();
    // 设置安全的HttpOnly Cookie - 针对Docker环境优化
    setCookie(c, 'auth_token', token, {
        httpOnly: true,
        secure: false, // Docker内部使用HTTP
        sameSite: 'Lax', // 放宽同站策略以支持跨域
        path: '/',
        maxAge: 60 * 60 * 24 * 7, // 7 天
        domain: undefined // 不设置domain，让浏览器自动处理
    });
    // 设置session ID cookie（用于额外安全验证）
    setCookie(c, 'session_id', sessionId, {
        httpOnly: true,
        secure: false, // Docker内部使用HTTP
        sameSite: 'Lax', // 放宽同站策略以支持跨域
        path: '/',
        maxAge: 60 * 60 * 24 * 7, // 7 天
        domain: undefined // 不设置domain，让浏览器自动处理
    });
    // 记录登录日志
    try {
        const ip = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP') || '127.0.0.1';
        const userAgent = c.req.header('User-Agent') || '';
        await LogService.log({
            user_id: 'admin',
            action: LOG_ACTIONS.LOGIN,
            ip_address: ip,
            user_agent: userAgent,
            details: { method: 'password' }
        });
    }
    catch (error) {
        // 日志记录失败不影响登录
    }
    return c.json({ ok: true, email: adminEmail || '' });
});
/* GitHub OAuth */
// 获取当前环境的基础URL
function getBaseUrl(c) {
    const host = c.req.header('host') || 'localhost:9915';
    const protocol = c.req.header('x-forwarded-proto') ||
        c.req.header('cf-visitor') ? 'https' :
        (host.includes('localhost') ? 'http' : 'https');
    // 检查是否是Cloudflare Pages环境
    const isCloudflarePages = c.env?.CLOUDFLARE_ENV === 'pages' ||
        c.req.header('cf-ray') ||
        host.includes('.pages.dev');
    if (isCloudflarePages) {
        // Cloudflare Pages环境
        const baseUrl = `${protocol}://${host}`;
        return {
            apiUrl: baseUrl,
            frontendUrl: baseUrl
        };
    }
    else if (process.env.NODE_ENV === 'development' || !process.env.NODE_ENV) {
        // 开发环境（包括未设置NODE_ENV的情况）
        return {
            apiUrl: 'http://localhost:9915',
            frontendUrl: 'http://localhost:5173'
        };
    }
    else {
        // 生产环境（Docker等）
        const baseUrl = `${protocol}://${host}`;
        return {
            apiUrl: baseUrl,
            frontendUrl: baseUrl
        };
    }
}
// OAuth回调和API路由已经正确处理重定向到前端
// 移除可能导致循环的页面重定向路由
// 添加OAuth配置调试端点
app.get('/api/auth/github/debug', c => {
    const enableGithub = getSetting('login.enable_github') === '1';
    const clientId = getSetting('github.client_id');
    const clientSecret = getSetting('github.client_secret');
    const { apiUrl, frontendUrl } = getBaseUrl(c);
    const redirectUri = `${apiUrl}/api/auth/github/callback`;
    return c.json({
        enabled: enableGithub,
        hasClientId: !!clientId,
        hasClientSecret: !!clientSecret,
        clientIdPreview: clientId ? clientId.substring(0, 8) + '...' : 'not set',
        redirectUri,
        apiUrl,
        frontendUrl,
        environment: process.env.NODE_ENV || 'development'
    });
});
app.get('/api/auth/github', c => {
    const enableGithub = getSetting('login.enable_github') === '1';
    if (!enableGithub) {
        return c.json({ error: 'GitHub login not enabled' }, 400);
    }
    const clientId = getSetting('github.client_id');
    if (!clientId) {
        return c.json({ error: 'GitHub client ID not configured' }, 500);
    }
    const { apiUrl, frontendUrl } = getBaseUrl(c);
    const redirectUri = `${apiUrl}/api/auth/github/callback`;
    const state = nanoid(32);
    // 保存 state 和前端URL 到 cookie 用于验证和重定向
    setCookie(c, 'github_oauth_state', state, {
        httpOnly: true,
        maxAge: 600, // 10 分钟
        path: '/'
    });
    setCookie(c, 'github_oauth_frontend', frontendUrl, {
        httpOnly: true,
        maxAge: 600, // 10 分钟
        path: '/'
    });
    const authUrl = new URL('https://github.com/login/oauth/authorize');
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('scope', 'user:email');
    authUrl.searchParams.set('state', state);
    return c.redirect(authUrl.toString());
});
app.get('/api/auth/github/callback', async (c) => {
    const code = c.req.query('code');
    const state = c.req.query('state');
    const savedState = getCookie(c, 'github_oauth_state');
    const frontendUrl = getCookie(c, 'github_oauth_frontend') || getBaseUrl(c).frontendUrl;
    if (!code || !state || state !== savedState) {
        return c.redirect(`${frontendUrl}/login?error=oauth_failed`);
    }
    // 清除 state 和 frontend URL cookies
    deleteCookie(c, 'github_oauth_state');
    deleteCookie(c, 'github_oauth_frontend');
    const clientId = getSetting('github.client_id');
    const clientSecret = getSetting('github.client_secret');
    if (!clientId || !clientSecret) {
        return c.redirect(`${frontendUrl}/login?error=oauth_config`);
    }
    try {
        // 交换 access token
        const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                client_id: clientId,
                client_secret: clientSecret,
                code: code,
            })
        });
        const tokenData = await tokenResponse.json();
        if (!tokenData.access_token) {
            return c.redirect(`${frontendUrl}/login?error=oauth_token`);
        }
        // 获取用户信息
        const userResponse = await fetch('https://api.github.com/user', {
            headers: {
                'Authorization': `Bearer ${tokenData.access_token}`,
                'Accept': 'application/vnd.github.v3+json',
            }
        });
        const userData = await userResponse.json();
        // 获取用户邮箱
        const emailResponse = await fetch('https://api.github.com/user/emails', {
            headers: {
                'Authorization': `Bearer ${tokenData.access_token}`,
                'Accept': 'application/vnd.github.v3+json',
            }
        });
        const emailData = await emailResponse.json();
        const primaryEmail = emailData.find((email) => email.primary)?.email || userData.email;
        // 检查是否是管理员邮箱
        const adminEmail = getSetting('admin.email');
        if (primaryEmail !== adminEmail) {
            return c.redirect(`${frontendUrl}/login?error=email_incorrect`);
        }
        // 生成JWT token
        const token = generateToken({
            userId: 'admin',
            email: adminEmail || '',
            role: 'admin'
        });
        // 生成session ID
        const sessionId = generateSessionId();
        // 根据环境设置cookie安全选项
        const isSecure = !frontendUrl.startsWith('http://localhost');
        const cookieOptions = {
            httpOnly: true,
            secure: isSecure,
            sameSite: 'Lax',
            path: '/',
            maxAge: 60 * 60 * 24 * 7, // 7 天
            domain: undefined
        };
        // 设置认证cookies
        setCookie(c, 'auth_token', token, cookieOptions);
        setCookie(c, 'session_id', sessionId, cookieOptions);
        // 记录GitHub登录日志
        try {
            const ip = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP') || '127.0.0.1';
            const userAgent = c.req.header('User-Agent') || '';
            await LogService.log({
                user_id: 'admin',
                action: LOG_ACTIONS.LOGIN,
                ip_address: ip,
                user_agent: userAgent,
                details: { method: 'github', github_user: userData.login }
            });
        }
        catch (error) {
            // 日志记录失败不影响登录
        }
        // 重定向回前端
        return c.redirect(`${frontendUrl}/`);
    }
    catch (error) {
        return c.redirect(`${frontendUrl}/login?error=oauth_error`);
    }
});
app.get('/api/me', requireInstallation, c => {
    const token = getCookie(c, 'auth_token');
    const sessionId = getCookie(c, 'session_id');
    if (!token || !sessionId) {
        return c.json({ loggedIn: false, reason: 'missing_cookies' }, 401);
    }
    // 验证JWT token
    const payload = verifyToken(token);
    if (!payload) {
        return c.json({ loggedIn: false, reason: 'invalid_token' }, 401);
    }
    return c.json({
        loggedIn: true,
        email: payload.email,
        role: payload.role
    });
});
app.post('/api/logout', c => {
    // 记录登出日志
    try {
        const ip = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP') || '127.0.0.1';
        const userAgent = c.req.header('User-Agent') || '';
        LogService.log({
            user_id: 'admin',
            action: LOG_ACTIONS.LOGOUT,
            ip_address: ip,
            user_agent: userAgent
        }).catch(() => { }); // 异步记录，不等待结果
    }
    catch (error) {
        // 忽略日志记录错误
    }
    // 清除所有认证相关的cookies
    deleteCookie(c, 'auth_token', { path: '/' });
    deleteCookie(c, 'session_id', { path: '/' });
    deleteCookie(c, 'session', { path: '/' }); // 兼容旧版本
    return c.json({ ok: true });
});
// 清理无效token的端点
app.post('/api/auth/cleanup', c => {
    // 清除所有可能的认证cookies
    deleteCookie(c, 'auth_token', { path: '/' });
    deleteCookie(c, 'session_id', { path: '/' });
    deleteCookie(c, 'session', { path: '/' });
    return c.json({ ok: true, message: 'Tokens cleared' });
});
/* Categories */
app.get('/api/categories', c => {
    const rows = db.prepare(`
    SELECT * FROM categories ORDER BY created_at
  `).all();
    return c.json(rows);
});
app.post('/api/categories', requireAuth, async (c) => {
    const { name } = await c.req.json();
    if (!name)
        return c.json({ error: 'BAD_REQUEST' }, 400);
    const id = nanoid();
    db.prepare(`
    INSERT INTO categories (id, name, created_at)
    VALUES (?, ?, ?)
  `).run(id, name, Date.now());
    // 记录创建分类日志
    try {
        await LogService.log({
            user_id: 'admin',
            action: LOG_ACTIONS.CREATE_CATEGORY,
            target_type: 'category',
            target_id: id,
            details: { name }
        });
    }
    catch (error) {
        // 忽略日志记录错误
    }
    return c.json({ ok: true, id });
});
app.put('/api/categories/:id', requireAuth, async (c) => {
    const id = c.req.param('id');
    const { name } = await c.req.json();
    if (!id || !name)
        return c.json({ error: 'BAD_REQUEST' }, 400);
    if (id === 'default')
        return c.json({ error: 'CANNOT_EDIT_DEFAULT' }, 400);
    const oldCategory = db.prepare('SELECT name FROM categories WHERE id = ?').get(id);
    db.prepare(`
    UPDATE categories SET name = ? WHERE id = ?
  `).run(name, id);
    // 记录更新分类日志
    try {
        await LogService.log({
            user_id: 'admin',
            action: LOG_ACTIONS.UPDATE_CATEGORY,
            target_type: 'category',
            target_id: id,
            details: { old_name: oldCategory?.name, new_name: name }
        });
    }
    catch (error) {
        // 忽略日志记录错误
    }
    return c.json({ ok: true });
});
app.delete('/api/categories/:id', requireAuth, c => {
    const id = c.req.param('id');
    if (!id)
        return c.json({ error: 'BAD_REQUEST' }, 400);
    if (id === 'default')
        return c.json({ error: 'CANNOT_DELETE_DEFAULT' }, 400);
    const category = db.prepare('SELECT name FROM categories WHERE id = ?').get(id);
    // 将该分类下的笔记转移到默认分类
    db.prepare(`
    UPDATE notes SET category_id = 'default' WHERE category_id = ?
  `).run(id);
    // 删除分类
    db.prepare('DELETE FROM categories WHERE id = ?').run(id);
    // 记录删除分类日志
    try {
        LogService.log({
            user_id: 'admin',
            action: LOG_ACTIONS.DELETE_CATEGORY,
            target_type: 'category',
            target_id: id,
            details: { name: category?.name }
        }).catch(() => { });
    }
    catch (error) {
        // 忽略日志记录错误
    }
    return c.json({ ok: true });
});
/* Image Upload */
// 确保上传目录存在
function ensureUploadDir(noteId) {
    const uploadDir = path.join(process.cwd(), 'data', 'upload', noteId);
    if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
    }
    return uploadDir;
}
// 获取文件扩展名
function getFileExtension(filename) {
    const ext = path.extname(filename).toLowerCase();
    const allowedExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg'];
    return allowedExts.includes(ext) ? ext : '.jpg';
}
// 生成文件hash
function generateFileHash(buffer) {
    return crypto.createHash('md5').update(buffer).digest('hex').substring(0, 8);
}
app.post('/api/upload/image/:noteId', requireAuth, async (c) => {
    try {
        const noteId = c.req.param('noteId');
        if (!noteId) {
            return c.json({ error: 'Note ID is required' }, 400);
        }
        // 验证笔记是否存在
        const note = db.prepare('SELECT id FROM notes WHERE id = ?').get(noteId);
        if (!note) {
            return c.json({ error: 'Note not found' }, 404);
        }
        const formData = await c.req.formData();
        const file = formData.get('file');
        if (!file) {
            return c.json({ error: 'No file uploaded' }, 400);
        }
        // 检查文件大小 (从设置中获取最大大小，默认10MB)
        const maxSizeMB = parseInt(getSetting('upload.max_file_size') || '10');
        const maxSize = maxSizeMB * 1024 * 1024;
        if (file.size > maxSize) {
            return c.json({ error: `File too large. Maximum size is ${maxSizeMB}MB` }, 400);
        }
        // 检查文件类型
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml'];
        if (!allowedTypes.includes(file.type)) {
            return c.json({ error: 'Invalid file type. Only images are allowed' }, 400);
        }
        // 读取文件内容
        const arrayBuffer = await file.arrayBuffer();
        const buffer = Buffer.from(arrayBuffer);
        // 生成文件名
        const timestamp = Date.now();
        const hash = generateFileHash(buffer);
        const ext = getFileExtension(file.name);
        const filename = `${timestamp}_${hash}${ext}`;
        // 确保上传目录存在
        const uploadDir = ensureUploadDir(noteId);
        const filePath = path.join(uploadDir, filename);
        // 保存文件
        fs.writeFileSync(filePath, buffer);
        // 返回文件URL
        const fileUrl = `/api/upload/image/${noteId}/${filename}`;
        return c.json({
            success: true,
            url: fileUrl,
            filename: filename
        });
    }
    catch (error) {
        return c.json({ error: 'Upload failed: ' + error.message }, 500);
    }
});
// 提供图片文件访问
app.get('/api/upload/image/:noteId/:filename', async (c) => {
    try {
        const noteId = c.req.param('noteId');
        const filename = c.req.param('filename');
        if (!noteId || !filename) {
            return c.text('Invalid parameters', 400);
        }
        const filePath = path.join(process.cwd(), 'data', 'upload', noteId, filename);
        if (!fs.existsSync(filePath)) {
            return c.text('File not found', 404);
        }
        // 获取文件扩展名来设置正确的Content-Type
        const ext = path.extname(filename).toLowerCase();
        const contentTypeMap = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.webp': 'image/webp',
            '.svg': 'image/svg+xml'
        };
        const contentType = contentTypeMap[ext] || 'application/octet-stream';
        // 读取并返回文件
        const fileBuffer = fs.readFileSync(filePath);
        return new Response(fileBuffer, {
            headers: {
                'Content-Type': contentType,
                'Cache-Control': 'public, max-age=31536000', // 缓存1年
            }
        });
    }
    catch (error) {
        return c.text('Server error', 500);
    }
});
/* Notes */
app.get('/api/notes', c => {
    const categoryId = c.req.query('category');
    const rows = categoryId
        ? db.prepare(`
        SELECT * FROM notes
        WHERE category_id=?
        ORDER BY updated_at DESC
      `).all(categoryId)
        : db.prepare(`
        SELECT * FROM notes
        ORDER BY updated_at DESC
      `).all();
    return c.json(rows);
});
app.post('/api/notes', async (c) => {
    const { categoryId } = await c.req.json();
    const noteId = nanoid();
    db.prepare(`
    INSERT INTO notes
    (id, title, content, tags, category_id, created_at, updated_at)
    VALUES (?, '', '', '', ?, ?, ?)
  `).run(noteId, categoryId ?? 'default', Date.now(), Date.now());
    // 记录创建笔记日志
    try {
        LogService.log({
            user_id: 'admin',
            action: LOG_ACTIONS.CREATE_NOTE,
            target_type: 'note',
            target_id: noteId,
            details: { category_id: categoryId ?? 'default' }
        }).catch(() => { });
    }
    catch (error) {
        // 忽略日志记录错误
    }
    return c.json({ ok: true });
});
app.put('/api/notes/:id', async (c) => {
    const id = c.req.param('id');
    if (!id)
        return c.json({ error: 'BAD_REQUEST' }, 400);
    const note = (await c.req.json());
    db.prepare(`
    UPDATE notes
    SET title=?, content=?, tags=?, category_id=?, updated_at=?
    WHERE id=?
  `).run(note.title, note.content, note.tags?.join(',') ?? '', note.category_id, Date.now(), id);
    return c.json({ ok: true });
});
app.delete('/api/notes/:id', c => {
    const id = c.req.param('id');
    if (!id)
        return c.json({ error: 'BAD_REQUEST' }, 400);
    // 获取笔记信息
    const note = db.prepare('SELECT * FROM notes WHERE id=?').get(id);
    if (!note)
        return c.json({ error: 'NOT_FOUND' }, 404);
    // 移动到回收站
    db.prepare(`
    INSERT INTO trash (id, title, content, tags, category_id, created_at, updated_at, deleted_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(note.id, note.title, note.content, note.tags, note.category_id, note.created_at, note.updated_at, Date.now());
    // 从笔记表中删除
    db.prepare('DELETE FROM notes WHERE id=?').run(id);
    // 记录删除笔记日志
    try {
        LogService.log({
            user_id: 'admin',
            action: LOG_ACTIONS.DELETE_NOTE,
            target_type: 'note',
            target_id: id,
            details: { title: note.title }
        }).catch(() => { });
    }
    catch (error) {
        // 忽略日志记录错误
    }
    return c.json({ ok: true });
});
/* Trash */
app.get('/api/trash', requireAuth, c => {
    const rows = db.prepare(`
    SELECT * FROM trash ORDER BY deleted_at DESC
  `).all();
    return c.json(rows);
});
app.post('/api/trash/:id/restore', requireAuth, c => {
    const id = c.req.param('id');
    if (!id)
        return c.json({ error: 'BAD_REQUEST' }, 400);
    // 获取回收站中的笔记
    const trashNote = db.prepare('SELECT * FROM trash WHERE id=?').get(id);
    if (!trashNote)
        return c.json({ error: 'NOT_FOUND' }, 404);
    // 恢复到笔记表
    db.prepare(`
    INSERT INTO notes (id, title, content, tags, category_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(trashNote.id, trashNote.title, trashNote.content, trashNote.tags, trashNote.category_id, trashNote.created_at, Date.now() // 更新修改时间
    );
    // 从回收站删除
    db.prepare('DELETE FROM trash WHERE id=?').run(id);
    // 记录恢复笔记日志
    try {
        LogService.log({
            user_id: 'admin',
            action: LOG_ACTIONS.RESTORE_NOTE,
            target_type: 'note',
            target_id: id,
            details: { title: trashNote.title }
        }).catch(() => { });
    }
    catch (error) {
        // 忽略日志记录错误
    }
    return c.json({ ok: true });
});
app.delete('/api/trash/:id', requireAuth, c => {
    const id = c.req.param('id');
    if (!id)
        return c.json({ error: 'BAD_REQUEST' }, 400);
    // 获取笔记信息用于日志
    const trashNote = db.prepare('SELECT title FROM trash WHERE id=?').get(id);
    // 永久删除
    db.prepare('DELETE FROM trash WHERE id=?').run(id);
    // 记录永久删除笔记日志
    try {
        LogService.log({
            user_id: 'admin',
            action: LOG_ACTIONS.PERMANENT_DELETE_NOTE,
            target_type: 'note',
            target_id: id,
            details: { title: trashNote?.title }
        }).catch(() => { });
    }
    catch (error) {
        // 忽略日志记录错误
    }
    return c.json({ ok: true });
});
app.delete('/api/trash', requireAuth, c => {
    // 清空回收站
    db.prepare('DELETE FROM trash').run();
    return c.json({ ok: true });
});
/* Share */
app.post('/api/share/:id', requireAuth, async (c) => {
    const id = c.req.param('id');
    if (!id)
        return c.json({ error: 'BAD_REQUEST' }, 400);
    const body = (await c.req.json());
    const code = nanoid(8);
    db.prepare(`
    INSERT INTO shares (id, note_id, password, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(code, id, body.password ?? null, body.expiresAt ?? null, Date.now());
    // 记录创建分享日志
    try {
        const note = db.prepare('SELECT title FROM notes WHERE id=?').get(id);
        LogService.log({
            user_id: 'admin',
            action: LOG_ACTIONS.CREATE_SHARE,
            target_type: 'share',
            target_id: code,
            details: {
                note_id: id,
                note_title: note?.title,
                has_password: !!body.password,
                expires_at: body.expiresAt
            }
        }).catch(() => { });
    }
    catch (error) {
        // 忽略日志记录错误
    }
    return c.json({ code });
});
app.get('/api/shares', requireAuth, c => {
    const noteId = c.req.query('note_id');
    if (!noteId)
        return c.json({ error: 'BAD_REQUEST' }, 400);
    const shares = db
        .prepare('SELECT * FROM shares WHERE note_id=? ORDER BY created_at DESC')
        .all(noteId);
    return c.json(shares);
});
app.delete('/api/shares/:id', requireAuth, c => {
    const id = c.req.param('id');
    if (!id)
        return c.json({ error: 'BAD_REQUEST' }, 400);
    // 获取分享信息用于日志
    const share = db.prepare('SELECT note_id FROM shares WHERE id=?').get(id);
    db.prepare('DELETE FROM shares WHERE id=?').run(id);
    // 记录删除分享日志
    try {
        LogService.log({
            user_id: 'admin',
            action: LOG_ACTIONS.DELETE_SHARE,
            target_type: 'share',
            target_id: id,
            details: { note_id: share?.note_id }
        }).catch(() => { });
    }
    catch (error) {
        // 忽略日志记录错误
    }
    return c.json({ ok: true });
});
app.post('/api/share/:code/view', async (c) => {
    const code = c.req.param('code');
    if (!code)
        return c.json({ error: 'BAD_REQUEST' }, 400);
    const body = (await c.req.json());
    const share = db
        .prepare('SELECT * FROM shares WHERE id=?')
        .get(code);
    if (!share) {
        return c.json({ error: 'NOT_FOUND' }, 404);
    }
    if (share.expires_at && Date.now() > share.expires_at) {
        return c.json({ error: 'EXPIRED' }, 403);
    }
    if (share.password && share.password !== body.password) {
        return c.json({ error: 'PASSWORD_REQUIRED' }, 401);
    }
    const note = db
        .prepare('SELECT * FROM notes WHERE id=?')
        .get(share.note_id);
    // 记录查看分享日志
    try {
        const ip = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP') || '127.0.0.1';
        const userAgent = c.req.header('User-Agent') || '';
        LogService.log({
            user_id: 'anonymous',
            action: LOG_ACTIONS.VIEW_SHARE,
            target_type: 'share',
            target_id: code,
            ip_address: ip,
            user_agent: userAgent,
            details: {
                note_id: share.note_id,
                note_title: note?.title
            }
        }).catch(() => { });
    }
    catch (error) {
        // 忽略日志记录错误
    }
    return c.json(note);
});
/* Search */
app.get('/api/search', c => {
    const q = c.req.query('q');
    if (!q)
        return c.json([]);
    // Use LIKE search for reliability
    const searchTerm = `%${q}%`;
    const rows = db.prepare(`
    SELECT * FROM notes 
    WHERE title LIKE ? OR content LIKE ? OR tags LIKE ?
    ORDER BY updated_at DESC
  `).all(searchTerm, searchTerm, searchTerm);
    return c.json(rows);
});
/* WebDAV Test */
app.post('/api/webdav/test', requireAuth, async (c) => {
    const { webdav } = await c.req.json();
    if (!webdav.url || !webdav.user || !webdav.password) {
        return c.json({ error: 'WebDAV 配置不完整' }, 400);
    }
    try {
        const result = await testWebDAVConnection(webdav);
        return c.json({ message: result });
    }
    catch (error) {
        console.error('WebDAV test error:', error);
        return c.json({ error: error?.message || 'WebDAV 连接测试失败' }, 500);
    }
});
async function testWebDAVConnection(webdav) {
    const url = webdav.url.endsWith('/') ? webdav.url : webdav.url + '/';
    // 测试基本连接 - 尝试列出根目录
    const response = await fetch(url, {
        method: 'PROPFIND',
        headers: {
            'Authorization': 'Basic ' + btoa(`${webdav.user}:${webdav.password}`),
            'Depth': '1',
            'Content-Type': 'application/xml'
        },
        body: `<?xml version="1.0" encoding="utf-8" ?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:displayname/>
    <D:resourcetype/>
  </D:prop>
</D:propfind>`
    });
    if (!response.ok) {
        const responseText = await response.text().catch(() => 'No response body');
        throw new Error(`WebDAV 连接失败: ${response.status} ${response.statusText}. 详情: ${responseText}`);
    }
    // 测试创建目录权限
    const testDirUrl = url + 'xa-note-test-' + Date.now() + '/';
    const mkcolResponse = await fetch(testDirUrl, {
        method: 'MKCOL',
        headers: {
            'Authorization': 'Basic ' + btoa(`${webdav.user}:${webdav.password}`)
        }
    });
    if (mkcolResponse.status === 201) {
        // 创建成功，尝试删除测试目录
        try {
            await fetch(testDirUrl, {
                method: 'DELETE',
                headers: {
                    'Authorization': 'Basic ' + btoa(`${webdav.user}:${webdav.password}`)
                }
            });
        }
        catch (error) {
            // 忽略清理错误
        }
        return 'WebDAV 连接成功！服务器支持读取和写入操作。';
    }
    else if (mkcolResponse.status === 405) {
        return 'WebDAV 连接成功！但可能没有创建目录的权限，请检查权限设置。';
    }
    else {
        const responseText = await mkcolResponse.text().catch(() => 'No response body');
        throw new Error(`WebDAV 权限测试失败: ${mkcolResponse.status} ${mkcolResponse.statusText}. 详情: ${responseText}`);
    }
}
/* Backup */
app.post('/api/backup', requireAuth, async (c) => {
    const { type, webdav } = await c.req.json();
    if (!webdav.url || !webdav.user || !webdav.password) {
        return c.json({ error: 'WebDAV 配置不完整' }, 400);
    }
    try {
        let result;
        if (type === 'notes') {
            result = await backupNotesToWebDAV(webdav);
            // 记录笔记备份日志
            try {
                LogService.log({
                    user_id: 'admin',
                    action: LOG_ACTIONS.BACKUP_DATA,
                    details: { type: 'notes', result }
                }).catch(() => { });
            }
            catch (error) {
                // 忽略日志记录错误
            }
            return c.json({ message: result });
        }
        else if (type === 'database') {
            result = await backupDatabaseToWebDAV(webdav);
            // 记录数据库备份日志
            try {
                LogService.log({
                    user_id: 'admin',
                    action: LOG_ACTIONS.BACKUP_DATA,
                    details: { type: 'database', result }
                }).catch(() => { });
            }
            catch (error) {
                // 忽略日志记录错误
            }
            return c.json({ message: result });
        }
        else {
            return c.json({ error: '不支持的备份类型' }, 400);
        }
    }
    catch (error) {
        return c.json({ error: error?.message || '备份失败' }, 500);
    }
});
async function backupNotesToWebDAV(webdav) {
    // 获取所有笔记和分类
    const notes = db.prepare('SELECT * FROM notes ORDER BY updated_at DESC').all();
    const categories = db.prepare('SELECT * FROM categories').all();
    const categoryMap = new Map();
    categories.forEach(cat => categoryMap.set(cat.id, cat.name));
    let successCount = 0;
    // 使用新的目录命名规则
    const timestamp = new Date().toISOString().slice(0, 10).replace(/-/g, ''); // YYYYMMDD
    const backupDir = `xanote-backup-${timestamp}`;
    for (const note of notes) {
        try {
            const categoryName = categoryMap.get(note.category_id) || '默认';
            const tags = note.tags ? note.tags.split(',').filter(Boolean) : [];
            // 构建文件名：分类_标题.md
            let filename = categoryName;
            if (note.title) {
                filename += `_${note.title}`;
            }
            else {
                filename += '_无标题';
            }
            filename = filename.replace(/[<>:"/\\|?*\s]/g, '_') + '.md';
            // 构建文件内容
            let content = '';
            if (note.title) {
                content += `# ${note.title}\n\n`;
            }
            content += `**分类：** ${categoryName}\n\n`;
            if (tags.length > 0) {
                content += `**标签：** ${tags.map((tag) => `#${tag}`).join(' ')}\n\n`;
            }
            content += `**创建时间：** ${new Date(note.created_at).toLocaleString('zh-CN')}\n\n`;
            content += `**更新时间：** ${new Date(note.updated_at).toLocaleString('zh-CN')}\n\n`;
            content += '---\n\n';
            content += note.content;
            // 上传到 WebDAV
            const filePath = `${backupDir}/notes/${filename}`;
            await uploadToWebDAV(webdav, filePath, content);
            successCount++;
        }
        catch (error) {
            // 忽略单个笔记备份失败
        }
    }
    return `成功备份 ${successCount}/${notes.length} 个笔记到 WebDAV`;
}
async function backupDatabaseToWebDAV(webdav) {
    // 使用新的目录命名规则
    const timestamp = new Date().toISOString().slice(0, 10).replace(/-/g, ''); // YYYYMMDD
    const backupDir = `xanote-backup-${timestamp}`;
    // 导出数据库为 SQL
    const tables = ['settings', 'categories', 'notes', 'shares', 'trash'];
    let sqlContent = `-- XA Note Database Backup\n-- Generated at: ${new Date().toISOString()}\n\n`;
    for (const table of tables) {
        try {
            const rows = db.prepare(`SELECT * FROM ${table}`).all();
            if (rows.length > 0) {
                sqlContent += `-- Table: ${table}\n`;
                // 获取表结构
                const schema = db.prepare(`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`).get(table);
                if (schema) {
                    sqlContent += `${schema.sql};\n\n`;
                }
                // 导出数据
                for (const row of rows) {
                    const columns = Object.keys(row).join(', ');
                    const values = Object.values(row).map(val => val === null ? 'NULL' : `'${String(val).replace(/'/g, "''")}'`).join(', ');
                    sqlContent += `INSERT INTO ${table} (${columns}) VALUES (${values});\n`;
                }
                sqlContent += '\n';
            }
        }
        catch (error) {
            // 忽略单个表导出失败
        }
    }
    // 上传到 WebDAV - 使用更短的文件名
    const filePath = `${backupDir}/database/xa-note-${timestamp}.sql`;
    await uploadToWebDAV(webdav, filePath, sqlContent);
    return `数据库备份完成，文件：${filePath}`;
}
async function uploadToWebDAV(webdav, filePath, content) {
    const url = webdav.url.endsWith('/') ? webdav.url : webdav.url + '/';
    const fullUrl = url + filePath;
    // 创建目录结构 - 必须按顺序逐级创建
    const pathParts = filePath.split('/').filter(part => part.length > 0);
    const fileName = pathParts.pop(); // 移除文件名，只处理目录
    if (pathParts.length > 0) {
        let currentPath = '';
        for (let i = 0; i < pathParts.length; i++) {
            currentPath += pathParts[i] + '/';
            const dirUrl = url + currentPath;
            try {
                const dirResponse = await fetch(dirUrl, {
                    method: 'MKCOL',
                    headers: {
                        'Authorization': 'Basic ' + btoa(`${webdav.user}:${webdav.password}`),
                        'Content-Type': 'application/xml'
                    }
                });
                // 201 = Created successfully
                // 405 = Method Not Allowed (directory already exists)
                // 409 = Conflict (parent doesn't exist - this shouldn't happen with our sequential approach)
                if (dirResponse.status === 201) {
                    // 给服务器一点时间处理目录创建
                    await new Promise(resolve => setTimeout(resolve, 100));
                }
                else if (dirResponse.status === 409) {
                    const responseText = await dirResponse.text().catch(() => 'No response body');
                    throw new Error(`无法创建目录 ${currentPath}: ${dirResponse.status} ${dirResponse.statusText}`);
                }
            }
            catch (error) {
                // 如果是网络错误，重新抛出
                if (error.message.includes('fetch')) {
                    throw error;
                }
                // 其他错误可能是目录已存在，继续尝试
            }
        }
    }
    // 上传文件
    const response = await fetch(fullUrl, {
        method: 'PUT',
        headers: {
            'Authorization': 'Basic ' + btoa(`${webdav.user}:${webdav.password}`),
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Length': Buffer.byteLength(content, 'utf8').toString()
        },
        body: content
    });
    if (!response.ok) {
        const responseText = await response.text().catch(() => 'No response body');
        throw new Error(`WebDAV upload failed: ${response.status} ${response.statusText}. Response: ${responseText}`);
    }
}
/* Data Import */
app.post('/api/import/sql', requireAuth, async (c) => {
    try {
        const { sqlContent } = await c.req.json();
        if (!sqlContent) {
            return c.json({ error: 'SQL content is required' }, 400);
        }
        // 执行SQL导入
        const statements = sqlContent
            .split(';')
            .map((stmt) => stmt.trim())
            .filter((stmt) => stmt.length > 0 && !stmt.startsWith('--'));
        let successCount = 0;
        let errorCount = 0;
        const errors = [];
        for (const statement of statements) {
            try {
                if (statement.toUpperCase().includes('INSERT') ||
                    statement.toUpperCase().includes('UPDATE') ||
                    statement.toUpperCase().includes('CREATE TABLE')) {
                    db.exec(statement);
                    successCount++;
                }
            }
            catch (error) {
                errorCount++;
                errors.push(`Statement failed: ${statement.substring(0, 50)}... - ${error.message}`);
            }
        }
        // 记录SQL导入日志
        try {
            LogService.log({
                user_id: 'admin',
                action: LOG_ACTIONS.IMPORT_DATA,
                details: {
                    type: 'sql_content',
                    success_count: successCount,
                    error_count: errorCount
                }
            }).catch(() => { });
        }
        catch (error) {
            // 忽略日志记录错误
        }
        return c.json({
            success: true,
            message: `导入完成：${successCount} 条语句成功，${errorCount} 条语句失败`,
            details: {
                successCount,
                errorCount,
                errors: errors.slice(0, 10) // 只返回前10个错误
            }
        });
    }
    catch (error) {
        return c.json({ error: `导入失败: ${error.message}` }, 500);
    }
});
// 从文件导入SQL
app.post('/api/import/sql-file', requireAuth, async (c) => {
    try {
        const { filename } = await c.req.json();
        if (!filename) {
            return c.json({ error: 'Filename is required' }, 400);
        }
        const filePath = path.join(process.cwd(), 'data', filename);
        if (!fs.existsSync(filePath)) {
            return c.json({ error: `File not found: ${filename}` }, 404);
        }
        const sqlContent = fs.readFileSync(filePath, 'utf-8');
        // 执行SQL导入
        const statements = sqlContent
            .split(';')
            .map((stmt) => stmt.trim())
            .filter((stmt) => stmt.length > 0 && !stmt.startsWith('--'));
        let successCount = 0;
        let errorCount = 0;
        const errors = [];
        for (const statement of statements) {
            try {
                if (statement.toUpperCase().includes('INSERT') ||
                    statement.toUpperCase().includes('UPDATE') ||
                    statement.toUpperCase().includes('CREATE TABLE')) {
                    db.exec(statement);
                    successCount++;
                }
            }
            catch (error) {
                errorCount++;
                errors.push(`Statement failed: ${statement.substring(0, 50)}... - ${error.message}`);
                console.error('SQL execution error:', error.message);
            }
        }
        // 记录SQL文件导入日志
        try {
            LogService.log({
                user_id: 'admin',
                action: LOG_ACTIONS.IMPORT_DATA,
                details: {
                    type: 'sql_file',
                    filename,
                    success_count: successCount,
                    error_count: errorCount
                }
            }).catch(() => { });
        }
        catch (error) {
            // 忽略日志记录错误
        }
        return c.json({
            success: true,
            message: `从 ${filename} 导入完成：${successCount} 条语句成功，${errorCount} 条语句失败`,
            details: {
                successCount,
                errorCount,
                errors: errors.slice(0, 10)
            }
        });
    }
    catch (error) {
        return c.json({ error: `文件导入失败: ${error.message}` }, 500);
    }
});
/* Sitemap */
app.get('/sitemap.xml', c => {
    // 获取当前请求的域名和协议
    const host = c.req.header('host') || 'localhost:9915';
    const protocol = c.req.header('x-forwarded-proto') ||
        c.req.header('cf-visitor') ? 'https' :
        (host.includes('localhost') ? 'http' : 'https');
    const baseUrl = `${protocol}://${host}`;
    // 获取当前日期
    const currentDate = new Date().toISOString().split('T')[0];
    const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml">
    
    <!-- 主页 -->
    <url>
        <loc>${baseUrl}/</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>daily</changefreq>
        <priority>1.0</priority>
        <xhtml:link rel="alternate" hreflang="zh-CN" href="${baseUrl}/" />
        <xhtml:link rel="alternate" hreflang="en" href="${baseUrl}/?lang=en" />
    </url>
    
    <!-- 登录页面 -->
    <url>
        <loc>${baseUrl}/login</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
        <xhtml:link rel="alternate" hreflang="zh-CN" href="${baseUrl}/login" />
        <xhtml:link rel="alternate" hreflang="en" href="${baseUrl}/login?lang=en" />
    </url>
    
    <!-- 功能介绍页面 -->
    <url>
        <loc>${baseUrl}/features</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>weekly</changefreq>
        <priority>0.7</priority>
        <xhtml:link rel="alternate" hreflang="zh-CN" href="${baseUrl}/features" />
        <xhtml:link rel="alternate" hreflang="en" href="${baseUrl}/features?lang=en" />
    </url>
    
    <!-- 帮助文档页面 -->
    <url>
        <loc>${baseUrl}/help</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>weekly</changefreq>
        <priority>0.6</priority>
        <xhtml:link rel="alternate" hreflang="zh-CN" href="${baseUrl}/help" />
        <xhtml:link rel="alternate" hreflang="en" href="${baseUrl}/help?lang=en" />
    </url>
    
    <!-- 隐私政策页面 -->
    <url>
        <loc>${baseUrl}/privacy</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.5</priority>
        <xhtml:link rel="alternate" hreflang="zh-CN" href="${baseUrl}/privacy" />
        <xhtml:link rel="alternate" hreflang="en" href="${baseUrl}/privacy?lang=en" />
    </url>

    <!-- 版权信息页面 -->
    <url>
        <loc>${baseUrl}/copyright</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.5</priority>
        <xhtml:link rel="alternate" hreflang="zh-CN" href="${baseUrl}/copyright" />
        <xhtml:link rel="alternate" hreflang="en" href="${baseUrl}/copyright?lang=en" />
    </url>
    
</urlset>`;
    return new Response(sitemap, {
        headers: {
            'Content-Type': 'application/xml',
            'Cache-Control': 'public, max-age=3600' // 缓存1小时
        }
    });
});
/* Robots.txt */
app.get('/robots.txt', c => {
    // 获取当前请求的域名和协议
    const host = c.req.header('host') || 'localhost:9915';
    const protocol = c.req.header('x-forwarded-proto') ||
        c.req.header('cf-visitor') ? 'https' :
        (host.includes('localhost') ? 'http' : 'https');
    const baseUrl = `${protocol}://${host}`;
    const robots = `User-agent: *
Allow: /

# 静态资源
Allow: /assets/
Allow: /favicon.png
Allow: /logo.png
Allow: /manifest.json

# 禁止访问的路径
Disallow: /api/
Disallow: /admin/
Disallow: /data/

# Sitemap
Sitemap: ${baseUrl}/sitemap.xml`;
    return new Response(robots, {
        headers: {
            'Content-Type': 'text/plain',
            'Cache-Control': 'public, max-age=86400' // 缓存24小时
        }
    });
});
/* System Info */
app.get('/api/system/info', c => {
    try {
        // Try to read build info first
        let buildInfo = null;
        try {
            const buildInfoPath = path.join(process.cwd(), 'dist-server', 'build-info.json');
            buildInfo = JSON.parse(fs.readFileSync(buildInfoPath, 'utf8'));
        }
        catch (e) {
            // Fallback to package.json for development
            try {
                const packagePath = path.join(process.cwd(), 'package.json');
                const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
                buildInfo = {
                    name: packageJson.name || 'XA Note',
                    version: packageJson.version || '1.0.0',
                    buildTime: new Date().toISOString()
                };
            }
            catch (e2) {
                buildInfo = {
                    name: 'XA Note',
                    version: '1.0.0',
                    buildTime: new Date().toISOString()
                };
            }
        }
        // 获取数据库统计信息
        const notesCount = db.prepare('SELECT COUNT(*) as count FROM notes').get();
        const categoriesCount = db.prepare('SELECT COUNT(*) as count FROM categories').get();
        // 获取数据库文件大小
        const dbPath = path.join(process.cwd(), 'data', 'data.db');
        let dbSize = 0;
        try {
            const stats = fs.statSync(dbPath);
            dbSize = Math.round(stats.size / 1024); // KB
        }
        catch (e) {
            dbSize = 0;
        }
        return c.json({
            name: buildInfo.name,
            version: buildInfo.version,
            buildTime: buildInfo.buildTime,
            notesCount: notesCount.count || 0,
            categoriesCount: categoriesCount.count || 0,
            databaseSize: `${dbSize} KB`
        });
    }
    catch (error) {
        return c.json({
            name: 'XA Note',
            version: '1.0.0',
            buildTime: new Date().toISOString(),
            notesCount: 0,
            categoriesCount: 0,
            databaseSize: '0 KB'
        });
    }
});
/* Settings */
app.get('/api/settings/debug', c => {
    const enableTurnstile = getSetting('login.enable_turnstile');
    const siteKey = getSetting('login.turnstile_site_key');
    const secretKey = getSetting('login.turnstile_secret_key');
    return c.json({
        turnstile_enabled: enableTurnstile,
        has_site_key: !!siteKey,
        has_secret_key: !!secretKey,
        site_key_preview: siteKey ? siteKey.substring(0, 10) + '...' : 'none',
        secret_key_preview: secretKey ? secretKey.substring(0, 10) + '...' : 'none'
    });
});
app.get('/api/settings/public', c => {
    return c.json({
        'login.enable_captcha': getSetting('login.enable_captcha') || '0',
        'login.enable_turnstile': getSetting('login.enable_turnstile') || '0',
        'login.turnstile_site_key': getSetting('login.turnstile_site_key') || '',
        'login.enable_github': getSetting('login.enable_github') || '0',
        'site.title': getSetting('site.title') || 'XA Note',
        'site.logo': getSetting('site.logo') || '/logo.png',
        'site.favicon': getSetting('site.favicon') || '/favicon.png',
        'site.avatar_prefix': getSetting('site.avatar_prefix') || 'https://www.gravatar.com/avatar/',
        'upload.max_file_size': getSetting('upload.max_file_size') || '10'
    });
});
app.get('/api/settings', requireAuth, c => {
    return c.json(getSettings());
});
app.post('/api/settings', requireAuth, async (c) => {
    const updates = await c.req.json();
    for (const [key, value] of Object.entries(updates)) {
        if (key === 'admin.password') {
            const hash = bcrypt.hashSync(String(value), 10);
            setSetting('admin.password_hash', hash);
            continue;
        }
        setSetting(key, String(value));
    }
    // 记录设置更新日志
    try {
        LogService.log({
            user_id: 'admin',
            action: LOG_ACTIONS.UPDATE_SETTINGS,
            details: {
                updated_keys: Object.keys(updates),
                keys_count: Object.keys(updates).length
            }
        }).catch(() => { });
    }
    catch (error) {
        // 忽略日志记录错误
    }
    // 如果备份相关设置有更新，重新调度备份任务
    const backupKeys = ['backup.frequency', 'webdav.url', 'webdav.user', 'webdav.password'];
    if (Object.keys(updates).some(key => backupKeys.includes(key))) {
        try {
            await backupScheduler.updateSchedule();
        }
        catch (error) {
            // 忽略备份调度更新错误
        }
    }
    return c.json({ ok: true });
});
app.put('/api/settings', requireAuth, async (c) => {
    const updates = await c.req.json();
    for (const [key, value] of Object.entries(updates)) {
        if (key === 'admin.password') {
            const hash = bcrypt.hashSync(String(value), 10);
            setSetting('admin.password_hash', hash);
            continue;
        }
        setSetting(key, String(value));
    }
    // 记录设置更新日志
    try {
        LogService.log({
            user_id: 'admin',
            action: LOG_ACTIONS.UPDATE_SETTINGS,
            details: {
                updated_keys: Object.keys(updates),
                keys_count: Object.keys(updates).length
            }
        }).catch(() => { });
    }
    catch (error) {
        // 忽略日志记录错误
    }
    return c.json({ ok: true });
});
/* Logs */
// 获取日志列表
app.get('/api/logs', requireAuth, async (c) => {
    try {
        const { LogService } = await import('./services/log-service.js');
        const limit = parseInt(c.req.query('limit') || '50');
        const offset = parseInt(c.req.query('offset') || '0');
        const action = c.req.query('action');
        const target_type = c.req.query('target_type');
        const start_date = c.req.query('start_date') ? parseInt(c.req.query('start_date')) : undefined;
        const end_date = c.req.query('end_date') ? parseInt(c.req.query('end_date')) : undefined;
        const result = await LogService.getLogs({
            user_id: 'admin', // 目前只有一个管理员用户
            limit,
            offset,
            action,
            target_type,
            start_date,
            end_date
        });
        return c.json(result);
    }
    catch (error) {
        console.error('Failed to get logs:', error);
        return c.json({ error: 'INTERNAL_ERROR' }, 500);
    }
});
// 获取日志统计
app.get('/api/logs/stats', requireAuth, async (c) => {
    try {
        const { LogService } = await import('./services/log-service.js');
        const days = parseInt(c.req.query('days') || '30');
        const stats = await LogService.getLogStats('admin', days);
        return c.json(stats);
    }
    catch (error) {
        console.error('Failed to get log stats:', error);
        return c.json({ error: 'INTERNAL_ERROR' }, 500);
    }
});
// 清理旧日志
app.post('/api/logs/cleanup', requireAuth, async (c) => {
    try {
        const { LogService } = await import('./services/log-service.js');
        const { days = 90 } = await c.req.json();
        const deletedCount = await LogService.cleanOldLogs(days);
        return c.json({ deletedCount });
    }
    catch (error) {
        console.error('Failed to cleanup logs:', error);
        return c.json({ error: 'INTERNAL_ERROR' }, 500);
    }
});
app.use('/api/notes/*', requireAuth);
app.use('/api/categories/*', requireAuth);
app.use('/api/settings', requireAuth);
app.use('/api/settings/*', requireAuth);
// 静态文件服务 - 生产环境提供前端文件
if (process.env.NODE_ENV?.trim() === 'production') {
    // 提供构建后的前端文件
    app.use('/*', serveStatic({
        root: './dist',
        index: 'index.html'
    }));
    // SPA路由支持 - 所有非API路由都返回index.html
    app.get('*', async (c, next) => {
        if (c.req.path.startsWith('/api/')) {
            await next();
            return;
        }
        try {
            const indexPath = path.join(process.cwd(), 'dist', 'index.html');
            let indexContent = fs.readFileSync(indexPath, 'utf-8');
            // 获取当前请求的域名和协议
            const host = c.req.header('host') || 'localhost:9915';
            const protocol = c.req.header('x-forwarded-proto') ||
                c.req.header('cf-visitor') ? 'https' :
                (host.includes('localhost') ? 'http' : 'https');
            const baseUrl = `${protocol}://${host}`;
            // 替换占位符
            indexContent = indexContent.replace(/%BASE_URL%/g, baseUrl);
            return c.html(indexContent);
        }
        catch (error) {
            return c.text('Application not found', 404);
        }
    });
}
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 9915;
serve({
    fetch: app.fetch,
    port: PORT
});
console.log(`API running at http://localhost:${PORT}`);
//# sourceMappingURL=index.js.map