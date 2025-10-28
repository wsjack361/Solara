// functions/api/[[route]].js
// Solara 用户系统后端 API - 完整版

// ==================== Redis 客户端封装 ====================
class RedisClient {
  async get(key) {
    try {
      const response = await fetch(`${this.url}/get/${key}`, {
        headers: { 'Authorization': `Bearer ${this.token}` }
      });
      const result = await response.json();
      
      // ⬇️ 关键：增加调试日志
      console.log(`[Redis GET] key=${key}, result=`, result);
      
      if (!result.result) {
        console.log(`[Redis GET] 键不存在: ${key}`);
        return null;
      }
      
      try {
        const parsed = JSON.parse(result.result);
        console.log(`[Redis GET] 解析成功:`, parsed);
        return parsed;
      } catch (parseError) {
        console.error(`[Redis GET] JSON 解析失败:`, parseError);
        console.error(`[Redis GET] 原始数据:`, result.result);
        return null;
      }
    } catch (error) {
      console.error('Redis GET error:', error);
      return null;
    }
  }

  async set(key, value, ex = null) {
    try {
      const body = { value: JSON.stringify(value) };
      if (ex) body.ex = ex;
      
      // ⬇️ 关键：增加调试日志
      console.log(`[Redis SET] key=${key}, value=`, value);
      console.log(`[Redis SET] body=`, body);
      
      const response = await fetch(`${this.url}/set/${key}`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
      });
      
      const result = await response.json();
      console.log(`[Redis SET] response=`, result);
      
      return true;
    } catch (error) {
      console.error('Redis SET error:', error);
      return false;
    }
  }
}

  async del(key) {
    try {
      await fetch(`${this.url}/del/${key}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${this.token}` }
      });
      return true;
    } catch (error) {
      console.error('Redis DEL error:', error);
      return false;
    }
  }

  async keys(pattern) {
    try {
      const response = await fetch(`${this.url}/keys/${pattern}`, {
        headers: { 'Authorization': `Bearer ${this.token}` }
      });
      const result = await response.json();
      return result.result || [];
    } catch (error) {
      console.error('Redis KEYS error:', error);
      return [];
    }
  }
}

// ==================== 工具函数 ====================
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyToken(redis, token) {
  if (!token) return null;
  const session = await redis.get(`session:${token}`);
  return session;
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}

// ==================== 主路由处理 ====================
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace('/api', '');
  
  console.log(`[API] ${request.method} ${path}`); // 调试日志
  
  // CORS 预检请求
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      }
    });
  }

  // 检查环境变量
  if (!env.UPSTASH_URL || !env.UPSTASH_TOKEN) {
    console.error('[API] 环境变量未配置');
    return jsonResponse({ 
      error: '服务器配置错误：未设置 UPSTASH_URL 和 UPSTASH_TOKEN',
      debug: {
        hasUrl: !!env.UPSTASH_URL,
        hasToken: !!env.UPSTASH_TOKEN
      }
    }, 500);
  }

  const redis = new RedisClient(env.UPSTASH_URL, env.UPSTASH_TOKEN);

  try {
    // 路由分发
    if (path.startsWith('/auth/')) {
      return await handleAuth(request, redis, env, path);
    } else if (path.startsWith('/user/')) {
      return await handleUser(request, redis, path);
    } else if (path.startsWith('/admin/')) {
      return await handleAdmin(request, redis, path);
    } else {
      return jsonResponse({ error: '未找到路由', path }, 404);
    }
  } catch (error) {
    console.error('[API] Error:', error);
    return jsonResponse({ 
      error: error.message,
      stack: error.stack 
    }, 500);
  }
}

// ==================== 认证路由 ====================
async function handleAuth(request, redis, env, path) {
  // 用户注册
  if (path === '/auth/register') {
    const registerEnabled = env.ENABLE_REGISTER === 'true';
    if (!registerEnabled) {
      return jsonResponse({ error: '注册功能已关闭，请联系管理员' }, 403);
    }

    const body = await request.json();
    const { username, password, email } = body;
    
    console.log(`[注册] 用户名: ${username}`);
    
    // 输入验证
    if (!username || !password) {
      return jsonResponse({ error: '用户名和密码不能为空' }, 400);
    }
    
    if (username.length < 3) {
      return jsonResponse({ error: '用户名至少3个字符' }, 400);
    }
    
    if (password.length < 6) {
      return jsonResponse({ error: '密码至少6个字符' }, 400);
    }

    // 检查用户是否存在
    const existingUser = await redis.get(`users:${username}`);
    if (existingUser) {
      return jsonResponse({ error: '用户名已被占用' }, 400);
    }

    // 创建用户
    const hashedPassword = await hashPassword(password);
    console.log(`[注册] 密码哈希: ${hashedPassword}`);
    
    const user = {
      username,
      password: hashedPassword,
      email: email || '',
      role: 'user',
      createdAt: new Date().toISOString(),
      lastLogin: new Date().toISOString(),
      status: 'active'
    };

    const saved = await redis.set(`users:${username}`, user);
    if (!saved) {
      return jsonResponse({ error: '保存用户失败' }, 500);
    }

    // 创建会话（7天过期）
    const token = generateToken();
    await redis.set(`session:${token}`, { username, role: user.role }, 604800);

    console.log(`[注册] 成功，Token: ${token.substring(0, 10)}...`);

    return jsonResponse({
      success: true,
      token,
      user: {
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  }

  // 用户登录
  if (path === '/auth/login') {
    const body = await request.json();
    const { username, password } = body;

    console.log(`[登录] 尝试登录: ${username}`);

    if (!username || !password) {
      return jsonResponse({ error: '用户名和密码不能为空' }, 400);
    }

    // 获取用户数据
    const user = await redis.get(`users:${username}`);
    console.log(`[登录] 用户存在: ${!!user}`);
    
    if (!user) {
      return jsonResponse({ error: '用户名或密码错误' }, 401);
    }

    // 验证密码
    const hashedPassword = await hashPassword(password);
    console.log(`[登录] 输入密码哈希: ${hashedPassword}`);
    console.log(`[登录] 存储密码哈希: ${user.password}`);
    console.log(`[登录] 密码匹配: ${user.password === hashedPassword}`);
    
    if (user.password !== hashedPassword) {
      return jsonResponse({ error: '用户名或密码错误' }, 401);
    }

    if (user.status !== 'active') {
      return jsonResponse({ error: '账户已被禁用，请联系管理员' }, 403);
    }

    // 更新最后登录时间
    user.lastLogin = new Date().toISOString();
    await redis.set(`users:${username}`, user);

    // 创建会话（7天过期）
    const token = generateToken();
    await redis.set(`session:${token}`, { username, role: user.role }, 604800);

    console.log(`[登录] 成功，Token: ${token.substring(0, 10)}...`);

    return jsonResponse({
      success: true,
      token,
      user: {
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  }

  // 用户登出
  if (path === '/auth/logout') {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    if (token) {
      await redis.del(`session:${token}`);
      console.log(`[登出] Token 已删除`);
    }
    return jsonResponse({ success: true });
  }

  // 验证Token
  if (path === '/auth/verify') {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    console.log(`[验证] Token: ${token ? token.substring(0, 10) + '...' : 'null'}`);
    
    const session = await verifyToken(redis, token);
    console.log(`[验证] Session 存在: ${!!session}`);
    
    if (!session) {
      return jsonResponse({ error: '未授权，请重新登录' }, 401);
    }

    const user = await redis.get(`users:${session.username}`);
    if (!user) {
      return jsonResponse({ error: '用户不存在' }, 401);
    }

    return jsonResponse({
      success: true,
      user: {
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  }

  return jsonResponse({ error: '未找到路由' }, 404);
}

// ==================== 用户数据路由 ====================
async function handleUser(request, redis, path) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  const session = await verifyToken(redis, token);
  
  if (!session) {
    return jsonResponse({ error: '请先登录' }, 401);
  }

  const username = session.username;

  // GET /user/playlist - 获取播放列表
  if (path === '/user/playlist' && request.method === 'GET') {
    const playlist = await redis.get(`users:${username}:playlist`) || [];
    return jsonResponse({ success: true, data: playlist });
  }

  // POST /user/playlist - 保存播放列表
  if (path === '/user/playlist' && request.method === 'POST') {
    const body = await request.json();
    await redis.set(`users:${username}:playlist`, body.playlist);
    return jsonResponse({ success: true });
  }

  // GET /user/history - 获取播放历史
  if (path === '/user/history' && request.method === 'GET') {
    const history = await redis.get(`users:${username}:history`) || [];
    return jsonResponse({ success: true, data: history });
  }

  // POST /user/history - 添加播放历史
  if (path === '/user/history' && request.method === 'POST') {
    const body = await request.json();
    const history = await redis.get(`users:${username}:history`) || [];
    
    history.unshift({ ...body.song, timestamp: Date.now() });
    if (history.length > 100) history.pop();
    
    await redis.set(`users:${username}:history`, history);
    return jsonResponse({ success: true });
  }

  // GET /user/settings - 获取用户设置
  if (path === '/user/settings' && request.method === 'GET') {
    const settings = await redis.get(`users:${username}:settings`) || {
      theme: 'dark',
      volume: 0.8,
      playMode: 'loop'
    };
    return jsonResponse({ success: true, data: settings });
  }

  // POST /user/settings - 保存用户设置
  if (path === '/user/settings' && request.method === 'POST') {
    const settings = await request.json();
    await redis.set(`users:${username}:settings`, settings);
    return jsonResponse({ success: true });
  }

  return jsonResponse({ error: '未找到路由' }, 404);
}

// ==================== 管理员路由 ====================
async function handleAdmin(request, redis, path) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  const session = await verifyToken(redis, token);
  
  if (!session || session.role !== 'admin') {
    return jsonResponse({ error: '无权限访问，仅管理员可访问' }, 403);
  }

  // GET /admin/users - 获取所有用户
  if (path === '/admin/users' && request.method === 'GET') {
    const userKeys = await redis.keys('users:*');
    const users = [];
    
    for (const key of userKeys) {
      if (!key.includes(':playlist') && !key.includes(':history') && !key.includes(':settings')) {
        const user = await redis.get(key);
        if (user) {
          users.push({
            username: user.username,
            email: user.email,
            role: user.role,
            status: user.status,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin
          });
        }
      }
    }
    
    return jsonResponse({ success: true, data: users });
  }

  // POST /admin/users/status - 更新用户状态
  if (path === '/admin/users/status' && request.method === 'POST') {
    const body = await request.json();
    const { username, status } = body;
    
    const user = await redis.get(`users:${username}`);
    if (!user) {
      return jsonResponse({ error: '用户不存在' }, 404);
    }

    user.status = status;
    await redis.set(`users:${username}`, user);
    
    return jsonResponse({ success: true });
  }

  // POST /admin/users/delete - 删除用户
  if (path === '/admin/users/delete' && request.method === 'POST') {
    const body = await request.json();
    const { username } = body;
    
    await redis.del(`users:${username}`);
    await redis.del(`users:${username}:playlist`);
    await redis.del(`users:${username}:history`);
    await redis.del(`users:${username}:settings`);
    
    return jsonResponse({ success: true });
  }

  // GET /admin/stats - 获取统计数据
  if (path === '/admin/stats' && request.method === 'GET') {
    const userKeys = await redis.keys('users:*');
    const totalUsers = userKeys.filter(k => 
      !k.includes(':playlist') && !k.includes(':history') && !k.includes(':settings')
    ).length;

    return jsonResponse({
      success: true,
      data: {
        totalUsers,
        timestamp: new Date().toISOString()
      }
    });
  }

  return jsonResponse({ error: '未找到路由' }, 404);
}
