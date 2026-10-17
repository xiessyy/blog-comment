/* =========================================================
 *  轻量评论系统 —— Cloudflare Worker + D1
 *  访客只需填昵称即可评论，不需要任何账号
 *  免费额度：每天 500 万次读取 / 10 万次写入 / 5GB 存储（无需信用卡）
 * ========================================================= */

/* 建表语句（首次访问自动执行，不用手动建） */
const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS comments (",
  "  id INTEGER PRIMARY KEY AUTOINCREMENT,",
  "  slug TEXT NOT NULL,",
  "  nick TEXT NOT NULL,",
  "  email TEXT,",
  "  content TEXT NOT NULL,",
  "  ip TEXT,",
  "  status INTEGER NOT NULL DEFAULT 1,",
  "  created_at INTEGER NOT NULL",
  ");",
  "CREATE INDEX IF NOT EXISTS idx_slug ON comments(slug);",
  "CREATE INDEX IF NOT EXISTS idx_time ON comments(created_at);"
].join("\n");

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Max-Age": "86400"
};

function json(data, status) {
  status = status || 200;
  return new Response(JSON.stringify(data), {
    status: status,
    headers: Object.assign({}, CORS, {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    })
  });
}

/* HTML 转义，防 XSS */
function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/* 极简 Markdown：支持 **粗体**、`代码`、> 引用、换行 */
function md(s) {
  var t = esc(s);
  t = t.replace(/`([^`\n]+)`/g, "<code>$1</code>");
  t = t.replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>");
  var lines = t.split("\n");
  var out = "";
  for (var i = 0; i < lines.length; i++) {
    var ln = lines[i];
    if (/^&gt;\s?/.test(ln)) {
      out += "<blockquote>" + ln.replace(/^&gt;\s?/, "") + "</blockquote>";
    } else if (ln.trim() === "") {
      out += "<br>";
    } else {
      out += ln + "<br>";
    }
  }
  return out;
}

function fmtTime(ms) {
  var d = new Date(ms);
  function p(n) { return n < 10 ? "0" + n : "" + n; }
  return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) +
    " " + p(d.getHours()) + ":" + p(d.getMinutes());
}

/* 取 IP */
function getIP(req) {
  return req.headers.get("CF-Connecting-IP") ||
         req.headers.get("X-Forwarded-For") || "0.0.0.0";
}

/* HMAC 签名（管理员令牌） */
async function sign(env, msg) {
  var secret = env.SECRET || (env.ADMIN_PASSWORD || "moll") + "|salt";
  var key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  var sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  var b = new Uint8Array(sig);
  var bin = "";
  for (var i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function isAdmin(req, env) {
  if (!env.ADMIN_PASSWORD) return false;
  var h = req.headers.get("Authorization") || "";
  if (h.indexOf("Bearer ") !== 0) return false;
  var tok = h.slice(7);
  var dot = tok.indexOf(".");
  if (dot < 1) return false;
  var exp = Number(tok.slice(0, dot));
  if (!exp || exp < Date.now()) return false;
  return (await sign(env, "admin|" + exp)) === tok.slice(dot + 1);
}

/* ---------- 列表 ---------- */
async function listComments(req, url, env) {
  var slug = url.searchParams.get("slug") || "";
  if (!slug) return json({ error: "缺少 slug" }, 400);
  var r = await env.DB.prepare(
    "SELECT id, nick, content, created_at FROM comments WHERE slug=? AND status=1 ORDER BY created_at ASC LIMIT 200"
  ).bind(slug).all();
  var rows = (r.results || []).map(function (o) {
    return {
      id: o.id,
      nick: o.nick,
      content: o.content,
      html: md(o.content),
      time: fmtTime(o.created_at)
    };
  });
  return json({ ok: true, list: rows });
}

/* ---------- 发表 ---------- */
async function postComment(req, env) {
  var body;
  try { body = await req.json(); } catch (e) { return json({ error: "格式错误" }, 400); }

  var slug = String(body.slug || "").slice(0, 200);
  var nick = String(body.nick || "").trim().slice(0, 24);
  var email = String(body.email || "").trim().slice(0, 60);
  var content = String(body.content || "").trim().slice(0, 2000);

  /* 蜜罐：正常用户看不到这个字段，填了就是机器人 */
  if (body.website) return json({ ok: true, id: 0 });

  if (!slug) return json({ error: "缺少文章标识" }, 400);
  if (!nick) return json({ error: "请填写昵称" }, 400);
  if (!content) return json({ error: "评论内容不能为空" }, 400);
  if (content.length < 2) return json({ error: "太短了" }, 400);

  /* 简单限流：同一 IP 60 秒内最多 3 条 */
  var ip = getIP(req);
  var since = Date.now() - 60000;
  var cnt = await env.DB.prepare(
    "SELECT COUNT(*) AS c FROM comments WHERE ip=? AND created_at>?"
  ).bind(ip, since).first();
  if (cnt && cnt.c >= 3) {
    return json({ error: "发得太快了，歇一会儿再来" }, 429);
  }

  var status = env.MODERATE === "1" ? 0 : 1;
  var ins = await env.DB.prepare(
    "INSERT INTO comments (slug, nick, email, content, ip, status, created_at) VALUES (?,?,?,?,?,?,?)"
  ).bind(slug, nick, email, content, ip, status, Date.now()).run();

  return json({
    ok: true,
    id: ins.meta && ins.meta.last_row_id ? ins.meta.last_row_id : 0,
    pending: status === 0
  });
}

/* ---------- 管理员登录 ---------- */
async function adminLogin(req, env) {
  if (!env.ADMIN_PASSWORD) {
    return json({ error: "服务器未设置 ADMIN_PASSWORD" }, 500);
  }
  var body;
  try { body = await req.json(); } catch (e) { return json({ error: "格式错误" }, 400); }
  if (body.password !== env.ADMIN_PASSWORD) return json({ error: "密码错误" }, 401);
  var exp = Date.now() + 7 * 24 * 3600 * 1000;
  var sig = await sign(env, "admin|" + exp);
  return json({ ok: true, token: exp + "." + sig });
}

/* ---------- 管理员删除 ---------- */
async function adminDelete(req, url, env) {
  if (!(await isAdmin(req, env))) return json({ error: "未授权" }, 401);
  var id = Number(url.searchParams.get("id") || 0);
  if (!id) return json({ error: "缺少 id" }, 400);
  await env.DB.prepare("DELETE FROM comments WHERE id=?").bind(id).run();
  return json({ ok: true });
}

/* ---------- 管理员统计 ---------- */
async function adminStats(req, env) {
  if (!(await isAdmin(req, env))) return json({ error: "未授权" }, 401);
  var r = await env.DB.prepare("SELECT COUNT(*) AS c FROM comments").first();
  var p = env.MODERATE === "1"
    ? await env.DB.prepare("SELECT COUNT(*) AS c FROM comments WHERE status=0").first()
    : { c: 0 };
  return json({ ok: true, total: r ? r.c : 0, pending: p ? p.c : 0 });
}

/* =========================================================
 *  前端小部件：博客里只放两行代码，剩下的全由它生成
 * ========================================================= */
const WIDGET = [
"(function(){",
"  var s = document.currentScript;",
"  if(!s){ var all=document.getElementsByTagName('script');",
"    for(var i=all.length-1;i>=0;i--){ if(all[i].src.indexOf('widget.js')>=0){ s=all[i]; break; } } }",
"  if(!s) return;",
"  var API = s.src.replace(/\\/widget\\.js.*$/, '');",
"  var slug = s.getAttribute('data-slug') || location.pathname;",
"  var box = document.getElementById('moll-comment');",
"  if(!box) return;",
"",
"  var TOKEN = '';",
"  try { TOKEN = localStorage.getItem('moll_admin_token') || ''; } catch(e){}",
"",
"  var css = document.createElement('style');",
"  css.textContent =",
"    '#mc-wrap{font-family:-apple-system,PingFang SC,Microsoft YaHei,sans-serif;font-size:15px;line-height:1.8;color:#1f1e1b;letter-spacing:.01em}' +",
"    '@media (prefers-color-scheme:dark){#mc-wrap{color:#e6e2d9}}' +",
"    '#mc-list{margin-bottom:26px}' +",
"    '.mc-item{border-bottom:1px solid #e4e0d8;padding:14px 0;margin-bottom:0}' +",
"    '.mc-item:last-child{border-bottom:none}' +",
"    '@media (prefers-color-scheme:dark){.mc-item{border-color:#302d27}}' +",
"    '.mc-top{display:flex;align-items:center;gap:9px;margin-bottom:6px}' +",
"    '.mc-av{width:26px;height:26px;border-radius:50%;background:#9c4221;color:#faf9f6;font-size:12px;' +",
"      'display:flex;align-items:center;justify-content:center;font-weight:600;flex:0 0 26px}' +",
"    '@media (prefers-color-scheme:dark){.mc-av{background:#d68b5e;color:#171715}}' +",
"    '.mc-nick{font-weight:600;font-size:14px}' +",
"    '.mc-time{color:#9a968e;font-family:ui-monospace,Menlo,monospace;font-size:11px;' +",
"      'letter-spacing:.06em;margin-left:auto}' +",
"    '.mc-del{color:#9c4221;font-size:12px;background:none;border:none;cursor:pointer;padding:0 2px}' +",
"    '@media (prefers-color-scheme:dark){.mc-del{color:#d68b5e}}' +",
"    '.mc-body{font-size:15px;word-break:break-word}' +",
"    '.mc-body code{background:#f4f1ea;padding:1px 5px;border-radius:3px;font-size:13px;' +",
"      'font-family:ui-monospace,Menlo,monospace}' +",
"    '@media (prefers-color-scheme:dark){.mc-body code{background:#211f1b}}' +",
"    '.mc-body blockquote{border-left:2px solid #9c4221;padding:2px 0 2px 12px;' +",
"      'margin:6px 0;color:#6b6862;font-style:italic;display:block}' +",
"    '@media (prefers-color-scheme:dark){.mc-body blockquote{border-color:#d68b5e;color:#a09b90}}' +",
"    '#mc-form input,#mc-form textarea{width:100%;padding:9px 11px;border:1px solid #e4e0d8;' +",
"      'border-radius:4px;background:#f4f1ea;color:#1f1e1b;font-size:15px;margin-bottom:9px;' +",
"      'font-family:inherit;outline:none;box-sizing:border-box}' +",
"    '@media (prefers-color-scheme:dark){#mc-form input,#mc-form textarea{background:#211f1b;' +",
"      'border-color:#302d27;color:#e6e2d9}}' +",
"    '#mc-form input:focus,#mc-form textarea:focus{border-color:#9c4221}' +",
"    '#mc-form textarea{min-height:88px;resize:vertical}' +",
"    '.mc-row{display:flex;gap:9px;flex-wrap:wrap}' +",
"    '.mc-row input{flex:1;min-width:130px}' +",
"    '#mc-submit{background:#9c4221;color:#faf9f6;border:none;border-radius:4px;padding:10px 24px;' +",
"      'font-size:15px;font-weight:600;cursor:pointer;font-family:inherit;letter-spacing:.04em}' +",
"    '@media (prefers-color-scheme:dark){#mc-submit{background:#d68b5e;color:#171715}}' +",
"    '#mc-submit:disabled{opacity:.6}' +",
"    '.mc-tip{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:#9a968e;' +",
"      'letter-spacing:.05em;margin-top:9px}' +",
"    '.mc-empty{color:#9a968e;font-size:14px;padding:18px 0;text-align:center;font-style:italic}' +",
"    '.mc-hp{position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden}' +",
"    '.mc-admin{font-size:11px;color:#9a968e;margin-bottom:12px;text-align:right;' +",
"      'font-family:ui-monospace,Menlo,monospace;letter-spacing:.06em}' +",
"    '.mc-admin button{background:none;border:none;color:#9a968e;font-size:11px;cursor:pointer;' +",
"      'font-family:inherit}' +",
"    '.mc-admin button:hover{color:#9c4221}' +",
"    '.mc-msg{font-size:13px;padding:8px 11px;border-radius:4px;margin-bottom:12px;display:none}' +",
"    '.mc-msg.err{display:block;background:#f7e6e1;color:#9c4221}' +",
"    '.mc-msg.ok{display:block;background:#f0e6d2;color:#6b4a2a}' +",
"    '@media (prefers-color-scheme:dark){.mc-msg.err{background:#33201a;color:#d68b5e}' +",
"      '.mc-msg.ok{background:#332a1c;color:#c9a87a}}'",
"  document.head.appendChild(css);",
"",
"  box.innerHTML =",
"    '<div id=\"mc-wrap\">' +",
"      '<div class=\"mc-admin\" id=\"mc-admin\"></div>' +",
"      '<div class=\"mc-msg\" id=\"mc-msg\"></div>' +",
"      '<div id=\"mc-list\"><div class=\"mc-empty\">评论加载中…</div></div>' +",
"      '<form id=\"mc-form\">' +",
"        '<div class=\"mc-row\">' +",
"          '<input id=\"mc-nick\" placeholder=\"昵称（必填）\" maxlength=\"24\">' +",
"          '<input id=\"mc-email\" placeholder=\"邮箱（选填，不公开）\" maxlength=\"60\">' +",
"        '</div>' +",
"        '<textarea id=\"mc-content\" placeholder=\"说点什么…支持 **粗体** 和 `代码`\" maxlength=\"2000\"></textarea>' +",
"        '<input class=\"mc-hp\" id=\"mc-website\" tabindex=\"-1\" autocomplete=\"off\">' +",
"        '<button id=\"mc-submit\" type=\"submit\">发表评论</button>' +",
"        '<div class=\"mc-tip\">无需注册，填个昵称就能留言。</div>' +",
"      '</form>' +",
"    '</div>';",
"",
"  function showMsg(t, ok){",
"    var m = document.getElementById('mc-msg');",
"    if(!t){ m.className='mc-msg'; m.textContent=''; return; }",
"    m.className = 'mc-msg ' + (ok ? 'ok' : 'err');",
"    m.textContent = t;",
"  }",
"",
"  function initial(n){ return (n||'?').slice(0,1).toUpperCase(); }",
"",
"  function render(list){",
"    var el = document.getElementById('mc-list');",
"    if(!list.length){ el.innerHTML = '<div class=\"mc-empty\">还没有评论，来抢第一个 👋</div>'; return; }",
"    var h = '';",
"    for(var i=0;i<list.length;i++){",
"      var c = list[i];",
"      h += '<div class=\"mc-item\">' +",
"        '<div class=\"mc-top\">' +",
"          '<span class=\"mc-av\">' + initial(c.nick) + '</span>' +",
"          '<span class=\"mc-nick\">' + c.nick + '</span>' +",
"          '<span class=\"mc-time\">' + c.time + '</span>' +",
"          (TOKEN ? '<button class=\"mc-del\" data-id=\"' + c.id + '\">删除</button>' : '') +",
"        '</div>' +",
"        '<div class=\"mc-body\">' + c.html + '</div>' +",
"      '</div>';",
"    }",
"    el.innerHTML = h;",
"    if(TOKEN){",
"      var btns = el.getElementsByClassName('mc-del');",
"      for(var j=0;j<btns.length;j++){",
"        btns[j].onclick = function(){",
"          if(!confirm('确定删除这条评论？')) return;",
"          var id = this.getAttribute('data-id');",
"          fetch(API + '/api/admin/delete?id=' + id, {",
"            method:'DELETE', headers:{'Authorization':'Bearer ' + TOKEN}",
"          }).then(function(r){return r.json();}).then(function(){ load(); });",
"        };",
"      }",
"    }",
"  }",
"",
"  function load(){",
"    fetch(API + '/api/comments?slug=' + encodeURIComponent(slug), {cache:'no-store'})",
"      .then(function(r){ return r.json(); })",
"      .then(function(d){",
"        if(d && d.list) render(d.list);",
"        else document.getElementById('mc-list').innerHTML =",
"          '<div class=\"mc-empty\">评论加载失败</div>';",
"      })",
"      .catch(function(){",
"        document.getElementById('mc-list').innerHTML =",
"          '<div class=\"mc-empty\">评论加载失败，稍后再试</div>';",
"      });",
"  }",
"",
"  document.getElementById('mc-form').onsubmit = function(e){",
"    e.preventDefault();",
"    var btn = document.getElementById('mc-submit');",
"    var nick = document.getElementById('mc-nick').value.trim();",
"    if(!nick){ showMsg('请填写昵称', false); return; }",
"    var content = document.getElementById('mc-content').value.trim();",
"    if(!content){ showMsg('评论内容不能为空', false); return; }",
"    btn.disabled = true; btn.textContent = '发送中…';",
"    fetch(API + '/api/comments', {",
"      method:'POST',",
"      headers:{'Content-Type':'application/json'},",
"      body: JSON.stringify({",
"        slug: slug,",
"        nick: nick,",
"        email: document.getElementById('mc-email').value.trim(),",
"        content: content,",
"        website: document.getElementById('mc-website').value",
"      })",
"    }).then(function(r){ return r.json(); })",
"      .then(function(d){",
"        btn.disabled = false; btn.textContent = '发表评论';",
"        if(d && d.ok){",
"          document.getElementById('mc-content').value = '';",
"          try{ localStorage.setItem('moll_nick', nick); }catch(e){}",
"          showMsg(d.pending ? '已提交，等待博主审核' : '发表成功 ✓', true);",
"          load();",
"        } else {",
"          showMsg((d && d.error) ? d.error : '发送失败', false);",
"        }",
"      })",
"      .catch(function(){",
"        btn.disabled = false; btn.textContent = '发表评论';",
"        showMsg('网络错误，稍后再试', false);",
"      });",
"  };",
"",
"  try{",
"    var saved = localStorage.getItem('moll_nick');",
"    if(saved) document.getElementById('mc-nick').value = saved;",
"  }catch(e){}",
"",
"  var ad = document.getElementById('mc-admin');",
"  if(TOKEN){",
"    ad.innerHTML = '<button id=\"mc-out\">退出管理</button>';",
"    document.getElementById('mc-out').onclick = function(){",
"      try{ localStorage.removeItem('moll_admin_token'); }catch(e){}",
"      location.reload();",
"    };",
"  } else {",
"    ad.innerHTML = '<button id=\"mc-in\">管理</button>';",
"    document.getElementById('mc-in').onclick = function(){",
"      var p = prompt('管理密码');",
"      if(!p) return;",
"      fetch(API + '/api/admin/login', {",
"        method:'POST', headers:{'Content-Type':'application/json'},",
"        body: JSON.stringify({password: p})",
"      }).then(function(r){return r.json();}).then(function(d){",
"        if(d && d.token){",
"          try{ localStorage.setItem('moll_admin_token', d.token); }catch(e){}",
"          location.reload();",
"        } else { alert((d && d.error) ? d.error : '登录失败'); }",
"      });",
"    };",
"  }",
"",
"  load();",
"})();"
].join("\n");

/* =========================================================
 *  路由
 * ========================================================= */
export default {
  async fetch(request, env) {
    var url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS });
    }

    if (!env.DB) {
      return json({ error: "还没绑定 D1 数据库。请在 Worker → Settings → Bindings 添加 D1，变量名填 DB" }, 500);
    }

    try {
      var p = url.pathname;

      /* 小部件 JS */
      if (p === "/widget.js") {
        return new Response(WIDGET, {
          headers: Object.assign({}, CORS, {
            "Content-Type": "application/javascript; charset=utf-8",
            "Cache-Control": "public, max-age=3600"
          })
        });
      }

      /* 建表（首次访问时执行，之后跳过） */
      if (p === "/api/init") {
        await env.DB.prepare(SCHEMA).run();
        return json({ ok: true, msg: "数据表已创建" });
      }

      if (p === "/api/comments") {
        if (request.method === "GET") return await listComments(request, url, env);
        if (request.method === "POST") return await postComment(request, env);
      }
      if (p === "/api/admin/login") return await adminLogin(request, env);
      if (p === "/api/admin/delete" && request.method === "DELETE") {
        return await adminDelete(request, url, env);
      }
      if (p === "/api/admin/stats") return await adminStats(request, env);

      return json({ error: "未知接口：" + p }, 404);
    } catch (e) {
      return json({ error: String(e && e.message ? e.message : e) }, 500);
    }
  }
};
