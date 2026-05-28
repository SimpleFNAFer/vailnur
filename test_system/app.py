"""
Deliberately vulnerable test web application for CSRF detection testing.

Endpoints split by CSRF-safety:

VULNERABLE (no anti-CSRF token, state-changing):
  POST /account/change-password
  POST /account/change-email
  POST /account/delete
  POST /admin/create-user
  POST /admin/set-role
  POST /posts/create
  POST /posts/delete
  POST /settings/notifications
  POST /wallet/transfer
  POST /social/follow
  POST /social/unfollow
  GET  /account/change-password (DVWA-style GET-based CSRF)

SAFE (read-only or has real CSRF token):
  GET  /
  GET  /dashboard
  GET  /account
  GET  /admin
  GET  /posts
  GET  /wallet
  GET  /social
  GET/POST /login    (has real token check)
  GET  /api/users
  GET  /api/posts
  GET  /search

Run:
  ../.venv/bin/uvicorn test_system.app:app --host 0.0.0.0 --port 9000
  or:
  ../.venv/bin/python test_system/app.py
"""

from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import secrets

app = FastAPI(title="VulnApp — CSRF Test Target")

# Fake in-memory state (resets on restart)
_users = {
    "alice": {"email": "alice@example.com", "role": "user",   "balance": 1000},
    "bob":   {"email": "bob@example.com",   "role": "user",   "balance": 500},
    "admin": {"email": "admin@example.com", "role": "admin",  "balance": 9999},
}
_posts = [
    {"id": 1, "author": "alice", "title": "Hello World",      "body": "First post!"},
    {"id": 2, "author": "bob",   "title": "My thoughts",      "body": "Interesting times."},
    {"id": 3, "author": "admin", "title": "Site announcement","body": "Welcome to VulnApp."},
]
_follows: set[tuple] = {("bob", "alice")}

# Shared CSRF token issued on login (always "statictoken" — bypassed trivially)
REAL_TOKEN = "statictoken"


# ── Layout helpers ────────────────────────────────────────────────────────────

NAV = """
<nav>
  <b class="logo">VulnApp</b>
  <a href="/">Главная</a>
  <a href="/dashboard">Панель</a>
  <a href="/account">Аккаунт</a>
  <a href="/posts">Посты</a>
  <a href="/wallet">Кошелёк</a>
  <a href="/social">Подписки</a>
  <a href="/admin">Панель администратора</a>
  <div class="nav-right">
    <div class="theme-sw" id="themeSw">
      <button onclick="setTheme('light')"  id="btn-light"  title="Светлая">☀</button>
      <button onclick="setTheme('dark')"   id="btn-dark"   title="Тёмная">🌙</button>
      <button onclick="setTheme('system')" id="btn-system" title="Системная">🖥</button>
    </div>
    <a href="/login">Войти</a>
  </div>
</nav>
<script>
(function(){
  var THEMES={light:1,dark:1,system:1};
  function applyTheme(t){
    var root=document.documentElement;
    if(t==='system'){
      root.setAttribute('data-theme', window.matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light');
    } else { root.setAttribute('data-theme',t); }
    Object.keys(THEMES).forEach(function(k){
      var b=document.getElementById('btn-'+k);
      if(b) b.className=k===t?'active':'';
    });
  }
  window.setTheme=function(t){ localStorage.setItem('vulnapp-theme',t); applyTheme(t); };
  var saved=localStorage.getItem('vulnapp-theme')||'system';
  applyTheme(saved);
  if(saved==='system') window.matchMedia('(prefers-color-scheme:dark)').addEventListener('change',function(){ applyTheme('system'); });
  document.addEventListener('DOMContentLoaded',function(){ applyTheme(localStorage.getItem('vulnapp-theme')||'system'); });
})();
</script>
<style>
  :root {
    --bg:#0f3460;--surface:#16213e;--surface2:#0f2040;--border:#2a3a6a;
    --text:#eee;--text2:#a8dadc;--nav-bg:#1a1a2e;--nav-text:#a8dadc;--nav-border:#2a3a6a;
    --accent:#e94560;--ok:#4caf50;--err:#e94560;
    --input-bg:#0f3460;--input-border:#2a3a6a;
    --tag-vuln-bg:#4a0000;--tag-vuln-text:#fca5a5;--tag-vuln-border:#7f1d1d;
    --tag-safe-bg:#052e16;--tag-safe-text:#4ade80;--tag-safe-border:#166534;
  }
  [data-theme="light"] {
    --bg:#f1f5f9;--surface:#ffffff;--surface2:#f8fafc;--border:#cbd5e1;
    --text:#1e293b;--text2:#334155;
    --nav-bg:#ffffff;--nav-text:#374151;--nav-border:#e2e8f0;
    --accent:#e94560;--ok:#15803d;--err:#dc2626;
    --input-bg:#f8fafc;--input-border:#cbd5e1;
    --tag-vuln-bg:#fef2f2;--tag-vuln-text:#b91c1c;--tag-vuln-border:#fca5a5;
    --tag-safe-bg:#f0fdf4;--tag-safe-text:#15803d;--tag-safe-border:#86efac;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',sans-serif;background:var(--bg);color:var(--text);line-height:1.5;transition:background .2s,color .2s}
  nav{background:var(--nav-bg);border-bottom:1px solid var(--nav-border);padding:10px 20px;display:flex;gap:20px;align-items:center;flex-wrap:wrap}
  nav a{color:var(--nav-text);text-decoration:none;font-size:14px}
  nav a:hover{color:var(--accent)}
  .logo{color:var(--accent);font-size:18px;font-weight:700;white-space:nowrap}
  .nav-right{margin-left:auto;display:flex;align-items:center;gap:16px}
  .theme-sw{display:flex;border:1px solid #444;border-radius:6px;overflow:hidden}
  .theme-sw button{padding:4px 10px;font-size:12px;background:transparent;border:none;cursor:pointer;color:var(--nav-text);transition:background .15s}
  .theme-sw button:hover{background:rgba(255,255,255,.1)}
  .theme-sw button.active{background:var(--accent);color:#fff}

  /* Основной контент */
  .page-content{padding:24px 20px;max-width:780px}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:24px;margin:0 20px 24px}
  .card h2{margin:0 0 18px;color:var(--accent);font-size:17px}
  .card h3{margin:22px 0 10px;font-size:14px;color:var(--text);display:flex;align-items:center;gap:8px}
  .card h3:first-of-type{margin-top:0}
  .card > form + form{border-top:1px solid var(--border);padding-top:20px;margin-top:4px}
  /* Заголовок таблицы, стоящий после формы или другого блока */
  .card > h3.section-heading{margin-top:28px;padding-top:20px;border-top:1px solid var(--border)}
  .card p{margin-bottom:12px;font-size:14px}

  /* Формы */
  input,select,textarea{
    width:100%;padding:8px 10px;margin:5px 0 10px;
    background:var(--input-bg);color:var(--text);
    border:1px solid var(--input-border);border-radius:5px;
    font-size:13px;font-family:inherit;
  }
  input:focus,select:focus,textarea:focus{outline:2px solid var(--accent);outline-offset:-1px}
  label{font-size:13px;display:inline-flex;align-items:center;gap:6px;margin:4px 0;cursor:pointer}
  label input[type=checkbox]{width:auto;margin:0}
  button[type=submit],button.action{
    display:inline-block;padding:8px 20px;
    background:var(--accent);color:#fff;border:none;border-radius:5px;
    cursor:pointer;font-size:13px;font-family:inherit;margin-top:4px;
    transition:opacity .15s;
  }
  button[type=submit]:hover,button.action:hover{opacity:.85}

  /* Таблицы */
  .ok{color:var(--ok)} .err{color:var(--err)}
  table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}
  th{padding:9px 10px;border-bottom:2px solid var(--border);text-align:left;font-weight:600;color:var(--text2)}
  td{padding:8px 10px;border-bottom:1px solid var(--border)}

  /* Ссылки внутри карточек */
  .card a{color:var(--accent);text-decoration:none}
  .card a:hover{text-decoration:underline}

  /* Встроенные формы в таблицах (кнопки удаления) */
  td form{margin:0}
  td button[type=submit]{padding:4px 12px;font-size:12px;margin-top:0;opacity:.85}
  td button[type=submit]:hover{opacity:1}

  /* Метки */
  .tag{display:inline-block;padding:2px 9px;border-radius:4px;font-size:11px;font-weight:600;white-space:nowrap}
  .vuln{background:var(--tag-vuln-bg);color:var(--tag-vuln-text);border:1px solid var(--tag-vuln-border)}
  .safe{background:var(--tag-safe-bg);color:var(--tag-safe-text);border:1px solid var(--tag-safe-border)}
</style>
"""


def page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(
        f'<!DOCTYPE html><html><head><meta charset="utf-8">'
        f'<title>{title} — VulnApp</title></head>'
        f'<body>{NAV}<div class="page-content">{body}</div></body></html>'
    )


def result_card(title: str, items: list[tuple[str, str]]) -> str:
    rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in items)
    return f'<div class="card"><h2>{title}</h2><table>{rows}</table></div>'


# ── Static / read-only pages (SAFE) ──────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def home():
    rows = ""
    endpoints = [
        ("GET",  "/",                        "safe",  "Главная страница"),
        ("GET",  "/dashboard",               "safe",  "Панель пользователя"),
        ("GET",  "/account",                 "safe",  "Настройки аккаунта"),
        ("POST", "/account/change-password", "vuln",  "Смена пароля — нет CSRF-токена"),
        ("GET",  "/account/change-password", "vuln",  "Смена пароля через GET — стиль DVWA"),
        ("POST", "/account/change-email",    "vuln",  "Смена email — нет CSRF-токена"),
        ("POST", "/account/delete",          "vuln",  "Удаление аккаунта — нет CSRF-токена"),
        ("GET",  "/posts",                   "safe",  "Список публикаций"),
        ("POST", "/posts/create",            "vuln",  "Создание публикации — нет CSRF-токена"),
        ("POST", "/posts/delete",            "vuln",  "Удаление публикации — нет CSRF-токена"),
        ("GET",  "/wallet",                  "safe",  "Кошелёк"),
        ("POST", "/wallet/transfer",         "vuln",  "Перевод средств — нет CSRF-токена"),
        ("GET",  "/social",                  "safe",  "Страница подписок"),
        ("POST", "/social/follow",           "vuln",  "Подписаться — нет CSRF-токена"),
        ("POST", "/social/unfollow",         "vuln",  "Отписаться — нет CSRF-токена"),
        ("GET",  "/admin",                   "safe",  "Административная панель"),
        ("POST", "/admin/create-user",       "vuln",  "Создать пользователя — нет CSRF-токена"),
        ("POST", "/admin/set-role",          "vuln",  "Изменить роль — нет CSRF-токена"),
        ("GET",  "/settings",                "safe",  "Настройки уведомлений"),
        ("POST", "/settings/notifications",  "vuln",  "Сохранить уведомления — нет CSRF-токена"),
        ("GET/POST", "/login",               "safe",  "Вход (есть проверка токена)"),
        ("GET",  "/search",                  "safe",  "Поиск (только чтение)"),
        ("GET",  "/api/users",               "safe",  "API: список пользователей"),
        ("GET",  "/api/posts",               "safe",  "API: список публикаций"),
    ]
    for method, path, safety, desc in endpoints:
        cls = "vuln" if safety == "vuln" else "safe"
        label = "уязвим" if safety == "vuln" else "безопасен"
        rows += (f'<tr><td><code>{method}</code></td>'
                 f'<td><a href="{path}">{path}</a></td>'
                 f'<td><span class="tag {cls}">{label}</span></td>'
                 f'<td>{desc}</td></tr>')
    return page("Главная", f"""
<div class="card">
  <h2>VulnApp — тестовое приложение для CSRF</h2>
  <p>Намеренно уязвимое веб-приложение для тестирования CSRF-детектора.</p>
  <p>Вы вошли как: <b>alice</b> (демо — реальной авторизации нет)</p>
  <table>
    <thead><tr><th>Метод</th><th>Путь</th><th>Безопасность</th><th>Описание</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>""")


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    user = _users["alice"]
    return page("Панель", f"""
<div class="card">
  <h2>Панель пользователя</h2>
  <p>Добро пожаловать, <b>alice</b>!</p>
  <table>
    <tr><td>Email</td><td>{user['email']}</td></tr>
    <tr><td>Роль</td><td>{user['role']}</td></tr>
    <tr><td>Баланс</td><td>${user['balance']}</td></tr>
  </table>
  <p>
    <a href="/account">Настройки аккаунта</a> ·
    <a href="/wallet">Кошелёк</a> ·
    <a href="/posts">Публикации</a> ·
    <a href="/social">Подписки</a>
  </p>
</div>""")


@app.get("/account", response_class=HTMLResponse)
def account():
    return page("Аккаунт", f"""
<div class="card">
  <h2>Настройки аккаунта</h2>
  <form method="POST" action="/account/change-password">
    <h3>Смена пароля <span class="tag vuln">CSRF-уязвимость</span></h3>
    <input name="current_password" type="password" placeholder="Текущий пароль">
    <input name="new_password" type="password" placeholder="Новый пароль">
    <input name="confirm_password" type="password" placeholder="Подтвердите новый пароль">
    <button type="submit">Сменить пароль</button>
  </form>
  <form method="POST" action="/account/change-email">
    <h3>Смена email <span class="tag vuln">CSRF-уязвимость</span></h3>
    <input name="new_email" type="email" placeholder="Новый email">
    <input name="password" type="password" placeholder="Текущий пароль">
    <button type="submit">Обновить email</button>
  </form>
  <form method="POST" action="/account/delete">
    <h3>Удаление аккаунта <span class="tag vuln">CSRF-уязвимость</span></h3>
    <input name="username" value="alice">
    <input name="confirmation" placeholder="Введите DELETE для подтверждения">
    <button type="submit">Удалить аккаунт</button>
  </form>
</div>""")


@app.get("/settings", response_class=HTMLResponse)
def settings():
    return page("Настройки", """
<div class="card">
  <h2>Настройки уведомлений</h2>
  <form method="POST" action="/settings/notifications">
    <h3>Уведомления <span class="tag vuln">CSRF-уязвимость</span></h3>
    <label><input name="notify_email" type="checkbox" value="1" checked> Email-уведомления</label><br>
    <label><input name="notify_sms" type="checkbox" value="1"> SMS-уведомления</label><br>
    <label><input name="notify_push" type="checkbox" value="1" checked> Push-уведомления</label><br>
    <select name="frequency">
      <option value="immediate" selected>Немедленно</option>
      <option value="daily">Ежедневный дайджест</option>
      <option value="weekly">Еженедельный дайджест</option>
    </select>
    <input name="webhook_url" placeholder="Webhook URL (необязательно)">
    <button type="submit">Сохранить настройки</button>
  </form>
</div>""")


@app.get("/posts", response_class=HTMLResponse)
def posts_page():
    rows = "".join(
        f"<tr><td>{p['id']}</td><td>{p['title']}</td><td>{p['author']}</td>"
        f"<td><form method='POST' action='/posts/delete'>"
        f"<input type='hidden' name='post_id' value='{p['id']}'>"
        f"<button type='submit'>Удалить</button></form></td></tr>"
        for p in _posts
    )
    return page("Публикации", f"""
<div class="card">
  <h2>Публикации</h2>
  <form method="POST" action="/posts/create">
    <h3>Новая публикация <span class="tag vuln">CSRF-уязвимость</span></h3>
    <input name="title" placeholder="Заголовок">
    <textarea name="body" rows="4" placeholder="Текст публикации"></textarea>
    <input name="author" value="alice">
    <button type="submit">Опубликовать</button>
  </form>
  <h3 class="section-heading">Все публикации</h3>
  <table>
    <thead><tr><th>ID</th><th>Заголовок</th><th>Автор</th><th>Действие</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>""")


@app.get("/wallet", response_class=HTMLResponse)
def wallet():
    return page("Кошелёк", """
<div class="card">
  <h2>Кошелёк</h2>
  <p>Баланс: <b>$1000</b></p>
  <form method="POST" action="/wallet/transfer">
    <h3>Перевод средств <span class="tag vuln">CSRF-уязвимость</span></h3>
    <input name="recipient" placeholder="Имя получателя">
    <input name="amount" type="number" placeholder="Сумма" min="1">
    <input name="note" placeholder="Комментарий к переводу (необязательно)">
    <button type="submit">Перевести</button>
  </form>
</div>""")


@app.get("/social", response_class=HTMLResponse)
def social():
    return page("Подписки", """
<div class="card">
  <h2>Подписки и контакты</h2>
  <form method="POST" action="/social/follow">
    <h3>Подписаться <span class="tag vuln">CSRF-уязвимость</span></h3>
    <input name="target_user" placeholder="Имя пользователя">
    <button type="submit">Подписаться</button>
  </form>
  <form method="POST" action="/social/unfollow">
    <h3>Отписаться <span class="tag vuln">CSRF-уязвимость</span></h3>
    <input name="target_user" placeholder="Имя пользователя">
    <button type="submit">Отписаться</button>
  </form>
</div>""")


@app.get("/admin", response_class=HTMLResponse)
def admin():
    rows = "".join(
        f"<tr><td>{u}</td><td>{d['email']}</td><td>{d['role']}</td><td>${d['balance']}</td></tr>"
        for u, d in _users.items()
    )
    return page("Панель администратора", f"""
<div class="card">
  <h2>Административная панель</h2>
  <form method="POST" action="/admin/create-user">
    <h3>Создать пользователя <span class="tag vuln">CSRF-уязвимость</span></h3>
    <input name="username" placeholder="Имя пользователя">
    <input name="email" type="email" placeholder="Email">
    <input name="password" type="password" placeholder="Пароль">
    <select name="role">
      <option value="user">Пользователь</option>
      <option value="admin">Администратор</option>
      <option value="moderator">Модератор</option>
    </select>
    <button type="submit">Создать</button>
  </form>
  <form method="POST" action="/admin/set-role">
    <h3>Изменить роль <span class="tag vuln">CSRF-уязвимость</span></h3>
    <input name="username" placeholder="Имя пользователя">
    <select name="role">
      <option value="user">Пользователь</option>
      <option value="admin">Администратор</option>
      <option value="moderator">Модератор</option>
    </select>
    <button type="submit">Изменить роль</button>
  </form>
  <h3 class="section-heading">Пользователи</h3>
  <table>
    <thead><tr><th>Логин</th><th>Email</th><th>Роль</th><th>Баланс</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>""")


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    return page("Поиск", f"""
<div class="card">
  <h2>Поиск</h2>
  <form method="GET" action="/search">
    <input name="q" value="{q}" placeholder="Поиск публикаций, пользователей...">
    <button type="submit">Найти</button>
  </form>
  {'<p>Нет результатов для: <b>' + q + '</b></p>' if q else '<p>Введите поисковый запрос.</p>'}
</div>""")


# ── Login (SAFE — has token) ──────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
def login_form():
    token = secrets.token_hex(16)
    return page("Вход", f"""
<div class="card">
  <h2>Вход <span class="tag safe">CSRF-защищён (есть токен)</span></h2>
  <form method="POST" action="/login">
    <input name="username" placeholder="Логин" value="alice">
    <input name="password" type="password" placeholder="Пароль">
    <input type="hidden" name="csrf_token" value="{token}">
    <button type="submit">Войти</button>
  </form>
</div>""")


@app.post("/login", response_class=HTMLResponse)
def login_submit(username: str = Form(""), password: str = Form(""),
                 csrf_token: str = Form("")):
    if not csrf_token:
        return page("Вход", '<div class="card"><p class="err">Отсутствует CSRF-токен.</p></div>')
    return page("Вход", f'<div class="card"><p class="ok">Вы вошли как {username}.</p>'
                        f'<a href="/dashboard">Перейти в панель →</a></div>')


# ── CSRF-vulnerable state-changing endpoints ──────────────────────────────────

@app.post("/account/change-password", response_class=HTMLResponse)
def change_password(current_password: str = Form(""), new_password: str = Form(""),
                    confirm_password: str = Form("")):
    return page("Результат", result_card("Пароль изменён", [
        ("Действие", "смена пароля"),
        ("Статус", '<span class="ok">Пароль успешно обновлён</span>'),
        ("Новый пароль", new_password or "(пусто)"),
    ]))


@app.get("/account/change-password", response_class=HTMLResponse)
def change_password_get(new_password: str = "", confirm_password: str = ""):
    """DVWA-style GET-based CSRF."""
    if new_password:
        return page("Результат", result_card("Пароль изменён (GET)", [
            ("Действие", "смена пароля через GET"),
            ("Статус", '<span class="ok">Пароль обновлён через GET-запрос</span>'),
            ("Новый пароль", new_password),
        ]))
    return page("Смена пароля (GET)", """
<div class="card">
  <h2>Смена пароля через GET <span class="tag vuln">CSRF-уязвимость</span></h2>
  <p>Стиль DVWA: пароль можно сменить через сформированный GET-URL.</p>
  <form method="GET" action="/account/change-password">
    <input name="new_password" placeholder="Новый пароль">
    <input name="confirm_password" placeholder="Подтвердите пароль">
    <button type="submit">Сменить</button>
  </form>
</div>""")


@app.post("/account/change-email", response_class=HTMLResponse)
def change_email(new_email: str = Form(""), password: str = Form("")):
    if new_email:
        _users["alice"]["email"] = new_email
    return page("Результат", result_card("Email изменён", [
        ("Действие", "смена email"),
        ("Статус", '<span class="ok">Email обновлён</span>'),
        ("Новый email", new_email or "(пусто)"),
    ]))


@app.post("/account/delete", response_class=HTMLResponse)
def delete_account(username: str = Form(""), confirmation: str = Form("")):
    return page("Результат", result_card("Аккаунт удалён", [
        ("Действие", "удаление аккаунта"),
        ("Цель", username),
        ("Статус", '<span class="ok">Аккаунт удалён</span>' if confirmation == "DELETE"
                   else '<span class="err">Подтверждение не совпадает — не удалено</span>'),
    ]))


@app.post("/posts/create", response_class=HTMLResponse)
def create_post(title: str = Form(""), body: str = Form(""), author: str = Form("alice")):
    new_id = max(p["id"] for p in _posts) + 1
    _posts.append({"id": new_id, "author": author, "title": title, "body": body})
    return page("Результат", result_card("Публикация создана", [
        ("Действие", "создание публикации"),
        ("ID", str(new_id)),
        ("Заголовок", title or "(пусто)"),
        ("Автор", author),
        ("Статус", '<span class="ok">Опубликовано</span>'),
    ]))


@app.post("/posts/delete", response_class=HTMLResponse)
def delete_post(post_id: int = Form(0)):
    removed = [p for p in _posts if p["id"] == post_id]
    _posts[:] = [p for p in _posts if p["id"] != post_id]
    return page("Result", result_card("Post Deleted", [
        ("Action", "delete-post"),
        ("Post ID", str(post_id)),
        ("Status", '<span class="ok">Deleted</span>' if removed
                   else '<span class="err">Not found</span>'),
    ]))


@app.post("/wallet/transfer", response_class=HTMLResponse)
def wallet_transfer(recipient: str = Form(""), amount: str = Form("0"),
                    note: str = Form("")):
    return page("Результат", result_card("Перевод выполнен", [
        ("Действие", "перевод средств"),
        ("Получатель", recipient or "(пусто)"),
        ("Сумма", f"${amount}"),
        ("Комментарий", note or "-"),
        ("Статус", '<span class="ok">Перевод выполнен</span>'),
    ]))


@app.post("/social/follow", response_class=HTMLResponse)
def follow(target_user: str = Form("")):
    _follows.add(("alice", target_user))
    return page("Результат", result_card("Подписка оформлена", [
        ("Действие", "подписаться"),
        ("Цель", target_user or "(пусто)"),
        ("Статус", '<span class="ok">Подписка оформлена</span>'),
    ]))


@app.post("/social/unfollow", response_class=HTMLResponse)
def unfollow(target_user: str = Form("")):
    _follows.discard(("alice", target_user))
    return page("Результат", result_card("Отписка выполнена", [
        ("Действие", "отписаться"),
        ("Цель", target_user or "(пусто)"),
        ("Статус", '<span class="ok">Отписка выполнена</span>'),
    ]))


@app.post("/settings/notifications", response_class=HTMLResponse)
def save_notifications(notify_email: str = Form(""), notify_sms: str = Form(""),
                       notify_push: str = Form(""), frequency: str = Form("immediate"),
                       webhook_url: str = Form("")):
    return page("Результат", result_card("Настройки сохранены", [
        ("Действие", "уведомления"),
        ("Email-уведомления", "вкл" if notify_email else "выкл"),
        ("SMS-уведомления",   "вкл" if notify_sms   else "выкл"),
        ("Push-уведомления",  "вкл" if notify_push  else "выкл"),
        ("Частота", frequency),
        ("Webhook", webhook_url or "-"),
        ("Статус", '<span class="ok">Сохранено</span>'),
    ]))


@app.post("/admin/create-user", response_class=HTMLResponse)
def admin_create_user(username: str = Form(""), email: str = Form(""),
                      password: str = Form(""), role: str = Form("user")):
    if username:
        _users[username] = {"email": email, "role": role, "balance": 0}
    return page("Результат", result_card("Пользователь создан", [
        ("Действие", "создание пользователя"),
        ("Логин", username or "(пусто)"),
        ("Email", email),
        ("Роль", role),
        ("Статус", '<span class="ok">Пользователь создан</span>' if username
                   else '<span class="err">Необходимо указать логин</span>'),
    ]))


@app.post("/admin/set-role", response_class=HTMLResponse)
def admin_set_role(username: str = Form(""), role: str = Form("user")):
    if username in _users:
        _users[username]["role"] = role
    return page("Результат", result_card("Роль обновлена", [
        ("Действие", "изменение роли"),
        ("Пользователь", username),
        ("Новая роль", role),
        ("Статус", '<span class="ok">Роль обновлена</span>' if username in _users
                   else '<span class="err">Пользователь не найден</span>'),
    ]))


# ── JSON API (SAFE — read-only) ───────────────────────────────────────────────

@app.get("/api/users")
def api_users():
    return [{"username": u, "email": d["email"], "role": d["role"]}
            for u, d in _users.items()]


@app.get("/api/posts")
def api_posts():
    return _posts


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("test_system.app:app", host="0.0.0.0", port=9000, reload=False)
