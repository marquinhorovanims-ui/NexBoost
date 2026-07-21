"""NexBoost License Server — painel de geração de chaves + API de ativação.

Executar:
    pip install flask
    set NEXBOOST_ADMIN_TOKEN=um-token-seguro   (Windows)
    python server.py

Painel:  http://localhost:8090        (login com o token de admin)
API:     POST /api/activate  {"key": "...", "machine": "..."}
         POST /api/check     {"key": "..."}

As chaves geradas aqui usam o MESMO algoritmo do aplicativo (checksum
SHA-256 + salt), então continuam funcionando offline; quando o app está
configurado com a URL deste servidor, a ativação também é registrada e
vinculada à máquina (1 chave = 1 máquina).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)

from keygen import generate_key, is_valid, normalize

DB_PATH = Path(__file__).with_name("licenses.db")
ADMIN_TOKEN = os.environ.get("NEXBOOST_ADMIN_TOKEN", "admin123")

# --- Configuração de e-mail (SMTP) -----------------------------------------
# Preencha via variáveis de ambiente. Exemplo para Gmail:
#   set SMTP_HOST=smtp.gmail.com
#   set SMTP_PORT=587
#   set SMTP_USER=seuemail@gmail.com
#   set SMTP_PASS=senha-de-app         (use "Senha de app", não a senha normal)
#   set SMTP_FROM=NexBoost <seuemail@gmail.com>
# Se SMTP_HOST não estiver definido, o código de verificação é apenas
# registrado no console (modo desenvolvimento) em vez de enviado.
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER or "NexBoost <no-reply@nexboost.app>")
CODE_TTL_MIN = 10  # validade do código de verificação em minutos

app = Flask(__name__)
app.secret_key = os.environ.get("NEXBOOST_FLASK_SECRET",
                                secrets.token_hex(32))


# ---------------------------------------------------------------------------
# Banco
# ---------------------------------------------------------------------------
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE IF NOT EXISTS licenses ("
        "key TEXT PRIMARY KEY,"
        "created_at TEXT NOT NULL,"
        "note TEXT DEFAULT '',"
        "machine TEXT DEFAULT '',"
        "activated_at TEXT DEFAULT '',"
        "revoked INTEGER DEFAULT 0)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS accounts ("
        "email TEXT PRIMARY KEY,"
        "name TEXT NOT NULL,"
        "pass_hash TEXT NOT NULL,"
        "verified INTEGER DEFAULT 0,"
        "code TEXT DEFAULT '',"
        "code_expires TEXT DEFAULT '',"
        "license TEXT DEFAULT '',"
        "created_at TEXT NOT NULL)")
    return conn


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")


# ---------------------------------------------------------------------------
# Senhas (PBKDF2) e verificação por e-mail
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Gera hash PBKDF2-SHA256 com salt aleatório."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"pbkdf2_sha256$200000${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _algo, iters, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(),
            bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:  # noqa: BLE001
        return False


def valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def send_verification_email(to_email: str, name: str, code: str) -> bool:
    """Envia o código de verificação. Retorna True se enviado via SMTP.

    Sem SMTP configurado, imprime no console (modo desenvolvimento) e
    retorna False — o chamador pode então expor o código para testes.
    """
    subject = "Seu código de verificação NexBoost"
    text = (
        f"Olá, {name}!\n\n"
        f"Seu código de verificação é: {code}\n\n"
        f"Ele expira em {CODE_TTL_MIN} minutos. "
        "Se você não criou uma conta no NexBoost, ignore este e-mail.\n\n"
        "— Equipe NexBoost"
    )
    html = f"""\
<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;
padding:32px;background:#0D111C;border-radius:16px;color:#E5EAF2">
  <h2 style="color:#3B82F6;margin:0 0 8px">NexBoost</h2>
  <p style="color:#9AA6B8">Olá, {name}! Use o código abaixo para
  confirmar seu e-mail:</p>
  <div style="font-size:34px;font-weight:800;letter-spacing:8px;
  text-align:center;padding:20px;background:#121A2A;border-radius:12px;
  color:#fff;margin:18px 0">{code}</div>
  <p style="color:#6B7688;font-size:13px">O código expira em
  {CODE_TTL_MIN} minutos. Se não foi você, ignore este e-mail.</p>
</div>"""
    if not SMTP_HOST:
        print(f"[DEV] Código de verificação para {to_email}: {code}")
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls(context=context)
        if SMTP_USER:
            server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
    return True


# ---------------------------------------------------------------------------
# API consumida pelo aplicativo
# ---------------------------------------------------------------------------
@app.post("/api/activate")
def api_activate():
    data = request.get_json(silent=True) or {}
    key = normalize(str(data.get("key", "")))
    machine = str(data.get("machine", ""))[:64]
    if not is_valid(key):
        return jsonify(ok=False, error="Chave inválida."), 400
    conn = db()
    row = conn.execute("SELECT * FROM licenses WHERE key=?",
                       (key,)).fetchone()
    if row is None:
        return jsonify(ok=False,
                       error="Chave não emitida por este servidor."), 404
    if row["revoked"]:
        return jsonify(ok=False, error="Chave revogada."), 403
    if row["machine"] and machine and row["machine"] != machine:
        return jsonify(ok=False,
                       error="Chave já ativada em outra máquina."), 403
    if not row["machine"]:
        conn.execute(
            "UPDATE licenses SET machine=?, activated_at=? WHERE key=?",
            (machine, now(), key))
        conn.commit()
    conn.close()
    return jsonify(ok=True)


@app.post("/api/check")
def api_check():
    data = request.get_json(silent=True) or {}
    key = normalize(str(data.get("key", "")))
    if not is_valid(key):
        return jsonify(ok=False, error="Chave inválida."), 400
    conn = db()
    row = conn.execute("SELECT revoked FROM licenses WHERE key=?",
                       (key,)).fetchone()
    conn.close()
    if row is None:
        return jsonify(ok=False, error="Chave não emitida."), 404
    if row["revoked"]:
        return jsonify(ok=False, error="Chave revogada."), 403
    return jsonify(ok=True)


# ---------------------------------------------------------------------------
# API de contas (consumida pelo site) — cadastro, 2FA por e-mail, login
# ---------------------------------------------------------------------------
def _gen_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _code_expiry() -> str:
    return (datetime.now(timezone.utc)
            + timedelta(minutes=CODE_TTL_MIN)).strftime("%Y-%m-%d %H:%M")


@app.post("/api/register")
def api_register():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()[:80]
    email = str(data.get("email", "")).strip().lower()[:120]
    password = str(data.get("password", ""))
    if len(name) < 2:
        return jsonify(ok=False, error="Informe seu nome."), 400
    if not valid_email(email):
        return jsonify(ok=False, error="E-mail inválido."), 400
    if len(password) < 6:
        return jsonify(ok=False,
                       error="A senha precisa de ao menos 6 caracteres."), 400
    conn = db()
    existing = conn.execute(
        "SELECT verified FROM accounts WHERE email=?", (email,)).fetchone()
    if existing and existing["verified"]:
        conn.close()
        return jsonify(ok=False,
                       error="Já existe uma conta com este e-mail."), 409
    code = _gen_code()
    if existing:  # conta não verificada: atualiza dados e reenvia
        conn.execute(
            "UPDATE accounts SET name=?, pass_hash=?, code=?, code_expires=? "
            "WHERE email=?",
            (name, hash_password(password), code, _code_expiry(), email))
    else:
        conn.execute(
            "INSERT INTO accounts(email,name,pass_hash,verified,code,"
            "code_expires,created_at) VALUES(?,?,?,0,?,?,?)",
            (email, name, hash_password(password), code,
             _code_expiry(), now()))
    conn.commit()
    conn.close()
    sent = send_verification_email(email, name, code)
    resp = {"ok": True, "sent": sent}
    if not sent:  # modo dev sem SMTP: devolve o código para testes
        resp["dev_code"] = code
    return jsonify(resp)


@app.post("/api/verify")
def api_verify():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    code = str(data.get("code", "")).strip()
    conn = db()
    row = conn.execute(
        "SELECT code, code_expires FROM accounts WHERE email=?",
        (email,)).fetchone()
    if row is None:
        conn.close()
        return jsonify(ok=False, error="Conta não encontrada."), 404
    if not row["code"] or not hmac.compare_digest(row["code"], code):
        conn.close()
        return jsonify(ok=False, error="Código incorreto."), 400
    if row["code_expires"] and row["code_expires"] < now():
        conn.close()
        return jsonify(ok=False,
                       error="Código expirado. Solicite um novo."), 400
    conn.execute(
        "UPDATE accounts SET verified=1, code='', code_expires='' "
        "WHERE email=?", (email,))
    conn.commit()
    conn.close()
    return jsonify(ok=True)


@app.post("/api/resend")
def api_resend():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    conn = db()
    row = conn.execute(
        "SELECT name, verified FROM accounts WHERE email=?",
        (email,)).fetchone()
    if row is None:
        conn.close()
        return jsonify(ok=False, error="Conta não encontrada."), 404
    if row["verified"]:
        conn.close()
        return jsonify(ok=False, error="Conta já verificada."), 400
    code = _gen_code()
    conn.execute(
        "UPDATE accounts SET code=?, code_expires=? WHERE email=?",
        (code, _code_expiry(), email))
    conn.commit()
    conn.close()
    sent = send_verification_email(email, row["name"], code)
    resp = {"ok": True, "sent": sent}
    if not sent:
        resp["dev_code"] = code
    return jsonify(resp)


@app.post("/api/login")
def api_login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    conn = db()
    row = conn.execute(
        "SELECT name, pass_hash, verified, license FROM accounts "
        "WHERE email=?", (email,)).fetchone()
    conn.close()
    if row is None or not verify_password(password, row["pass_hash"]):
        return jsonify(ok=False, error="E-mail ou senha incorretos."), 401
    if not row["verified"]:
        return jsonify(ok=False, error="unverified",
                       message="Confirme seu e-mail antes de entrar."), 403
    return jsonify(ok=True, name=row["name"], email=email,
                   license=row["license"] or "")


# ---------------------------------------------------------------------------
# Painel administrativo
# ---------------------------------------------------------------------------
PAGE = """
<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NexBoost — Servidor de Licenças</title><style>
:root{--bg:#090E18;--sidebar:#0D1424;--card:#131C2C;--hover:#1A2740;
--border:#1E2C46;--blue:#3B82F6;--green:#22C55E;--red:#EF4444;
--orange:#F59E0B;--text:#FFF;--muted:#8B9AB5}
*{box-sizing:border-box;font-family:'Segoe UI',system-ui,sans-serif}
body{margin:0;background:linear-gradient(135deg,#090E18,#0B1120 50%,#0A1226);
color:var(--text);min-height:100vh}
.wrap{max-width:1080px;margin:0 auto;padding:34px 22px}
.logo{font-size:26px;font-weight:800}.logo b{color:var(--blue)}
.sub{color:var(--muted);margin:4px 0 26px}
.card{background:linear-gradient(180deg,#16202F,#131C2C);
border:1px solid var(--border);border-radius:14px;padding:22px;
margin-bottom:18px}
h2{margin:0 0 12px;font-size:16px}
input,select{background:rgba(9,14,24,.85);border:1px solid var(--border);
border-radius:9px;color:var(--text);padding:10px 13px;font-size:14px}
input:focus{outline:none;border-color:var(--blue)}
button{background:linear-gradient(180deg,#4F8DF7,#3B82F6);border:none;
border-radius:9px;color:#fff;padding:10px 20px;font-weight:700;
cursor:pointer;font-size:14px}
button:hover{filter:brightness(1.08)}
button.ghost{background:transparent;border:1px solid var(--border);
color:var(--muted)}button.danger{background:transparent;
border:1px solid rgba(239,68,68,.55);color:#F87171}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:var(--muted);text-align:left;font-size:11px;letter-spacing:.8px;
text-transform:uppercase;padding:8px 10px;border-bottom:1px solid var(--border)}
td{padding:9px 10px;border-bottom:1px solid rgba(30,44,70,.5)}
tr:hover td{background:rgba(26,39,64,.35)}
.key{font-family:Consolas,monospace;font-weight:700;letter-spacing:1px}
.chip{display:inline-block;padding:3px 10px;border-radius:8px;font-size:11px;
font-weight:700}
.ok{color:var(--green);background:rgba(34,197,94,.1);
border:1px solid rgba(34,197,94,.4)}
.free{color:var(--muted);background:rgba(139,154,181,.08);
border:1px solid rgba(139,154,181,.3)}
.rev{color:#F87171;background:rgba(239,68,68,.1);
border:1px solid rgba(239,68,68,.4)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.copy{cursor:pointer;color:var(--blue);font-size:12px;margin-left:8px}
.msg{color:var(--green);margin:10px 0 0;font-size:13px}
.api{font-family:Consolas,monospace;font-size:12px;color:var(--muted);
background:rgba(9,14,24,.7);border-radius:9px;padding:12px;line-height:1.7}
</style></head><body><div class="wrap">
<div class="logo">⚡ <b>Nex</b>Boost <span style="color:var(--muted);
font-weight:400;font-size:16px">· Servidor de Licenças</span></div>
<div class="sub">Gere, acompanhe e revogue chaves de ativação.</div>
{% if not authed %}
<div class="card" style="max-width:420px">
<h2>Entrar</h2>
<form method="post" action="{{ url_for('login') }}" class="row">
<input type="password" name="token" placeholder="Token de administrador"
 style="flex:1" autofocus>
<button>Entrar</button></form>
{% if error %}<div class="msg" style="color:#F87171">{{ error }}</div>
{% endif %}</div>
{% else %}
<div class="card"><h2>Gerar chaves</h2>
<form method="post" action="{{ url_for('generate') }}" class="row">
<input type="number" name="count" value="5" min="1" max="100"
 style="width:90px">
<input type="text" name="note" placeholder="Anotação (cliente, lote…)"
 style="flex:1">
<button>Gerar</button>
<a href="{{ url_for('logout') }}"><button type="button" class="ghost">
Sair</button></a></form>
{% if new_keys %}<div class="msg">✔ {{ new_keys|length }} chaves geradas —
clique para copiar:</div>
{% for k in new_keys %}<div class="key" style="margin-top:6px"
 onclick="navigator.clipboard.writeText('{{ k }}');this.style.color='#22C55E'">
{{ k }} <span class="copy">copiar</span></div>{% endfor %}{% endif %}
</div>
<div class="card"><h2>Chaves emitidas ({{ rows|length }})</h2>
<table><tr><th>Chave</th><th>Status</th><th>Máquina</th><th>Criada</th>
<th>Ativada</th><th>Anotação</th><th></th></tr>
{% for r in rows %}<tr>
<td class="key">{{ r['key'] }}</td>
<td>{% if r['revoked'] %}<span class="chip rev">Revogada</span>
{% elif r['machine'] %}<span class="chip ok">Ativada</span>
{% else %}<span class="chip free">Disponível</span>{% endif %}</td>
<td style="font-family:Consolas,monospace;font-size:11px">
{{ r['machine'][:18] }}{{ '…' if r['machine']|length > 18 else '' }}</td>
<td>{{ r['created_at'] }}</td><td>{{ r['activated_at'] }}</td>
<td>{{ r['note'] }}</td>
<td>{% if not r['revoked'] %}
<form method="post" action="{{ url_for('revoke') }}" style="margin:0">
<input type="hidden" name="key" value="{{ r['key'] }}">
<button class="danger" style="padding:5px 12px;font-size:11px">Revogar
</button></form>{% endif %}</td></tr>{% endfor %}</table></div>
<div class="card"><h2>Integração com o aplicativo</h2>
<div class="api">No NexBoost → Configurações → "Servidor de ativação",
informe: <b style="color:#3B82F6">http://SEU-IP:8090</b><br>
API: POST /api/activate {"key": "...", "machine": "..."} ·
POST /api/check {"key": "..."}<br>
As chaves também funcionam offline (mesmo algoritmo do app); o servidor
adiciona rastreio, vínculo 1-chave-1-máquina e revogação.</div></div>
{% endif %}
</div></body></html>
"""


def authed() -> bool:
    return bool(session.get("authed"))


@app.get("/")
def index():
    rows = []
    if authed():
        conn = db()
        rows = conn.execute(
            "SELECT * FROM licenses ORDER BY created_at DESC").fetchall()
        conn.close()
    return render_template_string(PAGE, authed=authed(), rows=rows,
                                  new_keys=session.pop("new_keys", None),
                                  error=None)


@app.post("/login")
def login():
    if secrets.compare_digest(request.form.get("token", ""), ADMIN_TOKEN):
        session["authed"] = True
        return redirect(url_for("index"))
    return render_template_string(PAGE, authed=False, rows=[],
                                  new_keys=None, error="Token incorreto.")


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.post("/generate")
def generate():
    if not authed():
        return redirect(url_for("index"))
    count = max(1, min(100, int(request.form.get("count", 5))))
    note = request.form.get("note", "")[:120]
    conn = db()
    keys = []
    for _ in range(count):
        key = generate_key()
        conn.execute(
            "INSERT OR IGNORE INTO licenses(key,created_at,note) "
            "VALUES(?,?,?)", (key, now(), note))
        keys.append(key)
    conn.commit()
    conn.close()
    session["new_keys"] = keys
    return redirect(url_for("index"))


@app.post("/revoke")
def revoke():
    if not authed():
        return redirect(url_for("index"))
    conn = db()
    conn.execute("UPDATE licenses SET revoked=1 WHERE key=?",
                 (normalize(request.form.get("key", "")),))
    conn.commit()
    conn.close()
    return redirect(url_for("index"))


if __name__ == "__main__":
    print(f"Painel: http://localhost:8090  (token: "
          f"{'definido via NEXBOOST_ADMIN_TOKEN' if 'NEXBOOST_ADMIN_TOKEN' in os.environ else 'admin123 — TROQUE!'})")
    app.run(host="0.0.0.0", port=8090)
