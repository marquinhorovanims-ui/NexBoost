# NexBoost License Server

Painel web + API para gerar, rastrear e revogar chaves do NexBoost.

## Rodar

```bash
pip install flask
set NEXBOOST_ADMIN_TOKEN=um-token-forte    # Windows (Linux: export ...)
python server.py
```

Abra **http://localhost:8090** e entre com o token (sem definir a variável, o token é `admin123` — troque!).

## O que o painel faz
- Gera chaves em lote (com anotação de cliente/lote), clique para copiar.
- Lista todas as emitidas com status: **Disponível / Ativada / Revogada**, máquina vinculada e datas.
- Revoga chaves com um clique.

## API usada pelo aplicativo
- `POST /api/activate` `{"key": "...", "machine": "..."}` — valida, vincula à máquina (1 chave = 1 máquina) e registra a ativação.
- `POST /api/check` `{"key": "..."}` — só verifica.

## Integração no NexBoost
No app: **Configurações → Servidor de ativação** → `http://SEU-IP:8090`.
Comportamento do app:
1. chave com checksum inválido → recusada na hora, sem rede;
2. servidor configurado → ativa online (vínculo por máquina, via `MachineGuid` do Windows);
3. servidor recusou (revogada / usada em outra máquina / não emitida) → **recusa de verdade**, sem fallback;
4. servidor fora do ar → ativa offline e avisa (o app não pode ficar refém do seu servidor).

Para expor na internet, rode atrás de um proxy com HTTPS (Caddy/Nginx) — o token de admin viaja no login.

O banco `licenses.db` (SQLite) fica ao lado do `server.py`.
