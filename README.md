# 本地身份认证、令牌轮换与访问控制（Python / FastAPI）

一个**只依赖本机能力**、可完整本地复现的认证与访问控制示例服务：
登录签发双令牌、刷新令牌一次性轮换、重用即整会话撤销、
基于角色/权限的实时访问控制、单会话与用户级会话撤销，
并把所有关键事件写入本地 JSONL 审计日志。

- 令牌签名：标准库 `hmac`/`hashlib`（HS256 风格，自包含实现，不引外部 JWT 库）
- 密码存储：标准库 PBKDF2-HMAC-SHA256（每用户随机盐）
- 存储：进程内内存结构（无数据库、无外部服务、无真实凭据）
- 测试：`pytest`，含重用、并发刷新、过期/篡改/时钟偏差、权限变化等场景

## 1. 快速开始

```bash
# 环境已由 uv 锁定（Python 3.14）
uv sync
uv run python main.py
# 或: uv run uvicorn main:app --reload
# 服务监听 http://127.0.0.1:8000 ，交互文档在 /docs
```

运行测试（关键认证事件会打印到单测日志）：

```bash
uv run pytest                      # 静默
uv run pytest -o log_cli=true      # 打印每个用例的关键事件与判定依据
```

审计事件默认追加写入 `data/audit.log.jsonl`（每行一个 JSON，自动创建；
测试中写内存，不落盘）。

## 2. 演示账号

| 账号  | 密码        | 角色   | 说明        |
|-------|-------------|--------|-------------|
| alice | password123 | admin  | 全部权限    |
| bob   | password123 | editor | 读写文章    |
| carol | password123 | viewer | 只读文章    |
| dave  | password123 | viewer | 已停用，登录返回 `user_disabled` |

角色 → 权限：

- `admin` ：`article:read` `article:write` `user:manage` `session:revoke`
- `editor`：`article:read` `article:write`
- `viewer`：`article:read`

## 3. 认证与令牌轮换流程

### 3.1 登录：`POST /auth/login`

校验用户名 + 密码（PBKDF2），成功后：

1. 创建一条服务端 `Session`（含 session id、用户 id、创建时间）；
2. 签发**访问令牌**与**刷新令牌**（`header.payload.signature`，HMAC-SHA256）。

令牌声明（不包含权限快照）：

```json
{"typ": "access|refresh", "sub": "<user_id>", "sid": "<session_id>",
 "jti": "<token_id>", "iat": <签发时间>, "exp": "<过期时间>"}
```

默认 TTL：访问令牌 900 秒，刷新令牌 14 天（测试中为 300/600 秒）。

### 3.2 访问受保护资源

请求头：`Authorization: Bearer <access_token>`。

服务端每次请求都会做完整判定（顺序固定，结论稳定）：

1. 结构与 HMAC 签名是否合法 —— 否则 `token_invalid`（被篡改/伪造）；
2. `typ` 是否匹配（访问令牌不能当刷新令牌用，反之亦然）；
3. `iat` 是否在"未来"且超出时钟偏差容忍（默认 60 秒）—— 否则 `token_clock_skew`；
4. 当前时间是否超过 `exp` —— 否则 `token_expired`；
5. 会话是否存在 / 是否已撤销 —— `session_not_found` / `session_revoked`；
6. 用户是否存在 / 是否启用 —— `user_not_found` / `user_disabled`。

> 时钟偏差与过期是**两个独立错误码**：令牌来自未来（时钟不一致）
> 与令牌已经过期被明确区分。过期判定对 `iat` 不留宽限，只对未来时间
> 使用可配置容忍窗口。

### 3.3 刷新与轮换：`POST /auth/refresh`

刷新令牌是**一次性的**。服务端为每个刷新令牌保存状态
（`used` / `revoked` / `next_token_id`）。每次合法刷新：

1. 在**同一把存储锁**内完成"定位令牌 → 检查 → 标记旧令牌 used →
   签发新访问令牌 + 新刷新令牌"；
2. 旧刷新令牌立刻作废，新刷新令牌挂到**同一条会话**上；
3. 记录 `refresh_success`（含 old/new token id）。

**重用检测（核心安全语义）**：如果一个已标记 `used`（或已撤销）的
刷新令牌再次出现，服务端判定为刷新令牌被窃取/重用：

- 立即撤销**整条会话**（包括刚刚轮换出去的新刷新令牌）；
- 返回 `401 refresh_token_reused`，并记录 `refresh_failed(reason=reused,
  decision=revoke_entire_session)` 与 `session_revoked`；
- 同一个被重用的令牌无论重放多少次，结论稳定为 `refresh_token_reused`；
- 会话撤销后，其未过期的访问令牌也会在下一次请求被拒绝
  （`session_revoked`）——撤销不需要等待访问令牌自然过期。

**并发刷新**：多个请求同时拿同一个刷新令牌刷新时，由于"检查-标记-
签发"在同一把锁内原子完成，**恰好一个成功**，其余全部按重用拒绝，
不会重复签发，也不会出现状态错乱（见
`tests/test_concurrency.py`，32 线程屏障并发）。

**单纯过期不是攻击**：刷新令牌过期但从未被使用时，返回
`token_expired`，不撤销会话（语义与重用严格区分）。

## 4. 访问控制模型与"权限变化"语义

- 模型是 用户 → 角色 → 权限（RBAC），多角色权限取并集；
- **权限不写进令牌**。令牌只证明"你是谁、属于哪条会话"；
  每次请求都从用户存储实时聚合当前角色的权限。
- 因此对**已签发的会话**：
  - 修改用户角色（`POST /admin/users/{user_id}/roles`）后，
    下一个请求立刻按新权限判定——提权立即生效、降权立即失效，
    无需重新登录；
  - 停用用户后，其所有现有会话立即无法访问（`user_disabled`）；
  - HTTP 入口与直接调用服务层（`AuthService.require_permission`）
    走的是同一段判定代码，同一个令牌在任何入口结论一致。

未登录与权限不足严格区分：

| 情况                         | 状态码 | error.code            |
|------------------------------|--------|-----------------------|
| 没有/畸形 Authorization 头   | 401    | `not_authenticated`   |
| 令牌被篡改、签名错误、类型错 | 401    | `token_invalid`       |
| 时钟偏差过大                 | 401    | `token_clock_skew`    |
| 令牌过期                     | 401    | `token_expired`       |
| 刷新令牌重用                 | 401    | `refresh_token_reused`|
| 会话已撤销                   | 401    | `session_revoked`     |
| 用户已停用                   | 403    | `user_disabled`       |
| 已登录但缺少权限             | 403    | `permission_denied`   |

## 5. 会话撤销语义

- **撤销单条会话**：`POST /admin/sessions/revoke`
  （需 `session:revoke`），body `{"session_id": "..."}`。
  该会话的全部刷新令牌作废，访问令牌即时失效；同用户的其他会话不受影响。
- **撤销某用户全部会话**：`POST /admin/users/revoke-sessions`，
  body `{"user_id": "...", "reason": "..."}`，返回实际撤销数量；
  重复调用幂等（已撤销的不计入数量）。其他用户不受影响。
- 撤销原因会记录在会话与审计事件里
  （`manual_revoke` / `refresh_token_reuse` / 自定义 reason）。

## 6. HTTP 接口一览

| 方法 & 路径 | 权限 | 说明 |
|---|---|---|
| `GET /health` | 公开 | 健康检查 |
| `POST /auth/login` | 公开 | 登录，返回双令牌 |
| `POST /auth/refresh` | 公开（需刷新令牌） | 轮换并返回新双令牌 |
| `GET /me` | 登录 | 当前用户、角色、实时权限 |
| `GET /articles` | `article:read` | 读资源 |
| `POST /articles` | `article:write` | 写资源 |
| `POST /admin/sessions/revoke` | `session:revoke` | 撤销单会话 |
| `POST /admin/users/revoke-sessions` | `session:revoke` | 撤销用户全部会话 |
| `POST /admin/users/{user_id}/roles` | `user:manage` | 修改角色/启停（实时生效） |

错误响应统一格式：

```json
{"error": {"code": "permission_denied", "message": "缺少权限: article:write"}}
```

## 7. 本地手动验证（curl 示例）

```bash
BASE=http://127.0.0.1:8000

# 1) 登录
curl -s -X POST $BASE/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password123"}'

# 2) 带访问令牌访问（把 <AT> 换成上一步的 access_token）
curl -s $BASE/articles -H "Authorization: Bearer <AT>"

# 3) 刷新轮换（<RT> 为 refresh_token）
curl -s -X POST $BASE/auth/refresh -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<RT>"}'

# 4) 再次拿同一个 <RT> 刷新 => 401 refresh_token_reused，整条会话被撤销
curl -s -X POST $BASE/auth/refresh -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<RT>"}'

# 5) 查看审计事件
tail -f data/audit.log.jsonl
```

权限变化验证：以 alice 登录后调用
`POST /admin/users/u_carol/roles`，body `{"roles":["editor"]}`，
carol 手里**原有**的访问令牌立刻可以 `POST /articles`；改回
`{"roles":["viewer"]}` 后立刻又被拒绝（测试
`test_role_change_consistent_across_entries` 同时校验了
HTTP 入口与服务层入口结论一致）。

## 8. 审计日志

关键事件（写入内存列表并追加到 JSONL）：

`login_success` / `login_failed` / `refresh_success` /
`refresh_failed`（`reason` 为 `reused` / `expired` / `clock_skew` /
`session_revoked` / `session_not_found`）/ `session_revoked` /
`all_sessions_revoked` / `access_denied` / `roles_updated`。

事件携带判定依据，例如重用事件包含
`reason=reused, decision=revoke_entire_session`，权限拒绝包含
`effective_permissions`，便于解释"为什么是这个结论"。

## 9. 代码结构

```
authapp/
  errors.py    # 独立错误码：过期/篡改/时钟偏差/未登录/权限不足/重用/撤销...
  clock.py     # 可注入时钟（SystemClock / 测试用 FixedClock）
  security.py  # PBKDF2 密码哈希、HMAC 令牌签发与验签（仅标准库）
  models.py    # User / Role / Session / RefreshTokenState / 令牌声明
  store.py     # 内存存储 + 全局 RLock；权限实时聚合
  audit.py     # JSONL 审计日志（追加写 + 内存镜像）
  service.py   # 核心：登录/轮换+重用检测/统一校验/撤销（所有入口共享）
  deps.py      # FastAPI 依赖：Bearer 解析、登录与权限依赖
  http.py      # 路由与 AuthError -> HTTP 响应映射
  app.py       # 应用装配
  seed.py      # 本地演示角色与账号
main.py        # uvicorn 入口
tests/         # 安全基元 / 服务层 / 并发 / HTTP 入口
```

## 10. 边界与说明（本地演示定位）

- 内存存储重启即失效；生产应替换为带事务/条件更新的持久存储，
  但"检查-消费-签发必须原子化"这一约束不变。
- 演示密钥通过 `AuthService(secret=...)` 注入；生产应来自环境/密钥管理。
- 访问令牌撤销依赖会话状态实时检查（本实现每次请求都查），
  因此撤销即时生效；这是有意保留的语义，而非短令牌"等过期"。
