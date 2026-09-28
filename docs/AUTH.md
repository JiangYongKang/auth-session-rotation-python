# 身份认证、令牌轮换与会话撤销说明

本项目在本机即可完整运行，**不依赖任何外部服务、真实凭据或付费资源**：
密码哈希、令牌签名全部基于 Python 标准库（PBKDF2-HMAC-SHA256 / HMAC-SHA256），
用户与会话数据保存在进程内存，关键事件以 JSON Lines 落到本地文件。

## 1. 总体架构

```
HTTP 入口 (auth_app/api.py, FastAPI)
        │  只做参数解析与错误码映射，不做任何独立安全判定
        ▼
AuthService (auth_app/service.py)   ← 所有入口共享的唯一判定来源
        ├── tokens.py    自签名访问/刷新令牌，严格区分过期/篡改/时钟偏差
        ├── rbac.py      角色 + 权限，每次请求实时读取
        ├── store.py     线程安全内存存储（一把 RLock 保护刷新轮换）
        ├── audit.py     JSONL 审计日志（落盘 + 内存副本）
        ├── security.py  PBKDF2 密码哈希 / SHA-256 令牌摘要
        └── clock.py     可平移时钟（测试过期与时钟偏差）
```

因为所有入口（HTTP 接口、测试、程序化调用）都只经过 `AuthService` 的同一套方法，
同一份输入在任何入口下的结论都一致。

## 2. 令牌结构与校验

令牌为自包含的紧凑签名串：

```
base64url(payload_json) + "." + base64url(hmac_sha256(payload_b64))
```

- **访问令牌 (access)**：`typ/ sub(用户) / sid(会话) / jti / iat / exp / rol / perm`。
  默认有效期 15 分钟。
- **刷新令牌 (refresh)**：不含角色权限快照，默认有效期 7 天。
- 访问令牌里的 `rol/perm` 只是**签发时快照**，仅用于排查展示，**不参与授权**。
  授权永远以服务端实时的用户数据为准。

校验顺序固定，失败原因严格区分：

| 情况 | 判定 | 错误码 (HTTP) |
|---|---|---|
| 结构非法 / 签名不匹配 / 载荷被改 | 被篡改 | `token_tampered` (401) |
| `iat` 来自未来且超出容忍窗口 | 时钟偏差 | `clock_skew` (401) |
| 当前时间超过 `exp + leeway` | 已过期 | `token_expired` (401) |
| 一切正常 | 放行 | — |

默认容忍窗口 `AUTH_CLOCK_SKEW_LEEWAY=60` 秒（测试中设为 0 使边界精确）。
签名比对使用 `hmac.compare_digest`（常量时间）。

## 3. 登录与刷新令牌轮换 (Rotation)

1. `POST /auth/login` 校验用户名/密码（PBKDF2），创建一条**会话 (session)**，
   并签发一对令牌。服务端只保存刷新令牌的 SHA-256 哈希，不存明文。
2. `POST /auth/refresh` 提交刷新令牌：
   1. 先做密码学校验（过期/篡改/时钟偏差照常区分）；
   2. 在存储的**同一把锁**内完成「查记录 → 判定 → 旧令牌置 used → 签发新对 → 落库」，
      因此并发刷新同一令牌时**只有一个请求成功**；
   3. 每次成功刷新，旧刷新令牌立即标记 `used`，返回一对全新令牌
      （新刷新令牌有新的 `jti`，并记录 `parent_jti` 链）。

### 刷新令牌重用检测（关键安全语义）

> 已经被用过一次的刷新令牌再次出现，按**重用 (replay)** 处理：
> **立即撤销它所属的整条会话**，而不是悄悄再发一份新令牌。

判定细则：

- 已 `used` 的刷新令牌再现 → `refresh_token_reused`，撤销整条会话
  （会话及该会话下所有刷新令牌全部失效）；
- 一张尚未使用的刷新令牌，其会话已因**其他令牌重放**被撤销 →
  同样按重放告警（`reason=token_from_breached_chain`），因为出现来自已泄露链的令牌；
- 一张尚未使用的刷新令牌，其会话是被**外部主动撤销**的
  （管理员撤销/登出/撤销单会话）→ `session_revoked`，区别于重放。

重放之后：旧令牌、新令牌、该会话已签发的访问令牌**全部立即失效**。

## 4. 访问控制模型 (RBAC)

权限 = 角色权限的并集 ∪ 单独授予的权限；用户可被 `active=False` 停用。

| 角色 | 权限 |
|---|---|
| `admin` | `doc:read doc:write doc:delete session:manage user:manage` |
| `editor` | `doc:read doc:write` |
| `viewer` | `doc:read` |

- 未登录 / 令牌无效 → **401** 类（`not_authenticated` / `token_expired` /
  `token_tampered` / `clock_skew` / `session_revoked`）；
- 已登录但权限不足 → **403 `permission_denied`**，响应 `detail` 中带
  `required`（所需权限）与 `granted`（实际拥有权限），便于解释。

### 角色/权限变化的生效语义（明确且一直成立）

**每次**权限校验都实时读取内存中用户当前的 `roles/permissions/active`，
不读取访问令牌内的快照。因此管理员通过
`POST /admin/users/{id}/roles` 调整后：

- 提权 / 降权 / 单独授权或收权 / 停用用户，对该用户**所有已签发会话立即生效**，
  无需等待令牌过期、无需重新登录；
- 同一张令牌在变更前后结论可以不同，但在任一时刻、任一入口下结论一致。

## 5. 会话撤销语义

| 操作 | 语义 | 接口 |
|---|---|---|
| 撤销单个会话 | 该会话的访问令牌立即失效；其刷新令牌不可再换取新令牌 | `DELETE /sessions/{sid}`（本人或 admin） |
| 登出 | 等价于撤销当前会话 | `POST /auth/logout` |
| 撤销某用户全部会话 | 该用户当前所有会话与刷新令牌全部失效；之后新登录不受影响 | `POST /admin/users/{id}/revoke-sessions`（需 `user:manage`） |

撤销是幂等的：重复撤销不会改变结果。撤销其他用户的会话需要 `session:manage`，
否则返回 403。

## 6. 审计日志

路径由 `AUTH_AUDIT_LOG` 控制，默认 `data/audit.log.jsonl`，每行一个 JSON：
`ts / event / user_id / session_id / jti / reason / ...`。关键事件包括：

`login_ok` `login_failed` `access_granted` `access_denied` `permission_denied`
`refresh_rotated` `refresh_token_reuse_detected` `refresh_rejected`
`session_revoked` `user_all_sessions_revoked` `roles_changed`。

拒绝类事件都带判定依据，例如 `permission_denied` 带 `required/granted/roles`，
重放事件带 `jti/reason/action=whole_session_revoked`。
pytest 以 `-s` 运行时会在每个用例后打印本次产生的全部事件。

## 7. HTTP 接口一览

| 方法 路径 | 要求 | 说明 |
|---|---|---|
| `POST /auth/login` | 公开 | 登录，返回 access/refresh |
| `POST /auth/refresh` | 刷新令牌 | 轮换；重放即撤销整会话 |
| `POST /auth/logout` | 已登录 | 撤销当前会话 |
| `GET  /me` | 已登录 | 当前身份与实时角色/权限 |
| `GET  /sessions` | 已登录 | 列出自己的会话 |
| `DELETE /sessions/{sid}` | 本人或 admin | 撤销单个会话 |
| `GET  /docs` | `doc:read` | 示例受保护资源 |
| `POST /docs` | `doc:write` | 示例写接口 |
| `DELETE /docs/{id}` | `doc:delete` | 示例删除接口 |
| `POST /admin/users/{id}/roles` | `user:manage` | 实时变更角色/权限/启用状态 |
| `POST /admin/users/{id}/revoke-sessions` | `user:manage` | 撤销用户全部会话 |
| `GET  /api-docs` | 公开 | OpenAPI/Swagger 界面 |

错误响应统一形如：
`{"error": {"code": "...", "message": "...", "detail": {...}}}`。

## 8. 本地验证方法

### 启动服务

```bash
# 依赖已包含 fastapi[standard]；如需测试工具：uv pip install -r <dev group> 或 pip install pytest httpx
python3 main.py
# 或：python3 -m uvicorn main:app --port 8000
```

内置演示账号（仅本地）：`admin/admin123`、`editor/editor123`、`viewer/viewer123`。

### curl 快速验证

```bash
BASE=http://127.0.0.1:8000
# 登录
curl -s -X POST $BASE/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"viewer","password":"viewer123"}'
# 用返回的 access_token 访问
curl -s $BASE/docs -H "Authorization: Bearer <ACCESS_TOKEN>"
# 刷新；再用同一个 refresh_token 刷第二次 => 401 refresh_token_reused，整会话撤销
curl -s -X POST $BASE/auth/refresh -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<REFRESH_TOKEN>"}'
```

### 运行测试

```bash
python3 -m pytest -s          # -s 会打印每个用例的关键审计事件与判定依据
python3 -m pytest -q          # 只看结果
```

测试覆盖：刷新令牌重用撤销、并发刷新（5/20/50 线程，服务层 + HTTP 层）、
令牌过期 / 篡改 / 载荷改写 / 异密钥 / 时钟偏差、未登录与权限不足区分、
角色与权限升降级即时生效、停用用户、单会话与全用户撤销、
同一输入跨入口结论稳定性，以及审计落盘。

### 关键环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `AUTH_SIGNING_KEY` | 内置开发密钥 | HMAC 签名密钥（生产务必修改） |
| `AUTH_ACCESS_TTL` | `900` | 访问令牌秒数 |
| `AUTH_REFRESH_TTL` | `604800` | 刷新令牌秒数 |
| `AUTH_CLOCK_SKEW_LEEWAY` | `60` | 时钟偏差容忍秒数 |
| `AUTH_AUDIT_LOG` | `data/audit.log.jsonl` | 审计日志路径 |
| `AUTH_SEED_USERS` | `1` | 是否播种演示账号（`0` 关闭） |
