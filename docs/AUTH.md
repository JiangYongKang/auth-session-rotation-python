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
- **已轮换的旧令牌在自身过期之后才被重放**（攻击者攥着旧令牌拖到失效后
  再拿出来）→ 只要仍在保留窗口内（见第 4 节），同样判定为
  `refresh_token_reused`（`reason=used_after_expiry`），立即撤销整条会话，
  包括该会话里其他仍在有效期内的令牌，**绝不**再签发新令牌；
- 一张尚未使用的刷新令牌，其会话已因**其他令牌重放**被撤销 →
  同样按重放告警（`reason=token_from_breached_chain`），因为出现来自已泄露链的令牌；
- 一张尚未使用的刷新令牌，其会话是被**外部主动撤销**的
  （管理员撤销/登出/撤销单会话）→ `session_revoked`，区别于重放；
- 一张**从未被成功使用、只是单纯过期**的刷新令牌 → 普通的
  `token_expired`，会话不受影响，与重放严格区分。

重放之后：旧令牌、新令牌、该会话已签发的访问令牌**全部立即失效**。

## 4. 刷新令牌历史的保留与回收

重放检测依赖服务端保存的刷新令牌记录（只存 SHA-256 哈希）。为了让这份
历史不随服务长期运行无限膨胀，采用**有界保留策略**：

- 每条记录的保留截止时间为 **`exp` + `AUTH_REPLAY_RETENTION_SECONDS`**
  （默认 30 天）。在截止时间之前，对应令牌仍有可能被再次提交
  （包括“已轮换旧令牌在自身过期后被重放”的判定），记录**绝不**被回收；
- 过了截止时间，令牌早已无法通过密码学过期校验、绝不可能再换到新令牌，
  记录才允许回收。回收是**惰性**的：每次刷新前自动执行一次，
  也可以直接调用服务层的 `cleanup_refresh_history()`，无需外部定时任务；
- 回收与刷新、撤销共用存储的同一把锁，并发下不会交错，
  不会出现重复签发或状态错乱；
- **超出保留范围后的行为是安全且可解释的**：此时再提交该令牌，
  本地记录已不存在，一律按普通 `token_expired` 拒绝
  （审计 `reason=expired_no_record_or_purged`），宁可拒绝也绝不放行或签发；
- 未过期的令牌（无论是否 used）其保留截止时刻必然在未来，不会被误回收。

两类“已经不能用的刷新令牌”在结论与本地记录中的区分：

| 情况 | 结论 | 会话 | 审计依据 |
|---|---|---|---|
| 已轮换旧令牌，过期后在保留窗口内重放 | `refresh_token_reused` | 整条撤销，`revoke_reason=refresh_token_reuse:used_after_expiry` | `refresh_token_reuse_detected`，`reason=used_after_expiry`，带 `used_at` |
| 已轮换旧令牌，过期且超出保留窗口后重放 | `token_expired`（安全兜底） | 不动 | `refresh_rejected`，`reason=expired_no_record_or_purged` |
| 从未使用、单纯过期 | `token_expired` | 不动 | `refresh_rejected`，`reason=expired_unused` |

因重放而作废的会话，其 `revoke_reason` 以 `refresh_token_reuse:` 开头，
与用户主动登出（`logout`）、管理员/本人主动撤销（`manual_revoke` /
`revoked_by_owner_or_admin` / `user_all_revoked`）在本地记录中明确区分。

## 5. 访问控制模型 (RBAC)

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

## 6. 会话撤销语义

| 操作 | 语义 | 接口 |
|---|---|---|
| 撤销单个会话 | 该会话的访问令牌立即失效；其刷新令牌不可再换取新令牌 | `DELETE /sessions/{sid}`（本人或 admin） |
| 登出 | 等价于撤销当前会话 | `POST /auth/logout` |
| 撤销某用户全部会话 | 该用户当前所有会话与刷新令牌全部失效；之后新登录不受影响 | `POST /admin/users/{id}/revoke-sessions`（需 `user:manage`） |

撤销是幂等的：重复撤销不会改变结果。撤销其他用户的会话需要 `session:manage`，
否则返回 403。

## 7. 审计日志

路径由 `AUTH_AUDIT_LOG` 控制，默认 `data/audit.log.jsonl`，每行一个 JSON：
`ts / event / user_id / session_id / jti / reason / ...`。关键事件包括：

`login_ok` `login_failed` `access_granted` `access_denied` `permission_denied`
`refresh_rotated` `refresh_token_reuse_detected` `refresh_rejected`
`refresh_history_purged` `session_revoked` `user_all_sessions_revoked`
`roles_changed`。

拒绝类事件都带判定依据，例如 `permission_denied` 带 `required/granted/roles`，
重放事件带 `jti/reason/action=whole_session_revoked`（过期后重放另带 `used_at`），
回收事件 `refresh_history_purged` 带 `purged_count/purged_jtis/retention_seconds`。
pytest 以 `-s` 运行时会在每个用例后打印本次产生的全部事件。

## 8. HTTP 接口一览

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

## 9. 本地验证方法

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

测试覆盖：刷新令牌重用撤销、**已轮换旧令牌在自身过期后被重放**（含保留窗口
内/外、HTTP 与服务层一致性、并发重放）、从未使用令牌的单纯过期对照、
保留窗口边界与惰性回收、并发刷新 + 并发回收（5/20/50 线程，服务层 + HTTP 层）、
令牌过期 / 篡改 / 载荷改写 / 异密钥 / 时钟偏差、未登录与权限不足区分、
角色与权限升降级即时生效、停用用户、单会话与全用户撤销、
同一输入跨入口结论稳定性，以及审计落盘。

### 在本机复现“过期后重放”场景

```bash
# 用短 TTL + 短保留窗口启动，便于手工复现
AUTH_ACCESS_TTL=30 AUTH_REFRESH_TTL=60 AUTH_REPLAY_RETENTION_SECONDS=120 \
  python3 main.py
```

```bash
BASE=http://127.0.0.1:8000
# 1) 登录，记下 refresh_token 为 R1
curl -s -X POST $BASE/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"viewer","password":"viewer123"}'
# 2) 用 R1 刷新一次（R1 被轮换作废，得到 R2）
curl -s -X POST $BASE/auth/refresh -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<R1>"}'
# 3) 等 60 秒以上让 R1 自身过期，再拿 R1 重放：
#    => 401 refresh_token_reused（reason=used_after_expiry），整条会话被撤销
curl -s -X POST $BASE/auth/refresh -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<R1>"}'
# 4) 对照：重新登录拿到 R3，不做任何刷新，等它过期后再提交：
#    => 401 token_expired，会话不受影响
# 5) 等超过 保留窗口(60+120 秒) 后再重放 R1：
#    => 401 token_expired（reason=expired_no_record_or_purged），安全兜底
# 审计日志 data/audit.log.jsonl 中可看到 refresh_token_reuse_detected /
# refresh_rejected / refresh_history_purged 事件及判定依据。
```

### 关键环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `AUTH_SIGNING_KEY` | 内置开发密钥 | HMAC 签名密钥（生产务必修改） |
| `AUTH_ACCESS_TTL` | `900` | 访问令牌秒数 |
| `AUTH_REFRESH_TTL` | `604800` | 刷新令牌秒数 |
| `AUTH_CLOCK_SKEW_LEEWAY` | `60` | 时钟偏差容忍秒数 |
| `AUTH_AUDIT_LOG` | `data/audit.log.jsonl` | 审计日志路径 |
| `AUTH_SEED_USERS` | `1` | 是否播种演示账号（`0` 关闭） |
| `AUTH_REPLAY_RETENTION_SECONDS` | `2592000`（30 天） | 刷新令牌记录在其过期后再保留的秒数；窗口内过期重放仍可判重放，窗口外历史回收、一律按过期拒绝 |

### 兼容性说明

- 未过期令牌的行为完全不变：登录、正常轮换、未过期重放检测、撤销语义
  与之前一致；
- 新增行为只影响**已过期**的刷新令牌：过去一律返回 `token_expired`，
  现在若该令牌曾被成功轮换且仍在保留窗口内，会改判为
  `refresh_token_reused` 并撤销整条会话；从未使用的过期令牌结论不变；
- 保留窗口之外的过期令牌结论与过去相同（`token_expired`），属于安全兜底。
