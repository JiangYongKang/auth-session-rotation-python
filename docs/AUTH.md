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

#### 旧轮换令牌“迟到重放”：过期很久之后再拿出来也照样算重放

一个真实的攻击时序：攻击者拿到一张**已经被轮换掉**的旧刷新令牌后，
故意一直不用，拖到它**自身也过期**、甚至过期很久之后才拿出来重放，
试图让服务端把它当成一次“普通的令牌过期”轻轻挡回，从而逃避整会话撤销。

本服务不会上这个当。`/auth/refresh` 对过期刷新令牌**不会在密码学层直接
拒绝了事**，而是：签名仍然严格校验（篡改/异密钥依旧 `token_tampered`），
验签通过后读取其 `jti`/哈希，进入与正常刷新**同一把锁**查服务端历史，
把两类“都已经不能用”的刷新令牌严格分开：

| 过期刷新令牌在服务端的状态 | 结论 | 错误码 | 是否撤销会话 |
|---|---|---|---|
| 记录存在且 `used`（曾被成功轮换） | **重放**，撤销整条会话、不重签 | `refresh_token_reused`（`reason=used_token_replayed_after_expiry`） | 是 |
| 会话已因**别的令牌重放**被撤销 | 来自被攻破链路的令牌 | `refresh_token_reused` | 已撤销 |
| 记录存在但**从未使用**，会话也活着 | 普通的“已过期” | `token_expired`（`reason=expired_never_used`） | 否 |
| 从未使用，但会话是被登出/管理员主动撤销 | 普通会话撤销 | `session_revoked` | 已撤销 |
| 保留窗口内却查无此记录（从未成功签发/换走） | 普通无效 | `refresh_token_invalid` | 否 |
| **超过有界保留窗口**、历史已被回收 | 无法证明身份，**安全拒绝**（不放行/不重签） | `refresh_token_history_reaped` | 否（旧会话也不会复活） |

因此同一张令牌在“刚好过期”与“过期很久但仍在保留窗口内”两个时点，
结论都稳定是重放；它与“从未成功使用、只是过期”的令牌在错误码、
审计 `reason`、会话记录的 `revoke_reason` 上都分得清清楚楚，
不会被误读成一次超时。

## 3b. 重放历史的有界保留与回收

服务端为检测重放而保留的刷新令牌历史**不会无限膨胀**，采用
“**时间有界为主、条数软上限为辅**”的策略：

- 每张刷新令牌记录带一个 `retain_until`：

  ```
  retain_until = 令牌自身 exp + clock_skew_leeway + replay_retention_seconds
  ```

  默认额外保留 **30 天**（`AUTH_REPLAY_RETENTION_SECONDS=2592000`）。
  在 `retain_until` 之前**任何**清理都不得删除该记录——只要一张刷新令牌
  还有可能在保留范围内被再次提交，它的重放痕迹就一定还在；
- 回收只删除 `now >= retain_until` 的记录，即**等它彻底不可能再换到
  新令牌之后**才回收。回收有两个触发点：
  - **机会式**：每次 `/auth/refresh` 在同一把锁内、按
    `AUTH_REPLAY_PURGE_INTERVAL_SECONDS`（默认 60s）节流执行；
  - **显式**：`AuthService.purge_replay_history()`，或管理员接口
    `POST /admin/maintenance/replay-history/purge`（需 `user:manage`）；
- 条数软上限 `AUTH_REPLAY_HISTORY_MAX_RECORDS`（默认 200000）是防御性
  背压：超限时清理也**只回收已经过了保留窗口的记录**，绝不提前删除
  尚在窗口内的痕迹（宁可内存暂时增长，也不漏判）。仍超限时返回
  `over_limit=true` 与 `next_eligible_at`，只告警、不放水。

**并发安全**：清理、查历史、判定、签发、撤销全部在 `Store` 的同一把
`RLock` 内串行完成，因此并发刷新、并发撤销与清理同时发生时，不会出现
先删后判、重复签发或把本该拦下的请求放行。

**超出保留窗口后的行为**：历史既已回收，服务端无法证明该过期令牌是不是
重放，此时采取**安全且可解释**的结论 `refresh_token_history_reaped`
（401，`detail` 带 `jti/expired_at/presented_at/retain_deadline/reason`），
**拒绝访问且绝不重新签发**。这是有界保留固有的取舍：把检测窗口明确
划定在“令牌过期 + 保留期”内，而不是用无限内存换无限追溯。


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
`refresh_history_reaped_reject` `replay_history_purged`
`session_revoked` `user_all_sessions_revoked` `roles_changed`。

拒绝类事件都带判定依据，例如 `permission_denied` 带 `required/granted/roles`，
重放事件带 `jti/reason/action=whole_session_revoked`；过期旧令牌的迟到重放
额外带 `used_at/expired_at/presented_at`，超窗口拒绝带
`expired_at/presented_at/retain_deadline/action=deny_without_reissue`，
清理事件带 `reaped/remaining/over_limit/next_eligible_at`。
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
| `POST /admin/maintenance/replay-history/purge` | `user:manage` | 有界回收过期的重放历史 |
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
# 只看本轮新增：过期旧令牌迟到重放 / 对照普通过期 / 保留回收边界 / 并发
python3 -m pytest tests/test_expired_replay_retention.py -s
```

测试覆盖：刷新令牌重用撤销、**已轮换旧令牌在自身过期很久之后迟到重放仍被
识别并整会话撤销**、**从未使用仅过期按普通过期处理（两类严格对照）**、
**保留窗口内历史不被提前清理 / 到点才回收 / 超窗口安全拒绝不放行不重签**、
**清理与并发刷新/并发撤销同时发生的一致性**、HTTP 回收入口权限，
以及原有的并发刷新（5/20/50 线程，服务层 + HTTP 层）、
令牌过期 / 篡改 / 载荷改写 / 异密钥 / 时钟偏差、未登录与权限不足区分、
角色与权限升降级即时生效、停用用户、单会话与全用户撤销、
同一输入跨入口结论稳定性，以及审计落盘。

### 用脚本在本机复现“迟到重放”（可平移时钟，无需等待真实过期）

```bash
python3 - <<'PY'
from auth_app.config import Settings
from auth_app.bootstrap import build_service
from auth_app.errors import RefreshTokenReused, TokenExpired
from auth_app.models import User
from auth_app.security import hash_password

s = Settings(signing_key="k", access_token_ttl=60, refresh_token_ttl=300,
             clock_skew_leeway=0, audit_log_path="/tmp/demo-audit.jsonl",
             seed_users=False, replay_retention_seconds=1000,
             replay_purge_interval_seconds=0)
svc = build_service(s)
svc.store.upsert_user(User("u1", "bob", hash_password("pw"), set(), set()))

p1 = svc.login("bob", "pw")
svc.refresh(p1.refresh_token)          # 正常轮换：p1.refresh 立即变 used
svc.clock.advance(301 + 500)           # 拖到 p1 自身过期很久（仍在保留窗内）
try:
    svc.refresh(p1.refresh_token)      # 迟到重放
except RefreshTokenReused as e:
    print("重放 ->", e.code, e.detail["reason"])   # 整会话已撤销

svc.clock.reset()                     # 回到真实时间基准，再开一个干净会话
q1 = svc.login("bob", "pw")
svc.clock.advance(301)
try:
    svc.refresh(q1.refresh_token)      # 从未用过、只是过期
except TokenExpired as e:
    print("普通过期 ->", e.code, e.detail["reason"])
PY
```

预期输出：

```
重放 -> refresh_token_reused used_token_replayed_after_expiry
普通过期 -> token_expired expired_never_used
```

把时间推进到 `301 + 1001`（越过 `exp + leeway + 保留期`）后先调用
`svc.purge_replay_history()`，再提交同一张过期旧令牌，会得到
`refresh_token_history_reaped`（安全拒绝、不重签），可据此验证超窗口行为。

### 关键环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `AUTH_SIGNING_KEY` | 内置开发密钥 | HMAC 签名密钥（生产务必修改） |
| `AUTH_ACCESS_TTL` | `900` | 访问令牌秒数 |
| `AUTH_REFRESH_TTL` | `604800` | 刷新令牌秒数 |
| `AUTH_CLOCK_SKEW_LEEWAY` | `60` | 时钟偏差容忍秒数 |
| `AUTH_AUDIT_LOG` | `data/audit.log.jsonl` | 审计日志路径 |
| `AUTH_SEED_USERS` | `1` | 是否播种演示账号（`0` 关闭） |
| `AUTH_REPLAY_RETENTION_SECONDS` | `2592000`（30 天） | 刷新令牌过期后重放痕迹的额外保留秒数 |
| `AUTH_REPLAY_HISTORY_MAX_RECORDS` | `200000` | 重放历史条数软上限（只告警，不提前删窗口内记录） |
| `AUTH_REPLAY_PURGE_INTERVAL_SECONDS` | `60` | 刷新流程内机会式清理的最小间隔秒数 |
