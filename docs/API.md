# Kvmidc-SSH 终端 API 文档

本 API 用于创建短时有效、一次性使用的 SSH 登录链接。你的业务系统可以通过接口提交服务器 IP、端口、用户名、密码或私钥，然后把返回的 `url` 提供给用户访问，用户打开后会直接进入 SSH 终端页面。

请不要把 SSH 密码或私钥直接拼到浏览器 URL 里。正确方式是：由你的后端服务调用 `POST /api/session-token` 创建一次性会话 token，再把返回的 `url` 跳转给用户。

## 接口鉴权

需要先在 Cloudflare Worker 环境变量中配置：

```text
SSH_API_TOKEN=你的服务端 API 密钥
```

每次创建 token 的请求都必须带上：

```http
Authorization: Bearer 你的服务端 API 密钥
```

这个 API 只建议由你的服务端调用，不要直接放在浏览器前端页面中调用，否则 API 密钥会暴露。

## 创建一次性 SSH 会话

```http
POST https://ssh.kvmidc.com/api/session-token
Authorization: Bearer 你的服务端 API 密钥
Content-Type: application/json
```

### 密码登录请求体

```json
{
  "host": "203.0.113.10",
  "port": 22,
  "username": "root",
  "password": "你的SSH密码",
  "authMethod": "password",
  "ttl": 60,
  "label": "可选的订单号或服务器编号"
}
```

### 私钥登录请求体

```json
{
  "host": "203.0.113.10",
  "port": 22,
  "username": "root",
  "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
  "authMethod": "publickey",
  "ttl": 60,
  "label": "可选的订单号或服务器编号"
}
```

### 参数说明

| 参数 | 类型 | 是否必填 | 说明 |
|---|---:|---:|---|
| `host` | string | 是 | SSH 目标主机 IP 或域名。系统会拦截内网、保留地址等高风险目标。 |
| `port` | number | 否 | SSH 端口，默认 `22`。 |
| `username` | string | 是 | SSH 登录用户名。 |
| `password` | string | 密码登录必填 | SSH 登录密码。 |
| `privateKey` | string | 私钥登录必填 | SSH 私钥内容。 |
| `authMethod` | string | 否 | 登录方式，可填 `password` 或 `publickey`。不填时会自动判断。 |
| `ttl` | number | 否 | token 有效期，单位秒。默认 `60`，最小 `10`，最大 `300`。 |
| `label` | string | 否 | 可选的审计标识，例如订单号、服务器编号。不会展示给用户。 |

### 成功响应

```json
{
  "success": true,
  "token": "one-time-token",
  "url": "https://ssh.kvmidc.com/connect?token=one-time-token",
  "expiresIn": 60
}
```

你的业务系统拿到响应后，把用户跳转到 `url` 即可。浏览器会自动消费 token，并进入 SSH 终端页面。

注意：token 是一次性的，成功打开后会立即失效，不能重复访问。

### 失败响应

```json
{
  "success": false,
  "error": "Unauthorized"
}
```

常见 HTTP 状态码：

| 状态码 | 含义 |
|---:|---|
| `400` | 请求体格式错误、端口非法、缺少登录凭据，或目标地址被安全策略拦截。 |
| `401` | 未提供 API 密钥，或 API 密钥错误。 |
| `503` | Worker 没有配置 `SSH_API_TOKEN` 环境变量。 |

## 消费一次性 Token

前端页面会自动请求下面的接口，通常不需要你的业务系统手动调用：

```http
GET https://ssh.kvmidc.com/api/session-token/{token}
```

token 成功消费后会立即删除。

如果启用了 Turnstile 验证，消费 token 时会同时写入正常登录使用的验证 Cookie，这样后续 WebSocket SSH 连接可以直接建立，不需要再显示 Turnstile 验证组件。

## 对接流程

1. 用户在你的业务系统中点击“进入 SSH”。
2. 你的后端服务读取该服务器的 IP、端口、用户名和密码或私钥。
3. 你的后端服务调用 `POST https://ssh.kvmidc.com/api/session-token`。
4. 接口返回 `url`。
5. 你的业务系统把用户跳转到该 `url`。
6. Kvmidc-SSH 终端自动消费 token 并连接服务器。

## 安全说明

- 不要把 SSH 密码、私钥放在 URL 参数中。
- 不要在浏览器前端直接调用创建 token 接口。
- `SSH_API_TOKEN` 必须只保存在服务端，泄露后应立即更换。
- token 有效期很短，并且只允许使用一次。
- Worker 会拦截内网和保留地址，例如 `127.0.0.1`、`10.0.0.0/8`、`192.168.0.0/16`、`172.16.0.0/12`、`localhost` 和本地 IPv6 地址段。
- Worker 会拦截常见非 SSH 服务端口，例如 `80`、`443`、`3306`、`6379` 等风险端口。
- 使用 token 登录时，密码和私钥不会写入浏览器 `localStorage`。
- 你的业务后端不要记录包含密码或私钥的完整请求体日志。

## 后端调用示例

### JavaScript / Node.js

```js
const response = await fetch('https://ssh.kvmidc.com/api/session-token', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${process.env.SSH_API_TOKEN}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    host: '203.0.113.10',
    port: 22,
    username: 'root',
    password: '你的SSH密码',
    authMethod: 'password',
    ttl: 60,
    label: 'server-123',
  }),
});

const data = await response.json();
if (!response.ok || !data.success) {
  throw new Error(data.error || '创建 SSH 会话失败');
}

// 将用户跳转到 data.url
```

### PHP

```php
<?php
$apiToken = getenv('SSH_API_TOKEN');

$payload = [
    'host' => '203.0.113.10',
    'port' => 22,
    'username' => 'root',
    'password' => '你的SSH密码',
    'authMethod' => 'password',
    'ttl' => 60,
    'label' => 'server-123',
];

$ch = curl_init('https://ssh.kvmidc.com/api/session-token');
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => [
        'Authorization: Bearer ' . $apiToken,
        'Content-Type: application/json',
    ],
    CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_UNICODE),
]);

$raw = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$data = json_decode($raw, true);
if ($httpCode < 200 || $httpCode >= 300 || empty($data['success'])) {
    throw new RuntimeException($data['error'] ?? '创建 SSH 会话失败');
}

header('Location: ' . $data['url']);
exit;
```
