# Kvmidc-SSH Terminal API

This API creates short-lived one-time login links for opening an SSH terminal directly.

Never put SSH passwords or private keys in a browser URL. Use `POST /api/session-token` from your backend service, then redirect the user to the returned `url`.

## Authentication

Set a Worker environment variable:

```text
SSH_API_TOKEN=your-server-side-api-token
```

Every create-token request must include:

```http
Authorization: Bearer your-server-side-api-token
```

Do not call this API directly from a browser or frontend page. It is intended for your server-side system.

## Create One-Time Session Token

```http
POST https://ssh.kvmidc.com/api/session-token
Authorization: Bearer your-server-side-api-token
Content-Type: application/json
```

### Password Login Body

```json
{
  "host": "203.0.113.10",
  "port": 22,
  "username": "root",
  "password": "your-ssh-password",
  "authMethod": "password",
  "ttl": 60,
  "label": "optional order/server id"
}
```

### Private Key Login Body

```json
{
  "host": "203.0.113.10",
  "port": 22,
  "username": "root",
  "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
  "authMethod": "publickey",
  "ttl": 60,
  "label": "optional order/server id"
}
```

### Fields

| Field | Type | Required | Description |
|---|---:|---:|---|
| `host` | string | yes | SSH target host or IP. Private/reserved targets are blocked. |
| `port` | number | no | SSH port. Defaults to `22`. |
| `username` | string | yes | SSH username. |
| `password` | string | yes for password login | SSH password. |
| `privateKey` | string | yes for key login | SSH private key content. |
| `authMethod` | string | no | `password` or `publickey`. Auto-detected when omitted. |
| `ttl` | number | no | Token lifetime in seconds. Default `60`, minimum `10`, maximum `300`. |
| `label` | string | no | Optional audit label. Not shown to users. |

### Success Response

```json
{
  "success": true,
  "token": "one-time-token",
  "url": "https://ssh.kvmidc.com/connect?token=one-time-token",
  "expiresIn": 60
}
```

Redirect the user to `url`. The browser will consume the token and enter the terminal page automatically.

### Error Responses

```json
{
  "success": false,
  "error": "Unauthorized"
}
```

Common HTTP statuses:

| Status | Meaning |
|---:|---|
| `400` | Invalid body, invalid port, missing credentials, or blocked target. |
| `401` | Missing or wrong API token. |
| `503` | `SSH_API_TOKEN` is not configured. |

## Consume Token

The frontend consumes this endpoint automatically:

```http
GET https://ssh.kvmidc.com/api/session-token/{token}
```

Tokens are one-time use. A successful consume deletes the token immediately.

If Turnstile is enabled, the consume response also sets the same verification cookie used by normal login, so the following WebSocket connection can start without showing the Turnstile widget.

## Security Notes

- Do not send credentials in query strings.
- Create tokens only from your backend system.
- Keep `SSH_API_TOKEN` secret and rotate it if leaked.
- Tokens expire quickly and are deleted after first use.
- The Worker blocks private/reserved targets such as `127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`, localhost, and local IPv6 ranges.
- The Worker blocks common non-SSH service ports such as `80`, `443`, `3306`, `6379`, and similar risky ports.
- Passwords/private keys are not written into browser localStorage when using token login.
- Avoid logging request bodies in your own backend.

## Backend Example

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
    password: 'your-ssh-password',
    authMethod: 'password',
    ttl: 60,
    label: 'server-123',
  }),
});

const data = await response.json();
if (!response.ok || !data.success) {
  throw new Error(data.error || 'Failed to create SSH session token');
}

// Redirect user to data.url
```
