# Personal Media — Setup on the ZimaBoard

This guide sets up Personal Media on the ZimaBoard (ZimaOS + Docker) and makes it publicly reachable through **Tailscale Funnel**. TLS is terminated on the ZimaBoard itself, so no third party sees decrypted traffic.

> **Status:** v1 is implemented; the commands below match the code. The PWA, share target and iOS Shortcut are planned for v1.1 and aren't covered here. The Tailscale steps were checked against Tailscale's docs and source code (2026-11-16). Design: `docs/superpowers/specs/2026-11-16-personal-media-design.md`.

## Architecture

```
Internet ──HTTPS──► Tailscale Funnel relay (sees only encrypted TLS)
                          │
                          ▼
ZimaBoard ─ tailscale container (network_mode: host) ─ terminates TLS
                          │  http://127.0.0.1:8080
                          ▼
            personal-media container (network_mode: host, binds 127.0.0.1:8080)
                          │
                          ▼
            /DATA/AppData/personal-media   (6 TB pool — encrypted data only)
```

- The app listens on `127.0.0.1` only, so nothing else on the LAN (10.0.0.0/8) can reach it directly.
- Tailscale Funnel only proxies to `http://127.0.0.1:<port>`; that's why both containers use host networking.
- Cloudflare Tunnel is **not** used for this app: Cloudflare would decrypt the traffic.

## 1. Tailscale admin console (once)

1. **DNS** (<https://login.tailscale.com/admin/dns>): enable **MagicDNS** and **HTTPS Certificates**.
2. Optional: under DNS, rename the tailnet's random name to a nicer one. The public URL will be `https://<node-name>.<tailnet-name>.ts.net`.
3. **Access controls** (<https://login.tailscale.com/admin/acls>): make sure the ZimaBoard node may use Funnel. New tailnets usually already contain this; add it if missing:

   ```json
   "nodeAttrs": [
     { "target": ["autogroup:member"], "attr": ["funnel"] }
   ]
   ```

   If the ZimaBoard node is tagged (e.g. `tag:zimaboard`), use that tag as the target instead.

## 2. Data directory

Create a directory on the redundant 6 TB pool, for example:

```bash
mkdir -p /DATA/AppData/personal-media
chown -R 10001:10001 /DATA/AppData/personal-media   # the container runs as uid/gid 10001
```

Everything the app stores there is encrypted per user. You can back it up as-is (see section 8).

## 3. Deploy the app

`docker-compose.yml` in the repo root:

```yaml
services:
  personal-media:
    build: .
    image: personal-media
    container_name: personal-media
    restart: unless-stopped
    network_mode: host
    user: "10001:10001"
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 1g
    pids_limit: 256
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: "3"
    environment:
      PM_BIND: 127.0.0.1:8080
      PM_PUBLIC_URL: https://<node>.<tailnet>.ts.net   # edit: your Funnel URL
      PM_TRUSTED_PROXY: 127.0.0.1
      PM_MAX_UPLOAD_MB: "100"
    volumes:
      - /DATA/AppData/personal-media:/data
    tmpfs:
      # OCR scratch: plaintext never touches disk
      - /data/tmp:size=512m,mode=0700,uid=10001,gid=10001
```

Edit `PM_PUBLIC_URL` to your real `https://<node>.<tailnet>.ts.net` address first; the app refuses to start (and `invite` refuses to run) unless it is an `https://host[:port]` URL. The root filesystem is read-only; only `/data` and the tmpfs are writable.

Get the code onto the ZimaBoard in one of two ways (whether ZimaOS ships `git` is unverified):

- **With git on the board:**

  ```bash
  git clone <this repo> && cd personalmedia
  docker compose up -d --build      # first Rust build on the N150 takes a while; it also runs the tests
  ```

- **Without git:** build the image on your dev machine and transfer it, then start it from the compose file without `--build`:

  ```bash
  # on the dev machine
  docker build -t personal-media .
  docker save personal-media | ssh zima docker load
  # on the ZimaBoard, with docker-compose.yml copied over
  docker compose up -d
  ```

Then check it answers locally:

```bash
curl -sI http://127.0.0.1:8080/login   # should answer 200
```

The image installs German and English OCR data (`tesseract-ocr-deu`, `tesseract-ocr-eng`) and has a built-in health check (`personal-media healthcheck`, which requests `/healthz` and is not written to the access log).

## 4. Enable Funnel on the existing Tailscale container

> **Your ZimaOS setup:** the ZimaOS Tailscale app (`docs/tailscale.yaml`) overrides the entrypoint and runs `tailscaled` directly. Because of that, `TS_SERVE_CONFIG` (Option B) and `TS_EXTRA_ARGS` have no effect there. Use **`deploy/tailscale-funnel.yaml`** instead. It's the same config with one added line, `tailscale funnel --bg --yes --https=443 http://127.0.0.1:8080`, which runs before `tailscale web`. Paste it into the Tailscale app's compose settings in ZimaOS and restart the app. Then check with `docker exec tailscale tailscale funnel status`. If something else on the ZimaBoard already uses port 8080, change both `PM_BIND` and this line.

Your Tailscale container already runs with `network_mode: host`. Pick **one** of the two ways below.

### Option A — CLI (simplest)

```bash
docker exec <tailscale-container> tailscale funnel --bg --https=443 http://127.0.0.1:8080
docker exec <tailscale-container> tailscale funnel status
```

- `--bg` makes the configuration persistent. It survives restarts **as long as the container's state directory (`/var/lib/tailscale`, or `TS_STATE_DIR`) is on a persistent volume.**
- Funnel only allows ports **443, 8443 or 10000**. If 443 on this node is already used by another `tailscale serve`, use `--https=8443`; the URL then becomes `https://<node>.<tailnet>.ts.net:8443`.
- To turn it off, repeat the same command with `off` at the end:
  `docker exec <tailscale-container> tailscale funnel --https=443 http://127.0.0.1:8080 off`
- To clear everything: `tailscale funnel reset`.

### Option B — `TS_SERVE_CONFIG` (if your container is configured by env/compose)

Mount a JSON file into the container and set `TS_SERVE_CONFIG=/config/serve.json`. `${TS_CERT_DOMAIN}` is replaced automatically with the node's `*.ts.net` name:

```json
{
  "TCP": { "443": { "HTTPS": true } },
  "Web": {
    "${TS_CERT_DOMAIN}:443": {
      "Handlers": { "/": { "Proxy": "http://127.0.0.1:8080" } }
    }
  },
  "AllowFunnel": { "${TS_CERT_DOMAIN}:443": true }
}
```

Don't use Option A and Option B on the same node; the file in Option B overrides the CLI configuration.

### What the app receives from Funnel (verified in Tailscale's source, `ipn/ipnlocal/serve.go`)

- `X-Forwarded-For`: the **real public client IP**. Tailscale *sets* (overwrites) this header, so a client can't spoof it. The app trusts it only when the connection comes from `127.0.0.1`.
- `X-Forwarded-Proto: https` and `X-Forwarded-Host: <node>.<tailnet>.ts.net`.
- `Tailscale-Funnel-Request: ?1` on requests that came in over the public internet. Requests from your own tailnet devices carry `Tailscale-User-Login` and related headers instead.

## 4b. Test Funnel without the app (optional)

A tiny echo server stands in for the app and shows exactly which headers arrive:

```bash
# on the ZimaBoard
docker run -d --rm --name funnel-test --network host traefik/whoami --port 8080
curl -s http://127.0.0.1:8080          # works locally?
docker exec <tailscale-container> tailscale funnel --bg --https=443 http://127.0.0.1:8080
docker exec <tailscale-container> tailscale funnel status   # shows the public URL
```

Open the URL on a phone **on mobile data with Tailscale switched off**. The page should list:

- `X-Forwarded-For: <the phone's public IP>` (compare with https://ifconfig.me on the phone)
- `X-Forwarded-Proto: https`
- `Tailscale-Funnel-Request: ?1`

Open it again from a device **on** your tailnet: `Tailscale-Funnel-Request` is gone and `Tailscale-User-Login` appears instead.

Cleanup: `docker stop funnel-test`. `whoami` listens on all interfaces, so don't leave it running. You can leave Funnel on; the URL returns 502 until the real app runs on port 8080.

## 5. Check it

From a device **outside** your tailnet (e.g. a phone on mobile data with Tailscale off):

```bash
curl -sI https://<node-name>.<tailnet-name>.ts.net/
```

The first request after enabling Funnel can take a minute while the certificate is issued and DNS propagates.

### Supported browsers

State-changing requests are checked with the `Sec-Fetch-Site` header, so use a browser that sends it: Chrome 76+, Firefox 90+ or Safari 16.4+ (and the matching mobile versions). Older browsers send `Origin: null` on form posts because the app sets `Referrer-Policy: no-referrer`, and the app rejects those posts, so forms fail with 403 there. `PM_PUBLIC_URL` may be written with or without the default port (`https://host` and `https://host:443` are the same origin).

## 6. First admin and users

```bash
docker exec personal-media personal-media invite --admin
```

This prints a one-time invite URL. Open it, choose a username and password, and **save the recovery key**. Without the password or the recovery key, the data can't be recovered, not even by the admin.

Invite friends from the admin page. Each invite link is single-use and expires after 7 days.

## 7. Connect Hermes (MCP)

1. In the web UI: **Settings → Tokens → New token**. Choose the access (`read` / `read_write`), the content level (`metadata_only` / `full_text`) and optionally a tag allow-list. Copy the token (`pm_…`); it's shown only once.
2. Add it to `~/.hermes/config.yaml`:

   ```yaml
   mcp_servers:
     personal_media:
       url: "https://<node-name>.<tailnet-name>.ts.net/mcp"
       headers:
         Authorization: "Bearer pm_..."
   ```

3. In Hermes, run `/reload-mcp`, or test with `hermes mcp test`.

Treat the token like a key: it can unlock your documents within its scope. If it leaks, revoke it in the web UI.

## 7b. Share to Personal Media from a phone

- **Android (Chrome):** install the app (menu → *Install app*). Personal Media then appears in the share sheet for PDFs, images and text files. Shared files go to a review page where you can set a title and tags and press **Save**; nothing is stored before that. They wait in the server's memory only (never on disk), for 15 minutes at most, and a share is limited to `PM_MAX_UPLOAD_MB`. If your session has expired you log in first and land on the review page with the files still waiting.
- **iPhone/iPad:** iOS has no share target for web apps. Use the Shortcut in [`docs/ios-shortcut.md`](ios-shortcut.md), which uploads through `/api/upload` with a restricted token.

**SameSite note.** The Android share is a cross-site `POST` navigation into the app. Whether Chrome sends the `SameSite=Strict` session cookie with it is not guaranteed, so the flow does not depend on it. If the share arrives **without a session**, the server stages the files anonymously (at most 25 MiB, one share per client address), sets a short-lived `__Host-pm_continue` cookie (`SameSite=Lax`) holding only the staging id, and sends you through login; after login you land on the review page. If you are already logged in and the browser opens `/login` with that cookie, you are forwarded straight to the review page. Only the browser that holds the continue cookie can claim an anonymous share, and its review page warns that the files were sent before you logged in. The session cookie `__Host-pm_session` stays `Strict`: a `Lax` cookie is not sent on a cross-site `POST` either, so relaxing it would not help the share, and it would only expose pages to cross-site navigations. Do not relax it. Having to log in on each share is the accepted cost.

*Manual owner check, still outstanding:* share a file from a real Android phone with the installed app, both while logged in and after the session expired, and note here whether the session cookie arrived and what `Sec-Fetch-Site` was. This cannot be checked from the test suite. Offline, a share is simply lost (the browser shows its own error page); the service worker never intercepts the `POST`.

*Memory:* staged shares live in RAM only, counted while the upload streams in: anonymous 25 MiB in total, `PM_MAX_UPLOAD_MB` per logged-in user, and twice `PM_MAX_UPLOAD_MB` for everything together, with at most two share uploads read at a time. Keep that well below the container's `mem_limit` (1 GiB in the shipped compose file); with the default 100 MB it peaks at about 200 MB.

## 8. Backups

`/DATA/AppData/personal-media` contains only encrypted user data plus account metadata (usernames, sizes, timestamps), so you can copy it off-site as-is, e.g. with restic or rclone. For a consistent snapshot, stop the container first or back up while it's idle.

Test a restore with the recovery CLI against a **copy of the backup**, in a one-off container. It does not need the app to be running, it never writes to the backup (both databases are opened read-only, so a read-only mount or restic mount works), and it has no network:

```bash
mkdir -p /path/to/restore && chown 10001:10001 /path/to/restore
docker run --rm -it --network none \
  -v /path/to/backup:/data:ro \
  -v /path/to/restore:/out \
  personal-media recover --data /data --user NAME --out /out/NAME
```

It prompts for the account password (add `--recovery-key` to be asked for the recovery key instead) and refuses a non-empty `--out` directory. The output directory must be on the host, **outside** `/data` and outside the backed-up pool: what lands there is plaintext, so delete it when you are done, and never write it under `/data` (it would be encrypted-pool storage that the next backup picks up).

## Verify after deploy

- [ ] The login page loads over the `ts.net` URL from a phone on mobile data (Tailscale off).
- [ ] Signup with the admin invite works, and you saved the recovery key.
- [ ] Uploading a scanned German PDF gets it OCR'd, and a search for a word from it finds it.
- [ ] `docker exec personal-media sh -c 'ls /data/tmp'` prints nothing when the app is idle.
- [ ] `docker ps` shows `personal-media` as `healthy`.

## 9. Updating

```bash
git pull && docker compose up -d --build
```

Funnel needs no changes when the app updates.

## 10. Custom domain options (later)

Funnel only serves `*.ts.net` names today (checked 2026-11-16). For a domain like `docs.example.com`:

| Option | Privacy | Cost / effort | Notes |
|---|---|---|---|
| **Wait for Funnel custom domains** | ✅ TLS still terminated on the ZimaBoard | free (plan tier unknown) | In progress: feature request [#11563](https://github.com/tailscale/tailscale/issues/11563) is open, groundwork [PR #19910](https://github.com/tailscale/tailscale/pull/19910) merged May 2026, CLI [PR #19717](https://github.com/tailscale/tailscale/pull/19717) (`funnel` BYO domain) still open. Not usable yet. |
| **Redirect only** | ✅ | free, 5 min | Cloudflare redirect rule `docs.example.com → https://<node>.<tailnet>.ts.net`. The address bar shows ts.net afterwards. Use the ts.net URL directly for MCP. |
| **VPS with TLS passthrough** | ✅ VPS only forwards encrypted bytes | ~€4/month (or Oracle free tier), moderate effort | VPS runs HAProxy/nginx `stream` on :443 → ZimaBoard over Tailscale, with PROXY protocol for the client IP. The ZimaBoard then needs its own certificate (Caddy + Let's Encrypt DNS challenge via a Cloudflare API token). |
| **Pangolin / similar self-hosted tunnel** | ⚠️ TLS terminated on *your* VPS | VPS + setup | Fine if you trust the VPS, but the VPS sees decrypted traffic. |
| **Port forwarding at home** | ✅ | free, but double NAT | Only works if the Fritz!Box has a real public IPv4 (not DS-Lite). Exposes the home IP. |
| **Cloudflare Tunnel** | ❌ Cloudflare decrypts traffic | free | Rejected for this app. |

**Tailscale paid plans don't help here.** As of 2026-11-16, the plans are Personal (free, 6 users), Standard ($8/user/month: SCIM, MDM, device posture, advanced roles), Premium ($18/user/month: just-in-time access, flow logs, log streaming, regional routing) and Enterprise (custom tailnet subdomain, still under ts.net). None of them adds Funnel custom domains. Funnel visitors aren't tailnet users, so friends don't count toward the 6-user limit.
