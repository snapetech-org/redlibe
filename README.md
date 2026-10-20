# redlib-extended

> A fork of [Redlib](https://github.com/redlib-org/redlib) extending the privacy-first Reddit front-end with user authentication, OAuth, a REST API, voting, SSH session import, and more.

**Full feature list and details:** see [features.md](features.md).  
**Feature gap vs full Reddit clients (Sync/Hydra) and prioritized backlog:** see [docs/FEATURE_GAP_BACKLOG.md](docs/FEATURE_GAP_BACKLOG.md).

---

## Overview

**redlib-extended** builds on top of Redlib's fast, private, Rust-based Reddit front-end to add first-class support for authenticated Reddit accounts. The goal is to preserve everything that makes Redlib great — no tracking, no ads, no bloat — while enabling users to interact with Reddit through their own accounts when they choose to.

---

## Extended Features

### User Authentication
- Reddit OAuth 2.0 login flow (authorization code grant)
- **SSH session import** — log in without OAuth by importing your Reddit session from a Firefox or LibreWolf profile on a remote Linux host (see [SSH session import](#ssh-session-import) below)
- Secure session management via signed, server-side cookies
- Login / logout UI integrated into the existing Redlib interface
- Optional: anonymous browsing remains fully supported without an account

### REST API
- JSON API layer over the existing Redlib rendering logic
- Endpoints mirror standard Reddit API paths (`/r/{sub}`, `/u/{user}`, `/comments/{id}`, etc.)
- Bearer token auth for programmatic access
- Rate limiting and per-token scoping

### OAuth Integration
- Register a Reddit OAuth app and configure client ID/secret via environment variables or config file
- Scopes: `identity`, `read`, `vote`, `submit`, `subscribe`, `history`
- Token refresh handled transparently on behalf of the user

### Voting
- Upvote / downvote posts and comments through the proxied server
- Vote state reflected in the UI (no direct browser-to-Reddit requests)
- Requires a logged-in session

### Inbox, private messages, and compose
- **Inbox page** (`/inbox`) for inbox / unread / sent tabs
- **Private messages** — compose and send from Redlib UI (`/inbox/compose`)
- **Mark read / mark all read** actions for message workflows
- Responsive message cards and improved mobile-friendly inbox layout

### UI/UX and theme system improvements
- Refined inbox/message/compose surfaces with responsive card layouts
- Improved navbar and search responsiveness on smaller screens
- Upgraded settings UX with searchable controls, better form layout, and visual theme previews
- Expanded preset theme catalog (42 total themes), including more medium-dark, brown, sepia, olive, and light palettes

### SSH session import

You can sign in by importing the Reddit session cookie from a browser on a machine you can SSH into. No Reddit OAuth app is required.

**Requirements**

- **Remote host (the machine you SSH into):**
  - **Linux** — Supported paths and the import script are Linux-only.
  - **SSH** — `sshd` must be running; the redlib-extended server connects to this host via SSH.
  - **Browser** — One of:
    - **LibreWolf** — profile at `~/.librewolf` (default)
    - **Firefox** — profile at `~/.mozilla/firefox`
  - **sqlite3** — installed on the remote host (used to read `cookies.sqlite`).
  - You must have logged into Reddit in that browser so the `token_v2` cookie exists.

- **Server (where redlib-extended runs):** The image includes `openssh-client` and `sshpass` for key and password auth.

**How to use**

1. Open the instance login page and choose **Import session via SSH**.
2. Enter **SSH host** and **SSH user**.
3. Provide at least one of:
   - **SSH private key** — paste your private key into the textarea, or
   - **SSH password** — enter the SSH password (server uses `sshpass`).
4. Select **LibreWolf** or **Firefox** (profile paths above).
5. Click **Import session**. The server runs a one-off script on the remote host to read `token_v2` from the browser’s `cookies.sqlite`, then creates a session for you.

Keys and passwords are used only for that request and are not stored. See [features.md](features.md) for security notes and full details.

**SSH import without pasting a key (e.g. k3s on the same host)**  
If redlib-extended runs in a pod on a host you already SSH into (e.g. kspld0), you can use a key that lives in the cluster so users don’t paste anything: (1) Add the **public** key to the SSH host (e.g. `~/.ssh/authorized_keys` for `keith@kspld0`). (2) Create a Kubernetes secret from the **private** key:

```bash
kubectl create secret generic redlibe-ssh-key -n redlibe --from-file=ssh-privatekey=/home/keith/.ssh/id_ed25519
```

(3) The deployment mounts this at `/run/secrets/redlibe-ssh-key/ssh-privatekey` and sets `REDLIB_SSH_HOST`, `REDLIB_SSH_USER`, `REDLIB_SSH_KEY`. On the login form, leave the key field empty and (if needed) enter only host/user; the app uses the mounted key to log in.

### Comment reply and custom feeds
- **Reply to comments and posts** — When logged in, use **Reply** on any comment or **Add a comment** on a post. Your reply is submitted to Reddit via the API (requires `submit` scope; re-login if you signed in before this was added).
- **Custom feeds** — Create named multireddits (e.g. “Tech” = rust + programming + linux) from **Feeds → Manage feeds** or `/feeds`. They appear in the Feeds menu and at `/feed/YourFeedName`. Stored in a cookie; create, edit, and delete from the manage page.

### Planned / In Progress (see [feature gap backlog](docs/FEATURE_GAP_BACKLOG.md))
- **Must-have:** Post submission (text/link/image), edit/delete own content, saved/upvoted/hidden listing pages, Reddit subscriptions in Feeds
- **Nice-to-have:** Multiple accounts, media download/share, custom theme editor
- Subreddit subscription management (API done; UX to pull Reddit subs into nav), user flair display, moderation queue (basic)

---

## Architecture

redlib-extended is written in Rust and inherits Redlib's stack:

| Layer | Technology |
|---|---|
| Web framework | Hyper 0.14 |
| Templating | Askama |
| Async runtime | Tokio |
| TLS | Rustls / hyper-rustls |
| Serialization | Serde / serde_json |
| Session storage | Server-side (configurable backend) |
| OAuth tokens | Encrypted at rest, stored server-side |

---

## Getting Started

### Prerequisites

- Rust 1.81+
- For OAuth login: a Reddit OAuth application ([create one here](https://www.reddit.com/prefs/apps)). Optional if you use [SSH session import](#ssh-session-import) only.

### Environment Variables

```env
# Inherited from Redlib
REDLIB_DEFAULT_THEME=system
REDLIB_DEFAULT_SHOW_NSFW=false

# Extended: OAuth / Auth
REDLIB_OAUTH_CLIENT_ID=your_client_id
REDLIB_OAUTH_CLIENT_SECRET=your_client_secret
REDLIB_OAUTH_REDIRECT_URI=https://your-instance.example.com/auth/callback
REDLIB_SESSION_SECRET=a_long_random_secret_key

# Extended: API
REDLIB_API_ENABLED=true
REDLIB_API_RATE_LIMIT=100   # requests per minute per token
```

### Build & Run

```bash
git clone https://github.com/your-org/redlib-extended
cd redlib-extended
cargo build --release
./target/release/redlib
```

### Docker

```bash
docker compose up -d
```

### Build image used by the `redlibe` deployment (local source build)

This repo includes a deploy-oriented image build script that compiles the local Rust source and produces `redlibe:latest`:

```bash
./build-docker.sh
```

Notes:
- Uses `Dockerfile.ubuntu` (builds the local source in a Rust builder stage, then copies the binary into an Ubuntu runtime image).
- Uses `--network=host` to avoid DNS/index resolution issues during crate downloads on some home-lab setups.

### k3s rollout for `redlibe.home` (host-local image, `imagePullPolicy: IfNotPresent`)

If your `redlibe` deployment uses `redlibe:latest` with `IfNotPresent`, restarting the deployment is not enough. You must import the rebuilt image into k3s containerd on the node first.

Example flow on host `kspld0`:

```bash
# Build on the node (from this repo)
cd /home/keith/Documents/code/redlib-extended
./build-docker.sh

# Import Docker image into k3s containerd
docker save redlibe:latest | sudo k3s ctr images import -

# Roll the deployment
KUBECONFIG=~/.kube/config kubectl -n redlibe rollout restart deployment/redlibe
KUBECONFIG=~/.kube/config kubectl -n redlibe rollout status deployment/redlibe
```

---

## API Reference

All API endpoints are prefixed with `/api/v1`.

| Method | Path | Auth Required | Description |
|---|---|---|---|
| GET | `/api/v1/r/{sub}` | No | Subreddit posts |
| GET | `/api/v1/r/{sub}/comments/{id}` | No | Post comments |
| GET | `/api/v1/u/{user}` | No | User profile |
| POST | `/api/v1/vote` | Yes | Vote on a post or comment |
| GET | `/api/v1/me` | Yes | Current user info |
| POST | `/api/v1/subscribe` | Yes | Subscribe/unsubscribe from a sub |

Full OpenAPI spec: `docs/openapi.yaml` *(in progress)*

---

## Auth Flow

```
User clicks "Login"
  → Redirected to Reddit OAuth consent screen
  → Reddit redirects back to /auth/callback with code
  → Server exchanges code for access + refresh tokens
  → Tokens stored server-side, session cookie issued to browser
  → All subsequent Reddit API calls made server-side using stored tokens
```

No Reddit tokens are ever sent to the browser.

---

## Privacy Model

redlib-extended preserves Redlib's core privacy guarantees:

- All requests to Reddit are made **server-side**
- User IP addresses are **never** forwarded to Reddit
- No third-party JavaScript or tracking pixels
- OAuth tokens are stored **server-side only**, never in the browser
- Anonymous browsing requires **no account** and remains fully private

When a user logs in, their Reddit identity is used only for actions they explicitly take (voting, subscribing, etc.). The server does not log or retain activity history.

---

## Configuration

Full configuration reference: see `contrib/` and `redlib.toml.example` *(coming soon)*.

---

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for new behavior
4. Submit a pull request

Please read `CONTRIBUTING.md` before opening a PR.

---

## License

AGPL-3.0-only — same as upstream Redlib.

---

## Credits

- Upstream [Redlib](https://github.com/redlib-org/redlib) by Matthew Esposito and contributors
- Original [Libreddit](https://github.com/libreddit/libreddit) by spikecodes

## Security scanning

Run scripts/security-scan-local.sh for local Semgrep Community Edition and applicable Trivy scans. Public GitHub Actions workflows run these scans on changes and weekly, alongside any existing CodeQL workflow. See docs/security-scanning.md for offline setup and updates. Run scripts/install-security-hooks.sh once to enable the staged Semgrep pre-commit hook.
