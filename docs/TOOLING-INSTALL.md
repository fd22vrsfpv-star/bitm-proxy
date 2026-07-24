# Operator Tooling — Install Guide

Two optional local tools that plug into `bitm-proxy`:

1. **Ollama** (+ the `gemma4:latest` model) — powers the dashboard's
   **Analyze (Ollama)** button on flow traces (local, offline LLM analysis).
2. **Burp Suite Community** + the **RagScanBridge** extension — syncs captured
   flows/findings with the built-in RAG API on `:8000`.

Both run on the **operator's machine**, alongside the app. Neither is required
for the core capture/proxy features.

> Platforms covered per section: **Windows**, **macOS**, **Linux (Kali)**.

---

## Part 1 — Ollama + `gemma4:latest`

`gemma4` is Google's open-weights model (the one the app's config comments call
out as a reasoning model). If `ollama pull gemma4:latest` ever reports the tag
doesn't exist on your Ollama version, check <https://ollama.com/library/gemma4>
or fall back to `gemma3` / `llama3.1:8b` (the shipped default).

### Windows

1. Download the installer: <https://ollama.com/download/windows> → run
   `OllamaSetup.exe`. Ollama installs as a background service and serves
   `http://localhost:11434`.
2. Open a new PowerShell and verify:
   ```powershell
   ollama --version
   ```
3. Pull the model (~ multi-GB download, one time):
   ```powershell
   ollama pull gemma4:latest
   ```
4. Smoke-test:
   ```powershell
   ollama run gemma4:latest "reply with OK"
   ```

### macOS

1. Download <https://ollama.com/download/mac> → open the `.dmg` → drag
   **Ollama** to Applications → launch it once (menu-bar icon appears; the
   server starts on `http://localhost:11434`).
   *Or via Homebrew:* `brew install --cask ollama` then launch the app.
2. Pull + test:
   ```bash
   ollama pull gemma4:latest
   ollama run gemma4:latest "reply with OK"
   ```

### Linux (Kali)

1. Install:
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ```
   The script installs a `systemd` service on Kali. Confirm it's running:
   ```bash
   systemctl status ollama --no-pager    # or: ollama serve  (foreground)
   ```
2. Pull + test:
   ```bash
   ollama pull gemma4:latest
   ollama run gemma4:latest "reply with OK"
   ```
   > No GPU in a VM? It runs on CPU — slower, but fine for testing.

### Wire it into bitm-proxy

The app runs in Docker, so it reaches Ollama **on the host**. Two knobs:

**A. Make Ollama listen on all interfaces** (so the container can reach it —
loopback-only won't be reachable from inside Docker):

| OS | How |
|---|---|
| Windows | Set a system env var `OLLAMA_HOST=0.0.0.0`, then restart Ollama (`setx OLLAMA_HOST 0.0.0.0` and re-launch, or set it under System → Environment Variables). |
| macOS | `launchctl setenv OLLAMA_HOST 0.0.0.0` then quit & relaunch the app. |
| Linux (Kali) | `sudo systemctl edit ollama` → add under `[Service]`: `Environment="OLLAMA_HOST=0.0.0.0"` → `sudo systemctl restart ollama`. |

**B. Point the app at the host:**

- **Windows / macOS (Docker Desktop):** the default `ollama_url` of
  `http://host.docker.internal:11434` already resolves to the host — no change
  needed.
- **Linux (Kali, native Docker):** `host.docker.internal` is **not** mapped by
  default. Either add it to the `app` service in `docker-compose.yml`:
  ```yaml
      extra_hosts:
        - "host.docker.internal:host-gateway"
  ```
  (then `docker compose up -d`), **or** set `ollama_url` to the docker bridge
  gateway, typically `http://172.17.0.1:11434`.

**C. Turn it on in the dashboard** — **Settings → Integrations**
(Flow / RAG / Ollama):

| Setting | Value |
|---|---|
| `ollama_enabled` | `true` |
| `ollama_model` | `gemma4:latest` |
| `ollama_url` | `http://host.docker.internal:11434` (Desktop) / `http://172.17.0.1:11434` (Kali) |
| `ollama_think` | **`false`** (keep default) |

> **Why `ollama_think=false`:** `gemma4` is a reasoning model. With thinking
> on and a `num_predict` cap, it can spend the whole token budget on
> chain-of-thought and return **empty** analysis. `false` = answer directly
> (the app auto-retries without the param if a model rejects it).

**Verify end-to-end:** open a flow trace (or a 🧪 test trace) in **Flow Trace**
and click **Analyze (Ollama)**. First run is slow while the model loads into
memory (`ollama_keep_alive=30m` keeps it warm after that).

---

## Part 2 — Burp Suite Community Edition

### Windows

1. Download: <https://portswigger.net/burp/communitydownload> → run the
   `.exe` (bundles its own Java runtime).
2. Launch **Burp Suite Community** → **Temporary project** → **Use Burp
   defaults** → **Start Burp**.

### macOS

1. Same download page → grab the `.dmg` for your chip (**Apple Silicon** or
   **Intel**) → install → launch.
2. If Gatekeeper blocks it: **System Settings → Privacy & Security → Open
   Anyway**.

### Linux (Kali)

Kali usually ships it — check first:
```bash
which burpsuite || sudo apt update && sudo apt install -y burpsuite
```
Launch from the menu (**Applications → Web Application Analysis → burpsuite**)
or run `burpsuite`. For the newest version instead of the packaged one, use the
PortSwigger installer:
```bash
chmod +x burpsuite_community_linux_*.sh && ./burpsuite_community_linux_*.sh
```

---

## Part 3 — The RagScanBridge plugin (into Burp)

`burp-extension/RagScanBridge.py` is a **Jython (Python) Burp extension** that
syncs findings with bitm-proxy's built-in RAG API on `:8000`.

> **Run Burp on the same host as the app.** The RAG API is published
> loopback-only (`127.0.0.1:8000`), so the plugin must reach `localhost:8000`.
> Burp on a different machine can't hit it without an SSH tunnel to `:8000`.

### Step 1 — Give Burp a Python engine (Jython)

Burp runs Python extensions via Jython, which isn't bundled.

1. Download **`jython-standalone-2.7.3.jar`** (or newer 2.7.x) from
   <https://www.jython.org/download> (or Maven Central: `org.python:jython-standalone`).
2. In Burp: **Extensions → Extensions settings → Python environment**
   *(older Burp: **Extender → Options → Python Environment**)* → set
   **"Location of Jython standalone JAR file"** to the file you downloaded.

### Step 2 — Get the extension file

- **Easiest:** in the dashboard, **Settings → Integrations →
  "Download Burp extension"** (serves `RagScanBridge.py`).
- **Or** copy `burp-extension/RagScanBridge.py` straight from the repo.

### Step 3 — Load it

1. Burp: **Extensions → Installed → Add**.
2. **Extension type: Python** → **Select file** → pick `RagScanBridge.py` →
   **Next** → **Close**. It should load with no errors in the **Output** tab.
3. Open the extension's own tab and set the **API URL** to bitm-proxy's RAG
   API: **`http://localhost:8000`** (plain HTTP — the RAG API doesn't do TLS).

### Notes / limits

- **Community vs Pro:** the extension loads and its finding-sync UI works in
  Community. Burp's **active Scanner is Pro-only**, so scanner-driven flows
  aren't available in Community, but pushing/pulling findings against the RAG
  API on `:8000` works regardless.
- Captured bitm-proxy flows auto-surface as RAG findings (`backend/rag_bridge.py`),
  so once connected the extension can pull them into Burp.
- The extension's SOCKS **tunnel-node** and **Follow-Up Queue** tabs call
  RAG-Scan-Stack-specific endpoints bitm-proxy doesn't implement — they'll just
  log a connection error, not crash anything.
