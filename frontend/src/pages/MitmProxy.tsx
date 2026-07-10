import { useEffect, useState } from "react";
import BrowserAuth from "../components/BrowserAuth";
import { apiFetch } from "../api/client";

export default function MitmProxy() {
  const [loginUrl, setLoginUrl] = useState("");
  const [browserOpen, setBrowserOpen] = useState(false);
  const [error, setError] = useState("");
  const [privateMode, setPrivateMode] = useState(false);
  // Chrome mode: URL ?chrome=... wins; otherwise cfg.browser_chrome; default "none".
  const [chromeEffective, setChromeEffective] =
    useState<"full" | "minimal" | "none">("none");

  const params = new URLSearchParams(window.location.search);
  const isPopup = params.has("auto");
  const isPrivateParam = params.has("private");
  const isStealth = params.has("stealth");
  const urlOverride = params.get("url") || "";
  const chromeParam = params.get("chrome");
  const normalizeChrome = (v: string | null | undefined): "full" | "minimal" | "none" => {
    const s = (v || "").toLowerCase();
    // Default is "none" now — matches backend shared.py browser_chrome default.
    if (s === "full") return "full";
    if (s === "minimal") return "minimal";
    return "none";
  };

  // Always fetch config and auto-launch with default_login_url (or ?url=...)
  useEffect(() => {
    apiFetch<Record<string, any>>("/api/config").then((cfg) => {
      const url = urlOverride || cfg.default_login_url;
      // Private if URL param says so OR config toggle is on
      setPrivateMode(isPrivateParam || !!cfg.private_mode);
      setChromeEffective(chromeParam ? normalizeChrome(chromeParam) : normalizeChrome(cfg.browser_chrome));
      if (url) {
        setLoginUrl(url);
        setBrowserOpen(true);
      } else {
        setError("No default login URL configured. Set one in the Debug Dashboard (:8092).");
      }
    }).catch(() => {
      setError("Failed to load config. Is the server running?");
    });
  }, []);

  if (error) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="bg-gray-900 rounded-lg p-8 border border-gray-800 max-w-md text-center">
          <p className="text-gray-400 mb-4">{error}</p>
          <a href="http://localhost:8092" target="_blank" rel="noreferrer"
            className="text-blue-400 underline hover:text-blue-300 text-sm">
            Open Debug Dashboard
          </a>
        </div>
      </div>
    );
  }

  if (!browserOpen) {
    return (
      <div className="flex items-center justify-center h-screen text-gray-500">Loading...</div>
    );
  }

  return (
    <BrowserAuth
      loginUrl={loginUrl}
      onClose={() => {
        if (isPopup) { window.close(); return; }
        setBrowserOpen(false);
        // Re-fetch config in case URL changed, then relaunch
        apiFetch<Record<string, any>>("/api/config").then((cfg) => {
          const url = urlOverride || cfg.default_login_url;
          setPrivateMode(isPrivateParam || !!cfg.private_mode);
          setChromeEffective(chromeParam ? normalizeChrome(chromeParam) : normalizeChrome(cfg.browser_chrome));
          if (url) { setLoginUrl(url); setBrowserOpen(true); }
          else setError("No default login URL configured. Set one in the Debug Dashboard (:8092).");
        }).catch(() => setError("Failed to load config."));
      }}
      showCapture={false}
      privateMode={privateMode}
      stealth={isStealth}
      chrome={chromeEffective}
    />
  );
}
