"""MITM Proxy - Windows Service wrapper.

Install/run as a Windows service using pywin32, or run directly on Linux via systemd.

Usage (Windows, elevated cmd from the app dir):
    python -m backend.service install
    python -m backend.service start
    python -m backend.service stop
    python -m backend.service remove
    python -m backend.service debug    (run as service in console for testing)

Usage (direct, any platform):
    python -m backend.service run
"""

import asyncio
import os
import sys
import logging
import traceback

# Resolve paths BEFORE anything else - the service needs absolute paths
# because Windows services start with cwd=C:\Windows\system32
_THIS_FILE = os.path.abspath(__file__)
_BACKEND_DIR = os.path.dirname(_THIS_FILE)
_APP_DIR = os.path.dirname(_BACKEND_DIR)

# Determine data directory
if sys.platform == "win32":
    # For services running as SYSTEM, LOCALAPPDATA is C:\Windows\system32\config\...
    # Use a fixed path instead
    _DEFAULT_DATA = os.path.join(_APP_DIR, "data")
else:
    _DEFAULT_DATA = "/data"

DATA_DIR = os.environ.get("DATA_DIR", _DEFAULT_DATA)
os.makedirs(DATA_DIR, exist_ok=True)
LOG_FILE = os.path.join(DATA_DIR, "service.log")

# Set environment so backend modules find the right paths
os.environ.setdefault("DATA_DIR", DATA_DIR)
os.environ.setdefault("SCREENSHOTS_DIR", os.path.join(DATA_DIR, "screenshots"))
os.environ.setdefault("CERTS_DIR", os.path.join(_APP_DIR, "certs"))
os.environ.setdefault("PYTHONUNBUFFERED", "1")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("mitm-proxy")


def run_server():
    """Start the uvicorn servers (blocking)."""
    # Ensure the app dir is on sys.path so 'backend' package is importable
    if _APP_DIR not in sys.path:
        sys.path.insert(0, _APP_DIR)

    # Change to app dir so relative paths (e.g. ../static) work
    os.chdir(_APP_DIR)

    log.info(f"Starting MITM Proxy servers...")
    log.info(f"  App dir:  {_APP_DIR}")
    log.info(f"  Data dir: {DATA_DIR}")
    log.info(f"  Python:   {sys.executable}")
    log.info(f"  CWD:      {os.getcwd()}")

    from backend.run import main
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Shutting down (keyboard interrupt)")
    except Exception as e:
        log.exception(f"Server error: {e}")
        raise


# ── Windows Service ──────────────────────────────────────

if sys.platform == "win32":
    try:
        import win32serviceutil
        import win32service
        import win32event
        import servicemanager

        class MitmProxyService(win32serviceutil.ServiceFramework):
            _svc_name_ = "MitmProxy"
            _svc_display_name_ = "MITM Proxy"
            _svc_description_ = (
                "MITM Proxy - Remote browser login and API testing. "
                "Serves on ports 8091 (main) and 8092 (debug)."
            )
            # Tell pywin32 where to find this module
            _exe_args_ = f'"{os.path.join(_APP_DIR, "venv", "Scripts", "python.exe")}" -m backend.service'

            def __init__(self, args):
                win32serviceutil.ServiceFramework.__init__(self, args)
                self.stop_event = win32event.CreateEvent(None, 0, 0, None)

            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                log.info("Service stop requested")
                win32event.SetEvent(self.stop_event)

            def SvcDoRun(self):
                try:
                    servicemanager.LogMsg(
                        servicemanager.EVENTLOG_INFORMATION_TYPE,
                        servicemanager.PYS_SERVICE_STARTED,
                        (self._svc_name_, ""),
                    )
                except Exception:
                    pass
                log.info("Service starting via SvcDoRun")
                self._run()

            def _run(self):
                import threading

                def _server_wrapper():
                    try:
                        run_server()
                    except Exception as e:
                        log.exception(f"Server thread crashed: {e}")

                server_thread = threading.Thread(target=_server_wrapper, daemon=True)
                server_thread.start()
                log.info("Server thread started, waiting for stop signal")

                # Wait for stop event
                win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
                log.info("Service stopped")

    except ImportError:
        MitmProxyService = None


# ── CLI ──────────────────────────────────────────────────

def print_usage():
    print("MITM Proxy Service Manager")
    print()
    print("Usage: python -m backend.service <command>")
    print()
    print("Commands:")
    print("  run       Run directly in foreground (no service)")
    if sys.platform == "win32":
        print("  install   Install as Windows service")
        print("  start     Start the Windows service")
        print("  stop      Stop the Windows service")
        print("  restart   Restart the Windows service")
        print("  remove    Remove the Windows service")
        print("  status    Check service status")
        print("  debug     Run as service in console (for troubleshooting)")
    else:
        print("  install   Install systemd unit file")
        print("  start     Start via systemctl")
        print("  stop      Stop via systemctl")
        print("  restart   Restart via systemctl")
        print("  remove    Remove systemd unit file")
        print("  status    Check service status")
    print()
    print(f"  App dir:  {_APP_DIR}")
    print(f"  Data dir: {DATA_DIR}")
    print(f"  Log file: {LOG_FILE}")


def windows_service_cmd(cmd):
    """Run pywin32 service commands."""
    if MitmProxyService is None:
        print("ERROR: pywin32 is not installed.")
        print("Install it:  pip install pywin32")
        print("Then run:    python -m pywin32_postinstall -install")
        sys.exit(1)

    if cmd == "install":
        # Use HandleCommandLine which does everything properly
        sys.argv = [sys.argv[0], "--startup", "auto", "install"]
        win32serviceutil.HandleCommandLine(MitmProxyService)
        print()
        print(f"Data dir: {DATA_DIR}")
        print(f"Log file: {LOG_FILE}")
        print()
        print("Start with:  python -m backend.service start")
        print("  or:        net start MitmProxy")
        print("  or:        Start-Service MitmProxy")
    elif cmd == "debug":
        # Run the service logic in console mode for troubleshooting
        print(f"Running in debug mode (foreground)...")
        print(f"  App dir:  {_APP_DIR}")
        print(f"  Data dir: {DATA_DIR}")
        print(f"  Log file: {LOG_FILE}")
        print()
        run_server()
    elif cmd in ("remove", "start", "stop", "restart", "update"):
        sys.argv = [sys.argv[0], cmd]
        win32serviceutil.HandleCommandLine(MitmProxyService)
    elif cmd == "status":
        try:
            status = win32serviceutil.QueryServiceStatus(MitmProxyService._svc_name_)
            states = {
                win32service.SERVICE_STOPPED: "STOPPED",
                win32service.SERVICE_START_PENDING: "START_PENDING",
                win32service.SERVICE_STOP_PENDING: "STOP_PENDING",
                win32service.SERVICE_RUNNING: "RUNNING",
                win32service.SERVICE_CONTINUE_PENDING: "CONTINUE_PENDING",
                win32service.SERVICE_PAUSE_PENDING: "PAUSE_PENDING",
                win32service.SERVICE_PAUSED: "PAUSED",
            }
            state_str = states.get(status[1], f"UNKNOWN ({status[1]})")
            print(f"Service status: {state_str}")
            if state_str == "RUNNING":
                print("  http://localhost:8091  (main)")
                print("  http://localhost:8092  (debug)")
        except Exception as e:
            print(f"Service not found or error: {e}")


def linux_systemd_cmd(cmd):
    """Manage systemd service on Linux."""
    unit_name = "mitm-proxy"
    unit_path = f"/etc/systemd/system/{unit_name}.service"

    if cmd == "install":
        python_exe = sys.executable
        data_dir = os.environ.get("DATA_DIR", "/opt/mitm-proxy-data")

        unit_content = f"""[Unit]
Description=MITM Proxy - Remote browser login and API testing
After=network.target

[Service]
Type=simple
User={os.environ.get('USER', 'root')}
WorkingDirectory={_APP_DIR}
ExecStart={python_exe} -m backend.run
Environment=DATA_DIR={data_dir}
Environment=SCREENSHOTS_DIR={data_dir}/screenshots
Environment=CERTS_DIR={_APP_DIR}/certs
Environment=PYTHONUNBUFFERED=1
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
        try:
            with open(unit_path, "w") as f:
                f.write(unit_content)
            os.system("systemctl daemon-reload")
            os.system(f"systemctl enable {unit_name}")
            print(f"Service installed: {unit_path}")
            print(f"  Data dir: {data_dir}")
            print(f"  Start with: sudo systemctl start {unit_name}")
        except PermissionError:
            print(f"ERROR: Need root to write {unit_path}")
            print("Run: sudo python -m backend.service install")
            sys.exit(1)

    elif cmd == "remove":
        os.system(f"systemctl stop {unit_name} 2>/dev/null")
        os.system(f"systemctl disable {unit_name} 2>/dev/null")
        try:
            os.unlink(unit_path)
            os.system("systemctl daemon-reload")
            print("Service removed.")
        except FileNotFoundError:
            print("Service not installed.")
        except PermissionError:
            print("ERROR: Need root. Run: sudo python -m backend.service remove")

    elif cmd in ("start", "stop", "restart", "status"):
        os.system(f"systemctl {cmd} {unit_name}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)

    command = sys.argv[1].lower()

    if command == "run":
        run_server()
    elif command in ("install", "start", "stop", "restart", "remove", "status", "debug", "update"):
        if sys.platform == "win32":
            windows_service_cmd(command)
        else:
            linux_systemd_cmd(command)
    elif command in ("--help", "-h", "help"):
        print_usage()
    else:
        print(f"Unknown command: {command}")
        print_usage()
        sys.exit(1)
