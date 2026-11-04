# Running modes (what is true today)
1. **Local development**: `run.bat` + `run_worker.bat` in two windows. Stops when you close them. *Implemented.*
2. **While Windows is active**: same, plus Task Scheduler "at log on". Stops on sleep/shutdown; the worker recovers on restart (jobs persist). *Not set up.*
3. **Windows background service**: needs a service wrapper (e.g., NSSM) running the worker and uvicorn with restart-on-failure. *Not implemented or tested.*
4. **Always-on server**: Linux VM + systemd (`Restart=always`), reverse proxy with TLS, firewall, backups of `data/`. *Not implemented.*
5. **Approved production**: requires organizational authorization, per-user auth/roles, central logging/monitoring, encrypted storage, backup/restore tests, incident procedures, data-protection review. *Out of scope.*
Do not describe the project as 24/7 until a deployment in mode 3-5 has been built and tested.

## Update (2.3)
Mode 2/3 above is now implemented as a **per-user background engine** (see WINDOWS_INSTALLATION.md). A Windows service remains NOT implemented by design (per-user secrets, interactive OAuth). Untested on real Windows.
