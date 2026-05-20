# Network Recon

**Network Recon** is a cross-platform toolkit for **authorized lab use** - discover live hosts on private subnets, fingerprint services, export scan results, and run safe web checks (headers, TLS, CSRF).

**Author:** Abdellah ERRAOUI

<p align="center">
  <img src="https://raw.githubusercontent.com/abdo342003/Network-Recon/main/assets/NetworkRecon.png" alt="Network Recon GUI" width="900"/>
</p>

---

## Project layout

```
NetworkRecon/
|-- README.md
|-- pyproject.toml
|-- requirements.txt
|-- install.bat / install.sh
|
|-- src/                      # Application source code
|   |-- network_recon.py      # Main GUI app
|   |-- scan_export.py        # CSV/JSON export CLI
|   |-- report_generator.py   # Markdown report CLI
|   +-- check_*.py            # Web assessment helpers
|
|-- scripts/
|   +-- install.py            # Shared venv bootstrap
|
|-- windows/                  # Windows install and packaging
|   |-- install.bat
|   |-- build_exe.bat
|   |-- build_installer.bat
|   |-- installer.iss
|   +-- network_recon.spec
|
|-- linux/                    # Linux install and packaging
|   |-- install.sh
|   +-- build_exe.sh
|
|-- assets/                   # Icons, screenshots, branding
|-- docs/                     # Lab guides and report templates
+-- .github/workflows/        # CI build and release
```

---

## Quick install

### Windows

Double-click `install.bat`, or run:

```bat
windows\install.bat
```

### Linux

```bash
chmod +x linux/install.sh install.sh
./linux/install.sh
```

Both run `scripts/install.py`, which creates `.venv`, installs dependencies, and opens the GUI.

---

## Build executables

### Windows

1. Put your icon at `assets/app.ico` (256x256 recommended).
2. Run `install.bat` once to create `.venv`.
3. Build the standalone exe:

```bat
windows\build_exe.bat
```

Output: `dist\network_recon.exe`

4. Optional - build an installer ([Inno Setup](https://jrsoftware.org/isinfo.php) required):

```bat
windows\build_installer.bat
```

Output: `Output\build_*\NetworkRecon_*_Installer.exe`

> Root-level `build_exe.bat` and `build_installer.bat` forward to the scripts in `windows/`.

### Linux

```bash
./linux/build_exe.sh
```

Output: `dist/network_recon`

---

## Command-line tools

After install (`pip install -e .` in the venv):

| Command | Module | Purpose |
|---------|--------|---------|
| `network-recon` | `src/network_recon.py` | GUI network recon |
| `scan-export` | `src/scan_export.py` | Export scan results |
| `report-generator` | `src/report_generator.py` | Aggregate checks into a report |

---

## Lab documentation

Assessment guides and templates in `docs/`:

- [assessment_checklist.md](docs/assessment_checklist.md)
- [auth_testing_methodology.md](docs/auth_testing_methodology.md)
- [account_recovery_guidance.md](docs/account_recovery_guidance.md)
- [recommended_tools.md](docs/recommended_tools.md)
- [report_template.md](docs/report_template.md)

---

## Notes

These tools are intended for **authorized lab or assessment use only**.
