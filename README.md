# CertPeek

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

CertPeek is a small Go desktop app that watches your clipboard for PEM-encoded X.509 certificates and displays certificate details in a GUI.

## Features

- Clipboard monitoring
- PEM certificate detection
- X.509 certificate analysis
- Tray icon support
- Optional auto-open behavior
- Custom app icon

## Requirements

- Go 1.20+
- Fyne GUI toolkit
- Linux desktop environment with tray/notification support

## Usage

### Desktop App (GUI)

```bash
go run .
```

Copy a PEM certificate to the clipboard and CertPeek will detect it automatically.

### Background Service

Build and install to `~/.local/bin/`:

```bash
curl -L https://github.com/YOUR_REPO/certpeek/releases/download/latest/certpeek -o ~/.local/bin/certpeek && chmod +x ~/.local/bin/certpeek
```

Install systemd service:

```bash
mkdir -p ~/.config/systemd/user
curl -L https://github.com/YOUR_REPO/certpeek/releases/download/latest/certpeek.service -o ~/.config/systemd/user/certpeek.service
systemctl --user daemon-reload
systemctl --user enable --now certpeek
journalctl --user -u certpeek -f
```

The service watches your clipboard and logs certificate details to `journalctl`.

## License

Licensed under the [MIT License](LICENSE).