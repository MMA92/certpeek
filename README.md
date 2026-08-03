# CertPeek

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

```bash
go run .
```

Copy a PEM certificate to the clipboard and CertPeek will detect it automatically.

## License

MIT