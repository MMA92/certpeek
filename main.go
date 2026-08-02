package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/atotto/clipboard"
)

type CertData struct {
	ParseError  string
	Subject     string
	Issuer      string
	Serial      string
	NotBefore   string
	NotAfter    string
	Fingerprint string
	PubKeyAlgo  string
	IsCA        string
	DNSNames    []string
	Emails      []string
	IPs         []string
	Raw         string
}

func detectDesktop() string {
	candidates := []string{
		os.Getenv("XDG_CURRENT_DESKTOP"),
		os.Getenv("DESKTOP_SESSION"),
		os.Getenv("GDMSESSION"),
	}
	s := strings.ToLower(strings.Join(candidates, " "))
	switch {
	case strings.Contains(s, "kde"), strings.Contains(s, "plasma"):
		return "KDE"
	case strings.Contains(s, "gnome"):
		return "GNOME"
	case strings.Contains(s, "hyprland"):
		return "Hyprland"
	default:
		return "unbekannt"
	}
}

func firstNLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[:n], "\n") + "\n\n[...]"
}

func parseCert(pemText string) CertData {
	out := CertData{Raw: pemText}

	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		out.ParseError = "kein PEM-Block gefunden"
		out.Raw = firstNLines(pemText, 12)
		return out
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		out.ParseError = err.Error()
		out.Raw = firstNLines(pemText, 12)
		return out
	}

	sum := sha256.Sum256(cert.Raw)
	ips := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}

	out.Subject = cert.Subject.String()
	out.Issuer = cert.Issuer.String()
	out.Serial = cert.SerialNumber.String()
	out.NotBefore = cert.NotBefore.Format(time.RFC3339)
	out.NotAfter = cert.NotAfter.Format(time.RFC3339)
	out.Fingerprint = fmt.Sprintf("%X", sum[:])
	out.PubKeyAlgo = cert.PublicKeyAlgorithm.String()
	out.IsCA = fmt.Sprintf("%v", cert.IsCA)
	out.DNSNames = append([]string(nil), cert.DNSNames...)
	out.Emails = append([]string(nil), cert.EmailAddresses...)
	out.IPs = ips
	out.Raw = firstNLines(pemText, 20)

	return out
}

func setUI(
	status, parseState, subject, issuer, serial, validity, fingerprint, pubkey, isCA *widget.Label,
	dns, emails, ips, raw, preview *widget.Entry,
	c CertData,
) {
	if c.ParseError != "" {
		status.SetText("Clipboard enthält kein lesbares Zertifikat")
		parseState.SetText("Parse: " + c.ParseError)
	} else {
		status.SetText("PEM-Zertifikat erkannt")
		parseState.SetText("Parse: ok")
	}

	subject.SetText("Subject: " + c.Subject)
	issuer.SetText("Issuer: " + c.Issuer)
	serial.SetText("Serial: " + c.Serial)
	validity.SetText("Validity: " + c.NotBefore + "  ->  " + c.NotAfter)
	fingerprint.SetText("SHA-256: " + c.Fingerprint)
	pubkey.SetText("Public Key: " + c.PubKeyAlgo)
	isCA.SetText("Is CA: " + c.IsCA)

	dns.SetText(strings.Join(c.DNSNames, "\n"))
	emails.SetText(strings.Join(c.Emails, "\n"))
	ips.SetText(strings.Join(c.IPs, "\n"))

	raw.SetText(c.Raw)
	preview.SetText(c.Raw)
}

func buildDummyCert() string {
	return strings.TrimSpace(`
-----BEGIN CERTIFICATE-----
MIIDWTCCAkGgAwIBAgIUEXAMPLE1234567890ABCDEwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCREUxEjAQBgNVBAgMCkhlc3Nlbi1TdGFkMRIwEAYDVQQHDAlG
cmFua2Z1cnQxFDASBgNVBAoMC1Rlc3QgT3JnIEx0ZDAeFw0yNjA4MDIwMDAwMDBa
Fw0yNzA4MDIwMDAwMDBaME8xCzAJBgNVBAYTAkRFMRIwEAYDVQQIDAlIZXNzZW4t
U3RhZDESMBAGA1UEBwwJRnJhbmtmdXJ0MRQwEgYDVQQKDAtUZXN0IE9yZyBMdGQw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7EXAMPLEEXAMPLEEXAMPL
EEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE
EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE
-----END CERTIFICATE-----
`)
}

func main() {
	a := app.New()
	w := a.NewWindow("CertPeek")
	w.Resize(fyne.NewSize(1100, 800))

	status := widget.NewLabel("Warte auf PEM-Zertifikat in der Zwischenablage ...")
	desktopLabel := widget.NewLabel("Desktop: " + detectDesktop())
	parseState := widget.NewLabel("Parse: -")

	subject := widget.NewLabel("Subject: -")
	issuer := widget.NewLabel("Issuer: -")
	serial := widget.NewLabel("Serial: -")
	validity := widget.NewLabel("Validity: -")
	fingerprint := widget.NewLabel("SHA-256: -")
	pubkey := widget.NewLabel("Public Key: -")
	isCA := widget.NewLabel("Is CA: -")

	dns := widget.NewMultiLineEntry()
	dns.Disable()

	emails := widget.NewMultiLineEntry()
	emails.Disable()

	ips := widget.NewMultiLineEntry()
	ips.Disable()

	raw := widget.NewMultiLineEntry()
	raw.Disable()

	preview := widget.NewMultiLineEntry()
	preview.Disable()

	btnRefresh := widget.NewButton("Neu prüfen", func() {
		text, err := clipboard.ReadAll()
		if err != nil {
			status.SetText("Clipboard-Fehler: " + err.Error())
			return
		}
		if !strings.Contains(text, "-----BEGIN CERTIFICATE-----") {
			status.SetText("Kein PEM-Zertifikat im Clipboard")
			parseState.SetText("Parse: -")
			raw.SetText(firstNLines(text, 20))
			return
		}
		c := parseCert(text)
		setUI(status, parseState, subject, issuer, serial, validity, fingerprint, pubkey, isCA, dns, emails, ips, raw, preview, c)
		w.Show()
	})

	btnDummy := widget.NewButton("Dummy laden", func() {
		c := parseCert(buildDummyCert())
		setUI(status, parseState, subject, issuer, serial, validity, fingerprint, pubkey, isCA, dns, emails, ips, raw, preview, c)
		w.Show()
	})

	btnQuit := widget.NewButton("Beenden", func() {
		a.Quit()
	})

	top := container.NewVBox(
		desktopLabel,
		status,
		parseState,
		container.NewHBox(btnRefresh, btnDummy, btnQuit),
	)

	overview := container.NewVScroll(container.NewVBox(
		subject,
		issuer,
		serial,
		validity,
		fingerprint,
		pubkey,
		isCA,
	))

	sans := container.NewVScroll(container.NewVBox(
		widget.NewLabel("DNS SANs"),
		dns,
		widget.NewLabel("Email SANs"),
		emails,
		widget.NewLabel("IP SANs"),
		ips,
	))

	rawTab := container.NewVScroll(container.NewVBox(
		widget.NewLabel("Preview"),
		preview,
		widget.NewSeparator(),
		widget.NewLabel("Raw"),
		raw,
	))

	tabs := container.NewAppTabs(
		container.NewTabItem("Übersicht", overview),
		container.NewTabItem("SANs", sans),
		container.NewTabItem("Raw", rawTab),
	)

	w.SetContent(container.NewBorder(top, nil, nil, nil, tabs))

	w.SetCloseIntercept(func() {
		w.Hide()
	})

	if desk, ok := interface{}(a).(desktop.App); ok {
		openItem := fyne.NewMenuItem("Öffnen", func() {
			w.Show()
			w.RequestFocus()
		})
		openItem.Icon = theme.ViewFullScreenIcon()

		quitItem := fyne.NewMenuItem("Beenden", func() {
			a.Quit()
		})

		desk.SetSystemTrayIcon(theme.FyneLogo())
		desk.SetSystemTrayMenu(fyne.NewMenu("CertPeek", openItem, quitItem))
		desk.SetSystemTrayWindow(w)
	}

	w.Hide()

	go func() {
		last := ""
		for {
			text, err := clipboard.ReadAll()
			if err == nil && text != last {
				last = text
				if strings.Contains(text, "-----BEGIN CERTIFICATE-----") {
					c := parseCert(text)
					fyne.Do(func() {
						setUI(status, parseState, subject, issuer, serial, validity, fingerprint, pubkey, isCA, dns, emails, ips, raw, preview, c)
						w.Show()
						w.RequestFocus()
						a.SendNotification(&fyne.Notification{
							Title:   "Zertifikat gefunden",
							Content: "Ein passendes Zertifikat wurde in der Zwischenablage erkannt.",
						})
					})
				}
			}
			time.Sleep(1 * time.Second)
		}
	}()

	w.ShowAndRun()
}
