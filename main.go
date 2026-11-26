package main

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"flag"
	"fmt"
	"image/color"
	"log/syslog"
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/atotto/clipboard"
)

//go:embed icon.png
var iconBytes []byte

// expiryWarnDays defines how many days before expiry a certificate is
// considered "expiring soon" and highlighted in orange.
const expiryWarnDays = 30

type CertData struct {
	ParseError   string
	Subject      string
	Issuer       string
	Serial       string
	NotBefore    string
	NotAfter     string
	NotAfterTime time.Time
	Fingerprint  string
	PubKeyAlgo   string
	IsCA         string
	DNSNames     []string
	Emails       []string
	IPs          []string
	Raw          string
}

func loadIcon() fyne.Resource {
	return fyne.NewStaticResource("icon.png", iconBytes)
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

// normalizePEM repairs two common copy-paste artifacts that break pem.Decode's
// strict line-based parsing: literal "\n"/"\r\n" escape sequences (e.g. pasted
// from a .env/JSON/YAML file instead of a raw .pem) and per-line indentation
// (e.g. pasted from an indented config block).
func normalizePEM(s string) string {
	if !strings.Contains(s, "\n") && strings.Contains(s, "\\n") {
		s = strings.ReplaceAll(s, "\\r\\n", "\n")
		s = strings.ReplaceAll(s, "\\n", "\n")
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	return strings.Join(lines, "\n")
}

func parseCert(pemText string) CertData {
	out := CertData{Raw: pemText}

	block, _ := pem.Decode([]byte(normalizePEM(pemText)))
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
	out.NotAfterTime = cert.NotAfter
	out.Fingerprint = fmt.Sprintf("%X", sum[:])
	out.PubKeyAlgo = cert.PublicKeyAlgorithm.String()
	out.IsCA = fmt.Sprintf("%v", cert.IsCA)
	out.DNSNames = append([]string(nil), cert.DNSNames...)
	out.Emails = append([]string(nil), cert.EmailAddresses...)
	out.IPs = ips
	out.Raw = firstNLines(pemText, 20)

	return out
}

// expiryColor determines the highlight color for a certificate's validity
// based on its NotAfter timestamp: red if expired, orange if expiring soon
// (within expiryWarnDays), and the default theme color otherwise.
func expiryColor(notAfter time.Time) color.Color {
	if notAfter.IsZero() {
		return theme.Color(theme.ColorNameForeground)
	}
	remaining := time.Until(notAfter)
	switch {
	case remaining < 0:
		return theme.Color(theme.ColorNameError)
	case remaining < expiryWarnDays*24*time.Hour:
		return theme.Color(theme.ColorNameWarning)
	default:
		return theme.Color(theme.ColorNameForeground)
	}
}

// expirySuffix returns a short human-readable hint appended to the validity
// text, e.g. "(abgelaufen)" or "(läuft in 5 Tagen ab)".
func expirySuffix(notAfter time.Time) string {
	if notAfter.IsZero() {
		return ""
	}
	remaining := time.Until(notAfter)
	days := int(remaining.Hours() / 24)
	switch {
	case remaining < 0:
		return fmt.Sprintf("  [ABGELAUFEN seit %d Tagen]", -days)
	case remaining < expiryWarnDays*24*time.Hour:
		return fmt.Sprintf("  [läuft in %d Tagen ab]", days)
	default:
		return ""
	}
}

func setUI(
	status, parseState, subject, issuer, serial, fingerprint, pubkey, isCA *widget.Label,
	validity *canvas.Text,
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
	validity.Text = "Validity: " + c.NotBefore + "  ->  " + c.NotAfter + expirySuffix(c.NotAfterTime)
	validity.Color = expiryColor(c.NotAfterTime)
	validity.Refresh()
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
MIID0TCCArmgAwIBAgIUGeYbTE7imbaPmlrvgF2X9PeVTkgwDQYJKoZIhvcNAQEL
BQAwaDELMAkGA1UEBhMCREUxDzANBgNVBAgMBkhlc3NlbjESMBAGA1UEBwwJRnJh
bmtmdXJ0MRUwEwYDVQQKDAxUZXN0IE9yZyBMdGQxHTAbBgNVBAMMFGR1bW15LmNl
cnRwZWVrLmxvY2FsMB4XDTI2MTEyNjA4MjU0MloXDTI3MTEyNjA4MjU0MlowaDEL
MAkGA1UEBhMCREUxDzANBgNVBAgMBkhlc3NlbjESMBAGA1UEBwwJRnJhbmtmdXJ0
MRUwEwYDVQQKDAxUZXN0IE9yZyBMdGQxHTAbBgNVBAMMFGR1bW15LmNlcnRwZWVr
LmxvY2FsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsXVTx3bnjzaB
8e3Vlj+6SEZBN2YDnfAO4aAZHFfiiL8S433eeFvOsCAGEpNVE8Nyo8Ii5VtWwYYt
MA67FC5y1ywMjqGvRwJ1/N/8IzivSlsvuzgxyrbkuXDbPfse2tGNvT5v3MW2zSbt
xt/AB8PN+g5r0Sh4b8rUsglyE5GBDZmdWkEclA3cuwfYkMqc3Nnd4cTfpkIu8I5y
MI4dvfbnkSNs5M3Hrjv5Wt65Kt3dcGsdVIPToBzJJVMGEg2K1VgAkhmRzwkn6nN7
Mzsed8B6FxY4VlH6KYYk7Km7CqHg3XJNHOdGRuLiDUQxKg6/P9cJeNknfEnVrcoi
zuJ+mgBRJQIDAQABo3MwcTAdBgNVHQ4EFgQU/JQif5j7LvFnRvr51OwRg8LGk5gw
DwYDVR0TAQH/BAUwAwEB/zA/BgNVHREEODA2ghRkdW1teS5jZXJ0cGVlay5sb2Nh
bIIYd3d3LmR1bW15LmNlcnRwZWVrLmxvY2FshwR/AAABMA0GCSqGSIb3DQEBCwUA
A4IBAQAwt3xiJS6hn1znV56/cwfBbJUAQDBbEMJSlj7yh1awprf7aHsgy7/k9IPv
yzuLk8sQIksi6JmQe/aexUr9iBVWJb+r2JMa76/D1v/m6nmWST1DlvR1IdsENEre
T9mWkOxYHqI/kUjgqwaK4h4NFmYWBi/gU5pBwlv7sFbb7qOb39yv7Z6v8M9dawdH
20SR0QBqsLGxWOadfNZkFQTgia1CvjwXToENBSWmIP6ptZMPxKIpXO4qOFhP1Fp4
Xfx3jb4co1AOKUVxtN0gbBz7IihKnmAYxBGuBEoi8ufLkUEqAYyQWBSmWXQPD+S7
1r7pvw6OEKTpzErt6TJNYsOOp/JY
-----END CERTIFICATE-----
`)
}

func runService(logger *syslog.Writer) {
	logger.Info("CertPeek service started")
	last := ""
	for {
		text, err := clipboard.ReadAll()
		if err == nil && text != last && strings.Contains(text, "-----BEGIN CERTIFICATE-----") {
			last = text
			c := parseCert(text)
			if c.ParseError == "" {
				logger.Info(fmt.Sprintf("Cert found: Subject=%s, NotAfter=%s", c.Subject, c.NotAfter))
			} else {
				logger.Info(fmt.Sprintf("Cert parse error: %s", c.ParseError))
			}
		}
		time.Sleep(1 * time.Second)
	}
}

func main() {
	serviceMode := flag.Bool("service", false, "run as background service (syslog output)")
	flag.Parse()

	if *serviceMode {
		logger, err := syslog.New(syslog.LOG_INFO, "certpeek")
		if err != nil {
			fmt.Fprintf(os.Stderr, "syslog error: %v\n", err)
			os.Exit(1)
		}
		defer logger.Close()
		runService(logger)
		return
	}

	a := app.NewWithID("com.example.certpeek")
	icon := loadIcon()
	a.SetIcon(icon)

	prefs := a.Preferences()
	autoOpenKey := "auto_open"

	w := a.NewWindow("CertPeek")
	w.SetIcon(icon)
	w.Resize(fyne.NewSize(1100, 800))

	status := widget.NewLabel("Warte auf PEM-Zertifikat in der Zwischenablage ...")
	desktopLabel := widget.NewLabel("Desktop: " + detectDesktop())
	parseState := widget.NewLabel("Parse: -")

	subject := widget.NewLabel("Subject: -")
	issuer := widget.NewLabel("Issuer: -")
	serial := widget.NewLabel("Serial: -")
	validity := canvas.NewText("Validity: -", theme.Color(theme.ColorNameForeground))
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

	autoOpen := widget.NewCheck("Auto öffnen bei erkanntem Zertifikat", func(v bool) {
		prefs.SetBool(autoOpenKey, v)
	})
	autoOpen.SetChecked(prefs.BoolWithFallback(autoOpenKey, false))

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
		setUI(status, parseState, subject, issuer, serial, fingerprint, pubkey, isCA, validity, dns, emails, ips, raw, preview, c)
	})

	btnDummy := widget.NewButton("Dummy laden", func() {
		c := parseCert(buildDummyCert())
		setUI(status, parseState, subject, issuer, serial, fingerprint, pubkey, isCA, validity, dns, emails, ips, raw, preview, c)
	})

	btnQuit := widget.NewButton("Beenden", func() {
		a.Quit()
	})

	btnShow := widget.NewButton("Öffnen", func() {
		w.Show()
		w.RequestFocus()
	})

	settingsTab := container.NewVBox(
		autoOpen,
		widget.NewLabel("Die Einstellung wird automatisch gespeichert."),
	)

	top := container.NewVBox(
		desktopLabel,
		status,
		parseState,
		container.NewHBox(btnRefresh, btnDummy, btnShow, btnQuit),
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
		container.NewTabItem("Einstellungen", settingsTab),
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

		desk.SetSystemTrayIcon(icon)
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
					setUI(status, parseState, subject, issuer, serial, fingerprint, pubkey, isCA, validity, dns, emails, ips, raw, preview, c)
					if c.ParseError == "" {
						a.SendNotification(&fyne.Notification{
							Title:   "Zertifikat gefunden",
							Content: "Ein passendes Zertifikat wurde in der Zwischenablage erkannt.",
						})
						if prefs.BoolWithFallback(autoOpenKey, false) {
							w.Show()
							w.RequestFocus()
						}
					}
				})
				}
			}
			time.Sleep(1 * time.Second)
		}
	}()

	w.ShowAndRun()
}
