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

//go:embed testdata/dummy_cert.pem
var dummyCertPEM string

//go:embed testdata/dummy_bundle.pem
var dummyBundlePEM string

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

// parseCertChain parses every CERTIFICATE PEM block in pemText (a bundle of
// leaf + intermediate + root certs, in any order) and returns one CertData
// per block. Non-certificate PEM blocks (e.g. private keys) are skipped.
// If pemText contains no certificate block at all, a single CertData with
// ParseError set is returned so callers can still show a "not found" state.
func parseCertChain(pemText string) []CertData {
	rest := []byte(normalizePEM(pemText))
	var out []CertData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		out = append(out, certDataFromDER(block.Bytes, pemText))
	}
	if len(out) == 0 {
		c := CertData{ParseError: "kein PEM-Zertifikat gefunden", Raw: firstNLines(pemText, 12)}
		out = append(out, c)
	}
	return out
}

// parseCert parses the first certificate found in pemText. Use
// parseCertChain to inspect a bundle containing multiple certificates.
func parseCert(pemText string) CertData {
	return parseCertChain(pemText)[0]
}

func certDataFromDER(der []byte, rawSource string) CertData {
	out := CertData{Raw: firstNLines(rawSource, 20)}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		out.ParseError = err.Error()
		out.Raw = firstNLines(rawSource, 12)
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

// chainSummaryCard renders a compact summary of one certificate in a chain,
// labelled with its position (e.g. "1/4 (Leaf)").
func chainSummaryCard(pos, total int, c CertData) fyne.CanvasObject {
	role := "Intermediate"
	if pos == 1 {
		role = "Leaf"
	} else if pos == total {
		role = "Root"
	}
	if c.ParseError != "" {
		return container.NewVBox(
			widget.NewLabelWithStyle(fmt.Sprintf("%d/%d (%s) - Fehler", pos, total, role), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			widget.NewLabel(c.ParseError),
			widget.NewSeparator(),
		)
	}
	validity := canvas.NewText("Validity: "+c.NotBefore+"  ->  "+c.NotAfter+expirySuffix(c.NotAfterTime), expiryColor(c.NotAfterTime))
	return container.NewVBox(
		widget.NewLabelWithStyle(fmt.Sprintf("%d/%d (%s)", pos, total, role), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Subject: "+c.Subject),
		widget.NewLabel("Issuer: "+c.Issuer),
		validity,
		widget.NewLabel("SHA-256: "+c.Fingerprint),
		widget.NewSeparator(),
	)
}

func watchClipboard(onChain func([]CertData)) {
	last := ""
	for {
		text, err := clipboard.ReadAll()
		if err == nil && text != last && strings.Contains(text, "-----BEGIN CERTIFICATE-----") {
			last = text
			onChain(parseCertChain(text))
		}
		time.Sleep(1 * time.Second)
	}
}

func runService(logger *syslog.Writer) {
	logger.Info("CertPeek service started")
	watchClipboard(func(chain []CertData) {
		for i, c := range chain {
			if c.ParseError == "" {
				logger.Info(fmt.Sprintf("Cert %d/%d found: Subject=%s, NotAfter=%s", i+1, len(chain), c.Subject, c.NotAfter))
			} else {
				logger.Info(fmt.Sprintf("Cert parse error: %s", c.ParseError))
			}
		}
	})
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

	chainBox := container.NewVBox()

	updateFromChain := func(chain []CertData) {
		setUI(status, parseState, subject, issuer, serial, fingerprint, pubkey, isCA, validity, dns, emails, ips, raw, preview, chain[0])
		chainBox.RemoveAll()
		if len(chain) > 1 {
			for i, c := range chain {
				chainBox.Add(chainSummaryCard(i+1, len(chain), c))
			}
		} else {
			chainBox.Add(widget.NewLabel("Nur ein Zertifikat gefunden (kein Bundle)."))
		}
		chainBox.Refresh()
	}

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
		updateFromChain(parseCertChain(text))
	})

	btnDummy := widget.NewButton("Dummy laden", func() {
		updateFromChain(parseCertChain(dummyCertPEM))
	})

	btnDummyBundle := widget.NewButton("Dummy-Kette laden", func() {
		updateFromChain(parseCertChain(dummyBundlePEM))
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
		container.NewHBox(btnRefresh, btnDummy, btnDummyBundle, btnShow, btnQuit),
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

	chainTab := container.NewVScroll(chainBox)

	tabs := container.NewAppTabs(
		container.NewTabItem("Übersicht", overview),
		container.NewTabItem("SANs", sans),
		container.NewTabItem("Kette", chainTab),
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

	go watchClipboard(func(chain []CertData) {
		fyne.Do(func() {
			updateFromChain(chain)
			if chain[0].ParseError == "" {
				content := "Ein passendes Zertifikat wurde in der Zwischenablage erkannt."
				if len(chain) > 1 {
					content = fmt.Sprintf("Eine Kette mit %d Zertifikaten wurde in der Zwischenablage erkannt.", len(chain))
				}
				a.SendNotification(&fyne.Notification{
					Title:   "Zertifikat gefunden",
					Content: content,
				})
				if prefs.BoolWithFallback(autoOpenKey, false) {
					w.Show()
					w.RequestFocus()
				}
			}
		})
	})

	w.ShowAndRun()
}
