package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
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
	"fyne.io/fyne/v2/layout"
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
	ParseError      string
	Subject         string
	Issuer          string
	Serial          string
	Version         string
	NotBefore       string
	NotAfter        string
	NotAfterTime    time.Time
	SigAlgo         string
	Fingerprint     string // SHA-256
	FingerprintSHA1 string
	PubKeyAlgo      string // e.g. "RSA 2048 bit" or "ECDSA P-256"
	IsCA            string
	DNSNames        []string
	Emails          []string
	IPs             []string
	Raw             string
	// ShortID is a quick visual identifier built from the PEM body's
	// base64 text: the first 8 and last 4 characters, e.g.
	// "MIID0TCC...p/JY". Useful for eyeballing
	// which certificate is which in a bundle without comparing fingerprints.
	ShortID string

	// cert holds the parsed certificate for chain-link verification
	// (CheckSignatureFrom). Not used for display.
	cert *x509.Certificate
}

// commonName extracts the CN= value from a Subject/Issuer string, falling
// back to the full string if no CN is present (e.g. empty subject).
func commonName(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "CN="); ok {
			return v
		}
	}
	return dn
}

// shortID re-encodes der as PEM to get its base64 body text, then returns
// the first 8 and last 4 characters joined by "...", e.g.
// "MIID0TCC...p/JY".
func shortID(der []byte) string {
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	lines := strings.Split(strings.TrimSpace(string(block)), "\n")
	if len(lines) < 3 {
		return ""
	}
	body := strings.Join(lines[1:len(lines)-1], "")
	if len(body) <= 16 {
		return body
	}
	return body[:8] + "..." + body[len(body)-4:]
}

// pubKeyDescription returns a human-readable public key summary like
// "RSA 2048 bit" or "ECDSA P-256", matching common certificate viewers.
func pubKeyDescription(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bit", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + pub.Curve.Params().Name
	default:
		return cert.PublicKeyAlgorithm.String()
	}
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

	sum256 := sha256.Sum256(cert.Raw)
	sum1 := sha1.Sum(cert.Raw)
	ips := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}

	out.Subject = cert.Subject.String()
	out.Issuer = cert.Issuer.String()
	out.Serial = fmt.Sprintf("%X", cert.SerialNumber)
	out.Version = fmt.Sprintf("V%d", cert.Version)
	out.NotBefore = cert.NotBefore.Format(time.RFC1123Z)
	out.NotAfter = cert.NotAfter.Format(time.RFC1123Z)
	out.NotAfterTime = cert.NotAfter
	out.SigAlgo = cert.SignatureAlgorithm.String()
	out.Fingerprint = fmt.Sprintf("%X", sum256[:])
	out.FingerprintSHA1 = fmt.Sprintf("%X", sum1[:])
	out.PubKeyAlgo = pubKeyDescription(cert)
	out.IsCA = fmt.Sprintf("%v", cert.IsCA)
	out.DNSNames = append([]string(nil), cert.DNSNames...)
	out.Emails = append([]string(nil), cert.EmailAddresses...)
	out.IPs = ips
	out.cert = cert
	out.ShortID = shortID(der)

	return out
}

// chainLinkStatus describes how certificate chain[i] relates to chain[i+1]
// (its presumed issuer in the bundle), or whether it is a self-signed root.
func chainLinkStatus(chain []CertData, i int) string {
	c := chain[i]
	if c.cert == nil {
		return ""
	}
	if i == len(chain)-1 {
		if c.cert.CheckSignatureFrom(c.cert) == nil {
			return "✓ selbstsigniert (Root)"
		}
		return "⚠ nicht selbstsigniert - Root fehlt in der Kette"
	}
	next := chain[i+1]
	if next.cert == nil {
		return "⚠ nächstes Zertifikat fehlerhaft"
	}
	if c.cert.CheckSignatureFrom(next.cert) == nil {
		return "✓ signiert von #" + fmt.Sprint(i+2) + " (" + next.Subject + ")"
	}
	return "✗ NICHT signiert von #" + fmt.Sprint(i+2) + " - Kette gebrochen"
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

// badge renders a small colored pill label, e.g. for "Valid"/"Expired".
func badge(text string, bg color.Color) fyne.CanvasObject {
	rect := canvas.NewRectangle(bg)
	rect.CornerRadius = 8
	lbl := widget.NewLabelWithStyle(text, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	return container.NewStack(rect, container.NewPadded(lbl))
}

// kvFormRow returns the (label, content) pair for one row of a form-layout
// metaRow renders a small italic, accent-colored row for tool-generated
// helper info (like the PEM snippet) that is NOT an actual certificate
// field - visually distinct from the gray-chip rows in kvSection so it's
// obvious this value doesn't come from the certificate itself.
func metaRow(label, value string) fyne.CanvasObject {
	accent := activePalette.Loud
	muted := color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 0xB0}
	l := canvas.NewText(label+":", muted)
	l.TextStyle = fyne.TextStyle{Italic: true}
	v := canvas.NewText(value, muted)
	v.TextStyle = fyne.TextStyle{Italic: true}
	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		_ = clipboard.WriteAll(value)
	})
	copyBtn.Importance = widget.LowImportance
	return container.NewHBox(l, v, copyBtn)
}

// section: a dimmed label on the left and the value plus an orange copy
// icon on the right, value left-aligned and stretched to fill the column.
func kvFormRow(label, value string) (fyne.CanvasObject, fyne.CanvasObject) {
	l := widget.NewLabel(label)
	l.Importance = widget.LowImportance
	labelChip := canvas.NewRectangle(lighten(activePalette.Main, 0x1E))
	labelChip.CornerRadius = 6
	labelCell := container.NewStack(labelChip, container.NewPadded(l))

	v := widget.NewLabel(value)
	v.Wrapping = fyne.TextWrapWord
	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		_ = clipboard.WriteAll(value)
	})
	copyBtn.Importance = widget.HighImportance // tints the icon with the Loud accent

	// Reserve a minimum width for short values (e.g. "V3", "false") so the
	// copy icon doesn't sit right next to the text; long values (Subject,
	// SAN, ...) simply grow past it and push the icon further right still.
	spacer := canvas.NewRectangle(color.Transparent)
	spacer.SetMinSize(fyne.NewSize(380, 1))

	return labelCell, container.NewBorder(nil, nil, nil, copyBtn, container.NewStack(spacer, v))
}

// kvSection renders a bold section title followed by a compact two-column
// form of label/value rows (each with its own copy button), set against a
// lighter "category panel" background so the grouping is visible at a glance.
func kvSection(title string, rows [][2]string) fyne.CanvasObject {
	form := container.New(layout.NewFormLayout())
	for _, r := range rows {
		l, v := kvFormRow(r[0], r[1])
		form.Add(l)
		form.Add(v)
	}
	panel := canvas.NewRectangle(lighten(activePalette.Main, 0x12))
	panel.CornerRadius = 8
	// Wrapped in an HBox so the panel hugs the form's natural width instead
	// of stretching edge-to-edge like its VBox parent would otherwise do.
	panelRow := container.NewHBox(container.NewStack(panel, container.NewPadded(form)))
	if title == "" {
		return panelRow
	}
	return container.NewVBox(
		widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		panelRow,
	)
}

// certStatus classifies a certificate's validity into a short label and
// the color it should be shown with (valid/warning/error).
func certStatus(c CertData) (string, color.Color) {
	if c.ParseError != "" {
		return "Fehler", theme.Color(theme.ColorNameError)
	}
	remaining := time.Until(c.NotAfterTime)
	switch {
	case remaining < 0:
		return "Expired", theme.Color(theme.ColorNameError)
	case remaining < expiryWarnDays*24*time.Hour:
		return "Expiring soon", theme.Color(theme.ColorNameWarning)
	default:
		return "Valid", activePalette.Valid
	}
}

// renderCertCard builds the full "Übersicht" card for one certificate:
// a header with common name, status badge and a "Copy all" button, plus
// General/Fingerprints/Extensions sections with per-field copy buttons.
func renderCertCard(c CertData) fyne.CanvasObject {
	if c.ParseError != "" {
		return container.NewVBox(
			widget.NewLabelWithStyle("Kein lesbares Zertifikat", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			widget.NewLabel(c.ParseError),
		)
	}

	statusText, statusColor := certStatus(c)
	title := widget.NewLabelWithStyle(commonName(c.Subject), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	title.TextStyle.Bold = true

	copyAll := widget.NewButtonWithIcon("Copy all", theme.ContentCopyIcon(), func() {
		summary := fmt.Sprintf(
			"Subject: %s\nIssuer: %s\nSerial: %s\nVersion: %s\nValid from: %s\nValid until: %s\nSignature algorithm: %s\nPublic key: %s\nSHA-256: %s\nSHA-1: %s\nSAN: %s",
			c.Subject, c.Issuer, c.Serial, c.Version, c.NotBefore, c.NotAfter, c.SigAlgo, c.PubKeyAlgo,
			c.Fingerprint, c.FingerprintSHA1, sanSummary(c),
		)
		_ = clipboard.WriteAll(summary)
	})
	copyAll.Importance = widget.HighImportance

	header := container.NewBorder(nil, nil,
		container.NewHBox(title, badge(statusText, statusColor)),
		copyAll,
	)

	general := kvSection("General", [][2]string{
		{"Subject", c.Subject},
		{"Issuer", c.Issuer},
		{"Serial", c.Serial},
		{"Version", c.Version},
		{"Valid from", c.NotBefore},
		{"Valid until", c.NotAfter + expirySuffix(c.NotAfterTime)},
		{"Signature algorithm", c.SigAlgo},
		{"Public key", c.PubKeyAlgo},
		{"Is CA", c.IsCA},
	})

	fingerprints := kvSection("Fingerprints", [][2]string{
		{"SHA-256", c.Fingerprint},
		{"SHA-1", c.FingerprintSHA1},
	})

	extensions := kvSection("Extensions", [][2]string{
		{"SAN", sanSummary(c)},
	})

	return container.NewVBox(header, metaRow("Base64 snippet", c.ShortID), widget.NewSeparator(), general, widget.NewSeparator(), fingerprints, widget.NewSeparator(), extensions)
}

// sanSummary joins all subject alternative names into one comma-separated
// string, prefixed by type like a typical certificate viewer.
func sanSummary(c CertData) string {
	var parts []string
	for _, d := range c.DNSNames {
		parts = append(parts, "DNS:"+d)
	}
	for _, e := range c.Emails {
		parts = append(parts, "email:"+e)
	}
	for _, ip := range c.IPs {
		parts = append(parts, "IP Address:"+ip)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// chainSummaryCard renders a compact summary of one certificate in a chain,
// labelled with its position (e.g. "1/4 (Leaf)") and how it links to the
// next certificate (signature verified, broken, or self-signed root).
func chainSummaryCard(pos, total int, c CertData, linkStatus string) fyne.CanvasObject {
	role := "Intermediate"
	if pos == 1 {
		role = "Leaf"
	} else if pos == total {
		role = "Root"
	}
	heading := widget.NewLabelWithStyle(fmt.Sprintf("#%d/%d", pos, total), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	header := container.NewHBox(heading, badge(role, activePalette.Loud))

	if c.ParseError != "" {
		return container.NewVBox(header, widget.NewLabel(c.ParseError), widget.NewSeparator())
	}

	rows := [][2]string{
		{"Subject", c.Subject},
		{"Issuer", c.Issuer},
		{"Valid until", c.NotAfter + expirySuffix(c.NotAfterTime)},
		{"SHA-256", c.Fingerprint},
	}
	if linkStatus != "" {
		rows = append(rows, [2]string{"Kettenprüfung", linkStatus})
	}

	box := container.NewVBox(header, metaRow("Base64 snippet", c.ShortID), kvSection("", rows))
	if pos < total {
		box.Add(widget.NewLabel("  ↓"))
	}
	box.Add(widget.NewSeparator())
	return box
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
	a.Settings().SetTheme(certPeekTheme{})
	icon := loadIcon()
	a.SetIcon(icon)

	prefs := a.Preferences()
	autoOpenKey := "auto_open"
	themeKey := "theme_palette"
	activePalette = paletteByName(prefs.StringWithFallback(themeKey, "Charcoal"))

	w := a.NewWindow("CertPeek")
	w.SetIcon(icon)
	w.Resize(fyne.NewSize(1100, 800))

	status := widget.NewLabel("Warte auf PEM-Zertifikat in der Zwischenablage ...")
	desktopLabel := widget.NewLabel("Desktop: " + detectDesktop())
	parseState := widget.NewLabel("Parse: -")

	raw := widget.NewMultiLineEntry()
	raw.Disable()
	preview := widget.NewMultiLineEntry()
	preview.Disable()

	autoOpen := widget.NewCheck("Auto öffnen bei erkanntem Zertifikat", func(v bool) {
		prefs.SetBool(autoOpenKey, v)
	})
	autoOpen.SetChecked(prefs.BoolWithFallback(autoOpenKey, false))

	overviewBox := container.NewVBox()
	chainBox := container.NewVBox()
	var lastChain []CertData

	var updateFromChain func(chain []CertData)
	updateFromChain = func(chain []CertData) {
		lastChain = chain
		c := chain[0]
		if c.ParseError != "" {
			status.SetText("Clipboard enthält kein lesbares Zertifikat")
			parseState.SetText("Parse: " + c.ParseError)
		} else {
			status.SetText("PEM-Zertifikat erkannt")
			parseState.SetText("Parse: ok")
		}
		raw.SetText(c.Raw)
		preview.SetText(c.Raw)

		overviewBox.RemoveAll()
		overviewBox.Add(renderCertCard(c))
		overviewBox.Refresh()

		chainBox.RemoveAll()
		if len(chain) > 1 {
			for i, cc := range chain {
				chainBox.Add(chainSummaryCard(i+1, len(chain), cc, chainLinkStatus(chain, i)))
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

	btnDummyBundle := widget.NewButton("Dummy-Kette laden", func() {
		updateFromChain(parseCertChain(dummyBundlePEM))
	})

	btnQuit := widget.NewButton("Beenden", func() {
		a.Quit()
	})

	themeSelect := widget.NewSelect(paletteNames, func(name string) {
		activePalette = paletteByName(name)
		prefs.SetString(themeKey, name)
		a.Settings().SetTheme(certPeekTheme{})
		if lastChain != nil {
			updateFromChain(lastChain)
		}
	})
	themeSelect.SetSelected(prefs.StringWithFallback(themeKey, "Charcoal"))

	settingsTab := container.NewVBox(
		autoOpen,
		widget.NewLabel("Die Einstellung wird automatisch gespeichert."),
		widget.NewSeparator(),
		widget.NewLabel("Farbschema"),
		themeSelect,
	)

	top := container.NewVBox(
		desktopLabel,
		status,
		parseState,
		container.NewHBox(btnRefresh, btnDummyBundle, btnQuit),
	)

	overview := container.NewVScroll(container.NewPadded(overviewBox))

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
