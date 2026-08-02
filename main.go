package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/atotto/clipboard"
)

func main() {
	text, err := clipboard.ReadAll()
	if err != nil {
		text = fmt.Sprintf("Fehler beim Lesen der Zwischenablage: %v", err)
	}

	desktop := detectDesktop()

	a := app.New()
	w := a.NewWindow("Clipboard Viewer")

	label := widget.NewLabel(text)
	label.Wrapping = fyne.TextWrapWord

	info := widget.NewLabel("Erkannte Umgebung: " + desktop)
	copyBtn := widget.NewButton("Fensterinhalt erneut laden", func() {
		t, err := clipboard.ReadAll()
		if err != nil {
			label.SetText("Fehler beim Lesen der Zwischenablage: " + err.Error())
			return
		}
		label.SetText(t)
	})

	content := container.NewVBox(
		info,
		widget.NewSeparator(),
		label,
		widget.NewSeparator(),
		copyBtn,
	)

	w.SetContent(content)
	w.Resize(fyne.NewSize(700, 400))
	w.ShowAndRun()
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
