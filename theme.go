package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// The app's palette is deliberately reduced to four colors:
//
//   - colorMain:      main window/app background (darkest)
//   - colorSecondary: panels, cards, rows, borders (one step lighter)
//   - colorLoud:      accent color for buttons, links, active state
//   - colorValid:     success/valid state (certificate not expired)
//
// Everything else (text, error, warning) reuses Fyne's defaults so the
// theme stays readable without hand-tuning every color name.
var (
	colorMain      = color.NRGBA{R: 0x16, G: 0x18, B: 0x1f, A: 0xff}
	colorSecondary = color.NRGBA{R: 0x22, G: 0x25, B: 0x2e, A: 0xff}
	colorLoud      = color.NRGBA{R: 0xff, G: 0x7a, B: 0x1a, A: 0xff}
	colorValid     = color.NRGBA{R: 0x22, G: 0xc5, B: 0x5e, A: 0xff}
)

// certPeekTheme is a dark theme built from the four colors above, layered
// on top of Fyne's built-in dark theme for anything not explicitly styled.
type certPeekTheme struct{}

func (certPeekTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return colorMain
	case theme.ColorNameMenuBackground, theme.ColorNameOverlayBackground,
		theme.ColorNameInputBackground, theme.ColorNameHeaderBackground,
		theme.ColorNameSeparator:
		return colorSecondary
	case theme.ColorNamePrimary, theme.ColorNameButton, theme.ColorNameHover,
		theme.ColorNameFocus, theme.ColorNameSelection:
		return colorLoud
	case theme.ColorNameSuccess:
		return colorValid
	default:
		return theme.DefaultTheme().Color(name, variant)
	}
}

func (certPeekTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (certPeekTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (certPeekTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}
