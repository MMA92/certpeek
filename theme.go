package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// palette holds the app's four-color design: main background, a secondary
// color for panels/rows/borders, a loud accent for buttons/links/active
// state, and a valid/success color for non-expired certificates.
type palette struct {
	Main, Secondary, Loud, Valid color.NRGBA
	// Foreground is the main text color, chosen for contrast against Main.
	// Fyne's default foreground follows the OS light/dark variant, not our
	// custom Main color, so each palette must set its own.
	Foreground color.NRGBA
}

var (
	// paletteCream: light cream background, dark navy panels, orange accent.
	paletteCream = palette{
		Main:       color.NRGBA{R: 0xEC, G: 0xDF, B: 0xC6, A: 0xff},
		Secondary:  color.NRGBA{R: 0x1A, G: 0x22, B: 0x38, A: 0xff},
		Loud:       color.NRGBA{R: 0xFF, G: 0x62, B: 0x16, A: 0xff},
		Valid:      color.NRGBA{R: 0x2F, G: 0x6F, B: 0x4E, A: 0xff}, // forest green
		Foreground: color.NRGBA{R: 0x1A, G: 0x1A, B: 0x1A, A: 0xff}, // near-black
	}

	// paletteCharcoal: dark charcoal background, warm beige panels, orange accent.
	paletteCharcoal = palette{
		Main:       color.NRGBA{R: 0x2B, G: 0x2D, B: 0x31, A: 0xff},
		Secondary:  color.NRGBA{R: 0xD2, G: 0xC6, B: 0xB4, A: 0xff},
		Loud:       color.NRGBA{R: 0xFF, G: 0x62, B: 0x16, A: 0xff},
		Valid:      color.NRGBA{R: 0x7A, G: 0x9D, B: 0x54, A: 0xff}, // olive green
		Foreground: color.NRGBA{R: 0xF2, G: 0xF0, B: 0xEC, A: 0xff}, // near-white
	}

	// activePalette is the palette currently applied to the app.
	activePalette = paletteCharcoal

	// paletteNames maps the names shown in the UI to their palette, in
	// display order.
	paletteNames = []string{"Charcoal", "Cream"}
)

// paletteByName resolves a UI palette name to its palette, defaulting to
// paletteCharcoal for unknown/empty names.
func paletteByName(name string) palette {
	if name == "Cream" {
		return paletteCream
	}
	return paletteCharcoal
}

// lighten returns c with each channel moved delta steps towards white,
// used to derive a subtle "category panel" background a bit lighter than
// the active Main background, independent of what hue Secondary happens
// to be in the current palette.
func lighten(c color.NRGBA, delta int) color.NRGBA {
	bump := func(v uint8) uint8 {
		n := int(v) + delta
		if n > 255 {
			n = 255
		}
		return uint8(n)
	}
	return color.NRGBA{R: bump(c.R), G: bump(c.G), B: bump(c.B), A: c.A}
}

// certPeekTheme is a dark theme built from the four colors above, layered
// on top of Fyne's built-in dark theme for anything not explicitly styled.
type certPeekTheme struct{}

func (certPeekTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return activePalette.Main
	case theme.ColorNameForeground:
		return activePalette.Foreground
	case theme.ColorNameMenuBackground, theme.ColorNameOverlayBackground,
		theme.ColorNameInputBackground, theme.ColorNameHeaderBackground,
		theme.ColorNameSeparator:
		return activePalette.Secondary
	case theme.ColorNamePrimary, theme.ColorNameButton, theme.ColorNameSelection:
		return activePalette.Loud
	case theme.ColorNameForegroundOnPrimary:
		// Text/icons drawn on top of the orange Loud color (e.g. the
		// "Copy all" button) need to stay black regardless of the palette.
		return color.NRGBA{R: 0x1A, G: 0x1A, B: 0x1A, A: 0xff}
	case theme.ColorNameHover, theme.ColorNameFocus:
		// A selected tab's label is always drawn in Primary (orange) by
		// Fyne, with no per-state override. Using Loud here too would make
		// an orange hovered+selected tab unreadable, so hover gets a
		// translucent tint instead - subtle on any background and never
		// orange-on-orange.
		f := activePalette.Foreground
		return color.NRGBA{R: f.R, G: f.G, B: f.B, A: 0x30}
	case theme.ColorNameDisabled:
		// Used for LowImportance labels (e.g. field names in the overview
		// card). Fyne's default disabled gray has too little contrast
		// against our custom backgrounds, so dim the palette's own
		// Foreground color instead of switching to an unrelated gray.
		f := activePalette.Foreground
		return color.NRGBA{R: f.R, G: f.G, B: f.B, A: 0xB0}
	case theme.ColorNameSuccess:
		return activePalette.Valid
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
