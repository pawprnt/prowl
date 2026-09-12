package output

import (
	"fmt"
	"strings"
)

func MainBanner() {
	banner := `
 ██╗   ██╗██╗   ██╗██╗      ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██║   ██║██║     ██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║   ██║██║     ██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗╚██████╗██║  ██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝`

	fox := `
        /\\_/\\
   ____/ o o \\
 /~____  =ω= /
(______)__m_m_/

`

	if isTerminal {
		fmt.Println(colorize(colorBold+colorMagenta, banner))
		fmt.Println(colorize(colorDim, fox))
		fmt.Println(colorize(colorDim, "  security research toolkit"))
		fmt.Println(colorize(colorDim, "  github.com/foxinwinter/prowl"))
	} else {
		fmt.Println(banner)
		fmt.Println(fox)
		fmt.Println("  security research toolkit")
		fmt.Println("  github.com/foxinwinter/prowl")
	}
	fmt.Println()
}

func SmallBanner() {
	banner := `  ___  ___  ___  ___  ___  ___  ___
 | _ \/ _ \/ __|| _ \/ _ \/ __|| _ \
 |  _/ (_) \__ \|  _/ (_) \__ \|   /
 |_|  \___/|___/|_|  \___/|___/|_|\_\
`
	if isTerminal {
		fmt.Println(colorize(colorBold+colorMagenta, banner))
		fmt.Println(colorize(colorDim, "  prowl - security research toolkit"))
	} else {
		fmt.Println(banner)
		fmt.Println("  prowl - security research toolkit")
	}
}

func VersionBanner(version, commit string) {
	banner := `  ___  ___  ___  ___  ___  ___  ___
 | _ \/ _ \/ __|| _ \/ _ \/ __|| _ \
 |  _/ (_) \__ \|  _/ (_) \__ \|   /
 |_|  \___/|___/|_|  \___/|___/|_|\_\`

	info := fmt.Sprintf("\n  Version: %s\n  Commit:  %s\n  Built:   %s\n", version, commit, "2026")

	if isTerminal {
		fmt.Println(colorize(colorBold+colorCyan, banner))
		fmt.Println(colorize(colorDim, info))
	} else {
		fmt.Println(banner)
		fmt.Println(info)
	}
}

func ScanBanner(target, profile string) {
	width := 60
	sep := strings.Repeat("━", width)

	fox := `   /\\_/\\
  ( o.o )
   > ^ <
  /|   |\\
 (_|   |_)`

	if isTerminal {
		fmt.Println()
		fmt.Println(colorize(colorCyan, "┌"+sep+"┐"))
		fmt.Println(colorize(colorCyan, "│") + colorize(colorBold, centerText("SCAN INITIATED", width-2)) + colorize(colorCyan, "│"))
		fmt.Println(colorize(colorCyan, "├"+sep+"┤"))
		fmt.Println(colorize(colorCyan, "│") + " " + colorize(colorBold, "Target:  ") + target + padRight(width-12-len(target)) + colorize(colorCyan, "│"))
		fmt.Println(colorize(colorCyan, "│") + " " + colorize(colorBold, "Profile: ") + profile + padRight(width-12-len(profile)) + colorize(colorCyan, "│"))
		fmt.Println(colorize(colorCyan, "│") + " " + colorize(colorDim, strings.Repeat("─", width-4)) + " " + colorize(colorCyan, "│"))
		for _, line := range strings.Split(fox, "\n") {
			padded := fmt.Sprintf("%-58s", line)
			fmt.Println(colorize(colorCyan, "│") + colorize(colorDim, " "+padded) + colorize(colorCyan, "│"))
		}
		fmt.Println(colorize(colorCyan, "└"+sep+"┘"))
	} else {
		fmt.Println()
		fmt.Println("+" + sep + "+")
		fmt.Println("|" + centerText("SCAN INITIATED", width-2) + "|")
		fmt.Println("+" + sep + "+")
		fmt.Printf("| Target:  %-56s|\n", target)
		fmt.Printf("| Profile: %-56s|\n", profile)
		fmt.Println("+" + sep + "+")
	}
	fmt.Println()
}

func ReportBanner() {
	banner := `    _____                            _
   / ____|                          | |
  | (___   __ _ _   _  ___  ___  __| |
   \___ \ / _` + "`" + ` | | | |/ _ \/ __|/ _` + "`" + ` |
   ____) | (_| | |_| |  __/\__ \ (_| |
  |_____/ \__,_|\__, |\___||___/\__,_|
                  __/ |
                 |___/`

	if isTerminal {
		fmt.Println(colorize(colorBold+colorCyan, banner))
		fmt.Println(colorize(colorDim, "  Generating report..."))
	} else {
		fmt.Println(banner)
		fmt.Println("  Generating report...")
	}
	fmt.Println()
}

func ToolBanner(tool, target string) {
	toolArt := map[string]string{
		"nmap": `   __
  /  \
 /    \__
|  ()   |
 \    /
  \__/
`,
		"nuclei": `    ___
   /   \
  | (o) |
   \   /
   /| |\
  / |_| \
`,
		"ffuf": `   _____
  |  _  |
  | |_| |
  |_____|
   |   |
   |___|
`,
	}

	art, ok := toolArt[tool]
	if !ok {
		art = `   /\\_/\\
  ( o.o )
   > ^ <
`
	}

	if isTerminal {
		fmt.Println(colorize(colorCyan, fmt.Sprintf("  Running: %s", tool)))
		fmt.Println(colorize(colorCyan, fmt.Sprintf("  Target:  %s", target)))
		for _, line := range strings.Split(art, "\n") {
			if line != "" {
				fmt.Println(colorize(colorDim, "  "+line))
			}
		}
	} else {
		fmt.Printf("  Running: %s\n", tool)
		fmt.Printf("  Target:  %s\n", target)
	}
}

func StatusBanner(status, message string) {
	if isTerminal {
		var color string
		switch strings.ToLower(status) {
		case "success", "done", "complete":
			color = colorGreen
		case "error", "failed", "fail":
			color = colorRed
		case "warning", "warn":
			color = colorYellow
		default:
			color = colorCyan
		}
		fmt.Printf("\r  %s %s\n", colorize(color, "["+strings.ToUpper(status)+"]"), message)
	} else {
		fmt.Printf("  [%s] %s\n", strings.ToUpper(status), message)
	}
}

func ProgressBanner(current, total int, label string) {
	width := 40
	percent := float64(current) / float64(total) * 100
	filled := int(percent / 100 * float64(width))
	if filled > width {
		filled = width
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)

	if isTerminal {
		fmt.Printf("\r  %s [%s] %d/%d %s",
			colorize(colorCyan, ">>"),
			bar,
			current,
			total,
			label,
		)
		if current == total {
			fmt.Println()
		}
	} else {
		fmt.Printf("  [%s] %d/%d %s", bar, current, total, label)
		if current == total {
			fmt.Println()
		}
	}
}

func centerText(text string, width int) string {
	if len(text) >= width {
		return text[:width]
	}
	padding := (width - len(text)) / 2
	return strings.Repeat(" ", padding) + text + strings.Repeat(" ", width-padding-len(text))
}

func padRight(width int) string {
	if width <= 0 {
		return ""
	}
	return strings.Repeat(" ", width)
}
