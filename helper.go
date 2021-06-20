package carbo

import (
	"fmt"
	"strings"

	"golang.org/x/term"
)

func PadToWidth(input, char string, inputLengthOverride int, trimToWidth bool) (output string) {
	var lines []string

	var newLines []string

	if strings.Contains(input, "\n") {
		lines = strings.Split(input, "\n")
	} else {
		lines = []string{input}
	}

	var paddingSize int

	for i, line := range lines {
		width, _, _ := term.GetSize(0)
		if width == -1 {
			width = 80
		}
		// No padding for a line that already meets or exceeds console width
		var length int
		if inputLengthOverride > 0 {
			length = inputLengthOverride
		} else {
			length = len(line)
		}

		if length >= width {
			if trimToWidth {
				output = line[0:width]
			} else {
				output = input
			}

			return
		} else if i == len(lines)-1 {
			if inputLengthOverride != 0 {
				paddingSize = width - inputLengthOverride
			} else {
				paddingSize = width - len(line)
			}

			if paddingSize >= 1 {
				newLines = append(newLines, fmt.Sprintf("%s%s\r", line, strings.Repeat(char, paddingSize)))
			} else {
				newLines = append(newLines, fmt.Sprintf("%s\r", line))
			}
		} else {
			var suffix string

			newLines = append(newLines, fmt.Sprintf("%s%s%s\n", line, strings.Repeat(char, paddingSize), suffix))
		}
	}

	output = strings.Join(newLines, "")

	return
}

func stringInSlice(s string, ss []string, ic bool) bool {
	for _, o := range ss {
		if ic {
			if strings.EqualFold(o, s) {
				return true
			}
		}

		if o == s {
			return true
		}
	}

	return false
}

func confirm(item, request string) bool {
	fmt.Println(item)
	fmt.Printf("%s [y|N]: ", request)

	var s string

	if _, err := fmt.Scanln(&s); err != nil {
		return false
	}

	s = strings.TrimSpace(s)

	s = strings.ToLower(s)

	if s == "y" || s == "yes" {
		return true
	}

	return false
}
