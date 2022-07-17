package helpers

import (
	"fmt"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"
	"golang.org/x/term"
	"runtime"
	"sort"
	"strings"
)

//
// func GetResourceIDsFromGenericResources(gres []resources.GenericResourceExpanded) (rids []carbo.ResourceID) {
// 	for _, gre := range gres {
// 		rids = append(rids, carbo.ParseResourceID(*gre.ID))
// 	}
//
// 	return
// }
//
// func StringInSlice(s string, ss []string, ic bool) bool {
// 	for _, o := range ss {
// 		if ic {
// 			if strings.EqualFold(o, s) {
// 				return true
// 			}
// 		}
//
// 		if o == s {
// 			return true
// 		}
// 	}
//
// 	return false
// }

func GetFunctionName() string {
	pc, _, _, _ := runtime.Caller(1)
	complete := fmt.Sprintf("%s", runtime.FuncForPC(pc).Name())
	split := strings.Split(complete, "/")

	return split[len(split)-1]
}

func StringInSlice(s string, ss []string, ic bool) bool {
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

func Confirm(item, request string) bool {
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

func SortRules(customRules []frontdoor.CustomRule) {
	sort.Slice(customRules, func(i, j int) bool {
		return *customRules[i].Priority < *customRules[j].Priority
	})
}

// PrefixFromAction accepts an action as string and returns the correct prefix to use in a custom rule
func PrefixFromAction(action string) (prefix string, err error) {
	switch action {
	case "Block":
		return BlockNetsPrefix, nil
	case "Allow":
		return AllowNetsPrefix, nil
	case "Log":
		return LogNetsPrefix, nil
	default:
		return "", fmt.Errorf("unexpected action: %s", action)
	}
}

// SplitExtendedID accepts an extended id <resource id>|<resource item name>, which it parses and then returns
// the individual components, or any error encountered in deriving them.
func SplitExtendedID(eid string) (id, name string, err error) {
	components := strings.Split(eid, "|")
	if len(components) != 2 {
		err = fmt.Errorf("invalid format")

		return
	}

	return components[0], components[1], nil
}
