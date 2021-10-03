package carbo

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/pkg/errors"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"
	"github.com/alexeyco/simpletable"
	"github.com/gookit/color"
)

// splitExtendedID accepts an extended id <resource id>|<resource item name>, which it parses and then returns
// the individual components, or any error encountered in deriving them.
func splitExtendedID(eid string) (id, name string, err error) {
	components := strings.Split(eid, "|")
	if len(components) != 2 {
		err = fmt.Errorf("invalid format")

		return
	}

	return components[0], components[1], nil
}

// getRawPolicyCustomRuleByID returns a custom rule matching the resource id.
// the id is an extended resource id: <policy>|<custom rule name>.
func getRawPolicyCustomRuleByID(s *session, id string) (pcr frontdoor.CustomRule, err error) {
	pid, ruleName, err := splitExtendedID(id)
	if err != nil {
		return
	}

	rid := ParseResourceID(pid)

	p, err := s.getRawPolicy(rid.SubscriptionID, rid.ResourceGroup, rid.Name)
	if err != nil {
		return pcr, err
	}

	for _, r := range *p.CustomRules.Rules {
		if *r.Name == ruleName {
			pcr = r

			break
		}
	}

	if pcr.Name == nil {
		return pcr, fmt.Errorf("custom rule '%s' not found", ruleName)
	}

	return
}

// PrintPolicyCustomRule outputs the custom rule for a given resource.
// the id is an extended resource id: <policy>|<custom rule name>.
func PrintPolicyCustomRule(id string) error {
	s := session{}

	cr, err := getRawPolicyCustomRuleByID(&s, id)
	if err != nil {
		return err
	}

	var b []byte

	b, err = json.MarshalIndent(cr, "", "    ")
	if err != nil {
		return errors.Wrap(err, "failed to marshall custom rule")
	}

	fmt.Println(string(b))

	return nil
}

// PrintPolicy outputs the raw json policy with the provided resource id.
func PrintPolicy(id string) error {
	s := session{}

	components := ParseResourceID(id)

	fmt.Println(components)

	p, err := s.getRawPolicy(components.SubscriptionID, components.ResourceGroup, components.Name)
	if err != nil {
		return err
	}

	var b []byte

	b, err = json.MarshalIndent(p, "", "    ")
	if err != nil {
		return errors.Wrap(err, "failed to marshall custom rule")
	}

	fmt.Println(string(b))

	return nil
}

// showFrontDoors displays a table listing front doors, their endpoints, and their associated policies.
func showFrontDoors(afds FrontDoors) {
	table := simpletable.New()
	table.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Front Door")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Endpoint")},
			{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Policy")},
		},
	}

	for _, afd := range afds {
		var r []*simpletable.Cell

		for x1, endpoint := range afd.endpoints {
			afdName := ""
			if x1 == 0 {
				afdName = afd.name
			}

			r = []*simpletable.Cell{
				{Text: afdName},
				{Text: endpoint.name},
				{Text: *endpoint.wafPolicy.Name},
			}
			table.Body.Cells = append(table.Body.Cells, r)
		}
	}

	table.Println()
}

// formatCRAction accepts a waf policy's action type and returns a coloured text representation
func formatCRAction(a frontdoor.ActionType) string {
	action := strings.ToUpper(string(a))
	switch action {
	case "BLOCK":
		return color.HiRed.Sprint(action)
	case "LOG":
		return color.HiYellow.Sprint(action)
	case "ALLOW":
		return color.HiGreen.Sprint(action)
	default:
		panic(fmt.Sprintf("unexpected rule action: %s", string(a)))
	}
}

// outputPolicy accepts a waf policy and outputs it in the form of a table
func outputPolicy(policy frontdoor.WebApplicationFirewallPolicy, showFull bool) {
	color.Bold.Printf("Name ")
	fmt.Println(*policy.Name)
	color.Bold.Printf("Provisioning State ")
	fmt.Println(*policy.ProvisioningState)
	color.Bold.Printf("Resource State ")
	fmt.Println(policy.ResourceState)
	fmt.Println()

	table := simpletable.New()

	if len(*policy.CustomRules.Rules) > 0 {
		color.Bold.Println("Custom Rules")

		var maxCRNameLen int

		for _, cr := range *policy.CustomRules.Rules {
			if len(*cr.Name) > maxCRNameLen {
				maxCRNameLen = len(*cr.Name)
			}

			rldim := " "
			if cr.RateLimitDurationInMinutes != nil {
				rldim = strconv.Itoa(int(*cr.RateLimitDurationInMinutes))
			}

			rlt := " "

			if cr.RateLimitThreshold != nil {
				rldim = strconv.Itoa(int(*cr.RateLimitThreshold))
			}

			table.Header = &simpletable.Header{
				Cells: []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Rule Name")},
					{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("State")},
					{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Priority")},
					{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Rule Type")},
					{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Rate Limit Duration (mins)")},
					{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Rate Limit Threshold")},
					{Align: simpletable.AlignCenter, Text: color.Bold.Sprintf("Action")},
				},
			}
			table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
				{Text: *cr.Name + "\n" + strings.Repeat("-", 11)},
				{Text: string(cr.EnabledState) + "\n" + strings.Repeat("-", 9)},
				{Text: strconv.Itoa(int(*cr.Priority)) + "\n" + strings.Repeat("-", 10)},
				{Text: string(cr.RuleType) + "\n" + strings.Repeat("-", 13)},
				{Text: rldim + "\n" + strings.Repeat("-", 28)},
				{Text: rlt + "\n" + strings.Repeat("-", 22)},
				{Align: simpletable.AlignCenter, Text: formatCRAction(cr.Action) + "\n" + strings.Repeat("-", 8)},
			})
			table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
				{Text: color.HiBlue.Sprintf("Match Variable")},
				{Text: color.HiBlue.Sprintf("Selector")},
				{Text: color.HiBlue.Sprintf("Negate")},
				{Text: color.HiBlue.Sprintf("Operator")},
				{Text: color.HiBlue.Sprintf("Transforms")},
				{Text: color.HiBlue.Sprintf("Match Value")},
				{Text: ""},
			})

			for _, mc := range *cr.MatchConditions {
				// cast the transforms slice to string slice
				var transformsOutput strings.Builder

				for x, t := range *mc.Transforms {
					if x+1 == len(*mc.Transforms) {
						transformsOutput.WriteString(string(t))

						continue
					}

					transformsOutput.WriteString(fmt.Sprintf("%s, ", string(t)))
				}

				table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
					{Text: string(mc.MatchVariable)},
					{Text: dashIfEmptyString(mc.Selector)},
					{Text: strconv.FormatBool(*mc.NegateCondition)},
					{Text: dashIfEmptyString(string(mc.Operator))},
					{Text: dashIfEmptyString(transformsOutput.String())},
					{Text: wrapMatchValues(*mc.MatchValue, showFull)},
					{Text: ""},
				})
			}
			// separator
			table.Body.Cells = append(table.Body.Cells, []*simpletable.Cell{
				{Text: ""},
				{Text: ""},
				{Text: ""},
				{Text: ""},
				{Text: ""},
				{Text: ""},
				{Text: ""},
			})
		}
	}

	table.SetStyle(simpletable.StyleRounded)

	table.Println()

	d, err := PolicyHasDefaultDeny(policy)
	if err != nil {
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			color.Red.Println("[ERROR] Failed to check if Policy has default deny.", err)
			os.Exit(1)
		}

		color.Red.Println("[ERROR] Failed to check if Policy has default deny. run with debug for error")
	}

	if err == nil && !d {
		color.Yellow.Println("[WARNING] Policy does not have default deny")
	}
}
//
// var StyleRounded = &simpletable.Style{
// 	Border: &simpletable.BorderStyle{
// 		TopLeft:            ".",
// 		Top:                "-",
// 		TopRight:           ".",
// 		Right:              "|",
// 		BottomRight:        "'",
// 		Bottom:             "-",
// 		BottomLeft:         "'",
// 		Left:               "|",
// 		TopIntersection:    ".",
// 		BottomIntersection: "'",
// 	},
// 	Divider: &simpletable.DividerStyle{
// 		Left:         "+",
// 		Center:       "-",
// 		Right:        "+",
// 		Intersection: "+",
// 	},
// 	Cell: "|",
// }

// dashIfEmptyString returns the string value (or value pointed to) or a hyphen if the pointer is nil or value empty
func dashIfEmptyString(val interface{}) string {
	switch v := val.(type) {
	case *string:
		if v != nil && len(*v) > 0 {
			return *v
		}
	case string:
		// s := val.(string)
		if len(v) > 0 {
			return v
		}
	default:
		return "-"
	}

	return "-"
}

// wrapMatchValues accepts a slice of strings and returns a single comma/line-break separated representation
func wrapMatchValues(mvs []string, showFull bool) string {
	builder := strings.Builder{}

	for x, mv := range mvs {
		x++

		builder.WriteString(fmt.Sprintf("%s, ", mv))

		if x > 0 && x != len(mvs) && x%MaxMatchValuesPerColumn == 0 {
			builder.WriteString("\n")
		}

		if x == MaxMatchValuesOutput && !showFull {
			builder.WriteString(fmt.Sprintf("... %d remaining", len(mvs)-x))

			break
		}
	}

	list := builder.String()

	return strings.TrimRight(list, ", ")
}
