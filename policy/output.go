package policy

import (
	"encoding/json"
	"fmt"
	"github.com/jonhadfield/carbo/helpers"
	"github.com/wI2L/jsondiff"
	"github.com/ztrue/tracerr"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/pkg/errors"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"
	"github.com/alexeyco/simpletable"
	"github.com/gookit/color"
)

// PrintPolicy outputs the raw json policy with the provided resource id.
func PrintPolicy(id string) error {
	s := Session{}

	components := ParseResourceID(id)

	fmt.Println(components)

	p, err := s.GetRawPolicy(components.SubscriptionID, components.ResourceGroup, components.Name)
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

// ShowFrontDoors displays a table listing front doors, their endpoints, and their associated policies.
func ShowFrontDoors(afds FrontDoors) {
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

		for x1, endpoint := range afd.Endpoints {
			afdName := ""
			if x1 == 0 {
				afdName = afd.Name
			}

			r = []*simpletable.Cell{
				{Text: afdName},
				{Text: endpoint.Name},
				{Text: *endpoint.WafPolicy.Name},
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

		if x > 0 && x != len(mvs) && x%helpers.MaxMatchValuesPerColumn == 0 {
			builder.WriteString("\n")
		}

		if x == helpers.MaxMatchValuesOutput && !showFull {
			builder.WriteString(fmt.Sprintf("... %d remaining", len(mvs)-x))

			break
		}
	}

	list := builder.String()

	return strings.TrimRight(list, ", ")
}

func GeneratePolicyPatch(i GeneratePolicyPatchInput) (output GeneratePolicyPatchOutput, err error) {
	var originalBytes []byte
	switch v := i.Original.(type) {
	case []byte:
		originalBytes = v
	case frontdoor.WebApplicationFirewallPolicy:
		originalBytes, err = json.Marshal(v)
		if err != nil {
			return output, tracerr.Wrap(err)
		}
	case WrappedPolicy:
		originalBytes, err = json.Marshal(v.Policy)
		if err != nil {
			return output, tracerr.Wrap(err)
		}
	default:
		return output, tracerr.Errorf("unexpected type: %s", reflect.TypeOf(i.Original).String())
	}

	// sort New custom rules by priority to match existing order
	helpers.SortRules(*i.New.CustomRules.Rules)
	newPolicyJSON, err := json.MarshalIndent(i.New, "", "    ")
	if err != nil {
		return output, tracerr.Wrap(err)
	}

	var patch jsondiff.Patch
	patch, err = jsondiff.CompareJSON(originalBytes, newPolicyJSON)
	if err != nil {
		return output, tracerr.Wrap(err)
	}

	logrus.Tracef("%+v\n", patch)

	output.TotalDifferences = len(patch)

	for _, op := range patch {
		switch op.Type {
		case "add":
			if strings.HasPrefix(string(op.Path), "/properties/customRules/") {
				output.CustomRuleAdditions++
			}

			if strings.HasPrefix(string(op.Path), "/properties/managedRules/") {
				output.ManagedRuleAdditions++
			}
		case "remove":
			if strings.HasPrefix(string(op.Path), "/properties/customRules/") {
				output.CustomRuleRemovals++
			}

			if strings.HasPrefix(string(op.Path), "/properties/managedRules/") {
				output.ManagedRuleRemovals++
			}
		case "replace":
			if strings.HasPrefix(string(op.Path), "/properties/customRules/") {
				output.CustomRuleReplacements++
			}

			if strings.HasPrefix(string(op.Path), "/properties/managedRules/") {
				output.ManagedRuleReplacements++
			}
		}
	}

	output.CustomRuleChanges = output.CustomRuleAdditions + output.CustomRuleRemovals + output.CustomRuleReplacements
	output.ManagedRuleChanges = output.ManagedRuleAdditions + output.ManagedRuleRemovals + output.ManagedRuleReplacements
	output.TotalRuleDifferences = output.CustomRuleChanges + output.ManagedRuleChanges

	logrus.Debugf("output: %+v\n", output)

	return
}

func ShowPolicy(policyID string, showFull bool) error {
	rid := ParseResourceID(policyID)

	s := Session{}

	p, err := s.GetRawPolicy(rid.SubscriptionID, rid.ResourceGroup, rid.Name)
	if err != nil {
		return err
	}

	OutputPolicy(p, showFull)

	return nil
}

type GeneratePolicyPatchOutput struct {
	TotalDifferences        int
	TotalRuleDifferences    int
	CustomRuleAdditions     int
	CustomRuleChanges       int
	CustomRuleRemovals      int
	CustomRuleReplacements  int
	ManagedRuleChanges      int
	ManagedRuleAdditions    int
	ManagedRuleRemovals     int
	ManagedRuleReplacements int
}

type GeneratePolicyPatchInput struct {
	Original interface{}
	New      frontdoor.WebApplicationFirewallPolicy
}

func ListFrontDoors(subID string) error {
	s := Session{}

	frontDoors, err := GetFrontDoors(&s, subID)
	if err != nil {
		return err
	}

	if len(frontDoors) == 0 {
		fmt.Println("no front doors found")

		return nil
	}

	ShowFrontDoors(frontDoors)

	return nil
}

// OutputPolicy accepts a waf policy and outputs it in the form of a table
func OutputPolicy(policy frontdoor.WebApplicationFirewallPolicy, showFull bool) {
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

	d, err := helpers.PolicyHasDefaultDeny(policy)
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
