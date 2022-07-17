package helpers

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"
)

// ValidateResourceID will tokenise and check the format is valid
// 'extended' parameter is used to indicate if pipe separated value follows id
func ValidateResourceID(rawID string, extended bool) error {
	if len(strings.Split(rawID, "/")) != 9 {
		return fmt.Errorf("resource id has incorrect number of sections")
	}

	isValid := regexp.MustCompile(`(?i)/subscriptions/(.+?)/resourcegroups/(.+?)/providers/(.+?)/(.+?)/(.+)`).MatchString
	if !isValid(rawID) {
		return fmt.Errorf("resource id has invalid format")
	}

	if !extended && strings.Contains(rawID, "|") {
		return fmt.Errorf("invalid format for resource id")
	}

	if extended {
		if !strings.Contains(rawID, "|") {
			return fmt.Errorf("invalid format for extended resource id")
		}
	}

	return nil
}

func ValidateResourceIDs(ids []string) error {
	for _, id := range ids {
		if err := ValidateResourceID(id, false); err != nil {
			return fmt.Errorf("%w: %s", err, id)
		}
	}

	return nil
}

func MatchValuesHasMatchAll(mvs *[]string, matchVariable frontdoor.MatchVariable, operator frontdoor.Operator) (res bool, err error) {
	switch matchVariable {
	case "RemoteAddr":
		switch operator {
		case "IPMatch":
			if StringInSlice("0.0.0.0/0", *mvs, false) {
				return true, nil
			}
		}
	default:
		err = fmt.Errorf("not implemented")
	}

	return
}

func MatchConditionHasDefaultUnknown(mc frontdoor.MatchCondition) (result bool, err error) {
	// if match condition doesn't negate, and the match values contains a match all, then true
	hasMatchAll, err := MatchValuesHasMatchAll(mc.MatchValue, mc.MatchVariable, mc.Operator)

	if !*mc.NegateCondition && hasMatchAll {
		return true, err
	}

	if *mc.NegateCondition && !hasMatchAll {
		return true, err
	}

	return
}

func CustomRuleHasDefaultDeny(c frontdoor.CustomRule) (defaultDeny bool, err error) {
	// if all match conditions have "if not... then deny" (other than a single rule saying if not 0.0.0.0/0 then deny) then they do
	// if a rule only has "if ip 0.0.0.0/0 then deny" then true
	switch c.Action {
	case "Block":
		var du bool
		// check if any match condition has a default unknown
		for _, mc := range *c.MatchConditions {
			du, err = MatchConditionHasDefaultUnknown(mc)
			if err != nil {
				return
			}

			if du {
				return true, nil
			}
		}
	}

	return
}

func PolicyHasDefaultDeny(p frontdoor.WebApplicationFirewallPolicy) (defaultDeny bool, err error) {
	// if Policy has "if not... then deny" then they do
	// if Policy has "if ip 0.0.0.0/0 then deny" then true
	for _, cr := range *p.CustomRules.Rules {
		if cr.EnabledState != "CustomRuleEnabledStateEnabled" {
			var dd bool

			dd, err = CustomRuleHasDefaultDeny(cr)
			if dd {
				return true, err
			}
		}
	}

	return
}

// TODO: Add a default deny option where it's Deny if IP 0.0.0.0/0 (IPv6?)
// func AddDefaultDeny(p frontdoor.WebApplicationFirewallPolicy) (up frontdoor.WebApplicationFirewallPolicy, err error) {
//
// }
