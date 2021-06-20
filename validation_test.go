package carbo

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"
	"github.com/stretchr/testify/require"
)

func strToPointer(s string) (p *string) {
	return &s
}

func boolToPointer(b bool) (p *bool) {
	return &b
}

func int32ToPointer(i int32) (p *int32) {
	return &i
}

func ipMatchValuesWithPublicInternet() []string {
	return []string{
		"1.1.1.1/32",
		"2.2.2.2/32",
		"0.0.0.0/0",
		"4.4.4.4/32",
	}
}

func ipMatchValuesNoPublicInternet() []string {
	return []string{
		"5.5.5.5/32",
		"52.0.0.0/24",
		"34.0.0.0/8",
	}
}

func TestResourceIDValidation(t *testing.T) {
	require.NoError(t, ValidateResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicy", false))
	validateEmptyResource := ValidateResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicy", false)
	require.Error(t, validateEmptyResource)
	require.Contains(t, validateEmptyResource.Error(), "number of sections")
	validateInvalidFormatNonExtended := ValidateResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/fly|ing/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicy", false)
	require.Error(t, validateInvalidFormatNonExtended)
	require.Contains(t, validateInvalidFormatNonExtended.Error(), "format")
	validateInvalidFormatExtended := ValidateResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicy", true)
	require.Error(t, validateInvalidFormatExtended)
	require.Contains(t, validateInvalidFormatExtended.Error(), "extended")
	validateFormatExtended := ValidateResourceID("/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicy|test", true)
	require.NoError(t, validateFormatExtended)
	validateInvalidSection := ValidateResourceID("/sub/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicy", false)
	require.Error(t, validateInvalidSection)
	require.Contains(t, validateInvalidSection.Error(), "resource id has invalid format")
}

func TestValidateResourceIDs(t *testing.T) {
	idOne := "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/volcanos"
	idTwo := "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/spaghetti/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/noodles"
	idThree := "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/monster/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/pirates"
	idFour := "/subs/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/monster/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/pirates"

	require.NoError(t, ValidateResourceIDs([]string{idOne}))
	require.NoError(t, ValidateResourceIDs([]string{idOne, idThree}))
	require.Error(t, ValidateResourceIDs([]string{idTwo, idThree}))
	require.Error(t, ValidateResourceIDs([]string{idTwo}))
	require.Error(t, ValidateResourceIDs([]string{idFour}))
}

// Block Rule where only condition has public internet match should result in default deny
func TestCustomRuleHasDefaultDenyOne(t *testing.T) {
	ipwpi := ipMatchValuesWithPublicInternet()

	// mcSet1 matches a default deny (blocks anything as 0.0.0.0/0 is a match)
	mcSet1 := []frontdoor.MatchCondition{{
		MatchVariable:   "RemoteAddr",
		Operator:        "IPMatch",
		NegateCondition: boolToPointer(false),
		MatchValue:      &ipwpi,
	}}

	dd, err := CustomRuleHasDefaultDeny(frontdoor.CustomRule{
		Name:            strToPointer("CustomRuleWithDefaultDeny"),
		Priority:        int32ToPointer(1),
		EnabledState:    "Enabled",
		RuleType:        "MatchRule",
		MatchConditions: &mcSet1,

		Action: "Block",
	})
	require.NoError(t, err)
	require.True(t, dd)
}

// Block Rule with two conditions
// Condition 1: public internet match (positive match for 0.0.0.0/0)
// Condition 2: public internet match (negative match for specific ranges)
func TestCustomRuleHasDefaultDenyTwo(t *testing.T) {
	ipwpi := ipMatchValuesWithPublicInternet()
	ipnpi := ipMatchValuesNoPublicInternet()

	// mcSet1 matches a default deny (blocks anything as 0.0.0.0/0 is a match)
	mc1 := frontdoor.MatchCondition{
		MatchVariable:   "RemoteAddr",
		Selector:        nil,
		Operator:        "IPMatch",
		NegateCondition: boolToPointer(false),
		MatchValue:      &ipwpi,
		Transforms:      nil,
	}

	mc2 := frontdoor.MatchCondition{
		MatchVariable:   "RemoteAddr",
		Operator:        "IPMatch",
		NegateCondition: boolToPointer(true),
		MatchValue:      &ipnpi,
	}

	mcSet := []frontdoor.MatchCondition{mc1, mc2}

	dd, err := CustomRuleHasDefaultDeny(frontdoor.CustomRule{
		Name:            strToPointer("CustomRuleWithDefaultDeny"),
		Priority:        int32ToPointer(1),
		EnabledState:    "Enabled",
		RuleType:        "MatchRule",
		MatchConditions: &mcSet,
		Action:          "Block",
	})
	require.NoError(t, err)
	require.True(t, dd)
}

// Block Rule with one condition
// Condition 1: postive match for specific ranges
func TestCustomRuleHasDefaultDenyThree(t *testing.T) {
	ipnpi := ipMatchValuesNoPublicInternet()

	mcSet := []frontdoor.MatchCondition{{
		MatchVariable:   "RemoteAddr",
		Selector:        nil,
		Operator:        "IPMatch",
		NegateCondition: boolToPointer(false),
		MatchValue:      &ipnpi,
		Transforms:      nil,
	}}

	dd, err := CustomRuleHasDefaultDeny(frontdoor.CustomRule{
		Name:            strToPointer("CustomRuleWithDefaultDeny"),
		Priority:        int32ToPointer(1),
		EnabledState:    "Enabled",
		RuleType:        "MatchRule",
		MatchConditions: &mcSet,
		Action:          "Block",
	})
	require.NoError(t, err)
	require.False(t, dd)
}

// Condition 1: negative match for public internet (matches everything)
func TestCustomRuleHasDefaultDenyFour(t *testing.T) {
	ipwpi := ipMatchValuesWithPublicInternet()

	mcSet := []frontdoor.MatchCondition{{
		MatchVariable:   "RemoteAddr",
		Operator:        "IPMatch",
		NegateCondition: boolToPointer(true),
		MatchValue:      &ipwpi,
	}}

	dd, err := CustomRuleHasDefaultDeny(frontdoor.CustomRule{
		Name:            strToPointer("CustomRuleWithDefaultDeny"),
		Priority:        int32ToPointer(1),
		EnabledState:    "Enabled",
		RuleType:        "MatchRule",
		MatchConditions: &mcSet,
		Action:          "Block",
	})
	require.NoError(t, err)
	require.False(t, dd)
}

// Condition 1: negative match for specific ips
func TestCustomRuleHasDefaultDenyFive(t *testing.T) {
	ipnpi := ipMatchValuesNoPublicInternet()

	mcSet := []frontdoor.MatchCondition{{
		MatchVariable:   "RemoteAddr",
		Operator:        "IPMatch",
		NegateCondition: boolToPointer(true),
		MatchValue:      &ipnpi,
	}}

	dd, err := CustomRuleHasDefaultDeny(frontdoor.CustomRule{
		Name:            strToPointer("CustomRuleWithDefaultDeny"),
		Priority:        int32ToPointer(1),
		EnabledState:    "Enabled",
		RuleType:        "MatchRule",
		MatchConditions: &mcSet,
		Action:          "Block",
	})
	require.NoError(t, err)
	require.True(t, dd)
}

func customRuleWithDefaultDeny() frontdoor.CustomRule {
	ipnpi := ipMatchValuesNoPublicInternet()
	mc1 := frontdoor.MatchCondition{
		MatchVariable:   "RemoteAddr",
		Selector:        nil,
		Operator:        "IPMatch",
		NegateCondition: boolToPointer(true),
		MatchValue:      &ipnpi,
		Transforms:      nil,
	}

	mcSet := []frontdoor.MatchCondition{mc1}

	return frontdoor.CustomRule{
		Name:            strToPointer("CustomRuleWithDefaultDeny"),
		Priority:        int32ToPointer(1),
		EnabledState:    "Enabled",
		RuleType:        "MatchRule",
		MatchConditions: &mcSet,
		Action:          "Block",
	}
}

func customRuleWithDefaultAllow() frontdoor.CustomRule {
	ipnpi := ipMatchValuesNoPublicInternet()
	ipwpi := ipMatchValuesWithPublicInternet()
	mc1 := frontdoor.MatchCondition{
		MatchVariable:   "RemoteAddr",
		Selector:        nil,
		Operator:        "IPMatch",
		NegateCondition: boolToPointer(true),
		MatchValue:      &ipnpi,
		Transforms:      nil,
	}
	mc2 := frontdoor.MatchCondition{
		MatchVariable:   "RemoteAddr",
		Selector:        nil,
		Operator:        "IPMatch",
		NegateCondition: boolToPointer(false),
		MatchValue:      &ipwpi,
		Transforms:      nil,
	}

	mcSet := []frontdoor.MatchCondition{mc1, mc2}

	return frontdoor.CustomRule{
		Name:            strToPointer("CustomRuleWithDefaultDeny"),
		Priority:        int32ToPointer(1),
		EnabledState:    "Enabled",
		RuleType:        "MatchRule",
		MatchConditions: &mcSet,
		Action:          "Allow",
	}
}

//
// func customRuleWithoutDefaultDeny() frontdoor.CustomRule {
//	ipnpi := ipMatchValuesNoPublicInternet()
//	ipwpi := ipMatchValuesWithPublicInternet()
//	mc1 := frontdoor.MatchCondition{
//		MatchVariable:   "RemoteAddr",
//		Selector:        nil,
//		Operator:        "IPMatch",
//		NegateCondition: boolToPointer(true),
//		MatchValue:      &ipnpi,
//		Transforms:      nil,
//	}
//	mc2 := frontdoor.MatchCondition{
//		MatchVariable:   "RemoteAddr",
//		Selector:        nil,
//		Operator:        "IPMatch",
//		NegateCondition: boolToPointer(false),
//		MatchValue:      &ipwpi,
//		Transforms:      nil,
//	}
//
//	mcSet := []frontdoor.MatchCondition{mc1, mc2}
//	return frontdoor.CustomRule{
//		Name:            strToPointer("CustomRuleWithDefaultDeny"),
//		Priority:        int32ToPointer(1),
//		EnabledState:    "Enabled",
//		RuleType:        "MatchRule",
//		MatchConditions: &mcSet,
//		Action:          "Block",
//	}
// }

func TestMatchValuesHasMatchAll(t *testing.T) {
	ipwpi := ipMatchValuesWithPublicInternet()
	ipnpi := ipMatchValuesNoPublicInternet()

	res, err := MatchValuesHasMatchAll(&ipwpi, "RemoteAddr", "IPMatch")
	require.NoError(t, err)
	require.True(t, res)
	res, err = MatchValuesHasMatchAll(&ipnpi, "RemoteAddr", "IPMatch")
	require.NoError(t, err)
	require.False(t, res)
}

// func MatchValuesHasMatchAll(mvs *[]string, matchVariable frontdoor.MatchVariable, operator frontdoor.Operator) (res bool, err error) {
//	switch matchVariable {
//	case "RemoteAddr":
//		switch operator {
//		case "IPMatch":
//			if stringInSlice("0.0.0.0/0", *mvs, false) {
//				return true, nil
//			}
//		}
//	default:
//		err = fmt.Errorf("not implemented")
//	}
//
//	return
// }
