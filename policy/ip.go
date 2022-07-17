package policy

import (
	"fmt"
	"github.com/jonhadfield/carbo/helpers"
	"github.com/sirupsen/logrus"
	"net"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"
)

type ApplyIPsInput struct {
	RID      ResourceID
	Action   string
	Output   bool
	DryRun   bool
	Filepath string
	Nets     IPNets
	MaxRules int
}

type IPNets []net.IPNet

// toString receives slice of net.IPNet and returns a slice of their string representations
func (ipns IPNets) toString() []string {
	var res []string
	for _, ipn := range ipns {
		res = append(res, ipn.String())
	}

	return res
}

// deDupeIPNets accepts a slice of net.IPNet and returns a unique slice of their string representations
func deDupeIPNets(ipns IPNets) (res []string, err error) {
	// check overlaps
	seen := make(map[string]bool)
	for _, i := range ipns.toString() {
		if _, ok := seen[i]; ok {
			continue
		}

		res = append(res, i)
		seen[i] = true
	}

	return
}

// createCustomRule will return a frontdoor CustomRule constructed from the provided input
func createCustomRule(name, action string, priority int32, items []string) frontdoor.CustomRule {
	f := false

	t := &[]frontdoor.TransformType{}

	return frontdoor.CustomRule{
		Name:         &name,
		Priority:     &priority,
		EnabledState: "Enabled",
		RuleType:     "MatchRule",
		MatchConditions: &[]frontdoor.MatchCondition{{
			MatchVariable:   "RemoteAddr",
			NegateCondition: &f,
			Operator:        "IPMatch",
			MatchValue:      &items,
			Transforms:      t,
		}},
		Action: frontdoor.ActionType(action),
	}
}

// GenCustomRulesFromIPNets accepts a list of IPs, plus the action to be taken with them, and the maximum
// number of rules to create and then returns a slice of CustomRules
func GenCustomRulesFromIPNets(ipns IPNets, maxRules int, action string) (crs []frontdoor.CustomRule, err error) {
	var priorityStart int

	var ruleNamePrefix string

	switch action {
	case "Block":
		priorityStart = helpers.BlockNetsPriorityStart
		ruleNamePrefix = helpers.BlockNetsPrefix
	case "Allow":
		priorityStart = helpers.AllowNetsPriorityStart
		ruleNamePrefix = helpers.AllowNetsPrefix
	case "Log":
		priorityStart = helpers.LogNetsPriorityStart
		ruleNamePrefix = helpers.LogNetsPrefix
	default:
		return nil, fmt.Errorf("invalid action: %s", action)
	}

	deDupedNets, err := deDupeIPNets(ipns)
	if err != nil {
		return
	}

	logrus.Debugf("total networks after deduplication: %d", len(deDupedNets))

	strDeDupedNets := deDupedNets

	priorityCount := int32(priorityStart)

	var lastChunkEnd int

	var matchValues []string

	var customRulesGenerated int32

	for x := range strDeDupedNets {
		if x > 0 && x%helpers.MaxIPMatchValues == 0 {
			matchValues = strDeDupedNets[x-helpers.MaxIPMatchValues : x]
			lastChunkEnd = x
		} else if x+1 == len(strDeDupedNets) {
			matchValues = strDeDupedNets[lastChunkEnd:]
		}

		if len(matchValues) > 0 {
			ruleName := fmt.Sprintf("%s%d", ruleNamePrefix, priorityCount)

			bic := createCustomRule(ruleName, action, priorityCount, matchValues)

			priorityCount++

			crs = append(crs, bic)

			customRulesGenerated++
			if customRulesGenerated > 0 && customRulesGenerated == int32(maxRules) {
				return
			}

			// reset matchValues
			matchValues = nil
		}
	}

	return
}
