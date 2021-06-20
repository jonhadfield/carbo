package carbo

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

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

// ApplyIPChanges accepts user input specifying IPs, or filepath containing IPs, and then adds them to custom rules
// matching the specified action
func ApplyIPChanges(input ApplyIPsInput) (err error) {
	s := session{}

	return applyIPChanges(&s, input)
}

// applyIPChanges updates an existing custom policy with IPs matching the requested action
func applyIPChanges(s *session, input ApplyIPsInput) (err error) {
	prefix, err := prefixFromAction(input.Action)
	if err != nil {
		return
	}

	lowercaseAction := strings.ToLower(input.Action)

	if input.Filepath != "" {
		var fipns IPNets

		fipns, err = loadIPsFromPath(input.Filepath)
		if err != nil {
			return
		}

		input.Nets = append(input.Nets, fipns...)
	}

	if len(input.Nets) == 0 {
		return fmt.Errorf("no IPs loaded")
	}

	var p frontdoor.WebApplicationFirewallPolicy

	subscription := input.RID.SubscriptionID
	resourceGroup := input.RID.ResourceGroup
	name := input.RID.Name

	// check if Policy exists
	p, err = s.getRawPolicy(subscription, resourceGroup, name)
	if err != nil {
		return err
	}

	if p.Name == nil {
		return fmt.Errorf("specified Policy not found")
	}

	// take a copy of the Policy for later comparison
	origPolicyJSON, err := json.MarshalIndent(p, "", "    ")
	if err != nil {
		return
	}

	crs, err := genCustomRulesFromIPNets(input.Nets, input.MaxRules, input.Action)
	if err != nil {
		return
	}

	// remove existing net rules from Policy before adding new
	var ecrs []frontdoor.CustomRule

	for _, existingCustomRule := range *p.CustomRules.Rules {
		// if new custom rule name doesn't have the prefix in the Action, then add it
		// this means all the ones not matching the action go at the beginning #### WRONG BEHAVIOUR - MUST BE IN PRIORITY ORDER
		if !strings.HasPrefix(*existingCustomRule.Name, prefix) {
			ecrs = append(ecrs, existingCustomRule)
		}
	}

	// new rule list
	// for existing-rule in existing-rules
	//		for new rule in new rules
	//			  if existing-rule.priority < new-rule.priority:
	//					new-rule-list = append(new-rule-list

	// add the new custom rules to the existing
	*p.CustomRules.Rules = append(ecrs, crs...)
	// check we don't exceed Azure rules limit
	if len(*p.CustomRules.Rules) > MaxCustomRules {
		return fmt.Errorf("operation exceededs custom rules limit of %d", MaxCustomRules)
	}
	//
	// // check we don't exceed the user specified max rules limit
	// if len(*p.CustomRules.Rules) > input.MaxRules {
	//	return fmt.Errorf("operation exceededs custom rules limit of %d", MaxCustomRules)
	// }

	// sortRules(*p.CustomRules.Rules)
	// check if rules differ from original
	// num, patch, err := generatePolicyPatch(origPolicyJSON, p)
	gppO, err := generatePolicyPatch(generatePolicyPatchInput{original: origPolicyJSON, new: p})
	if err != nil {
		return err
	}

	if gppO.customRuleChanges == 0 {
		log.Println("nothing to do")

		return nil
	}

	if input.DryRun {
		log.Printf("%d changes to %s list would be applied\n", gppO.customRuleChanges, lowercaseAction)
		return nil
	}

	if input.Output {
		o, _ := json.MarshalIndent(p, "", "    ")
		fmt.Println(string(o))

		return nil
	}

	log.Printf("updating Policy %s\n", *p.Name)

	err = s.pushPolicy(pushPolicyInput{
		Name:          *p.Name,
		subscription:  input.RID.SubscriptionID,
		resourceGroup: input.RID.ResourceGroup,
		policy:        p,
	})

	if err == nil {
		fmt.Printf("%d changes to %s list have been applied\n", gppO.customRuleChanges, lowercaseAction)
	}

	return err
}

type IPNets []net.IPNet

// prefixFromAction accepts an action as string and returns the correct prefix to use in a custom rule
func prefixFromAction(action string) (prefix string, err error) {
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

// genCustomRulesFromIPNets accepts a list of IPs, plus the action to be taken with them, and the maximum
// number of rules to create and then returns a slice of CustomRules
func genCustomRulesFromIPNets(ipns IPNets, maxRules int, action string) (crs []frontdoor.CustomRule, err error) {
	var priorityStart int

	var ruleNamePrefix string

	switch action {
	case "Block":
		priorityStart = BlockNetsPriorityStart
		ruleNamePrefix = BlockNetsPrefix
	case "Allow":
		priorityStart = AllowNetsPriorityStart
		ruleNamePrefix = AllowNetsPrefix
	case "Log":
		priorityStart = LogNetsPriorityStart
		ruleNamePrefix = LogNetsPrefix
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
		if x > 0 && x%MaxIPMatchValues == 0 {
			matchValues = strDeDupedNets[x-MaxIPMatchValues : x]
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

// readIPsFromFile accepts a file path from which to load IPs (one per line) as strings and return a slice of
func readIPsFromFile(fPath string) (ipnets IPNets, err error) {
	file, err := os.Open(fPath)
	if err != nil {
		log.Fatalf("failed to open")
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	var ipnet *net.IPNet

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			if !strings.Contains(line, "/") {
				line = line + "/32"
			}

			_, ipnet, err = net.ParseCIDR(line)
			if err != nil {
				return
			}

			ipnets = append(ipnets, *ipnet)
		}
	}

	return
}

// loadIPsFromPath accepts a file path or directory and then generates a fully qualified path
// in order to call a function to load the ips from each fully qualified file path
func loadIPsFromPath(path string) (ipNets IPNets, err error) {
	// if path is a folder, then loop through contents
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return
	}

	if info.IsDir() {
		var files []fs.FileInfo

		files, err = ioutil.ReadDir(path)
		if err != nil {
			return
		}

		for _, file := range files {
			if !file.IsDir() {
				var n IPNets

				p := filepath.Join(path, file.Name())

				n, err = readIPsFromFile(p)
				if err != nil {
					return
				}

				logrus.Printf("loaded %d ips from file %s\n", len(n), p)

				ipNets = append(ipNets, n...)
			}
		}

		return
	}

	var n IPNets

	n, err = readIPsFromFile(path)
	if err != nil {
		return
	}

	logrus.Debugf("loaded %d ips from file %s\n", len(n), path)

	ipNets = append(ipNets, n...)

	return
}
