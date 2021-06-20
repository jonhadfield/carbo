package carbo

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/sirupsen/logrus"
	"github.com/wI2L/jsondiff"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"
	"github.com/ztrue/tracerr"
)

func ListPolicies(subID, appVersion string, max int) error {
	if max == 0 {
		return fmt.Errorf("invalid maximum number of policies to return")
	}

	s := session{}

	o, err := s.getAllPolicies(getWrappedPoliciesInput{
		subscriptionID:    subID,
		appVersion:        appVersion,
		max:               max,
		filterResourceIDs: nil,
	})
	if err != nil {
		return err
	}

	if len(o) == 0 {
		fmt.Println("no policies found")

		return nil
	}

	// print the policy ids
	for _, p := range o {
		fmt.Println(*p.ID)
	}

	return nil
}

func ShowPolicy(policyID string, showFull bool) error {
	rid := ParseResourceID(policyID)

	s := session{}

	p, err := s.getRawPolicy(rid.SubscriptionID, rid.ResourceGroup, rid.Name)
	if err != nil {
		return err
	}

	outputPolicy(p, showFull)

	return nil
}

func (s *session) getRawPolicy(subscription string, resourceGroup string, name string) (wafPolicy frontdoor.WebApplicationFirewallPolicy, err error) {
	err = s.getFrontDoorPoliciesClient(subscription)
	if err != nil {
		return
	}

	logrus.Debugf("requesting AFD policy with: %s %s %s", subscription, resourceGroup, name)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	wafPolicy, err = s.frontDoorPoliciesClients[subscription].Get(ctx, resourceGroup, name)

	return
}

func (s *session) getAllPolicies(i getWrappedPoliciesInput) (gres []resources.GenericResourceExpanded, err error) {
	err = s.getResourcesClient(i.subscriptionID)
	if err != nil {
		return
	}

	ctx := context.Background()

	top := int32(i.max)
	if i.max == 0 {
		top = MaxPoliciesToFetch
	}

	logrus.Debugf("listing first %d policies in subscription: %s", top, i.subscriptionID)

	it, err := s.resourcesClients[i.subscriptionID].ListComplete(ctx, "resourceType eq 'Microsoft.Network/frontdoorWebApplicationFirewallPolicies'", "", &top)
	if err != nil {
		return
	}

	var total int

	for it.NotDone() {
		if it.Value().ID == nil {
			tracerr.Errorf("Azure returned a WAF policy without a resource ID: %+v", it.Value())
		}

		// add if filters not provided, or filters are provided, and we have a match
		if len(i.filterResourceIDs) == 0 || stringInSlice(*it.Value().ID, i.filterResourceIDs, true) {
			gres = append(gres, it.Value())
		}

		total++

		// passing top as top number of items isn't working due to an API bug
		// if we have reached top here, then return
		if total == int(top) {
			return
		}

		if err = it.NextWithContext(ctx); err != nil {
			return
		}
	}

	logrus.Debugf("retrieved %d resources", total)

	return gres, err
}

func getResourceIDsFromGenericResources(gres []resources.GenericResourceExpanded) (rids []ResourceID) {
	for _, gre := range gres {
		rids = append(rids, ParseResourceID(*gre.ID))
	}

	return
}

func (s *session) getWrappedPolicies(i getWrappedPoliciesInput) (o getWrappedPoliciesOutput, err error) {
	var rids []ResourceID

	if len(i.filterResourceIDs) > 0 {
		// if ids to filter have been provided then simply parse as ResourceIDs
		rids = ParseResourceIDs(i.filterResourceIDs)
	} else {
		// retrieve all policies as generic resources
		var gres []resources.GenericResourceExpanded
		gres, err = s.getAllPolicies(i)
		if err != nil {
			return
		}

		rids = getResourceIDsFromGenericResources(gres)
	}

	for _, rid := range rids {
		var p frontdoor.WebApplicationFirewallPolicy
		logrus.Debugf("retrieving raw policy with: %s %s %s", rid.SubscriptionID, rid.ResourceGroup, rid.Name)

		p, err = s.getRawPolicy(rid.SubscriptionID, rid.ResourceGroup, rid.Name)
		if err != nil {
			return
		}

		wp := WrappedPolicy{
			Date:           time.Now().UTC(),
			SubscriptionID: rid.SubscriptionID,
			ResourceGroup:  rid.ResourceGroup,
			Name:           rid.Name,
			Policy:         p,
			PolicyID:       rid.Raw,
			AppVersion:     i.appVersion,
		}

		o.policies = append(o.policies, wp)
	}

	return
}

// matchExistingPolicyByID returns the raw policy matched by the policy id of its origin, e.g. where the backup was from
func matchExistingPolicyByID(targetPolicyID string, existingPolicies []WrappedPolicy) (found bool, policy WrappedPolicy) {
	for x := range existingPolicies {
		if strings.EqualFold(existingPolicies[x].PolicyID, targetPolicyID) {
			return true, existingPolicies[x]
		}
	}

	return
}

func getPoliciesToRestore(s *session, policyBackups []WrappedPolicy, i RestorePoliciesInput) (policiesToRestore []WrappedPolicy, err error) {
	// get all existing policies in subscription, filtered by target policy id if provided
	var filterResourceIDs []string
	if i.TargetPolicy != "" {
		filterResourceIDs = []string{i.TargetPolicy}
	}

	logrus.Debugf("retrieving target policy: %s", i.TargetPolicy)
	o, err := s.getWrappedPolicies(getWrappedPoliciesInput{
		filterResourceIDs: filterResourceIDs,
		subscriptionID:    i.SubscriptionID,
	})
	if err != nil {
		return policiesToRestore, tracerr.Wrap(err)
	}

	existingPolicies := o.policies

	// compare each backup policy id (or target policy id if provided) with existing policy ids
	for _, policyBackup := range policyBackups {
		matchPolicyID := policyBackup.PolicyID
		if i.TargetPolicy != "" {
			matchPolicyID = i.TargetPolicy
		}

		var foundExisting bool

		var matchedExistingPolicy WrappedPolicy

		foundExisting, matchedExistingPolicy = matchExistingPolicyByID(matchPolicyID, existingPolicies)

		if foundExisting {
			// var gppInput generatePolicyPatchInput
			var output generatePolicyPatchOutput

			output, err = generatePolicyPatch(
				generatePolicyPatchInput{
					original: matchedExistingPolicy,
					new:      policyBackup.Policy,
				})
			if err != nil {
				return
			}

			if i.CustomRulesOnly && output.customRuleChanges == 0 {
				fmt.Println("target policy's custom rules are identical to those in backup")

				continue
			}

			if i.ManagedRulesOnly && output.managedRuleChanges == 0 {
				fmt.Println("target policy's managed rules are identical to those in backup")

				continue
			}

			if output.totalRuleDifferences == 0 {
				fmt.Println("target policy rules are identical to backup")

				continue
			}
		}

		var op string
		if i.CustomRulesOnly {
			op = "custom "
		}

		if i.ManagedRulesOnly {
			op = "managed "
		}

		switch {
		case i.TargetPolicy != "" && !foundExisting:
			// if targeted policy wasn't found, return error
			err = fmt.Errorf("target policy does not exist")

		case i.TargetPolicy != "" && foundExisting && !i.Force:
			// if targeted policy was found, but not forced, then ask before replacing
			if i.TargetPolicy != "" && !confirm(fmt.Sprintf("confirm replacement of %srules in target policy %s", op, i.TargetPolicy),
				fmt.Sprintf("with backup %s\ntaken %v",
					policyBackup.PolicyID,
					policyBackup.Date.Format(time.RFC850),
				)) {

				continue
			}
		case i.TargetPolicy == "" && foundExisting && !i.Force:
			// if non-targeted match found, then ask user if they want to replace rules
			if !confirm(fmt.Sprintf("found an existing policy: %s", matchedExistingPolicy.PolicyID),
				fmt.Sprintf("confirm replacement of %srules with backup taken %v", op, policyBackup.Date.Format(time.RFC850))) {

				continue
			}
		case matchedExistingPolicy.PolicyID == "" && i.ResourceGroup == "":
			// if we need to create a new policy we need a resource group to be specified
			err = fmt.Errorf("unable to create new policy without specifying its resource group")

		default:
			err = fmt.Errorf("unexpected restore operation")
		}

		if err != nil {
			return
		}

		// policy is either:
		// - existing and user confirmed replacement
		// - existing and user chose to force apply
		// - new, and safe to apply
		policyToRestore := generatePolicyToRestore(matchedExistingPolicy, policyBackup, i)

		policiesToRestore = append(policiesToRestore, policyToRestore)
	}

	return
}

// generatePolicyToRestore accepts two policies (original and backup) and options on which parts (custom and or managed rules) to replace
// without options, the original will have both custom and managed rules parts replaced
// options allow for custom or managed rules in original to replaced with those in backup
func generatePolicyToRestore(existing WrappedPolicy, backup WrappedPolicy, i RestorePoliciesInput) WrappedPolicy {
	// if there isn't an existing policy, then just add backup
	if existing.PolicyID == "" {
		return WrappedPolicy{
			SubscriptionID: i.SubscriptionID,
			ResourceGroup:  i.ResourceGroup,
			Name:           backup.Name,
			Policy:         backup.Policy,
		}
	}

	switch {
	case i.CustomRulesOnly:
		existing.Policy.CustomRules.Rules = backup.Policy.CustomRules.Rules
		rID := ParseResourceID(existing.PolicyID)

		return WrappedPolicy{
			SubscriptionID: rID.SubscriptionID,
			ResourceGroup:  rID.ResourceGroup,
			Name:           rID.Name,
			Policy:         existing.Policy,
			PolicyID:       existing.PolicyID,
		}
	case i.ManagedRulesOnly:
		if backup.Policy.ManagedRules == nil {
			existing.Policy.ManagedRules = nil
		} else {
			existing.Policy.ManagedRules = backup.Policy.ManagedRules
		}

		rID := ParseResourceID(existing.PolicyID)

		return WrappedPolicy{
			SubscriptionID: rID.SubscriptionID,
			ResourceGroup:  rID.ResourceGroup,
			Name:           rID.Name,
			Policy:         existing.Policy,
			PolicyID:       existing.PolicyID,
		}
	default:
		// if both original and backup are provided, then return original with both custom and managed rules replaced
		rID := ParseResourceID(existing.PolicyID)
		existing.Policy.CustomRules = backup.Policy.CustomRules
		existing.Policy.ManagedRules = backup.Policy.ManagedRules

		return WrappedPolicy{
			SubscriptionID: rID.SubscriptionID,
			ResourceGroup:  rID.ResourceGroup,
			Name:           rID.Name,
			Policy:         existing.Policy,
			PolicyID:       existing.PolicyID,
		}
	}
}

type WrappedPolicy struct {
	Date           time.Time
	SubscriptionID string
	ResourceGroup  string
	Name           string
	Policy         frontdoor.WebApplicationFirewallPolicy
	PolicyID       string
	AppVersion     string
}

type generatePolicyPatchInput struct {
	original interface{}
	new      frontdoor.WebApplicationFirewallPolicy
}

type generatePolicyPatchOutput struct {
	totalDifferences        int
	totalRuleDifferences    int
	customRuleAdditions     int
	customRuleChanges       int
	customRuleRemovals      int
	customRuleReplacements  int
	managedRuleChanges      int
	managedRuleAdditions    int
	managedRuleRemovals     int
	managedRuleReplacements int
}

func generatePolicyPatch(i generatePolicyPatchInput) (output generatePolicyPatchOutput, err error) {
	var originalBytes []byte
	switch i.original.(type) {
	case []byte:
		originalBytes = i.original.([]byte)
	case frontdoor.WebApplicationFirewallPolicy:
		originalBytes, err = json.Marshal(i.original)
		if err != nil {
			return output, tracerr.Wrap(err)
		}
	case WrappedPolicy:
		wp := i.original.(WrappedPolicy)
		originalBytes, err = json.Marshal(wp.Policy)
		if err != nil {
			return output, tracerr.Wrap(err)
		}
	default:
		return output, tracerr.Errorf("unexpected type: %s", reflect.TypeOf(i.original).String())
	}

	// sort new custom rules by priority to match existing order
	sortRules(*i.new.CustomRules.Rules)
	newPolicyJSON, err := json.MarshalIndent(i.new, "", "    ")
	if err != nil {
		return output, tracerr.Wrap(err)
	}

	var patch jsondiff.Patch
	patch, err = jsondiff.CompareJSON(originalBytes, newPolicyJSON)
	if err != nil {
		return output, tracerr.Wrap(err)
	}

	logrus.Tracef("%+v\n", patch)

	output.totalDifferences = len(patch)

	for _, op := range patch {
		switch op.Type {
		case "add":
			if strings.HasPrefix(string(op.Path), "/properties/customRules/") {
				output.customRuleAdditions++
			}

			if strings.HasPrefix(string(op.Path), "/properties/managedRules/") {
				output.managedRuleAdditions++
			}
		case "remove":
			if strings.HasPrefix(string(op.Path), "/properties/customRules/") {
				output.customRuleRemovals++
			}

			if strings.HasPrefix(string(op.Path), "/properties/managedRules/") {
				output.managedRuleRemovals++
			}
		case "replace":
			if strings.HasPrefix(string(op.Path), "/properties/customRules/") {
				output.customRuleReplacements++
			}

			if strings.HasPrefix(string(op.Path), "/properties/managedRules/") {
				output.managedRuleReplacements++
			}
		}
	}

	output.customRuleChanges = output.customRuleAdditions + output.customRuleRemovals + output.customRuleReplacements
	output.managedRuleChanges = output.managedRuleAdditions + output.managedRuleRemovals + output.managedRuleReplacements
	output.totalRuleDifferences = output.customRuleChanges + output.managedRuleChanges

	logrus.Debugf("output: %+v\n", output)

	return
}

func sortRules(customRules []frontdoor.CustomRule) {
	sort.Slice(customRules, func(i, j int) bool {
		return *customRules[i].Priority < *customRules[j].Priority
	})
}
