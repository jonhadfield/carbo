package carbo

import (
	"fmt"
	"github.com/jonhadfield/carbo/helpers"
	"github.com/jonhadfield/carbo/policy"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/ztrue/tracerr"
)

// CopyRulesInput are the arguments provided to the CopyRules function.
type CopyRulesInput struct {
	SubscriptionID   string
	Source           string
	Target           string
	CustomRulesOnly  bool
	ManagedRulesOnly bool
	Async            bool
	Quiet            bool
}

// CopyRules copies managed and custom rules between policies
func CopyRules(i CopyRulesInput) error {
	if strings.EqualFold(i.Source, i.Target) {
		return fmt.Errorf("source and target must be different")
	}

	s := policy.Session{}

	if err := helpers.ValidateResourceID(i.Source, false); err != nil {
		return err
	}

	if err := helpers.ValidateResourceID(i.Target, false); err != nil {
		return err
	}

	logrus.Debug("copy source: ", i.Source)
	logrus.Debug("copy target: ", i.Target)
	src := policy.ParseResourceID(i.Source)
	trc := policy.ParseResourceID(i.Target)

	sourcePolicy, err := s.GetWrappedPolicies(policy.GetWrappedPoliciesInput{
		SubscriptionID:    src.SubscriptionID,
		FilterResourceIDs: []string{src.Raw},
	})
	if err != nil {
		return err
	}
	if len(sourcePolicy.Policies) == 0 {
		return tracerr.New("source policy not found")
	}

	targetPolicy, err := s.GetWrappedPolicies(policy.GetWrappedPoliciesInput{
		SubscriptionID:    trc.SubscriptionID,
		FilterResourceIDs: []string{trc.Raw},
	})
	if err != nil {
		return err
	}
	if len(targetPolicy.Policies) == 0 {
		return tracerr.New("target policy not found")
	}

	// check change is required
	o, err := policy.GeneratePolicyPatch(policy.GeneratePolicyPatchInput{
		Original: sourcePolicy.Policies[0].Policy,
		New:      targetPolicy.Policies[0].Policy,
	})
	if err != nil {
		return err
	}

	switch {
	case o.CustomRuleChanges == 0 && i.CustomRulesOnly:
		return fmt.Errorf("custom rules are already identical")
	case o.ManagedRuleChanges == 0 && i.ManagedRulesOnly:
		return fmt.Errorf("managed rules are already identical")
	case o.TotalRuleDifferences == 0:
		return fmt.Errorf("rules are already identical")
	}

	updatedTarget := copyRules(sourcePolicy.Policies[0], targetPolicy.Policies[0], i.CustomRulesOnly, i.ManagedRulesOnly)

	return s.PushPolicy(policy.PushPolicyInput{
		Name:          updatedTarget.Name,
		Subscription:  updatedTarget.SubscriptionID,
		ResourceGroup: updatedTarget.ResourceGroup,
		Policy:        updatedTarget.Policy,
		Async:         i.Async,
	})
}

// copyRules takes two policies and copies the chosen sections from source to the target
func copyRules(source, target policy.WrappedPolicy, customRulesOnly, managedRulesOnly bool) policy.WrappedPolicy {
	switch {
	case customRulesOnly:
		target.Policy.CustomRules = source.Policy.CustomRules
	case managedRulesOnly:
		target.Policy.ManagedRules = source.Policy.ManagedRules
	default:
		target.Policy.CustomRules = source.Policy.CustomRules
		target.Policy.ManagedRules = source.Policy.ManagedRules
	}

	return target
}
