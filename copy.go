package carbo

import (
	"fmt"
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

	s := session{}

	if err := ValidateResourceID(i.Source, false); err != nil {
		return err
	}

	if err := ValidateResourceID(i.Target, false); err != nil {
		return err
	}

	logrus.Debug("copy source: ", i.Source)
	logrus.Debug("copy target: ", i.Target)
	src := ParseResourceID(i.Source)
	trc := ParseResourceID(i.Target)

	sourcePolicy, err := s.getWrappedPolicies(getWrappedPoliciesInput{
		subscriptionID:    src.SubscriptionID,
		filterResourceIDs: []string{src.Raw},
	})
	if err != nil {
		return err
	}
	if len(sourcePolicy.policies) == 0 {
		return tracerr.New("source policy not found")
	}

	targetPolicy, err := s.getWrappedPolicies(getWrappedPoliciesInput{
		subscriptionID:    trc.SubscriptionID,
		filterResourceIDs: []string{trc.Raw},
	})
	if err != nil {
		return err
	}
	if len(targetPolicy.policies) == 0 {
		return tracerr.New("target policy not found")
	}

	// check change is required
	o, err := generatePolicyPatch(generatePolicyPatchInput{
		original: sourcePolicy.policies[0].Policy,
		new:      targetPolicy.policies[0].Policy,
	})
	if err != nil {
		return err
	}

	switch {
	case o.customRuleChanges == 0 && i.CustomRulesOnly:
		return fmt.Errorf("custom rules are already identical")
	case o.managedRuleChanges == 0 && i.ManagedRulesOnly:
		return fmt.Errorf("managed rules are already identical")
	case o.totalRuleDifferences == 0:
		return fmt.Errorf("rules are already identical")
	}

	updatedTarget := copyRules(sourcePolicy.policies[0], targetPolicy.policies[0], i.CustomRulesOnly, i.ManagedRulesOnly)

	return s.pushPolicy(pushPolicyInput{
		Name:          updatedTarget.Name,
		subscription:  updatedTarget.SubscriptionID,
		resourceGroup: updatedTarget.ResourceGroup,
		policy:        updatedTarget.Policy,
		Async:         i.Async,
	})
}

// copyRules takes two policies and copies the chosen sections from source to the target
func copyRules(source, target WrappedPolicy, customRulesOnly, managedRulesOnly bool) WrappedPolicy {
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
