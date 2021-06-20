package carbo

import (
	"reflect"
	"testing"

	_ "github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"

	"github.com/stretchr/testify/require"
)

func TestMatchExistingPolicyByID(t *testing.T) {
	wp, err := loadWrappedPolicyFromFile("testfiles/wrapped-policy-one.json")
	require.NoError(t, err)
	targetPolicyID := "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicyone"
	found, policy := matchExistingPolicyByID(targetPolicyID, []WrappedPolicy{wp})
	require.True(t, found)
	require.NotNil(t, policy)
}

func TestGeneratePolicyToRestoreBackupOnly(t *testing.T) {
	policyTwo, err := loadWrappedPolicyFromFile("testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	policyTwoStatic, err := loadWrappedPolicyFromFile("testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	// test that if only backup provided, that backup is returned
	generatedPolicyOne := generatePolicyToRestore(WrappedPolicy{}, policyTwo, RestorePoliciesInput{})
	require.NotNil(t, generatedPolicyOne)
	require.True(t, reflect.DeepEqual(generatedPolicyOne.Policy, policyTwoStatic.Policy))
}

func TestGeneratePolicyToRestoreBackupWithoutOptions(t *testing.T) {
	policyOne, err := loadWrappedPolicyFromFile("testfiles/wrapped-policy-one.json")
	require.NoError(t, err)
	policyTwo, err := loadWrappedPolicyFromFile("testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	policyTwoStatic, err := loadWrappedPolicyFromFile("testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	// test that providing two policies without options returns original with backup rules replacing original's
	generatedPolicyTwo := generatePolicyToRestore(policyOne, policyTwo, RestorePoliciesInput{})
	require.NotNil(t, generatedPolicyTwo)
	require.True(t, reflect.DeepEqual(generatedPolicyTwo.Policy, policyTwoStatic.Policy))
}

func TestGeneratePolicyToRestoreBackupCustomOnly(t *testing.T) {
	policyOne, err := loadWrappedPolicyFromFile("testfiles/wrapped-policy-one.json")
	require.NoError(t, err)
	policyTwo, err := loadWrappedPolicyFromFile("testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	policyOneStatic, err := loadWrappedPolicyFromFile("testfiles/wrapped-policy-one.json")
	require.NoError(t, err)
	policyTwoStatic, err := loadWrappedPolicyFromFile("testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	// test that providing two policies (with both different custom rules and managed rules) with option to only replace
	// custom rules with backup's custom rules
	generatedPolicyThree := generatePolicyToRestore(policyOne, policyTwo, RestorePoliciesInput{
		CustomRulesOnly: true,
	})

	require.NotNil(t, generatedPolicyThree)
	// generated policy's custom rules should be identical to policy two's
	require.True(t, reflect.DeepEqual(generatedPolicyThree.Policy.CustomRules, policyTwoStatic.Policy.CustomRules))
	// generated policy's custom rules should be different from policy one's custom rules
	require.False(t, reflect.DeepEqual(generatedPolicyThree.Policy.CustomRules, policyOneStatic.Policy.CustomRules))
	// generated policy's managed rules should still be the same as policy one's, i.e. not replaced
	require.True(t, reflect.DeepEqual(generatedPolicyThree.Policy.ManagedRules, policyOneStatic.Policy.ManagedRules))
	// generated policy's managed rules should still be different from policy two's
	require.False(t, reflect.DeepEqual(generatedPolicyThree.Policy.ManagedRules, policyTwoStatic.Policy.ManagedRules))
}

func TestGeneratePolicyToRestoreBackupManagedOnly(t *testing.T) {
	policyOne, err := loadWrappedPolicyFromFile("testfiles/wrapped-policy-one.json")
	require.NoError(t, err)
	policyTwo, err := loadWrappedPolicyFromFile("testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	policyOneStatic, err := loadWrappedPolicyFromFile("testfiles/wrapped-policy-one.json")
	require.NoError(t, err)
	policyTwoStatic, err := loadWrappedPolicyFromFile("testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	// test that providing two policies (with both different custom rules and managed rules) with option to only replace
	// custom rules with backup's custom rules
	generatedPolicyThree := generatePolicyToRestore(policyOne, policyTwo, RestorePoliciesInput{
		ManagedRulesOnly: true,
	})

	require.NotNil(t, generatedPolicyThree)
	// generated policy's custom rules should be identical to policy one's
	require.True(t, reflect.DeepEqual(generatedPolicyThree.Policy.CustomRules, policyOneStatic.Policy.CustomRules))
	// generated policy's custom rules should be different from policy two's custom rules
	require.False(t, reflect.DeepEqual(generatedPolicyThree.Policy.CustomRules, policyTwoStatic.Policy.CustomRules))
	// generated policy's managed rules should be the same as policy two's, i.e. replaced
	require.True(t, reflect.DeepEqual(generatedPolicyThree.Policy.ManagedRules, policyTwoStatic.Policy.ManagedRules))
	// generated policy's managed rules should be different from policy one's
	require.False(t, reflect.DeepEqual(generatedPolicyThree.Policy.ManagedRules, policyOneStatic.Policy.ManagedRules))
}

// TestGeneratePolicyPatch compares two policies and checks that the differences match the operations:
// {"op":"remove","path":"/properties/customRules/rules/0/matchConditions/0/matchValue/1"}
// {"op":"remove","path":"/properties/customRules/rules/1/matchConditions/0/matchValue/1"}
// {"op":"replace","path":"/properties/managedRules/managedRuleSets/0/ruleGroupOverrides/0/rules/1/exclusions/0/selector","value":"example"}
func TestGeneratePolicyPatch(t *testing.T) {
	pOne, err := loadWrappedPolicyFromFile("testfiles/wrapped-policy-one.json")
	require.NoError(t, err)

	pTwo, err := loadWrappedPolicyFromFile("testfiles/wrapped-policy-two.json")
	require.NoError(t, err)

	patch, err := generatePolicyPatch(generatePolicyPatchInput{
		original: pOne,
		new:      pTwo.Policy,
	})

	require.NoError(t, err)
	require.Equal(t, 4, patch.totalRuleDifferences)
	require.Equal(t, 3, patch.customRuleChanges)
	require.Equal(t, 2, patch.customRuleRemovals)
	require.Equal(t, 1, patch.managedRuleChanges)
	require.Equal(t, 0, patch.customRuleReplacements)
	require.Equal(t, 1, patch.managedRuleReplacements)
}
