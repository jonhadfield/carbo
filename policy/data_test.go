package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadWrappedPolicyFromFile(t *testing.T) {
	wp, err := LoadWrappedPolicyFromFile("testfiles/wrapped-policy-one.json")
	require.NoError(t, err)
	require.Equal(t, "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/mypolicyone", wp.PolicyID)

	_, err = LoadWrappedPolicyFromFile("testfiles/non-existant-wrapped-policy-one.json")
	require.Error(t, err)
}

func TestLoadValidActionsFromPath(t *testing.T) {
	as, err := LoadActionsFromPath("testfiles/actions-one.yaml")
	require.NoError(t, err)

	for x := range as {
		switch x {
		case 0:
			require.Equal(t, "log", as[x].ActionType)
			require.Equal(t, 2, as[x].MaxRules)
			require.Equal(t, "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/lemon", as[x].Policy)
			require.Equal(t, "testfiles/ipsets/block-list-one.ipset", as[x].Paths[0])
			require.Equal(t, "testfiles/ipsets/block-list-two.ipset", as[x].Paths[1])
			require.Len(t, as[x].Nets, 1870)
		case 1:
			require.Equal(t, "block", as[x].ActionType)
			require.Equal(t, 3, as[x].MaxRules)
			require.Equal(t, "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/apple", as[x].Policy)
			require.Equal(t, "testfiles/ipsets/sslproxies_7d.ipset", as[x].Paths[0])
			// 2446 but the last IP is duplicated, so 2445 should be loaded after deduplication
			require.Len(t, as[x].Nets, 2445)
		case 2:
			require.Equal(t, "allow", as[x].ActionType)
			require.Equal(t, 4, as[x].MaxRules)
			require.Equal(t, "/subscriptions/0a914e76-4921-4c19-b460-a2d36003525a/resourceGroups/flying/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/banana", as[x].Policy)
			require.Equal(t, "testfiles/ipsets/allow-list-one.ipset", as[x].Paths[0])
			require.Equal(t, "testfiles/ipsets/block-list-two.ipset", as[x].Paths[1])
			require.Len(t, as[x].Nets, 1900)
		}
	}
}

func TestLoadInvalidActionsPath(t *testing.T) {
	_, err := LoadActionsFromPath("testfiles/does-not-exist.yaml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no such file")
}

func TestValidActionsFromPathWithInvalidIP(t *testing.T) {
	_, err := LoadActionsFromPath("testfiles/actions-two.yaml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid CIDR")
	require.Contains(t, err.Error(), "64.238.183.333")
}
