package carbo

import (
	"github.com/jonhadfield/carbo/helpers"
	"github.com/jonhadfield/carbo/policy"
	"log"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// generateIPNets takes a CIDR and produces a list of IPNets within that range
func generateIPNets(cidr string) (ipns policy.IPNets) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatal(err)
	}

	for ip = ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ipstring := ip.String() + "/32"

		var ipn *net.IPNet
		_, ipn, err = net.ParseCIDR(ipstring)

		if err != nil {
			log.Fatal(err)
		}

		ipns = append(ipns, *ipn)
	}

	if len(ipns) > 0 {
		ipns = ipns[1 : len(ipns)-1]
	}

	return
}

func TestGenerateCustomRulesFromIPNets(t *testing.T) {
	ipns := generateIPNets("10.0.0.0/18")

	require.Len(t, ipns, 16382)

	crs, err := policy.GenCustomRulesFromIPNets(ipns, 90, "Block")
	require.NoError(t, err)
	require.Len(t, crs, 28)

	for x, cr := range crs {
		matchConditions := *cr.MatchConditions
		mc := matchConditions[0]

		for y, mv := range *mc.MatchValue {
			require.Equal(t, ipns[x*helpers.MaxIPMatchValues+y].String(), mv)
		}
	}
}

// Require that setting a positive value for max rules limits the number of rules generated
func TestGenerateCustomRulesFromIPNetsLimitsToMaxRules(t *testing.T) {
	ipns := generateIPNets("10.0.0.0/21")
	require.Len(t, ipns, 2046)

	crs, err := policy.GenCustomRulesFromIPNets(ipns, 3, "Block")
	require.NoError(t, err)

	require.Len(t, crs, 3)
}

// Require that setting a zero value for max rules does not limit the number of rules generated
func TestGenerateCustomRulesFromIPNetsLimitsNotLimitedWhenMaxRulesZero(t *testing.T) {
	ipns := generateIPNets("10.0.0.0/21")
	require.Len(t, ipns, 2046)

	crs, err := policy.GenCustomRulesFromIPNets(ipns, 0, "Block")

	require.NoError(t, err)
	require.Len(t, crs, 4)
}

// Require error if action not recognised
func TestGenerateCustomRulesFromIPNetsWithInvalidAction(t *testing.T) {
	ipns := generateIPNets("10.0.0.0/21")

	require.Len(t, ipns, 2046)
	_, err := policy.GenCustomRulesFromIPNets(ipns, 0, "Blocker")
	require.Error(t, err)
}
