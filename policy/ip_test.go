package policy

import (
	"github.com/jonhadfield/carbo/helpers"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// func PrefixFromAction(action string) (prefix string, err error) {
//	switch action {
//	case "Block":
//		return BlockNetsPrefix, nil
//	case "Allow":
//		return AllowNetsPrefix, nil
//	case "Log":
//		return LogNetsPrefix, nil
//	default:
//		return "", fmt.Errorf("unexpected action: %s", action)
//	}
// }

func TestPrefixFromAction(t *testing.T) {
	r, err := helpers.PrefixFromAction("Block")
	require.NoError(t, err)
	require.Equal(t, helpers.BlockNetsPrefix, r)

	r, err = helpers.PrefixFromAction("Allow")
	require.NoError(t, err)
	require.Equal(t, helpers.AllowNetsPrefix, r)

	r, err = helpers.PrefixFromAction("Log")
	require.NoError(t, err)
	require.Equal(t, helpers.LogNetsPrefix, r)

	r, err = helpers.PrefixFromAction("Deny")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected action")
	require.Equal(t, "", r)
}

func TestGenCustomRulesFromIPNets(t *testing.T) {
	r, err := helpers.PrefixFromAction("Block")
	require.NoError(t, err)
	require.Equal(t, helpers.BlockNetsPrefix, r)
	// var ipns IPNets
	ipns, err := LoadIPsFromPath(filepath.Join("testdata", "ten-ips.txt"))
	require.NoError(t, err)

	// Block testing
	crs, err := GenCustomRulesFromIPNets(ipns, 10, "Block")
	require.NoError(t, err)
	require.Len(t, crs, 10)

	crs, err = GenCustomRulesFromIPNets(ipns, 5, "Block")
	require.NoError(t, err)
	require.Len(t, crs, 5)

	// Allow testing
	crs, err = GenCustomRulesFromIPNets(ipns, 10, "Allow")
	require.NoError(t, err)
	require.Len(t, crs, 10)

	crs, err = GenCustomRulesFromIPNets(ipns, 5, "Allow")
	require.NoError(t, err)
	require.Len(t, crs, 5)

	// Log testing
	crs, err = GenCustomRulesFromIPNets(ipns, 10, "Log")
	require.NoError(t, err)
	require.Len(t, crs, 10)

	crs, err = GenCustomRulesFromIPNets(ipns, 5, "Log")
	require.NoError(t, err)
	require.Len(t, crs, 5)
}

