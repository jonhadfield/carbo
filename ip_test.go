package carbo

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// func prefixFromAction(action string) (prefix string, err error) {
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
	r, err := prefixFromAction("Block")
	require.NoError(t, err)
	require.Equal(t, BlockNetsPrefix, r)

	r, err = prefixFromAction("Allow")
	require.NoError(t, err)
	require.Equal(t, AllowNetsPrefix, r)

	r, err = prefixFromAction("Log")
	require.NoError(t, err)
	require.Equal(t, LogNetsPrefix, r)

	r, err = prefixFromAction("Deny")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected action")
	require.Equal(t, "", r)
}
