package carbo

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStringInSlice(t *testing.T) {
	// without case-insensitive match
	require.True(t, stringInSlice("test", []string{"apple", "lemon", "test"}, false))
	// without case-insensitive match and no match
	require.False(t, stringInSlice("test", []string{"apple", "lemon", "Test"}, false))
	// check string in slice with sensitive match
	require.True(t, stringInSlice("test", []string{"apple", "lemon", "Test"}, true))
	// check string in slice with sensitive match, different order
	require.True(t, stringInSlice("tesT", []string{"apple", "Test", "lemon"}, true))
}
