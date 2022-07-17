package helpers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStringInSlice(t *testing.T) {
	// without case-insensitive match
	require.True(t, StringInSlice("test", []string{"apple", "lemon", "test"}, false))
	// without case-insensitive match and no match
	require.False(t, StringInSlice("test", []string{"apple", "lemon", "Test"}, false))
	// check string in slice with sensitive match
	require.True(t, StringInSlice("test", []string{"apple", "lemon", "Test"}, true))
	// check string in slice with sensitive match, different order
	require.True(t, StringInSlice("tesT", []string{"apple", "Test", "lemon"}, true))
}
