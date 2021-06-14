package node

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/stretchr/testify/require"
)

// TestWrapper initializes an AEAD wrapping.Wrapper for testing
func TestWrapper(t *testing.T) wrapping.Wrapper {
	t.Helper()
	require := require.New(t)
	rootKey := make([]byte, 32)
	n, err := rand.Read(rootKey)
	require.NoErrorf(err, "unable to read random data for test wrapper")
	require.Equalf(n, 32, "random data for test wrapper is not the proper length of 32 bytes")

	root := aead.NewWrapper(nil)
	_, err = root.SetConfig(map[string]string{
		"key_id": base64.StdEncoding.EncodeToString(rootKey),
	})
	require.NoErrorf(err, "unable to encode key for wrapper")

	err = root.SetAESGCMKeyBytes(rootKey)
	require.NoErrorf(err, "unable to set wrapper's key bytes")

	return root
}

// TestMapField defines a const for a field name used for testing TestTaggedMap
const TestMapField = "foo"

// TestTaggedMap is a map that implements the Taggable interface for testing
type TestTaggedMap map[string]interface{}

// Tags implements the taggable interface for the TestTaggedMap type
func (t TestTaggedMap) Tags() ([]PointerTag, error) {
	return []PointerTag{
		{
			Pointer:        "/" + TestMapField,
			Classification: SecretClassification,
			Filter:         RedactOperation,
		},
	}, nil
}