package node_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/observability/events/node"
	"github.com/hashicorp/eventlogger"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestAuditEncryptFilter_Process(t *testing.T) {
	ctx := context.Background()
	wrapper := node.TestWrapper(t)
	now := time.Now()
	testEncryptingFilter := &node.AuditEncryptFilter{
		Wrapper:       wrapper,
		HmacSalt:      []byte("salt"),
		HmacInfo:      []byte("info"),
		EncryptFields: true,
	}

	tests := []struct {
		name            string
		filter          *node.AuditEncryptFilter
		testEvent       *eventlogger.Event
		wantEvent       *eventlogger.Event
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:   "simple",
			filter: testEncryptingFilter,
			testEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &testPayload{
					UserInfo: &testUserInfo{
						Id:           "id-12",
						UserFullName: "Alice Eve Doe",
					},
					Keys: [][]byte{[]byte("key1"), []byte("key2")},
				},
			},
			wantEvent: &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload: &testPayload{
					UserInfo: &testUserInfo{
						Id:           "id-12",
						UserFullName: testEncryptValue(t, wrapper, []byte("Alice Eve Doe")),
					},
					Keys: [][]byte{[]byte(node.RedactedData), []byte(node.RedactedData)},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := tt.filter.Process(ctx, tt.testEvent)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				if tt.wantErrIs != nil {
					assert.ErrorIs(err, eventlogger.ErrInvalidParameter)
				}

				return
			}
			require.NoError(err)
			assert.Equal(tt.wantEvent, got)
		})
	}
}

func testEncryptValue(t *testing.T, w wrapping.Wrapper, value []byte) string {
	t.Helper()
	require := require.New(t)
	blobInfo, err := w.Encrypt(context.Background(), value, nil)
	require.NoError(err)
	marshaledBlob, err := proto.Marshal(blobInfo)
	require.NoError(err)
	return "encrypted:" + base64.RawURLEncoding.EncodeToString(marshaledBlob)
}

type testUserInfo struct {
	Id             string `classified:"public"`
	UserFullName   string `classified:"sensitive"`
	LoginTimestamp time.Time
}

type testPayload struct {
	UserInfo *testUserInfo
	Keys     [][]byte `classified:"secret"`
}