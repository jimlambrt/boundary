package servers

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Test RootCertificate storage, using transactional storage
func TestStoreRootCertificates(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsCache := kms.TestKms(t, conn, wrapper)
	// Ensures the global scope contains a valid root key
	err := kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(err)
	wrapper, err = kmsCache.GetWrapper(context.Background(), scope.Global.String(), kms.KeyPurposeDatabase)
	require.NoError(err)
	require.NotNil(wrapper)

	rw := db.New(conn)
	workerAuthRepo, err := NewRepositoryStorage(ctx, rw, rw, kmsCache, (*store.Worker)(nil), true)
	require.NoError(err)

	// Rotate will generate and store next and current, as we have none
	roots, err := rotation.RotateRootCertificates(ctx, workerAuthRepo)
	require.NoError(err)
	rootIds, err := workerAuthRepo.List(ctx, (*types.RootCertificate)(nil))
	require.NoError(err)
	assert.Len(rootIds, 2)

	// Read the next cert and validate the stored values are valid after encrypt and decrypt
	nextCert := &types.RootCertificate{Id: "next"}
	err = workerAuthRepo.Load(ctx, nextCert)
	require.NoError(err)
	assert.Equal(roots.Next.PrivateKeyPkcs8, nextCert.PrivateKeyPkcs8)

	// Red the current cert and validate the stored values are valid after encrypt and decrypt
	currentCert := &types.RootCertificate{Id: "current"}
	err = workerAuthRepo.Load(ctx, currentCert)
	require.NoError(err)
	assert.Equal(roots.Current.PrivateKeyPkcs8, currentCert.PrivateKeyPkcs8)

	// Remove next
	require.NoError(workerAuthRepo.Remove(ctx, &types.RootCertificate{Id: "next"}))
	rootIds, err = workerAuthRepo.List(ctx, (*types.RootCertificate)(nil))
	require.NoError(err)
	assert.Len(rootIds, 1)

	// Rotate again; next should be regenerated
	_, err = rotation.RotateRootCertificates(ctx, workerAuthRepo)
	require.NoError(err)
	rootIds, err = workerAuthRepo.List(ctx, (*types.RootCertificate)(nil))
	require.NoError(err)
	assert.Len(rootIds, 2)

	// Flush storage
	err = workerAuthRepo.Flush(true)
	require.NoError(err)
}

// Test WorkerAuth storage, using non-transactional storage
func TestStoreWorkerAuth(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsCache := kms.TestKms(t, conn, wrapper)

	// Ensures the global scope contains a valid root key
	err := kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(err)
	wrapper, err = kmsCache.GetWrapper(context.Background(), scope.Global.String(), kms.KeyPurposeDatabase)
	require.NoError(err)
	require.NotNil(wrapper)

	rw := db.New(conn)
	rootStorage, err := NewRepositoryStorage(ctx, rw, rw, kmsCache, (*store.Worker)(nil), false)
	require.NoError(err)

	_, err = rotation.RotateRootCertificates(ctx, rootStorage)
	require.NoError(err)

	worker := TestWorker(t, conn, wrapper)

	// This happens on the worker
	fileStorage, err := file.NewFileStorage(ctx)
	require.NoError(err)
	nodeCreds, err := types.NewNodeCredentials(ctx, fileStorage)
	require.NoError(err)
	keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
	require.NoError(err)
	nodePubKey, err := curve25519.X25519(nodeCreds.EncryptionPrivateKeyBytes, curve25519.Basepoint)
	require.NoError(err)

	// Add in node information to storage so we have a key to use
	nodeInfo := &types.NodeInformation{
		Id:                       keyId,
		CertificatePublicKeyPkix: nodeCreds.CertificatePublicKeyPkix,
		CertificatePublicKeyType: nodeCreds.CertificatePrivateKeyType,
		EncryptionPublicKeyBytes: nodePubKey,
		EncryptionPublicKeyType:  nodeCreds.EncryptionPrivateKeyType,
		RegistrationNonce:        nodeCreds.RegistrationNonce,
		FirstSeen:                timestamppb.Now(),
	}
	registrationCache := new(nodeenrollment.TestCache)
	registrationCache.Set(nodeInfo.Id, nodeInfo)

	// Create storage for authentication and pass it the worker
	storage, err := NewRepositoryStorage(ctx, rw, rw, kmsCache, worker.Worker, false)
	require.NoError(err)

	// The AuthorizeNode request will result in a WorkerAuth record being stored
	require.NoError(registration.AuthorizeNode(ctx, storage, keyId, nodeenrollment.WithRegistrationCache(registrationCache)))

	// We should now look for a node information value in storage and validate that it's populated
	nodeInfos, err := storage.List(ctx, (*types.NodeInformation)(nil))
	require.NoError(err)
	require.NotEmpty(nodeInfos)
	assert.Len(nodeInfos, 1)

	// Validate the stored fields match those from the worker
	nodeLookup := &types.NodeInformation{
		Id: keyId,
	}
	err = storage.Load(ctx, nodeLookup)
	require.NoError(err)
	assert.NotEmpty(nodeLookup)
	assert.Equal(nodeInfo.EncryptionPublicKeyBytes, nodeLookup.EncryptionPublicKeyBytes)
	assert.Equal(nodeInfo.RegistrationNonce, nodeLookup.RegistrationNonce)
	assert.Equal(nodeInfo.CertificatePublicKeyPkix, nodeLookup.CertificatePublicKeyPkix)

	// Remove node
	err = storage.Remove(ctx, nodeLookup)
	require.NoError(err)
	err = storage.Load(ctx, nodeLookup)
	require.Error(err)
}

func TestUnsupportedMessages(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsCache := kms.TestKms(t, conn, wrapper)

	rw := db.New(conn)
	storage, err := NewRepositoryStorage(ctx, rw, rw, kmsCache, (*store.Worker)(nil), false)
	require.NoError(err)

	err = storage.Store(ctx, &types.NodeCredentials{})
	require.Error(err)

	err = storage.Load(ctx, &types.NodeCredentials{Id: "bogus"})
	require.Error(err)

	_, err = storage.List(ctx, (*types.NodeCredentials)(nil))
	require.Error(err)

	err = storage.Remove(ctx, &types.NodeCredentials{Id: "bogus"})
	require.Error(err)
}
