package servers

import (
	"context"
	"crypto/x509"
	"database/sql"
	"fmt"
	"strconv"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/proto"
)

// Ensure we implement the Storage interfaces
var (
	_ nodee.Storage              = (*WorkerAuthRepositoryStorage)(nil)
	_ nodee.TransactionalStorage = (*WorkerAuthRepositoryStorage)(nil)
)

// WorkerAuthRepositoryStorage is the Worker Auth database repository
type WorkerAuthRepositoryStorage struct {
	reader                db.Reader
	writer                db.Writer
	kms                   *kms.Kms
	worker                *store.Worker
	workerAuthTransaction *WorkerAuthTransaction
}

type WorkerAuthTransaction struct {
	transactionWriter *db.Db
	transaction       *dbw.RW
}

// NewRepositoryStoragecreates a new Worker Auth WorkerAuthRepositoryStorage that implements the Storage interface
// If used to authenticate and store a workerAuth record, a worker must be passed
// If transactional is set to true, all operations conducted in the lifetime of this storage instance are executed
// within the context of a single transaction; Flush must be called to either commit or rollback this transaction
func NewRepositoryStorage(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, wrk *store.Worker, transactional bool) (*WorkerAuthRepositoryStorage, error) {
	const op = "workerauth.NewRepository"
	if r == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil reader")
	}
	if w == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil writer")
	}
	if kms == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil kms")
	}

	workerAuthRepoStorage := &WorkerAuthRepositoryStorage{
		reader:                r,
		writer:                w,
		kms:                   kms,
		worker:                wrk,
		workerAuthTransaction: nil,
	}

	if transactional {
		workerTransaction, err := createTransaction(ctx, w)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		workerAuthRepoStorage.workerAuthTransaction = workerTransaction
	}

	return workerAuthRepoStorage, nil
}

func createTransaction(ctx context.Context, w db.Writer) (*WorkerAuthTransaction, error) {
	const op = "workerauth.(WorkerAuthRepositoryStorage).createTransaction"
	txWriter, transaction, err := w.BeginTx(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	workerTransaction := &WorkerAuthTransaction{
		transactionWriter: txWriter,
		transaction:       transaction,
	}

	return workerTransaction, nil
}

// Flush is called when storage is done being performed. The boolean parameter
// indicates whether the operation was successful (true) or failed (false).
func (r *WorkerAuthRepositoryStorage) Flush(b bool) error {
	const op = "workerauth.(WorkerAuthRepositoryStorage).Flush"
	if r.workerAuthTransaction == nil {
		return nil
	}
	if b == false {
		err := r.workerAuthTransaction.transaction.Rollback(nil)
		if err != nil {
			return fmt.Errorf("(%s) Transaction rollback failed: %w", op, err)
		}
	} else {
		err := r.workerAuthTransaction.transaction.Commit(nil)
		if err != nil {
			return fmt.Errorf("(%s) Transaction commit failed: %w", op, err)
		}
	}
	return nil
}

// Store implements the Storage interface
func (r *WorkerAuthRepositoryStorage) Store(ctx context.Context, msg nodee.MessageWithId) error {
	const op = "workerauth.(WorkerAuthRepositoryStorage).Store"
	if err := types.ValidateMessage(msg); err != nil {
		return fmt.Errorf("(%s) given message cannot be stored: %w", op, err)
	}
	if msg.GetId() == "" {
		return fmt.Errorf("(%s) given message cannot be stored as it has no ID.", op)
	}

	// Determine type of message to store
	marshaledBytes, err := proto.Marshal(msg.(proto.Message))
	if err != nil {
		return fmt.Errorf("error marshaling nodee.MessageWithId: %w", err)
	}
	switch msg.(type) {
	case *types.NodeInformation:
		node, err := unmarshalNodeInformation(ctx, marshaledBytes)
		if err != nil {
			return err
		}
		err = r.storeNodeInformation(ctx, node)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
	case *types.RootCertificate:
		cert, err := unmarshalRootCertificate(ctx, marshaledBytes)
		if err != nil {
			return err
		}
		err = r.storeRootCertificate(ctx, cert)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
	default:
		err = fmt.Errorf("(%s) Message type not supported for Store", op)
		return errors.Wrap(ctx, err, op)
	}

	return nil
}

// Node information is stored in two parts:
// * the workerAuth record is stored with a reference to a worker
// * certificate bundles are stored with a reference to the workerAuth record and issuing root certificate
func (r *WorkerAuthRepositoryStorage) storeNodeInformation(ctx context.Context, node *types.NodeInformation) error {
	const op = "workerauth.(WorkerAuthRepositoryStorage).storeNodeInformation"

	if r.worker == nil {
		return errors.Wrap(ctx, fmt.Errorf("Cannot store workerAuthentication without a worker reference"), op)
	}

	nodeAuth := AllocWorkerAuth()
	nodeAuth.WorkerKeyIdentifier = node.Id
	nodeAuth.WorkerEncryptionPubKey = node.EncryptionPublicKeyBytes
	nodeAuth.WorkerSigningPubKey = node.CertificatePublicKeyPkix
	nodeAuth.Nonce = node.RegistrationNonce

	// Encrypt the private key
	databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	nodeAuth.KeyId, err = databaseWrapper.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	nodeAuth.ControllerEncryptionPrivKey, err = encrypt(ctx, node.ServerEncryptionPrivateKeyBytes, databaseWrapper)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	nodeAuth.WorkerId = r.worker.PublicId

	err = nodeAuth.ValidateNewWorkerAuth(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	onConflict := &db.OnConflict{
		Target: db.Constraint("worker_auth_authorized_pkey"),
		Action: db.SetColumns([]string{"controller_encryption_priv_key"}),
	}
	if r.workerAuthTransaction != nil {
		// Store WorkerAuth
		if err := r.workerAuthTransaction.transactionWriter.Create(ctx, &nodeAuth, db.WithOnConflict(onConflict)); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		// Then store cert bundles associated with this WorkerAuth
		for _, c := range node.CertificateBundles {
			err := r.storeWorkerCertBundle(ctx, c, nodeAuth.WorkerKeyIdentifier, r.workerAuthTransaction.transactionWriter)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
	} else {
		_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(read db.Reader, w db.Writer) error {
			// Store WorkerAuth
			if err := w.Create(ctx, &nodeAuth, db.WithOnConflict(onConflict)); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			// Then store cert bundles associated with this WorkerAuth
			for _, c := range node.CertificateBundles {
				err := r.storeWorkerCertBundle(ctx, c, nodeAuth.WorkerKeyIdentifier, w)
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
			}
			return nil
		},
		)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}

func (r *WorkerAuthRepositoryStorage) storeWorkerCertBundle(ctx context.Context, bundle *types.CertificateBundle,
	workerKeyIdentifier string, writer db.Writer,
) error {
	const op = "workerauth.(WorkerAuthRepositoryStorage).storeWorkerCertBundle"

	workerCertBundle := AllocWorkerCertBundle()
	bundleBytes, err := proto.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("error marshaling nodetypes.CertificateBundle: %w", err)
	}

	// Extract serial number from CA cert
	caCert := bundle.CaCertificateDer
	parsedCert, err := x509.ParseCertificate(caCert)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	workerCertBundle.CertificatePublicKey = parsedCert.AuthorityKeyId
	workerCertBundle.CertBundle = bundleBytes
	workerCertBundle.WorkerKeyIdentifier = workerKeyIdentifier

	err = workerCertBundle.ValidateNewWorkerCertBundle(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if r.workerAuthTransaction != nil {
		err = r.workerAuthTransaction.transactionWriter.Create(ctx, &workerCertBundle)
	} else {
		err = writer.Create(ctx, &workerCertBundle)
	}
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (r *WorkerAuthRepositoryStorage) storeRootCertificate(ctx context.Context, cert *types.RootCertificate) error {
	const op = "workerauth.(WorkerAuthRepositoryStorage).storeRootCertificate"

	rootCert := AllocRootCertificate()

	parsedCert, err := x509.ParseCertificate(cert.CertificateDer)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	rootCert.SerialNumber = parsedCert.SerialNumber.Uint64()
	rootCert.Certificate = cert.CertificateDer
	rootCert.NotValidAfter = timestamp.New(cert.NotAfter.AsTime())
	rootCert.NotValidBefore = timestamp.New(cert.NotBefore.AsTime())
	rootCert.PublicKey = cert.PublicKeyPkix
	rootCert.State = cert.Id

	// Encrypt the private key
	databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	rootCert.KeyId, err = databaseWrapper.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	rootCert.PrivateKey, err = encrypt(ctx, cert.PrivateKeyPkcs8, databaseWrapper)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	err = rootCert.ValidateNewRootCertificate(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if r.workerAuthTransaction != nil {
		r.removeRootCertificateWithWriter(ctx, cert.Id, r.workerAuthTransaction.transactionWriter)
		if err = r.workerAuthTransaction.transactionWriter.Create(ctx, &rootCert); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	} else {
		_, err = r.writer.DoTx(
			ctx,
			db.StdRetryCnt,
			db.ExpBackoff{},
			func(read db.Reader, w db.Writer) error {
				// Delete the old cert with this id first- there can only ever be one next or current at a time
				r.removeRootCertificateWithWriter(ctx, cert.Id, w)

				// Then insert the new cert
				if err = w.Create(ctx, &rootCert); err != nil {
					return errors.Wrap(ctx, err, op)
				}
				return nil
			},
		)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}

// Load implements the Storage interface.
// Load loads values into the given message. The message must be populated
// with the ID value. If not found, the returned error should be ErrNotFound.
func (r *WorkerAuthRepositoryStorage) Load(ctx context.Context, msg nodee.MessageWithId) error {
	const op = "workerauth.(WorkerAuthRepositoryStorage).Load"
	if err := types.ValidateMessage(msg); err != nil {
		return fmt.Errorf("(%s) given message cannot be loaded: %w", op, err)
	}
	if msg.GetId() == "" {
		return fmt.Errorf("(%s) given message cannot be stored as it has no ID.", op)
	}

	marshaledBytes, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("error marshaling nodee.MessageWithId: %w", err)
	}

	switch msg.(type) {
	case *types.NodeInformation:
		node, err := unmarshalNodeInformation(ctx, marshaledBytes)
		if err != nil {
			return err
		}
		err = r.loadNodeInformation(ctx, node, msg)
		if err != nil {
			return err
		}
	case *types.RootCertificate:
		cert, err := unmarshalRootCertificate(ctx, marshaledBytes)
		if err != nil {
			return err
		}
		err = r.loadRootCertificate(ctx, cert, msg)
		if err != nil {
			return err
		}
	default:
		err = fmt.Errorf("(%s) Message type not supported for Load", op)
		return err
	}

	return nil
}

// Node information is loaded in two parts:
// * the workerAuth record
// * its certificate bundles
func (r *WorkerAuthRepositoryStorage) loadNodeInformation(ctx context.Context, node *types.NodeInformation, result proto.Message) error {
	const op = "workerauth.(WorkerAuthRepositoryStorage).loadNodeInformation"

	authorizedWorker, err := r.findWorkerAuth(ctx, node)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if authorizedWorker == nil {
		node.Authorized = false
		return nodee.ErrNotFound
	}

	node.EncryptionPublicKeyBytes = authorizedWorker.WorkerEncryptionPubKey
	node.CertificatePublicKeyPkix = authorizedWorker.WorkerSigningPubKey
	node.RegistrationNonce = authorizedWorker.Nonce

	// Default values are used for key types
	node.EncryptionPublicKeyType = types.KEYTYPE_KEYTYPE_X25519
	node.CertificatePublicKeyType = types.KEYTYPE_KEYTYPE_ED25519
	node.ServerEncryptionPrivateKeyType = types.KEYTYPE_KEYTYPE_X25519

	// Decrypt private key
	databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase, kms.WithKeyId(authorizedWorker.KeyId))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	node.ServerEncryptionPrivateKeyBytes, err = decrypt(ctx, authorizedWorker.ControllerEncryptionPrivKey, databaseWrapper)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Get cert bundles from the other table
	certBundles, err := r.findCertBundles(ctx, node.Id)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	node.CertificateBundles = certBundles

	node.Authorized = true

	return unmarshalNodeToResult(ctx, node, result)
}

func (r *WorkerAuthRepositoryStorage) findCertBundles(ctx context.Context, workerKeyId string) ([]*types.CertificateBundle, error) {
	const op = "workerauth.(WorkerAuthRepositoryStorage).findCertBundles"

	where := fmt.Sprintf("worker_key_identifier= '%s'", workerKeyId)
	var bundles []*WorkerCertBundle
	var err error
	if r.workerAuthTransaction != nil {
		err = r.workerAuthTransaction.transactionWriter.SearchWhere(ctx, &bundles, where, []interface{}{}, db.WithLimit(-1))
	} else {
		err = r.reader.SearchWhere(ctx, &bundles, where, []interface{}{}, db.WithLimit(-1))
	}
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	certBundle := []*types.CertificateBundle{}
	for _, bundle := range bundles {
		thisBundle := &types.CertificateBundle{}
		if err := proto.Unmarshal(bundle.WorkerCertBundle.CertBundle, thisBundle); err != nil {
			return nil, errors.New(ctx, errors.Decode, op, "error unmarshaling message", errors.WithWrap(err))
		}
		certBundle = append(certBundle, thisBundle)
	}

	return certBundle, nil
}

func (r *WorkerAuthRepositoryStorage) findWorkerAuth(ctx context.Context, node *types.NodeInformation) (*WorkerAuth, error) {
	const op = "workerauth.(WorkerAuthRepositoryStorage).findWorkerAuth"

	worker := AllocWorkerAuth()
	worker.WorkerKeyIdentifier = node.Id
	var err error
	if r.workerAuthTransaction != nil {
		err = r.workerAuthTransaction.transactionWriter.LookupById(ctx, worker)
	} else {
		err = r.reader.LookupById(ctx, worker)
	}
	if err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}

	return worker, nil
}

func (r *WorkerAuthRepositoryStorage) loadRootCertificate(ctx context.Context, cert *types.RootCertificate, result proto.Message) error {
	const op = "workerauth.(WorkerAuthRepositoryStorage).loadRootCertificate"

	rootCertificate := AllocRootCertificate()
	var err error
	if r.workerAuthTransaction != nil {
		err = r.workerAuthTransaction.transactionWriter.SearchWhere(ctx, &rootCertificate, "state = ?",
			[]interface{}{cert.Id}, db.WithLimit(-1))
	} else {
		err = r.reader.SearchWhere(ctx, &rootCertificate, "state = ?", []interface{}{cert.Id}, db.WithLimit(-1))
	}
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if rootCertificate.Certificate == nil {
		return nodee.ErrNotFound
	}

	cert.CertificateDer = rootCertificate.Certificate
	cert.NotAfter = rootCertificate.NotValidAfter.Timestamp
	cert.NotBefore = rootCertificate.NotValidBefore.Timestamp
	cert.PublicKeyPkix = rootCertificate.PublicKey
	cert.PrivateKeyType = types.KEYTYPE_KEYTYPE_ED25519

	// decrypt private key
	databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase, kms.WithKeyId(rootCertificate.KeyId))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	cert.PrivateKeyPkcs8, err = decrypt(ctx, rootCertificate.PrivateKey, databaseWrapper)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	certBytes, err := proto.Marshal(cert)
	if err != nil {
		return errors.New(ctx, errors.Decode, op, "error marshaling RootCertificate", errors.WithWrap(err))
	}
	if err := proto.Unmarshal(certBytes, result); err != nil {
		return errors.New(ctx, errors.Decode, op, "error unmarshaling message", errors.WithWrap(err))
	}

	return nil
}

// Remove implements the Storage interface.
// Remove removes the given message. Only the ID field of the message is considered.
func (r *WorkerAuthRepositoryStorage) Remove(ctx context.Context, msg nodee.MessageWithId) error {
	const op = "workerauth.(WorkerAuthRepositoryStorage).Remove"
	if err := types.ValidateMessage(msg); err != nil {
		return fmt.Errorf("(%s) given message cannot be removed: %w", op, err)
	}

	// Determine type of message to remove
	switch msg.(type) {
	case *types.NodeInformation:
		err := r.removeNodeInformation(ctx, msg.GetId())
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
	case *types.RootCertificate:
		err := r.removeRootCertificate(ctx, msg.GetId())
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
	default:
		return errors.Wrap(ctx, fmt.Errorf("(%s) Message type not supported for Remove", op), op)
	}

	return nil
}

func (r *WorkerAuthRepositoryStorage) removeNodeInformation(ctx context.Context, id string) error {
	const op = "workerauth.(WorkerAuthRepositoryStorage).removeNodeInformation"

	if r.workerAuthTransaction != nil {
		_, err := r.workerAuthTransaction.transactionWriter.Exec(ctx, deleteWorkerAuthQuery, []interface{}{sql.Named("worker_key_identifier", id)})
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		_, err = r.workerAuthTransaction.transactionWriter.Exec(ctx, deleteWorkerCertBundlesQuery, []interface{}{sql.Named("worker_key_identifier", id)})
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete workerAuth"))
		}
	} else {
		_, err := r.writer.DoTx(
			ctx,
			db.StdRetryCnt,
			db.ExpBackoff{},
			func(reader db.Reader, w db.Writer) error {
				var err error
				_, err = w.Exec(ctx, deleteWorkerAuthQuery, []interface{}{sql.Named("worker_key_identifier", id)})
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				_, err = w.Exec(ctx, deleteWorkerCertBundlesQuery, []interface{}{sql.Named("worker_key_identifier", id)})
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete workerAuth"))
				}
				return nil
			},
		)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}

	return nil
}

func (r *WorkerAuthRepositoryStorage) removeRootCertificate(ctx context.Context, id string) error {
	if r.workerAuthTransaction != nil {
		return r.removeRootCertificateWithWriter(ctx, id, r.workerAuthTransaction.transactionWriter)
	} else {
		return r.removeRootCertificateWithWriter(ctx, id, r.writer)
	}
}

func (r *WorkerAuthRepositoryStorage) removeRootCertificateWithWriter(ctx context.Context, id string, writer db.Writer) error {
	const op = "workerauth.(WorkerAuthRepositoryStorage).removeRootCertificate"

	rows, err := writer.Exec(ctx, deleteRootCertificateQuery, []interface{}{
		sql.Named("state", id),
	})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete root certificate"))
	}
	if rows > 1 {
		return errors.New(ctx, errors.MultipleRecords, op, "more than 1 root certificate would have been deleted")
	}

	return nil
}

// List implements the Storage interface.
// List returns a list of IDs; the type of the message is used to disambiguate what to list.
func (r *WorkerAuthRepositoryStorage) List(ctx context.Context, msg proto.Message) ([]string, error) {
	const op = "workerauth.(WorkerAuthRepositoryStorage).List"

	var err error
	var ids []string
	// Determine type of message to store
	switch msg.(type) {
	case *types.NodeInformation:
		ids, err = r.listNodeInformation(ctx)
	case *types.RootCertificate:
		ids, err = r.listRootCertificates(ctx)
	default:
		ids, err = nil, fmt.Errorf("(%s) Message type not supported for List", op)
	}
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ids, nil
}

// Returns a list of node auth IDs
func (r *WorkerAuthRepositoryStorage) listNodeInformation(ctx context.Context) ([]string, error) {
	const op = "workerauth.(WorkerAuthRepositoryStorage).listNodeCertificates"

	var where string
	var nodeAuths []*WorkerAuth
	var err error
	if r.workerAuthTransaction != nil {
		err = r.workerAuthTransaction.transactionWriter.SearchWhere(ctx, &nodeAuths, where, []interface{}{}, db.WithLimit(-1))
	} else {
		err = r.reader.SearchWhere(ctx, &nodeAuths, where, []interface{}{}, db.WithLimit(-1))
	}

	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var nodeIds []string
	for _, auth := range nodeAuths {
		nodeIds = append(nodeIds, auth.WorkerKeyIdentifier)
	}
	return nodeIds, nil
}

// Returns a list of root certificate serial numbers
func (r *WorkerAuthRepositoryStorage) listRootCertificates(ctx context.Context) ([]string, error) {
	const op = "workerauth.(WorkerAuthRepositoryStorage).listRootCertificates"

	var where string
	var rootCertificates []*RootCertificate
	var err error
	if r.workerAuthTransaction != nil {
		err = r.workerAuthTransaction.transactionWriter.SearchWhere(ctx, &rootCertificates, where, []interface{}{}, db.WithLimit(-1))
	} else {
		err = r.reader.SearchWhere(ctx, &rootCertificates, where, []interface{}{}, db.WithLimit(-1))
	}
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var certIds []string
	for _, cert := range rootCertificates {
		certIds = append(certIds, strconv.FormatUint(cert.SerialNumber, 10))
	}
	return certIds, nil
}

// encrypt value before writing it to the db
func encrypt(ctx context.Context, value []byte, wrapper wrapping.Wrapper) ([]byte, error) {
	blobInfo, err := wrapper.Encrypt(ctx, value)
	if err != nil {
		return nil, fmt.Errorf("error encrypting recovery info: %w", err)
	}
	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return nil, fmt.Errorf("error marshaling encrypted blob: %w", err)
	}
	return marshaledBlob, nil
}

func decrypt(ctx context.Context, value []byte, wrapper wrapping.Wrapper) ([]byte, error) {
	blobInfo := new(wrapping.BlobInfo)
	if err := proto.Unmarshal(value, blobInfo); err != nil {
		return nil, fmt.Errorf("error decoding encrypted blob: %w", err)
	}

	marshaledInfo, err := wrapper.Decrypt(ctx, blobInfo)
	if err != nil {
		return nil, fmt.Errorf("error decrypting recovery info: %w", err)
	}

	return marshaledInfo, nil
}

func unmarshalNodeInformation(ctx context.Context, marshaledBytes []byte) (*types.NodeInformation, error) {
	const op = "auth.(WorkerAuthRepositoryStorage).unmarshalNodeInformation"
	node := &types.NodeInformation{}
	if err := proto.Unmarshal(marshaledBytes, node); err != nil {
		return nil, errors.New(ctx, errors.Decode, op, "error unmarshaling message", errors.WithWrap(err))
	}
	return node, nil
}

func unmarshalRootCertificate(ctx context.Context, marshaledBytes []byte) (*types.RootCertificate, error) {
	const op = "auth.(WorkerAuthRepositoryStorage).unmarshalRootCertificate"
	cert := &types.RootCertificate{}
	if err := proto.Unmarshal(marshaledBytes, cert); err != nil {
		return nil, errors.New(ctx, errors.Decode, op, "error unmarshaling message", errors.WithWrap(err))
	}
	return cert, nil
}

func unmarshalNodeToResult(ctx context.Context, node *types.NodeInformation, result proto.Message) error {
	const op = "auth.(WorkerAuthRepositoryStorage).unmarshalNodeToResult"
	nodeBytes, err := proto.Marshal(node)
	if err != nil {
		return fmt.Errorf("error marshaling nodetypes.NodeInformation: %w", err)
	}
	if err := proto.Unmarshal(nodeBytes, result); err != nil {
		return errors.New(ctx, errors.Decode, op, "error unmarshalling message", errors.WithWrap(err))
	}
	return nil
}
