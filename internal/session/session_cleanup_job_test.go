package session

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assert the interface
var _ = scheduler.Job(new(sessionConnectionCleanupJob))

// This test has been largely adapted from
// TestRepository_CloseDeadConnectionsOnWorker in
// internal/session/repository_connection_test.go.
func TestSessionConnectionCleanupJob(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const gracePeriod = 1 * time.Second

	require, assert := require.New(t), assert.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	serversRepo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(err)
	sessionRepo, err := NewRepository(rw, rw, kms)
	connectionRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
	require.NoError(err)

	numConns := 12

	// Create two "workers". One will remain untouched while the other "goes
	// away and comes back" (worker 2).
	worker1 := TestWorker(t, conn, wrapper, WithServerId("worker1"))
	worker2 := TestWorker(t, conn, wrapper, WithServerId("worker2"))

	// Create a few sessions on each, activate, and authorize a connection
	var connIds []string
	connIdsByWorker := make(map[string][]string)
	for i := 0; i < numConns; i++ {
		serverId := worker1.PrivateId
		if i%2 == 0 {
			serverId = worker2.PrivateId
		}
		sess := TestDefaultSession(t, conn, wrapper, iamRepo, WithServerId(serverId), WithDbOpts(db.WithSkipVetForWrite(true)))
		sess, _, err = sessionRepo.ActivateSession(ctx, sess.GetPublicId(), sess.Version, serverId, "worker", []byte("foo"))
		require.NoError(err)
		c, cs, _, err := AuthorizeConnection(ctx, sessionRepo, connectionRepo, sess.GetPublicId(), serverId)
		require.NoError(err)
		require.Len(cs, 1)
		require.Equal(StatusAuthorized, cs[0].Status)
		connIds = append(connIds, c.GetPublicId())
		if i%2 == 0 {
			connIdsByWorker[worker2.PrivateId] = append(connIdsByWorker[worker2.PrivateId], c.GetPublicId())
		} else {
			connIdsByWorker[worker1.PrivateId] = append(connIdsByWorker[worker1.PrivateId], c.GetPublicId())
		}
	}

	// Mark half of the connections connected and leave the others authorized.
	// This is just to ensure we have a spread when we test it out.
	for i, connId := range connIds {
		if i%2 == 0 {
			_, cs, err := connectionRepo.ConnectConnection(ctx, ConnectWith{
				ConnectionId:       connId,
				ClientTcpAddress:   "127.0.0.1",
				ClientTcpPort:      22,
				EndpointTcpAddress: "127.0.0.1",
				EndpointTcpPort:    22,
				UserClientIp:       "127.0.0.1",
			})
			require.NoError(err)
			require.Len(cs, 2)
			var foundAuthorized, foundConnected bool
			for _, status := range cs {
				if status.Status == StatusAuthorized {
					foundAuthorized = true
				}
				if status.Status == StatusConnected {
					foundConnected = true
				}
			}
			require.True(foundAuthorized)
			require.True(foundConnected)
		}
	}

	// Create the job.
	job, err := newSessionConnectionCleanupJob(rw, deadWorkerConnCloseMinGrace)
	job.gracePeriod = gracePeriod // by-pass factory assert so we dont have to wait so long
	require.NoError(err)

	// sleep the status grace period.
	time.Sleep(gracePeriod)

	// Push an upsert to the first worker so that its status has been
	// updated.
	_, rowsUpdated, err := serversRepo.UpsertServer(ctx, worker1, []servers.Option{}...)
	require.NoError(err)
	require.Equal(1, rowsUpdated)

	// Run the job.
	require.NoError(job.Run(ctx))

	// Assert connection state on both workers.
	assertConnections := func(workerId string, closed bool) {
		connIds, ok := connIdsByWorker[workerId]
		require.True(ok)
		require.Len(connIds, 6)
		for _, connId := range connIds {
			_, states, err := connectionRepo.LookupConnection(ctx, connId, nil)
			require.NoError(err)
			var foundClosed bool
			for _, state := range states {
				if state.Status == StatusClosed {
					foundClosed = true
					break
				}
			}
			assert.Equal(closed, foundClosed)
		}
	}

	// Assert that all connections on the second worker are closed
	assertConnections(worker2.PrivateId, true)
	// Assert that all connections on the first worker are still open
	assertConnections(worker1.PrivateId, false)
}

func TestSessionConnectionCleanupJobNewJobErr(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	const op = "session.newNewSessionConnectionCleanupJob"
	require := require.New(t)

	job, err := newSessionConnectionCleanupJob(nil, 0)
	require.Equal(err, errors.E(
		ctx,
		errors.WithCode(errors.InvalidParameter),
		errors.WithOp(op),
		errors.WithMsg("missing db writer"),
	))
	require.Nil(job)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	job, err = newSessionConnectionCleanupJob(rw, 0)
	require.Equal(err, errors.E(
		ctx,
		errors.WithCode(errors.InvalidParameter),
		errors.WithOp(op),
		errors.WithMsg(fmt.Sprintf("invalid gracePeriod, must be greater than %s", deadWorkerConnCloseMinGrace)),
	))
	require.Nil(job)
}

func TestCloseConnectionsForDeadWorkers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	require := require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)
	gracePeriod := 1 * time.Second
	connRepo, err := NewConnectionRepository(ctx, rw, rw, kms)
	require.NoError(err)
	serversRepo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(err)

	job, err := newSessionConnectionCleanupJob(rw, deadWorkerConnCloseMinGrace)
	require.NoError(err)

	// connection count = 6 * states(authorized, connected, closed = 3) * servers_with_open_connections(3)
	numConns := 54

	// Create four "workers". This is similar to the setup in
	// TestRepository_CloseDeadConnectionsOnWorker, but a bit more complex;
	// firstly, the last worker will have no connections at all, and we will be
	// closing the others in stages to test multiple servers being closed at
	// once.
	worker1 := TestWorker(t, conn, wrapper, WithServerId("worker1"))
	worker2 := TestWorker(t, conn, wrapper, WithServerId("worker2"))
	worker3 := TestWorker(t, conn, wrapper, WithServerId("worker3"))
	worker4 := TestWorker(t, conn, wrapper, WithServerId("worker4"))

	// Create sessions on the first three, activate, and authorize connections
	var worker1ConnIds, worker2ConnIds, worker3ConnIds []string
	for i := 0; i < numConns; i++ {
		var serverId string
		if i%3 == 0 {
			serverId = worker1.PrivateId
		} else if i%3 == 1 {
			serverId = worker2.PrivateId
		} else {
			serverId = worker3.PrivateId
		}
		sess := TestDefaultSession(t, conn, wrapper, iamRepo, WithServerId(serverId), WithDbOpts(db.WithSkipVetForWrite(true)))
		sess, _, err = repo.ActivateSession(ctx, sess.GetPublicId(), sess.Version, serverId, "worker", []byte("foo"))
		require.NoError(err)
		c, cs, err := connRepo.AuthorizeConnection(ctx, sess.GetPublicId(), serverId)
		require.NoError(err)
		require.Len(cs, 1)
		require.Equal(StatusAuthorized, cs[0].Status)
		if i%3 == 0 {
			worker1ConnIds = append(worker1ConnIds, c.GetPublicId())
		} else if i%3 == 1 {
			worker2ConnIds = append(worker2ConnIds, c.GetPublicId())
		} else {
			worker3ConnIds = append(worker3ConnIds, c.GetPublicId())
		}
	}

	// Mark a third of the connections connected, a third closed, and leave the
	// others authorized. This is just to ensure we have a spread when we test it
	// out.
	for i, connId := range func() []string {
		var s []string
		s = append(s, worker1ConnIds...)
		s = append(s, worker2ConnIds...)
		s = append(s, worker3ConnIds...)
		return s
	}() {
		if i%3 == 0 {
			_, cs, err := connRepo.ConnectConnection(ctx, ConnectWith{
				ConnectionId:       connId,
				ClientTcpAddress:   "127.0.0.1",
				ClientTcpPort:      22,
				EndpointTcpAddress: "127.0.0.1",
				EndpointTcpPort:    22,
				UserClientIp:       "127.0.0.1",
			})
			require.NoError(err)
			require.Len(cs, 2)
			var foundAuthorized, foundConnected bool
			for _, status := range cs {
				if status.Status == StatusAuthorized {
					foundAuthorized = true
				}
				if status.Status == StatusConnected {
					foundConnected = true
				}
			}
			require.True(foundAuthorized)
			require.True(foundConnected)
		} else if i%3 == 1 {
			resp, err := connRepo.closeConnections(ctx, []CloseWith{
				{
					ConnectionId: connId,
					ClosedReason: ConnectionCanceled,
				},
			})
			require.NoError(err)
			require.Len(resp, 1)
			cs := resp[0].ConnectionStates
			require.Len(cs, 2)
			var foundAuthorized, foundClosed bool
			for _, status := range cs {
				if status.Status == StatusAuthorized {
					foundAuthorized = true
				}
				if status.Status == StatusClosed {
					foundClosed = true
				}
			}
			require.True(foundAuthorized)
			require.True(foundClosed)
		}
	}

	// updateServer is a helper for updating the update time for our
	// servers. The controller is read back so that we can reference
	// the most up-to-date fields.
	updateServer := func(t *testing.T, w *servers.Server) *servers.Server {
		t.Helper()
		_, rowsUpdated, err := serversRepo.UpsertServer(ctx, w)
		require.NoError(err)
		require.Equal(1, rowsUpdated)
		servers, err := serversRepo.ListServers(ctx, servers.ServerTypeWorker)
		require.NoError(err)
		for _, server := range servers {
			if server.PrivateId == w.PrivateId {
				return server
			}
		}

		require.FailNowf("server %q not found after updating", w.PrivateId)
		// Looks weird but needed to build, as we fail in testify instead
		// of returning an error
		return nil
	}

	// requireConnectionStatus is a helper expecting all connections on a worker
	// to be closed.
	requireConnectionStatus := func(t *testing.T, connIds []string, expectAllClosed bool) {
		t.Helper()

		var conns []*Connection
		require.NoError(repo.list(ctx, &conns, "", nil))
		for i, connId := range connIds {
			var expected ConnectionStatus
			switch {
			case expectAllClosed:
				expected = StatusClosed

			case i%3 == 0:
				expected = StatusConnected

			case i%3 == 1:
				expected = StatusClosed

			case i%3 == 2:
				expected = StatusAuthorized
			}

			_, states, err := connRepo.LookupConnection(ctx, connId)
			require.NoError(err)
			require.Equal(expected, states[0].Status, "expected latest status for %q (index %d) to be %v", connId, i, expected)
		}
	}

	// We need this helper to fix the zone on protobuf timestamps
	// versus what gets reported in the
	// closeConnectionsForDeadWorkersResult.
	timestampPbAsUTC := func(t *testing.T, tm time.Time) time.Time {
		t.Helper()
		// utcLoc, err := time.LoadLocation("Etc/UTC")
		// require.NoError(err)
		return tm.In(time.Local)
	}

	// Now try some scenarios.
	{
		// Now, try the basis, or where all workers are reporting in.
		worker1 = updateServer(t, worker1)
		worker2 = updateServer(t, worker2)
		worker3 = updateServer(t, worker3)
		updateServer(t, worker4) // no re-assignment here because we never reference the server again

		result, err := job.closeConnectionsForDeadWorkers(ctx, gracePeriod)
		require.NoError(err)
		require.Empty(result)
		// Expect appropriate split connection state on worker1
		requireConnectionStatus(t, worker1ConnIds, false)
		// Expect appropriate split connection state on worker2
		requireConnectionStatus(t, worker2ConnIds, false)
		// Expect appropriate split connection state on worker3
		requireConnectionStatus(t, worker3ConnIds, false)
	}

	{
		// Now try a zero case - similar to the basis, but only in that no results
		// are expected to be returned for workers with no connections, even if
		// they are dead. Here, the server with no connections is worker #4.
		time.Sleep(gracePeriod)
		worker1 = updateServer(t, worker1)
		worker2 = updateServer(t, worker2)
		worker3 = updateServer(t, worker3)

		result, err := job.closeConnectionsForDeadWorkers(ctx, gracePeriod)
		require.NoError(err)
		require.Empty(result)
		// Expect appropriate split connection state on worker1
		requireConnectionStatus(t, worker1ConnIds, false)
		// Expect appropriate split connection state on worker2
		requireConnectionStatus(t, worker2ConnIds, false)
		// Expect appropriate split connection state on worker3
		requireConnectionStatus(t, worker3ConnIds, false)
	}

	{
		// The first induction is letting the first worker "die" by not updating it
		// too. All of its authorized and connected connections should be dead.
		time.Sleep(gracePeriod)
		worker2 = updateServer(t, worker2)
		worker3 = updateServer(t, worker3)

		result, err := job.closeConnectionsForDeadWorkers(ctx, gracePeriod)
		require.NoError(err)
		// Assert that we have one result with the appropriate ID and
		// number of connections closed. Due to how things are
		require.Equal([]closeConnectionsForDeadWorkersResult{
			{
				ServerId:                worker1.PrivateId,
				LastUpdateTime:          timestampPbAsUTC(t, worker1.UpdateTime.AsTime()),
				NumberConnectionsClosed: 12, // 18 per server, with 6 closed already
			},
		}, result)
		// Expect all connections closed on worker1
		requireConnectionStatus(t, worker1ConnIds, true)
		// Expect appropriate split connection state on worker2
		requireConnectionStatus(t, worker2ConnIds, false)
		// Expect appropriate split connection state on worker3
		requireConnectionStatus(t, worker3ConnIds, false)
	}

	{
		// The final case is having the other two workers die. After
		// this, we should have all connections closed with the
		// appropriate message from the next two servers acted on.
		time.Sleep(gracePeriod)

		result, err := job.closeConnectionsForDeadWorkers(ctx, gracePeriod)
		require.NoError(err)
		// Assert that we have one result with the appropriate ID and number of connections closed.
		require.Equal([]closeConnectionsForDeadWorkersResult{
			{
				ServerId:                worker2.PrivateId,
				LastUpdateTime:          timestampPbAsUTC(t, worker2.UpdateTime.AsTime()),
				NumberConnectionsClosed: 12, // 18 per server, with 6 closed already
			},
			{
				ServerId:                worker3.PrivateId,
				LastUpdateTime:          timestampPbAsUTC(t, worker3.UpdateTime.AsTime()),
				NumberConnectionsClosed: 12, // 18 per server, with 6 closed already
			},
		}, result)
		// Expect all connections closed on worker1
		requireConnectionStatus(t, worker1ConnIds, true)
		// Expect all connections closed on worker2
		requireConnectionStatus(t, worker2ConnIds, true)
		// Expect all connections closed on worker3
		requireConnectionStatus(t, worker3ConnIds, true)
	}
}
