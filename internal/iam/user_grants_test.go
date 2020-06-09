package iam

import (
	"context"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
)

func Test_UserGrants(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	}()
	org, _ := TestScopes(t, conn)

	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		id, err := uuid.GenerateUUID()
		assert.NoError(err)
		w := db.New(conn)

		role, err := NewRole(org.PublicId)
		assert.NoError(err)
		assert.NotNil(role)
		assert.Equal(org.PublicId, role.ScopeId)
		err = w.Create(context.Background(), role)
		assert.NoError(err)
		assert.NotEqual(role.PublicId, "")

		g, err := NewRoleGrant(role, "everything*"+id)
		assert.NoError(err)
		assert.NotNil(g)
		assert.Equal(g.RoleId, role.PublicId)
		assert.Equal(g.Grant, "everything*"+id)
		err = w.Create(context.Background(), g)
		assert.NoError(err)
		assert.NotEqual(g.PublicId, "")

		user := TestUser(t, conn, org.PublicId)
		uRole, err := NewAssignedRole(role, user)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetRoleId(), role.PublicId)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)
		err = w.Create(context.Background(), uRole)
		assert.NoError(err)
		assert.NotNil(uRole)
		assert.Equal(uRole.GetPrincipalId(), user.PublicId)

		userGrants, err := user.Grants(context.Background(), w)
		assert.NoError(err)
		assert.Equal(len(userGrants), 1)
		assert.Equal(userGrants[0], g)

		grp := TestGroup(t, conn, org.PublicId)

		gm, err := grp.AddUser(user.PublicId)
		assert.NoError(err)
		assert.NotNil(gm)
		err = w.Create(context.Background(), gm)
		assert.NoError(err)

		groupRole, err := NewRole(org.PublicId)
		assert.NoError(err)
		assert.NotNil(role)
		assert.Equal(org.PublicId, groupRole.ScopeId)
		err = w.Create(context.Background(), groupRole)
		assert.NoError(err)
		assert.NotEqual(groupRole.PublicId, "")

		groupGrant, err := NewRoleGrant(groupRole, "group-grant*"+id)
		assert.NoError(err)
		assert.NotNil(groupGrant)
		assert.Equal(groupGrant.RoleId, groupRole.PublicId)
		assert.Equal(groupGrant.Grant, "group-grant*"+id)
		err = w.Create(context.Background(), groupGrant)
		assert.NoError(err)
		assert.NotEqual(groupGrant.PublicId, "")

		gRole, err := NewAssignedRole(groupRole, grp)
		assert.NoError(err)
		assert.NotNil(gRole)
		assert.Equal(gRole.GetRoleId(), groupRole.PublicId)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)
		err = w.Create(context.Background(), gRole)
		assert.NoError(err)
		assert.NotNil(gRole)
		assert.Equal(gRole.GetPrincipalId(), grp.PublicId)

		allGrants, err := user.Grants(context.Background(), w, WithGroupGrants(true))
		assert.NoError(err)
		assert.Equal(len(allGrants), 2)
		for _, grant := range allGrants {
			assert.True(grant.PublicId == g.PublicId || grant.PublicId == groupGrant.PublicId)
		}
	})
}
