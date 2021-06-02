package aclclient_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/juju/simplekv/memsimplekv"
	errgo "gopkg.in/errgo.v1"
	httprequest "gopkg.in/httprequest.v1"

	aclstore "github.com/juju/aclstore/v2"
	"github.com/juju/aclstore/v2/aclclient"
	"github.com/juju/aclstore/v2/params"
)

func TestGet(t *testing.T) {
	ctx := context.Background()
	c := qt.New(t)
	manager, srv, client := newServer(ctx, c)
	defer srv.Close()

	err := manager.CreateACL(ctx, "test", "test1", "test2", "test3")
	c.Assert(err, qt.Equals, nil)
	users, err := client.Get(ctx, "test")
	c.Assert(err, qt.Equals, nil)
	c.Assert(users, qt.DeepEquals, []string{"test1", "test2", "test3"})
}

func TestGetError(t *testing.T) {
	ctx := context.Background()
	c := qt.New(t)
	_, srv, client := newServer(ctx, c)
	defer srv.Close()

	users, err := client.Get(ctx, "test")
	c.Assert(err, qt.ErrorMatches, `Get http.*/test: ACL not found`)
	rerr, ok := errgo.Cause(err).(*httprequest.RemoteError)
	c.Assert(ok, qt.Equals, true, qt.Commentf("unexpected error cause %T", errgo.Cause(err)))
	c.Assert(rerr.Code, qt.Equals, aclstore.CodeACLNotFound)
	c.Assert(users, qt.IsNil)
}

func TestSet(t *testing.T) {
	ctx := context.Background()
	c := qt.New(t)
	manager, srv, client := newServer(ctx, c)
	defer srv.Close()

	err := manager.CreateACL(ctx, "test", "test1", "test2", "test3")
	c.Assert(err, qt.Equals, nil)
	err = client.Set(ctx, "test", []string{"test4", "test5", "test6"})
	c.Assert(err, qt.Equals, nil)
	users, err := client.Get(ctx, "test")
	c.Assert(err, qt.Equals, nil)
	c.Assert(users, qt.DeepEquals, []string{"test4", "test5", "test6"})
}

func TestSetError(t *testing.T) {
	ctx := context.Background()
	c := qt.New(t)
	_, srv, client := newServer(ctx, c)
	defer srv.Close()

	err := client.Set(ctx, "test", []string{"test4", "test5", "test6"})
	c.Assert(err, qt.ErrorMatches, `Put http.*/test: ACL not found`)
	rerr, ok := errgo.Cause(err).(*httprequest.RemoteError)
	c.Assert(ok, qt.Equals, true, qt.Commentf("unexpected error cause %T", errgo.Cause(err)))
	c.Assert(rerr.Code, qt.Equals, aclstore.CodeACLNotFound)
}

func TestAdd(t *testing.T) {
	ctx := context.Background()
	c := qt.New(t)
	manager, srv, client := newServer(ctx, c)
	defer srv.Close()

	err := manager.CreateACL(ctx, "test", "test1", "test2", "test3")
	c.Assert(err, qt.Equals, nil)
	err = client.Add(ctx, "test", []string{"test4", "test5", "test6"})
	c.Assert(err, qt.Equals, nil)
	users, err := client.Get(ctx, "test")
	c.Assert(err, qt.Equals, nil)
	c.Assert(users, qt.DeepEquals, []string{"test1", "test2", "test3", "test4", "test5", "test6"})
}

func TestAddError(t *testing.T) {
	ctx := context.Background()
	c := qt.New(t)
	_, srv, client := newServer(ctx, c)
	defer srv.Close()

	err := client.Add(ctx, "test", []string{"test4", "test5", "test6"})
	c.Assert(err, qt.ErrorMatches, `Post http.*/test: ACL not found`)
	rerr, ok := errgo.Cause(err).(*httprequest.RemoteError)
	c.Assert(ok, qt.Equals, true, qt.Commentf("unexpected error cause %T", errgo.Cause(err)))
	c.Assert(rerr.Code, qt.Equals, aclstore.CodeACLNotFound)
}

func TestRemove(t *testing.T) {
	ctx := context.Background()
	c := qt.New(t)
	manager, srv, client := newServer(ctx, c)
	defer srv.Close()

	err := manager.CreateACL(ctx, "test", "test1", "test2", "test3", "test4", "test5", "test6")
	c.Assert(err, qt.Equals, nil)
	err = client.Remove(ctx, "test", []string{"test4", "test5", "test6"})
	c.Assert(err, qt.Equals, nil)
	users, err := client.Get(ctx, "test")
	c.Assert(err, qt.Equals, nil)
	c.Assert(users, qt.DeepEquals, []string{"test1", "test2", "test3"})
}

func TestRemoveError(t *testing.T) {
	ctx := context.Background()
	c := qt.New(t)
	_, srv, client := newServer(ctx, c)
	defer srv.Close()

	err := client.Remove(ctx, "test", []string{"test4", "test5", "test6"})
	c.Assert(err, qt.ErrorMatches, `Post http.*/test: ACL not found`)
	rerr, ok := errgo.Cause(err).(*httprequest.RemoteError)
	c.Assert(ok, qt.Equals, true, qt.Commentf("unexpected error cause %T", errgo.Cause(err)))
	c.Assert(rerr.Code, qt.Equals, aclstore.CodeACLNotFound)
}

func TestGetACLs(t *testing.T) {
	ctx := context.Background()
	c := qt.New(t)
	manager, srv, client := newServer(ctx, c)
	defer srv.Close()

	err := manager.CreateACL(ctx, "test1", "test1", "test2", "test3")
	c.Assert(err, qt.Equals, nil)
	err = manager.CreateACL(ctx, "test2", "test1", "test2", "test3")
	c.Assert(err, qt.Equals, nil)
	err = manager.CreateACL(ctx, "test3", "test1", "test2", "test3")
	c.Assert(err, qt.Equals, nil)

	acls, err := client.GetACLs(ctx, &params.GetACLsRequest{})
	c.Assert(err, qt.Equals, nil)
	sort.Strings(acls.ACLs)
	c.Assert(acls.ACLs, qt.DeepEquals, []string{"_test1", "_test2", "_test3", "admin", "test1", "test2", "test3"})
}

func newServer(ctx context.Context, c *qt.C) (*aclstore.Manager, *httptest.Server, *aclclient.Client) {
	store := aclstore.NewACLStore(memsimplekv.NewStore())

	manager, err := aclstore.NewManager(ctx, aclstore.Params{
		Store:             store,
		InitialAdminUsers: []string{"test-admin"},
	})
	c.Assert(err, qt.Equals, nil)

	srv := httptest.NewServer(manager.NewHandler(aclstore.HandlerParams{
		Authenticate: func(ctx context.Context, w http.ResponseWriter, req *http.Request) (aclstore.Identity, error) {
			return allowed{}, nil
		},
	}))
	client := aclclient.New(aclclient.NewParams{
		BaseURL: srv.URL,
		Doer:    srv.Client(),
	})
	return manager, srv, client
}

type allowed struct{}

func (allowed) Allow(context.Context, []string) (bool, error) {
	return true, nil
}
