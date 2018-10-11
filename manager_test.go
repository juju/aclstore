// Copyright 2018 Canonical Ltd.
// Licensed under the LGPL, see LICENCE file for details.

package aclstore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	qt "github.com/frankban/quicktest"
	httprequest "gopkg.in/httprequest.v1"

	aclstore "github.com/juju/aclstore/v2"
	"github.com/juju/aclstore/v2/params"
	"github.com/juju/simplekv/memsimplekv"
	"gopkg.in/errgo.v1"
)

var getACLTests = []struct {
	testName       string
	path           string
	rootPath       string
	users          map[string][]string
	expectCheckACL []string
	expectStatus   int
	expectResponse interface{}
}{{
	testName: "get_admin_ACL",
	rootPath: "/root",
	path:     "/root/admin",
	users: map[string][]string{
		"admin": {"alice", "bob"},
	},
	expectCheckACL: []string{"alice", "bob"},
	expectStatus:   http.StatusOK,
	expectResponse: map[string][]string{
		"users": {"alice", "bob"},
	},
}, {
	testName: "get_ACL_with_empty_root_path",
	path:     "/admin",
	users: map[string][]string{
		"admin": {"alice", "bob"},
	},
	expectCheckACL: []string{"alice", "bob"},
	expectStatus:   http.StatusOK,
	expectResponse: map[string][]string{
		"users": {"alice", "bob"},
	},
}, {
	testName:     "get outside of root",
	rootPath:     "/root",
	path:         "/blah/foo",
	expectStatus: http.StatusNotFound,
	expectResponse: httprequest.RemoteError{
		Message: "URL path not found",
		Code:    httprequest.CodeNotFound,
	},
}, {
	testName:     "get outside of root with root as prefix",
	rootPath:     "/root",
	path:         "/rootfoo/admin",
	expectStatus: http.StatusNotFound,
	expectResponse: httprequest.RemoteError{
		Message: "URL path not found",
		Code:    httprequest.CodeNotFound,
	},
}, {
	testName:     "get_nonexistent_ACL",
	rootPath:     "/root",
	path:         "/root/nonexistent",
	expectStatus: http.StatusNotFound,
	expectResponse: httprequest.RemoteError{
		Message: "ACL not found",
		Code:    aclstore.CodeACLNotFound,
	},
}, {
	testName: "get_nonadmin_ACL",
	rootPath: "/root",
	users: map[string][]string{
		"admin":    {"alice", "bob"},
		"someacl":  {"charlie", "daisy"},
		"_someacl": {"claire", "ed"},
	},
	path:           "/root/someacl",
	expectCheckACL: []string{"claire", "ed", "alice", "bob"},
	expectStatus:   http.StatusOK,
	expectResponse: map[string][]string{
		"users": {"charlie", "daisy"},
	},
}, {
	testName: "get_nonadmin_meta_ACL",
	rootPath: "/root",
	users: map[string][]string{
		"admin":    {"alice", "bob"},
		"someacl":  {"charlie", "daisy"},
		"_someacl": {"claire", "ed"},
	},
	path:           "/root/_someacl",
	expectCheckACL: []string{"alice", "bob"},
	expectStatus:   http.StatusOK,
	expectResponse: map[string][]string{
		"users": {"claire", "ed"},
	},
}}

func TestGetACL(t *testing.T) {
	c := qt.New(t)

	for _, test := range getACLTests {
		c.Run(test.testName, func(c *qt.C) {
			var checkedACL []string
			m := managerWithACLs(c, test.rootPath, test.users, &checkedACL)
			srv := httptest.NewServer(m)
			defer srv.Close()
			assertJSONCall(c, "GET", srv.URL+test.path, nil, test.expectStatus, test.expectResponse)
			c.Assert(checkedACL, qt.DeepEquals, test.expectCheckACL)
		})
	}
}

var setACLTests = []struct {
	testName       string
	path           string
	users          map[string][]string
	setACL         []string
	expectCheckACL []string
	expectACLName  string
	expectACL      []string
	expectStatus   int
	expectResponse interface{}
}{{
	testName: "set_admin_ACL",
	users: map[string][]string{
		"admin": {"alice", "bob"},
	},
	path:           "/root/admin",
	setACL:         []string{"foo", "bar", "alice"},
	expectCheckACL: []string{"alice", "bob"},
	expectACLName:  "admin",
	expectACL:      []string{"alice", "bar", "foo"},
	expectStatus:   http.StatusOK,
}, {
	testName:     "set_nonexistent_ACL",
	path:         "/root/nonexistent",
	expectStatus: http.StatusNotFound,
	expectResponse: httprequest.RemoteError{
		Message: "ACL not found",
		Code:    aclstore.CodeACLNotFound,
	},
}, {
	testName: "set_non_admin_ACL",
	users: map[string][]string{
		"admin":    {"boss"},
		"someacl":  {"charlie", "daisy"},
		"_someacl": {"a", "b"},
	},
	path:           "/root/someacl",
	setACL:         []string{"elouise", "fred"},
	expectCheckACL: []string{"a", "b", "boss"},
	expectACLName:  "someacl",
	expectACL:      []string{"elouise", "fred"},
	expectStatus:   http.StatusOK,
}, {
	testName: "set_meta_ACL",
	users: map[string][]string{
		"admin":    {"boss"},
		"someacl":  {"charlie", "daisy"},
		"_someacl": {"a", "b"},
	},
	path:           "/root/_someacl",
	setACL:         []string{"daisy"},
	expectCheckACL: []string{"boss"},
	expectACLName:  "_someacl",
	expectACL:      []string{"daisy"},
	expectStatus:   http.StatusOK,
}, {
	testName: "set_ACL_with_invalid_user",
	users: map[string][]string{
		"admin": {"boss"},
	},
	path:           "/root/admin",
	setACL:         []string{"daisy", ""},
	expectCheckACL: []string{"boss"},
	expectStatus:   http.StatusBadRequest,
	expectResponse: httprequest.RemoteError{
		Message: `invalid user name ""`,
		Code:    httprequest.CodeBadRequest,
	},
}}

func TestSetACL(t *testing.T) {
	c := qt.New(t)
	for _, test := range setACLTests {
		c.Run(test.testName, func(c *qt.C) {
			var checkedACL []string
			m := managerWithACLs(c, "/root", test.users, &checkedACL)
			srv := httptest.NewServer(m)
			defer srv.Close()
			assertJSONCall(c, "PUT", srv.URL+test.path, map[string][]string{
				"users": test.setACL,
			}, test.expectStatus, test.expectResponse)
			c.Assert(checkedACL, qt.DeepEquals, test.expectCheckACL)
			if test.expectACLName != "" {
				gotACL, err := m.ACL(context.Background(), test.expectACLName)
				c.Assert(err, qt.Equals, nil)
				c.Assert(gotACL, qt.DeepEquals, test.expectACL)
			}
		})
	}
}

var modifyACLTests = []struct {
	testName       string
	path           string
	users          map[string][]string
	addUsers       []string
	removeUsers    []string
	expectCheckACL []string
	expectACLName  string
	expectACL      []string
	expectStatus   int
	expectResponse interface{}
}{{
	testName: "add_admin_ACL",
	users: map[string][]string{
		"admin": {"alice", "bob"},
	},
	path:           "/root/admin",
	addUsers:       []string{"foo", "bar", "alice"},
	expectCheckACL: []string{"alice", "bob"},
	expectACLName:  "admin",
	expectACL:      []string{"alice", "bar", "bob", "foo"},
	expectStatus:   http.StatusOK,
}, {
	testName: "remove_admin_ACL",
	users: map[string][]string{
		"admin": {"alice", "bob"},
	},
	path:           "/root/admin",
	removeUsers:    []string{"bar", "alice"},
	expectCheckACL: []string{"alice", "bob"},
	expectACLName:  "admin",
	expectACL:      []string{"bob"},
	expectStatus:   http.StatusOK,
}, {
	testName:     "set_nonexistent_ACL",
	path:         "/root/nonexistent",
	expectStatus: http.StatusNotFound,
	expectResponse: httprequest.RemoteError{
		Message: "ACL not found",
		Code:    aclstore.CodeACLNotFound,
	},
}, {
	testName: "remove_and_add",
	users: map[string][]string{
		"admin": {"alice", "bob"},
	},
	path:           "/root/admin",
	addUsers:       []string{"edward"},
	removeUsers:    []string{"bar"},
	expectCheckACL: []string{"alice", "bob"},
	expectStatus:   http.StatusBadRequest,
	expectResponse: &httprequest.RemoteError{
		Message: `cannot add and remove users at the same time`,
		Code:    httprequest.CodeBadRequest,
	},
}, {
	testName: "add_to_non_admin_ACL",
	users: map[string][]string{
		"admin":    {"boss"},
		"someacl":  {"charlie", "daisy"},
		"_someacl": {"a", "b"},
	},
	path:           "/root/someacl",
	addUsers:       []string{"elouise", "fred"},
	expectCheckACL: []string{"a", "b", "boss"},
	expectACLName:  "someacl",
	expectACL:      []string{"charlie", "daisy", "elouise", "fred"},
	expectStatus:   http.StatusOK,
}, {
	testName: "add_to_meta_ACL",
	users: map[string][]string{
		"admin":    {"boss"},
		"someacl":  {"charlie", "daisy"},
		"_someacl": {"a", "b"},
	},
	path:           "/root/_someacl",
	addUsers:       []string{"charlie"},
	expectCheckACL: []string{"boss"},
	expectACLName:  "_someacl",
	expectACL:      []string{"a", "b", "charlie"},
	expectStatus:   http.StatusOK,
}, {
	testName: "add_invalid_user",
	users: map[string][]string{
		"admin": {"boss"},
	},
	path:           "/root/admin",
	addUsers:       []string{"daisy", ""},
	expectCheckACL: []string{"boss"},
	expectStatus:   http.StatusBadRequest,
	expectResponse: httprequest.RemoteError{
		Message: `invalid user name ""`,
		Code:    httprequest.CodeBadRequest,
	},
}}

func TestModifyACL(t *testing.T) {
	c := qt.New(t)
	for _, test := range modifyACLTests {
		c.Run(test.testName, func(c *qt.C) {
			var checkedACL []string
			m := managerWithACLs(c, "/root", test.users, &checkedACL)
			srv := httptest.NewServer(m)
			defer srv.Close()
			assertJSONCall(c, "POST", srv.URL+test.path, map[string][]string{
				"add":    test.addUsers,
				"remove": test.removeUsers,
			}, test.expectStatus, test.expectResponse)
			c.Assert(checkedACL, qt.DeepEquals, test.expectCheckACL)
			if test.expectACLName != "" {
				gotACL, err := m.ACL(context.Background(), test.expectACLName)
				c.Assert(err, qt.Equals, nil)
				c.Assert(gotACL, qt.DeepEquals, test.expectACL)
			}
		})
	}
}

func TestWithAuthenticate(t *testing.T) {
	ctx := context.Background()
	c := qt.New(t)
	m, err := aclstore.NewManager(ctx, aclstore.Params{
		Store:             aclstore.NewACLStore(memsimplekv.NewStore()),
		InitialAdminUsers: []string{"bob"},
		Authenticate: func(ctx context.Context, w http.ResponseWriter, req *http.Request) (aclstore.Identity, error) {
			req.ParseForm()
			user := req.Form.Get("auth")
			if user == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTeapot)
				w.Write([]byte(`"go away"`))
				return nil, errgo.Newf("no auth header found")
			}
			return identityFunc(func(ctx context.Context, acl []string) (bool, error) {
				for _, a := range acl {
					if a == user {
						return true, nil
					}
				}
				return false, nil
			}), nil
		},
	})
	c.Assert(err, qt.Equals, nil)
	srv := httptest.NewServer(m)
	defer srv.Close()

	assertJSONCall(c, "GET", srv.URL+"/admin", nil, http.StatusTeapot, "go away")
	assertJSONCall(c, "GET", srv.URL+"/admin?auth=bob", nil, http.StatusOK, params.GetACLResponse{
		Users: []string{"bob"},
	})
}

func TestForbidden(t *testing.T) {
	ctx := context.Background()
	c := qt.New(t)
	m, err := aclstore.NewManager(ctx, aclstore.Params{
		Store:             aclstore.NewACLStore(memsimplekv.NewStore()),
		InitialAdminUsers: []string{"bob"},
		Authenticate: func(ctx context.Context, w http.ResponseWriter, req *http.Request) (aclstore.Identity, error) {
			return identityFunc(func(ctx context.Context, acl []string) (bool, error) {
				return false, nil
			}), nil
		},
	})
	c.Assert(err, qt.Equals, nil)
	srv := httptest.NewServer(m)
	defer srv.Close()

	assertJSONCall(c, "GET", srv.URL+"/admin", nil, http.StatusForbidden, &httprequest.RemoteError{
		Code:    httprequest.CodeForbidden,
		Message: httprequest.CodeForbidden,
	})
}

func TestManagerCreateACL(t *testing.T) {
	c := qt.New(t)
	var checkedACL []string

	ctx := context.Background()

	m := managerWithACLs(c, "", nil, &checkedACL)

	err := m.CreateACL(ctx, "foo", "x", "y")
	c.Assert(err, qt.Equals, nil)

	acl, err := m.ACL(ctx, "foo")
	c.Assert(err, qt.Equals, nil)
	c.Assert(acl, qt.DeepEquals, []string{"x", "y"})

	err = m.CreateACL(ctx, "foo", "z", "w")
	c.Assert(err, qt.Equals, nil)

	acl, err = m.ACL(ctx, "foo")
	c.Assert(err, qt.Equals, nil)
	c.Assert(acl, qt.DeepEquals, []string{"x", "y"})

	// Check that the meta ACL is created too.
	acl, err = m.ACL(ctx, "_foo")
	c.Assert(err, qt.Equals, nil)
	c.Assert(acl, qt.DeepEquals, []string(nil))
}

func TestManagerCreateACLWithInvalidACLName(t *testing.T) {
	c := qt.New(t)
	var checkedACL []string

	ctx := context.Background()

	m := managerWithACLs(c, "", nil, &checkedACL)

	err := m.CreateACL(ctx, "_foo", "x", "y")
	c.Assert(err, qt.ErrorMatches, `invalid ACL name "_foo"`)
}

// managerWithACLs returns a Manager instance running an ACL manager
// primed with the given ACLs. When an ACL is checked, *checkedACL is set
// to the ACL that's checked.
func managerWithACLs(c *qt.C, rootPath string, acls map[string][]string, checkedACL *[]string) *aclstore.Manager {
	ctx := context.Background()
	store := aclstore.NewACLStore(memsimplekv.NewStore())
	for aclName, users := range acls {
		err := store.CreateACL(ctx, aclName, users)
		c.Assert(err, qt.Equals, nil)
	}
	m, err := aclstore.NewManager(ctx, aclstore.Params{
		Store:    store,
		RootPath: rootPath,
		Authenticate: func(ctx context.Context, w http.ResponseWriter, req *http.Request) (aclstore.Identity, error) {
			return identityFunc(func(ctx context.Context, acl []string) (bool, error) {
				*checkedACL = acl
				return true, nil
			}), nil
		},
	})
	c.Assert(err, qt.Equals, nil)
	return m
}

type identityFunc func(ctx context.Context, acl []string) (bool, error)

func (f identityFunc) Allow(ctx context.Context, acl []string) (bool, error) {
	return f(ctx, acl)
}

// assertJSONCall asserts that when the given handler is called with
// the given parameters, the result is as specified.
func assertJSONCall(c *qt.C, method, url string, body interface{}, expectStatus int, expectResponse interface{}) {
	var bodyr io.Reader
	if body != nil {
		bodyData, err := json.Marshal(body)
		c.Assert(err, qt.Equals, nil)
		bodyr = bytes.NewReader(bodyData)
	}
	req, err := http.NewRequest(method, url, bodyr)
	c.Assert(err, qt.Equals, nil)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	c.Assert(err, qt.Equals, nil)
	defer resp.Body.Close()
	respData, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, qt.Equals, nil)
	if expectResponse == nil {
		c.Assert(respData, qt.HasLen, 0, qt.Commentf("body: %s", respData))
		return
	}
	c.Assert(resp.StatusCode, qt.Equals, expectStatus, qt.Commentf("body: %s", respData))
	c.Assert(resp.Header.Get("Content-Type"), qt.Equals, "application/json")
	respValue := reflect.New(reflect.TypeOf(expectResponse))
	err = json.Unmarshal(respData, respValue.Interface())
	c.Assert(err, qt.Equals, nil)
	c.Assert(respValue.Elem().Interface(), qt.DeepEquals, expectResponse)
}
