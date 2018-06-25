// Copyright 2018 Canonical Ltd.
// Licensed under the LGPL, see LICENCE file for details.

package aclstore

import (
	"context"
	"net/http"
	"strings"

	"github.com/julienschmidt/httprouter"
	"gopkg.in/errgo.v1"
	httprequest "gopkg.in/httprequest.v1"

	"github.com/juju/aclstore/params"
)

// Params holds the parameters for a NewManager call.
type Params struct {
	// Store holds the persistent storage used by the handler.
	Store ACLStore

	// RootPath holds the root URL path prefix to use
	// for the ACL endpoints. All the endpoints will be
	// prefixed with this path.
	RootPath string

	// Authenticate authenticates the given HTTP request and returns
	// the resulting authenticated identity. If authentication
	// fails, Authenticate should write its own response and return
	// an error.
	Authenticate func(ctx context.Context, w http.ResponseWriter, req *http.Request) (Identity, error)

	// InitialAdminUsers holds the contents of the admin ACL
	// when it is first created.
	InitialAdminUsers []string
}

// Identity represents an authenticated user.
type Identity interface {
	// Allow reports whether the user should be allowed to access
	// any of the users or groups in the given ACL slice.
	Allow(ctx context.Context, acl []string) (bool, error)
}

// AdminACL holds the name of the administrator ACL.
const AdminACL = "admin"

// CodeACLNotFound holds the error code returned from
// the HTTP endpoints when an ACL name has not been
// created.
const CodeACLNotFound = "ACL not found"

// Manager implements an ACL manager.
type Manager struct {
	p      Params
	router *httprouter.Router
}

var errAuthenticationFailed = errgo.Newf("authentication failed")

var reqServer = &httprequest.Server{
	ErrorWriter: func(ctx context.Context, w http.ResponseWriter, err error) {
		if errgo.Cause(err) == errAuthenticationFailed {
			// The Authenticate method has already written its response.
			return
		}
		status, body := errorMapper(ctx, err)
		httprequest.WriteJSON(w, status, body)
	},
}

func errorMapper(ctx context.Context, err error) (int, interface{}) {
	switch errgo.Cause(err) {
	case ErrACLNotFound:
		return http.StatusNotFound, &httprequest.RemoteError{
			Message: err.Error(),
			Code:    CodeACLNotFound,
		}
	case ErrBadUsername:
		err = httprequest.Errorf(httprequest.CodeBadRequest, "%v", err)
	}
	return httprequest.DefaultErrorMapper(ctx, err)
}

// NewManager returns a new Manager instance that manages a
// set of ACLs. It ensures there is at least one ACL
// created, named "admin", which is given p.InitialAdminUsers
// when it is first created.
func NewManager(ctx context.Context, p Params) (*Manager, error) {
	if err := p.Store.CreateACL(ctx, AdminACL, p.InitialAdminUsers...); err != nil {
		return nil, errgo.Notef(err, "cannot create initial admin ACL")
	}
	m := &Manager{
		p:      p,
		router: httprouter.New(),
	}
	// TODO(rog) install custom NotFound handler into router?
	httprequest.AddHandlers(m.router, reqServer.Handlers(m.newHandler))
	return m, nil
}

// ServeHTTP implements http.Handler by serving an ACL administration
// interface that allows clients to manipulate the ACLs. The set of
// ACLs that can be manipulated can be changed with the Manager.CreateACL
// method.
//
// All the endpoints are situated underneath the RootPath prefix
// passed to NewManager.
func (m *Manager) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path
	if m.p.RootPath != "" {
		path = strings.TrimPrefix(path, m.p.RootPath)
		if len(path) == len(req.URL.Path) || path == "" || path[0] != '/' {
			httprequest.WriteJSON(w, http.StatusNotFound, &httprequest.RemoteError{
				Message: "URL path not found",
				Code:    httprequest.CodeNotFound,
			})
			return
		}
	}
	req.URL.Path = path
	m.router.ServeHTTP(w, req)
}

// ACL returns the members of the given ACL.
func (m *Manager) ACL(ctx context.Context, name string) ([]string, error) {
	// TODO implement a cache to avoid hitting the underlying
	// store each time.
	return m.p.Store.Get(ctx, name)
}

// CreateACL creates an ACL with the given name. It also creates an ACL
// _name which is the ACL that guards membership of the ACL itself. Any
// member of _name or any member of the admin ACL may change the
// membership of ACL name. Only members of the admin ACL may change the
// membership of _name.
//
// The name itself must not start with an underscore.
//
// This does nothing if an ACL with that name already exists.
func (h *Manager) CreateACL(ctx context.Context, name string, initialUsers ...string) error {
	if isMetaName(name) {
		return errgo.Newf("invalid ACL name %q", name)
	}
	if err := h.p.Store.CreateACL(ctx, name, initialUsers...); err != nil {
		return errgo.Mask(err)
	}
	if err := h.p.Store.CreateACL(ctx, metaName(name)); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// aclName is implemented by the request parameters for all endpoints
// to return the associated ACL name.
type aclName interface {
	ACLName() string
}

type handler struct {
	manager *Manager
}

// newHandler returns a handler instance to serve a particular HTTP request.
func (m *Manager) newHandler(p httprequest.Params, arg aclName) (handler, context.Context, error) {
	ctx := p.Context
	if err := m.authorizeRequest(ctx, p, arg.ACLName()); err != nil {
		return handler{}, nil, errgo.Mask(err, errgo.Any)
	}
	return handler{
		manager: m,
	}, p.Context, nil
}

// authorizeRequest checks that an HTTP request is authorized. If the
// authorization failed because Authenticate failed, it returns an error
// with an errAuthenticationFailed cause to signal that the desired
// error response has already been written.
func (m *Manager) authorizeRequest(ctx context.Context, p httprequest.Params, aclName string) error {
	if aclName == "" {
		return httprequest.Errorf(httprequest.CodeBadRequest, "empty ACL name")
	}
	identity, err := m.p.Authenticate(ctx, p.Response, p.Request)
	if err != nil {
		return errAuthenticationFailed
	}
	var checkACLName string
	if aclName == AdminACL || isMetaName(aclName) {
		// We're trying to access either the admin ACL or a meta-ACL; for either
		// of these, admin privileges are needed.
		checkACLName = AdminACL
	} else {
		// For all normal ACLs, access for a given ACL name is decided via membership
		// of the meta-ACL for that name.
		checkACLName = metaName(aclName)
	}
	acl, err := m.ACL(ctx, checkACLName)
	if err != nil {
		return errgo.Mask(err, errgo.Is(ErrACLNotFound))
	}
	if checkACLName != AdminACL {
		// Admin users always get permission to do anything.
		adminACL, err := m.ACL(ctx, AdminACL)
		if err != nil {
			return errgo.Notef(err, "cannot get admin ACL")
		}
		acl = append(acl, adminACL...)
	}
	ok, err := identity.Allow(ctx, acl)
	if err != nil {
		return errgo.Notef(err, "cannot check permissions")
	}
	if !ok {
		return httprequest.Errorf(httprequest.CodeForbidden, "")
	}
	return nil
}

// GetACL returns the members of the ACL with the requested name.
// Only administrators and members of the meta-ACL for the name
// may access this endpoint. The meta-ACL for meta-ACLs is "admin".
func (h handler) GetACL(p httprequest.Params, req *params.GetACLRequest) (*params.GetACLResponse, error) {
	users, err := h.manager.p.Store.Get(p.Context, req.Name)
	if err != nil {
		return nil, errgo.Mask(err, errgo.Is(ErrACLNotFound))
	}
	return &params.GetACLResponse{
		Users: users,
	}, nil
}

// SetACL sets the members of the ACL with the requested name.
// Only administrators and members of the meta-ACL for the name
// may access this endpoint. The meta-ACL for meta-ACLs is "admin".
func (h handler) SetACL(p httprequest.Params, req *params.SetACLRequest) error {
	err := h.manager.p.Store.Set(p.Context, req.Name, req.Body.Users...)
	return errgo.Mask(err, errgo.Is(ErrACLNotFound), errgo.Is(ErrBadUsername))
}

func metaName(aclName string) string {
	return "_" + aclName
}

func isMetaName(aclName string) bool {
	return strings.HasPrefix(aclName, "_")
}
