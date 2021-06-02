// Copyright 2018 Canonical Ltd.
// Licensed under the LGPL, see LICENCE file for details.

package aclstore

import (
	"context"
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/julienschmidt/httprouter"
	"gopkg.in/errgo.v1"
	httprequest "gopkg.in/httprequest.v1"

	"github.com/juju/aclstore/v2/params"
)

// Params holds the parameters for a NewManager call.
type Params struct {
	// Store holds the persistent storage used by the handler.
	Store ACLStore

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
	p Params
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
	if err := p.Store.CreateACL(ctx, AdminACL, p.InitialAdminUsers); err != nil {
		return nil, errgo.Notef(err, "cannot create initial admin ACL")
	}
	m := &Manager{
		p: p,
	}
	return m, nil
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
	if err := h.p.Store.CreateACL(ctx, name, initialUsers); err != nil {
		return errgo.Mask(err)
	}
	if err := h.p.Store.CreateACL(ctx, metaName(name), nil); err != nil {
		return errgo.Mask(err)
	}
	return nil
}

// aclName is implemented by the request parameters for all endpoints
// to return the associated ACL name.
type aclName interface {
	ACLName() string
}

// HandlerParams holds the parameters for a NewHandler call.
type HandlerParams struct {
	// RootPath holds the root URL path prefix to use
	// for the ACL endpoints. All the endpoints will be
	// prefixed with this path.
	RootPath string

	// Authenticate authenticates the given HTTP request and returns
	// the resulting authenticated identity. If authentication
	// fails, Authenticate should write its own response and return
	// an error.
	Authenticate func(ctx context.Context, w http.ResponseWriter, req *http.Request) (Identity, error)
}

// NewHandler creates an ACL administration interface that allows clients
// to manipulate the ACLs. The set of ACLs that can be manipulated can be
// changed with the Manager.CreateACL method.
func (m *Manager) NewHandler(p HandlerParams) http.Handler {
	h := &handler{
		p:      p,
		m:      m,
		router: httprouter.New(),
	}
	h.router.NotFound = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		httprequest.WriteJSON(w, http.StatusNotFound, &httprequest.RemoteError{
			Message: "URL path not found",
			Code:    httprequest.CodeNotFound,
		})
	})
	for _, ep := range reqServer.Handlers(h.newHandler) {
		h.router.Handle(ep.Method, path.Join(p.RootPath, ep.Path), ep.Handle)
	}
	return h
}

type handler struct {
	p      HandlerParams
	m      *Manager
	router *httprouter.Router
}

// ServeHTTP implements http.Handler.
func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.router.ServeHTTP(w, req)
}

type handler1 struct {
	h *handler
}

// newHandler returns a handler instance to serve a particular HTTP request.
func (h *handler) newHandler(p httprequest.Params, arg aclName) (handler1, context.Context, error) {
	ctx := p.Context
	if err := h.authorizeRequest(ctx, p, arg.ACLName()); err != nil {
		return handler1{}, nil, errgo.Mask(err, errgo.Any)
	}
	return handler1{
		h: h,
	}, p.Context, nil
}

// authorizeRequest checks that an HTTP request is authorized. If the
// authorization failed because Authenticate failed, it returns an error
// with an errAuthenticationFailed cause to signal that the desired
// error response has already been written.
func (h *handler) authorizeRequest(ctx context.Context, p httprequest.Params, aclName string) error {
	if aclName == "" {
		return httprequest.Errorf(httprequest.CodeBadRequest, "empty ACL name")
	}
	identity, err := h.p.Authenticate(ctx, p.Response, p.Request)
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
	acl, err := h.m.ACL(ctx, checkACLName)
	if err != nil {
		return errgo.Mask(err, errgo.Is(ErrACLNotFound))
	}
	if checkACLName != AdminACL {
		// Admin users always get permission to do anything.
		adminACL, err := h.m.ACL(ctx, AdminACL)
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
func (h handler1) GetACL(p httprequest.Params, req *params.GetACLRequest) (*params.GetACLResponse, error) {
	users, err := h.h.m.p.Store.Get(p.Context, req.Name)
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
func (h handler1) SetACL(p httprequest.Params, req *params.SetACLRequest) error {
	err := h.h.m.p.Store.Set(p.Context, req.Name, req.Body.Users)
	return errgo.Mask(err, errgo.Is(ErrACLNotFound), errgo.Is(ErrBadUsername))
}

// ModifyACL modifies the members of the ACL with the requested name.
// Only administrators and members of the meta-ACL for the name
// may access this endpoint. The meta-ACL for meta-ACLs is "admin".
func (h handler1) ModifyACL(p httprequest.Params, req *params.ModifyACLRequest) error {
	switch {
	case len(req.Body.Add) > 0 && len(req.Body.Remove) > 0:
		return httprequest.Errorf(httprequest.CodeBadRequest, "cannot add and remove users at the same time")
	case len(req.Body.Add) > 0:
		err := h.h.m.p.Store.Add(p.Context, req.Name, req.Body.Add)
		return errgo.Mask(err, errgo.Is(ErrACLNotFound), errgo.Is(ErrBadUsername))
	case len(req.Body.Remove) > 0:
		err := h.h.m.p.Store.Remove(p.Context, req.Name, req.Body.Remove)
		return errgo.Mask(err, errgo.Is(ErrACLNotFound), errgo.Is(ErrBadUsername))
	default:
		return nil
	}
}

// GetACLs returns the list of all ACLs.
// Only administrators may access this endpoint.
func (h handler1) GetACLs(p httprequest.Params, req *params.GetACLsRequest) (*params.GetACLsResponse, error) {
	lister, ok := h.h.m.p.Store.(ACLLister)
	if !ok {
		return nil, errgo.Newf("cannot list ACLs")
	}
	acls, err := lister.ACLs(p.Context)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	sort.Strings(acls)
	return &params.GetACLsResponse{
		ACLs: acls,
	}, nil
}

func metaName(aclName string) string {
	return "_" + aclName
}

func isMetaName(aclName string) bool {
	return strings.HasPrefix(aclName, "_")
}
