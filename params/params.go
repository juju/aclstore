// Copyright 2018 Canonical Ltd.
// Licensed under the LGPL, see LICENCE file for details.

package params

import "gopkg.in/httprequest.v1"

// SetACLRequest holds parameters for an aclstore.Manager.SetACL call.
type SetACLRequest struct {
	httprequest.Route `httprequest:"PUT /:name"`
	Body              SetACLRequestBody `httprequest:",body"`
	// Name holds the name of the ACL to change.
	Name string `httprequest:"name,path"`
}

// ACLName returns the name of the ACL that's being set.
func (r SetACLRequest) ACLName() string {
	return r.Name
}

// SetACLRequestBody holds the HTTP body for an aclstore.Manager.SetACL call.
type SetACLRequestBody struct {
	Users []string `json:"users"`
}

// ModifyACLRequest holds parameters for an aclstore.Manager.ModifyACL call.
type ModifyACLRequest struct {
	httprequest.Route `httprequest:"POST /:name"`
	Body              ModifyACLRequestBody `httprequest:",body"`
	// Name holds the name of the ACL to change.
	Name string `httprequest:"name,path"`
}

// ACLName returns the name of the ACL that's being modified.
func (r ModifyACLRequest) ACLName() string {
	return r.Name
}

// ModifyACLRequestBody holds the HTTP body for an aclstore.Manager.ModifyACL call.
// It is an error for both Add and Remove to be specified at the same time.
type ModifyACLRequestBody struct {
	// Add specifies users to add to the ACL.
	Add []string `json:"add,omitempty"`
	// Remove specifies users to remove from the ACL.
	Remove []string `json:"remove,omitempty"`
}

// GetACLRequest holds parameters for an aclstore.Manager.GetACL call.
type GetACLRequest struct {
	httprequest.Route `httprequest:"GET /:name"`
	Name              string `httprequest:"name,path"`
}

// ACLName returns the name of the ACL that's being retrieved.
func (r GetACLRequest) ACLName() string {
	return r.Name
}

// GetACLResponse holds the response body returned by an aclstore.Manager.GetACL call.
type GetACLResponse struct {
	Users []string `json:"users"`
}

// GetACLsRequest holds parameters for an aclstore.Manager.GetACLs call.
type GetACLsRequest struct {
	httprequest.Route `httprequest:"GET /"`
}

// ACLName returns the name of the ACL that's being retrieved.
func (r GetACLsRequest) ACLName() string {
	return "admin"
}

// GetACLsResponse holds the response body returned by an aclstore.Manager.GetACLs call.
type GetACLsResponse struct {
	ACLs []string `json:"acls"`
}
