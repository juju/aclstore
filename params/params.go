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
