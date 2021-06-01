package aclclient

import (
	"golang.org/x/net/context"
	errgo "gopkg.in/errgo.v1"
	"gopkg.in/httprequest.v1"

	"github.com/juju/aclstore/v2/params"
)

//go:generate httprequest-generate-client github.com/juju/aclstore/v2 handler client

// Client represents an ACL store client.
type Client struct {
	client
}

// NewParams holds the parameters for creating a new client.
type NewParams struct {
	// BaseURL holds the URL prefix of all the endpoints in the ACL store.
	BaseURL string
	// Doer is used to make HTTP requests to the ACL store.
	Doer httprequest.Doer
}

// New returns a new client.
func New(p NewParams) *Client {
	var c Client
	c.Client.BaseURL = p.BaseURL
	c.Client.Doer = p.Doer
	return &c
}

// Get retrieves the contents of the given ACL.
func (c *Client) Get(ctx context.Context, name string) ([]string, error) {
	resp, err := c.GetACL(ctx, &params.GetACLRequest{
		Name: name,
	})
	if err != nil {
		return nil, errgo.Mask(err, isRemoteError)
	}
	return resp.Users, nil
}

// Set updates the contents of the given ACL to the given user list.
func (c *Client) Set(ctx context.Context, name string, users []string) error {
	err := c.SetACL(ctx, &params.SetACLRequest{
		Name: name,
		Body: params.SetACLRequestBody{
			Users: users,
		},
	})
	return errgo.Mask(err, isRemoteError)
}

// Add updates the contents of the given ACL to include the given user
// list.
func (c *Client) Add(ctx context.Context, name string, users []string) error {
	err := c.ModifyACL(ctx, &params.ModifyACLRequest{
		Name: name,
		Body: params.ModifyACLRequestBody{
			Add: users,
		},
	})
	return errgo.Mask(err, isRemoteError)
}

// Remove updates the contents of the given ACL to remove those in the
// given user list.
func (c *Client) Remove(ctx context.Context, name string, users []string) error {
	err := c.ModifyACL(ctx, &params.ModifyACLRequest{
		Name: name,
		Body: params.ModifyACLRequestBody{
			Remove: users,
		},
	})
	return errgo.Mask(err, isRemoteError)
}

// isRemoteError determines whether the given error is a
// httprequest.RemoteError.
func isRemoteError(err error) bool {
	_, ok := err.(*httprequest.RemoteError)
	return ok
}
