package aclclient

import "gopkg.in/httprequest.v1"

//go:generate httprequest-generate-client github.com/juju/aclstore handler client

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
