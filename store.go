// Copyright 2018 Canonical Ltd.
// Licensed under the LGPL, see LICENCE file for details.

package aclstore

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/juju/simplekv"
	"gopkg.in/errgo.v1"
)

var (
	ErrACLNotFound = errgo.Newf("ACL not found")
	ErrBadUsername = errgo.Newf("bad username")
)

// separator is used as the character to divide usernames in the ACL.
// This needs to be a character that's illegal in usernames.
const separator = "\n"

// ACLStore is the persistent storage interface used by an ACLHandler.
type ACLStore interface {
	// CreateACL creates an ACL with the given name and initial users.
	// If the ACL already exists, this is a no-op and the initialUsers
	// argument is ignored.
	// It may return an error with an ErrBadUsername if the initial users
	// are not valid.
	CreateACL(ctx context.Context, aclName string, initialUsers []string) error

	// Add adds users to the ACL with the given name.
	// Adding a user that's already in the ACL is a no-op.
	// It returns an error with an ErrACLNotFound cause if the ACL
	// does not exist, or with an ErrBadUsername cause if any
	// of the usernames are not valid.
	Add(ctx context.Context, aclName string, users []string) error

	// Remove removes users from the ACL with the given name.
	// It returns an error with an ErrACLNotFound cause if the ACL
	// does not exist. It returns an error with an ErrUserNotFound
	// cause if any of the users do not exist.
	// TODO should it do nothing in that case?
	Remove(ctx context.Context, aclName string, users []string) error

	// Set sets the users held in the ACL with the given name.
	// It returns an ErrACLNotFound cause if the ACL does not
	// exist, or with an ErrBadUsername cause if any
	// of the usernames are not valid.
	Set(ctx context.Context, aclName string, users []string) error

	// Get returns the users held in the ACL with the given name,
	// sorted lexically. It returns an error with an ErrACLNotFound cause
	// if the ACL does not exist.
	Get(ctx context.Context, aclName string) ([]string, error)
}

// ACLLister enables clients to list stored ACLs.
type ACLLister interface {
	ACLs(ctx context.Context) ([]string, error)
}

// NewACLStore returns an ACLStore implementation that uses an underlying
// key-value store for persistent storage.
func NewACLStore(kv simplekv.Store) ACLStore {
	return &kvStore{kv}
}

type kvStore struct {
	kv simplekv.Store
}

var errAlreadyExists = errgo.Newf("ACL already exists")

// ACLs implements the ACLLister interface.
func (s *kvStore) ACLs(ctx context.Context) ([]string, error) {
	lister, ok := s.kv.(simplekv.KeyLister)
	if !ok {
		return nil, errgo.Newf("cannot list ACLs")
	}
	acls, err := lister.Keys(ctx)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return acls, nil
}

// CreateACL implements ACLStore.CreateACL.
func (s *kvStore) CreateACL(ctx context.Context, aclName string, initialUsers []string) error {
	err := s.kv.Update(ctx, aclName, time.Time{}, func(val []byte) ([]byte, error) {
		if val != nil {
			return nil, errAlreadyExists
		}
		newVal, err := s.aclToValue(initialUsers)
		if err != nil {
			return nil, errgo.Mask(err, errgo.Is(ErrBadUsername))
		}
		return newVal, nil
	})
	if err != nil {
		if errgo.Cause(err) == errAlreadyExists {
			return nil
		}
		return errgo.Mask(err, errgo.Is(ErrBadUsername))
	}
	return nil
}

// Add implements ACLStore.Add.
func (s *kvStore) Add(ctx context.Context, aclName string, users []string) error {
	err := s.kv.Update(ctx, aclName, time.Time{}, func(val []byte) ([]byte, error) {
		if val == nil {
			return nil, errgo.WithCausef(nil, ErrACLNotFound, "")
		}
		acl := s.valueToACL(val)
		acl = append(acl, users...)
		newVal, err := s.aclToValue(acl)
		if err != nil {
			return nil, errgo.Mask(err, errgo.Is(ErrBadUsername))
		}
		return newVal, nil
	})
	if err != nil {
		return errgo.Mask(err, errgo.Is(ErrACLNotFound), errgo.Is(ErrBadUsername))
	}
	return nil
}

// Remove implements ACLStore.Remove.
func (s *kvStore) Remove(ctx context.Context, aclName string, users []string) error {
	err := s.kv.Update(ctx, aclName, time.Time{}, func(val []byte) ([]byte, error) {
		if val == nil {
			return nil, errgo.WithCausef(nil, ErrACLNotFound, "")
		}
		acl := s.valueToACL(val)
		newACL := make([]string, 0, len(acl))
		for _, a := range acl {
			remove := false
			for _, r := range users {
				if r == a {
					remove = true
					break
				}
			}
			if !remove {
				newACL = append(newACL, a)
			}
		}
		newVal, err := s.aclToValue(newACL)
		if err != nil {
			return nil, errgo.Mask(err, errgo.Is(ErrBadUsername))
		}
		return newVal, nil
	})
	if err != nil {
		return errgo.Mask(err, errgo.Is(ErrACLNotFound), errgo.Is(ErrBadUsername))
	}
	return nil
}

// Set implements ACLStore.Set.
func (s *kvStore) Set(ctx context.Context, aclName string, users []string) error {
	newVal, err := s.aclToValue(users)
	if err != nil {
		return errgo.Mask(err, errgo.Is(ErrBadUsername))
	}
	err = s.kv.Update(ctx, aclName, time.Time{}, func(val []byte) ([]byte, error) {
		if val == nil {
			return nil, errgo.WithCausef(nil, ErrACLNotFound, "")
		}
		return newVal, nil
	})
	if err != nil {
		return errgo.Mask(err, errgo.Is(ErrACLNotFound))
	}
	return nil
}

// Get implements ACLStore.Get.
func (s *kvStore) Get(ctx context.Context, aclName string) ([]string, error) {
	val, err := s.kv.Get(ctx, aclName)
	if err != nil {
		if errgo.Cause(err) == simplekv.ErrNotFound {
			return nil, errgo.WithCausef(nil, ErrACLNotFound, "")
		}
		return nil, errgo.Mask(err)
	}
	return s.valueToACL(val), nil
}

func (*kvStore) aclToValue(acl []string) ([]byte, error) {
	if len(acl) == 0 {
		return nil, nil
	}
	acl = canonicalACL(acl)
	size := 0
	for _, a := range acl {
		size += len(a)
		if !validUser(a) {
			return nil, errgo.WithCausef(nil, ErrBadUsername, "invalid user name %q", a)
		}
	}
	out := make([]byte, 0, size+len(acl))
	out = append(out, acl[0]...)
	for _, a := range acl[1:] {
		out = append(out, separator...)
		out = append(out, a...)
	}
	return out, nil
}

func (*kvStore) valueToACL(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	return strings.Split(string(data), separator)
}

func canonicalACL(acl []string) []string {
	if len(acl) < 2 {
		return acl
	}
	needSort := false
	prev := acl[0]
	for _, a := range acl[1:] {
		if a <= prev {
			needSort = true
			break
		}
		prev = a
	}
	if !needSort {
		return acl
	}
	acl1 := make([]string, len(acl))
	copy(acl1, acl)
	sort.Strings(acl1)
	acl = acl1
	j := 1
	for i, a := range acl[1:] {
		if acl[i] == a {
			continue
		}
		acl[j] = a
		j++
	}
	return acl[:j]
}

func validUser(u string) bool {
	return len(u) > 0 && !strings.Contains(u, separator)
}
