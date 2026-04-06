package goexporter

import (
	"os/user"
	"strconv"
	"sync"
)

// UsernameResolver maps UIDs to usernames with a concurrent-safe cache.
type UsernameResolver struct {
	cache sync.Map // map[uint32]string
}

func NewUsernameResolver() *UsernameResolver {
	return &UsernameResolver{}
}

// Resolve returns the username for the given UID.
// Returns "unknown" if the UID cannot be resolved.
func (r *UsernameResolver) Resolve(uid uint32) string {
	if cached, ok := r.cache.Load(uid); ok {
		return cached.(string)
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		r.cache.Store(uid, "unknown")
		return "unknown"
	}
	r.cache.Store(uid, u.Username)
	return u.Username
}
