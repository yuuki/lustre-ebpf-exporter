package goexporter

import (
	"errors"
	"os/user"
	"strconv"
)

// UsernameResolver resolves UIDs to usernames. Only permanent "user not found"
// results are cached; transient NSS errors are retried on subsequent calls.
type UsernameResolver struct {
	cache map[uint32]string
}

func NewUsernameResolver() *UsernameResolver {
	return &UsernameResolver{cache: map[uint32]string{}}
}

// Resolve returns the username for the given UID.
// Returns "unknown" if the UID does not exist in the user database.
func (r *UsernameResolver) Resolve(uid uint32) string {
	if cached, ok := r.cache[uid]; ok {
		return cached
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		var unknownErr user.UnknownUserIdError
		if errors.As(err, &unknownErr) {
			r.cache[uid] = "unknown"
		}
		// Transient NSS errors are not cached so the next call retries.
		return "unknown"
	}
	r.cache[uid] = u.Username
	return u.Username
}
