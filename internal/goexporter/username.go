package goexporter

import (
	"errors"
	"os/user"
	"strconv"
	"sync"
)

// UsernameResolver resolves UIDs to usernames. Only permanent "user not found"
// results are cached; transient NSS errors are retried on subsequent calls.
// Thread-safe: accessed from both the perf-event loop and drain goroutine.
type UsernameResolver struct {
	mu    sync.Mutex
	cache map[uint32]string
}

func NewUsernameResolver() *UsernameResolver {
	return &UsernameResolver{cache: map[uint32]string{}}
}

// Resolve returns the username for the given UID.
// Returns "unknown" if the UID does not exist in the user database.
func (r *UsernameResolver) Resolve(uid uint32) string {
	r.mu.Lock()
	if cached, ok := r.cache[uid]; ok {
		r.mu.Unlock()
		return cached
	}
	r.mu.Unlock()

	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		var unknownErr user.UnknownUserIdError
		if errors.As(err, &unknownErr) {
			r.mu.Lock()
			r.cache[uid] = "unknown"
			r.mu.Unlock()
		}
		// Transient NSS errors are not cached so the next call retries.
		return "unknown"
	}
	r.mu.Lock()
	r.cache[uid] = u.Username
	r.mu.Unlock()
	return u.Username
}
