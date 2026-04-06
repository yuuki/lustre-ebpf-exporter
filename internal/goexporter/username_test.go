package goexporter

import (
	"os/user"
	"strconv"
	"testing"
)

func TestUsernameResolverResolvesCurrentUser(t *testing.T) {
	t.Parallel()

	current, err := user.Current()
	if err != nil {
		t.Skipf("cannot get current user: %v", err)
	}
	uid64, err := strconv.ParseUint(current.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}

	resolver := NewUsernameResolver()
	got := resolver.Resolve(uint32(uid64))
	if got != current.Username {
		t.Fatalf("expected %q, got %q", current.Username, got)
	}
}

func TestUsernameResolverCachesResult(t *testing.T) {
	t.Parallel()

	resolver := NewUsernameResolver()
	// Use a UID that is extremely unlikely to exist on any system.
	const bogusUID uint32 = 4294967200
	got := resolver.Resolve(bogusUID)
	// second call should return the same cached value
	got2 := resolver.Resolve(bogusUID)
	if got != got2 {
		t.Fatalf("expected consistent result, got %q then %q", got, got2)
	}
}

func TestUsernameResolverCacheHit(t *testing.T) {
	t.Parallel()

	resolver := NewUsernameResolver()
	resolver.cache[12345] = "cacheduser"

	got := resolver.Resolve(12345)
	if got != "cacheduser" {
		t.Fatalf("expected \"cacheduser\", got %q", got)
	}
}
