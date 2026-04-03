// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"sync"
	_ "unsafe" // for linkname
)

// systemRoots should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/breml/rootcerts
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname systemRoots
var (
	once             sync.Once
	systemRootsMu    sync.RWMutex
	systemRoots      *CertPool
	systemRootsErr   error
	fallbacksSet     bool
	useFallbackRoots bool
)

func systemRootsPool() *CertPool {
	once.Do(initSystemRoots)
	systemRootsMu.RLock()
	defer systemRootsMu.RUnlock()
	return systemRoots
}

func initSystemRoots() {
	systemRootsMu.Lock()
	defer systemRootsMu.Unlock()

	fallbackRoots := systemRoots
	systemRoots, systemRootsErr = loadSystemRoots()
	if systemRootsErr != nil {
		systemRoots = nil
	}

	if fallbackRoots == nil {
		return // no fallbacks to try
	}

	systemCertsAvail := systemRoots != nil && (systemRoots.len() > 0 || systemRoots.systemPool)

	if !useFallbackRoots && systemCertsAvail {
		return
	}

	systemRoots, systemRootsErr = fallbackRoots, nil
}

// SetFallbackRoots sets the roots to use during certificate verification, if no
// custom roots are specified and a platform verifier or a system certificate
// pool is not available (for instance in a container which does not have a root
// certificate bundle). SetFallbackRoots will panic if roots is nil.
//
// SetFallbackRoots may only be called once, if called multiple times it will
// panic.
func SetFallbackRoots(roots *CertPool) {
	if roots == nil {
		panic("roots must be non-nil")
	}

	systemRootsMu.Lock()
	defer systemRootsMu.Unlock()

	if fallbacksSet {
		panic("SetFallbackRoots has already been called")
	}
	fallbacksSet = true

	// Handle case when initSystemRoots was not yet executed.
	// We handle that specially instead of calling loadSystemRoots, to avoid
	// spending excessive amount of cpu here, since the SetFallbackRoots in most cases
	// is going to be called at program startup.
	if systemRoots == nil && systemRootsErr == nil {
		systemRoots = roots
		useFallbackRoots = false
		return
	}

	once.Do(func() { panic("unreachable") }) // asserts that system roots were indeed loaded before.

	systemCertsAvail := systemRoots != nil && (systemRoots.len() > 0 || systemRoots.systemPool)

	if systemCertsAvail {
		return
	}

	systemRoots, systemRootsErr = roots, nil
}
