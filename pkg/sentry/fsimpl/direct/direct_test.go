// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package direct

import (
	"io/ioutil"
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/time"
)

func TestDestroyIdempotent(t *testing.T) {
	dir, err := ioutil.TempDir("", "direct_test")
	if err != nil {
		t.Fatalf("ioutil.TempDir(): %v", err)
	}
	defer os.RemoveAll(dir)

	ctx := contexttest.Context(t)
	fs := filesystem{
		inoByKey: make(map[inoKey]uint64),
		clock:    time.RealtimeClockFromContext(ctx),
		// Test relies on no dentry being held in the cache.
		dentryCache: &dentryCache{maxCachedDentries: 0},
	}

	parentFD, err := tryOpen(func(flags int) (int, error) {
		return unix.Open(dir, flags, 0)
	})
	if err != nil {
		t.Fatalf("unix.Open(parent): %v", err)
	}
	parentDentry, err := fs.newDentry(parentFD)
	if err != nil {
		t.Fatalf("fs.newDentry(parent): %v", err)
	}

	childFD, err := os.CreateTemp(dir, "child")
	if err != nil {
		t.Fatalf("os.CreateTemp(child): %v", err)
	}
	childDentry, err := fs.newDentry(handle{int(childFD.Fd())})
	if err != nil {
		t.Fatalf("fs.newDentry(child): %v", err)
	}

	parentDentry.cacheNewChildLocked(childDentry, "child")

	fs.renameMu.Lock()
	defer fs.renameMu.Unlock()
	childDentry.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
	// Since cache size is 0, checkCachingLocked() should lead to child dentry
	// eviction. child dentry should have been destroyed.
	if got := childDentry.refs.Load(); got != -1 {
		t.Fatalf("child.refs=%d, want: -1", got)
	}
	// Parent will also be destroyed when child reference is removed.
	if got := parentDentry.refs.Load(); got != -1 {
		t.Fatalf("parent.refs=%d, want: -1", got)
	}
	childDentry.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
}
