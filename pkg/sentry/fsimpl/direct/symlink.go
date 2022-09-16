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
	"math"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func (d *dentry) isSymlink() bool {
	return d.fileType() == linux.S_IFLNK
}

// Precondition:
// - d.isSymlink().
// - If !d.cachedMetadataAuthoritative(), d should be have been revalidated.
func (d *dentry) readlink(mnt *vfs.Mount) (string, error) {
	if d.fs.opts.interop != InteropModeShared {
		d.touchAtime(mnt)
	}
	d.dataMu.Lock()
	defer d.dataMu.Unlock()
	if d.haveTarget {
		return d.target, nil
	}
	// This is similar to what os.Readlink does.
	for linkLen := 128; linkLen < math.MaxUint16; linkLen *= 2 {
		b := make([]byte, linkLen)
		n, err := unix.Readlinkat(d.controlHandle.fd, "", b)
		if err != nil {
			return "", err
		}
		if n < int(linkLen) {
			d.target = string(b[:n])
			d.haveTarget = true
			return d.target, nil
		}
	}
	return "", unix.ENOMEM
}
