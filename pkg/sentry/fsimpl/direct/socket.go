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
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/waiter"
)

func (d *dentry) isSocket() bool {
	return d.fileType() == linux.S_IFSOCK
}

// endpoint is a host-backed transport.BoundEndpoint.
//
// An endpoint's lifetime is the time between when filesystem.BoundEndpointAt()
// is called and either BoundEndpoint.BidirectionalConnect or
// BoundEndpoint.UnidirectionalConnect is called.
//
// +stateify savable
type endpoint struct {
	// dentry is the filesystem dentry which produced this endpoint.
	dentry *dentry

	// path is the sentry path where this endpoint is bound.
	path string
}

// BidirectionalConnect implements BoundEndpoint.BidirectionalConnect.
func (e *endpoint) BidirectionalConnect(ctx context.Context, ce transport.ConnectingEndpoint, returnConnect func(transport.Receiver, transport.ConnectedEndpoint)) *syserr.Error {
	// No lock ordering required as only the ConnectingEndpoint has a mutex.
	ce.Lock()

	// Check connecting state.
	if ce.Connected() {
		ce.Unlock()
		return syserr.ErrAlreadyConnected
	}
	if ce.ListeningLocked() {
		ce.Unlock()
		return syserr.ErrInvalidEndpointState
	}

	c, err := e.newConnectedEndpoint(ctx, ce.Type(), ce.WaiterQueue())
	if err != nil {
		ce.Unlock()
		return err
	}

	returnConnect(c, c)
	ce.Unlock()
	if err := c.Init(); err != nil {
		return syserr.FromError(err)
	}

	return nil
}

// UnidirectionalConnect implements
// transport.BoundEndpoint.UnidirectionalConnect.
func (e *endpoint) UnidirectionalConnect(ctx context.Context) (transport.ConnectedEndpoint, *syserr.Error) {
	c, err := e.newConnectedEndpoint(ctx, linux.SOCK_DGRAM, &waiter.Queue{})
	if err != nil {
		return nil, err
	}

	if err := c.Init(); err != nil {
		return nil, syserr.FromError(err)
	}

	// We don't need the receiver.
	c.CloseRecv()
	c.Release(ctx)

	return c, nil
}

func isSocketTypeSupported(sockType linux.SockType) bool {
	switch sockType {
	case unix.SOCK_STREAM, unix.SOCK_DGRAM, unix.SOCK_SEQPACKET:
		return true
	default:
		return false
	}
}

func (e *endpoint) newConnectedEndpoint(ctx context.Context, sockType linux.SockType, queue *waiter.Queue) (*transport.SCMConnectedEndpoint, *syserr.Error) {
	if !e.dentry.fs.opts.hostUDS {
		return nil, syserr.ErrConnectionRefused
	}

	if !isSocketTypeSupported(sockType) {
		log.Warningf("newConnectedEndpoint(): unsupported socket type %d", sockType)
		return nil, syserr.ErrConnectionRefused
	}

	sock, err := unix.Socket(unix.AF_UNIX, int(sockType), 0)
	if err != nil {
		log.Warningf("newConnectedEndpoint(): socket(2) failed: %v", err)
		return nil, syserr.ErrConnectionRefused
	}

	sa := unix.SockaddrUnix{Name: filepath.Join("/proc/self/fd", strconv.Itoa(e.dentry.controlHandle.fd))}
	if err := unix.Connect(sock, &sa); err != nil {
		unix.Close(sock)
		log.Warningf("newConnectedEndpoint(): connect(2) failed: %v", err)
		return nil, syserr.ErrConnectionRefused
	}

	c, serr := transport.NewSCMEndpoint(sock, queue, e.path)
	if serr != nil {
		unix.Close(sock)
		log.Warningf("NewSCMEndpoint failed: sockType %d: %v", sockType, serr)
		return nil, serr
	}
	return c, nil
}

// Release implements transport.BoundEndpoint.Release.
func (e *endpoint) Release(ctx context.Context) {
	e.dentry.DecRef(ctx)
}

// Passcred implements transport.BoundEndpoint.Passcred.
func (e *endpoint) Passcred() bool {
	return false
}

type boundSocketFD struct {
	sock handle
}

// Close closes the host and gofer-backed FDs associated to this bound socket.
func (fd *boundSocketFD) Close(ctx context.Context) {
	fd.sock.close()
}

// NotificationFD is a host FD that can be used to notify when new clients
// connect to the socket.
func (fd *boundSocketFD) NotificationFD() int32 {
	return int32(fd.sock.fd)
}

// Listen makes a Listen RPC.
func (fd *boundSocketFD) Listen(ctx context.Context, backlog int32) error {
	return unix.Listen(int(fd.sock.fd), int(backlog))
}

// Accept makes an Accept RPC.
func (fd *boundSocketFD) Accept(ctx context.Context) (int, error) {
	flags := unix.O_NONBLOCK | unix.O_CLOEXEC
	nfd, _, err := unix.Accept4(int(fd.sock.fd), flags)
	if err != nil {
		return -1, err
	}
	return nfd, nil
}

// Preconditions:
// - filesystem.renameMu must be locked.
// - d.dirMu must be locked.
// - d.isDir().
// - opts.Endpoint != nil and is of type transport.HostBoundEndpoint.
// - d.fs.opts.hostUDS.
func (d *dentry) bindAtLocked(ctx context.Context, name string, creds *auth.Credentials, opts vfs.MknodOptions, ds **[]*dentry) error {
	// This mknod(2) is coming from unix bind(2), as opts.Endpoint is set.
	sockType := opts.Endpoint.(transport.Endpoint).Type()
	if !isSocketTypeSupported(sockType) {
		return unix.ENXIO
	}
	// Create and bind the socket using the sockPath.
	sockFD, err := unix.Socket(unix.AF_UNIX, int(sockType), 0)
	if err != nil {
		return err
	}
	bsFD := &boundSocketFD{handle{sockFD}}
	cu := cleanup.Make(func() {
		bsFD.Close(ctx)
	})
	defer cu.Clean()

	hbep := opts.Endpoint.(transport.HostBoundEndpoint)
	if err := hbep.SetBoundSocketFD(bsFD); err != nil {
		return err
	}
	// Ownership of bsFD has been transferred to hbep. So previous cleanup is not required.
	cu.Release()
	cu.Add(func() {
		hbep.ResetBoundSocketFD(ctx)
	})

	// fchmod(2) has to happen *before* the bind(2). sockFD's file mode will
	// be used in creating the filesystem-object in bind(2).
	if err := unix.Fchmod(sockFD, uint32(opts.Mode&^unix.S_IFMT)); err != nil {
		return err
	}

	// Because there is no "bindat" syscall in Linux, we must create an
	// absolute path to the socket we are creating. But go through /proc/self/fd
	// to avoid host path walk of the entire host path.
	sockPath := filepath.Join("/proc/self/fd", strconv.Itoa(d.controlHandle.fd), name)
	if err := unix.Bind(sockFD, &unix.SockaddrUnix{Name: sockPath}); err != nil {
		return err
	}
	cu.Add(func() {
		// Best effort attempt to remove the file in case of failure.
		if err := unix.Unlinkat(d.controlHandle.fd, name, 0); err != nil {
			log.Warningf("error unlinking socket file %q after failure: %v", sockPath, err)
		}
	})

	sockFileHandle, err := tryOpen(func(flags int) (int, error) {
		return unix.Openat(d.controlHandle.fd, name, flags, 0)
	})
	if err != nil {
		return err
	}
	cu.Add(func() {
		sockFileHandle.close()
	})

	if err := fchown(sockFileHandle.fd, int(creds.EffectiveKUID), int(creds.EffectiveKGID)); err != nil {
		return err
	}

	// In case of failure, insertCreatedChildLocked unlinks the created child and
	// closes sockFileHandle. So we can release cu, and manually do the remaining
	// cleanup work.
	cu.Release()
	if err := d.insertCreatedChildLocked(sockFileHandle, name, func(child *dentry) {
		// Set the endpoint on the newly created child dentry.
		child.endpoint = opts.Endpoint
	}, ds); err != nil {
		hbep.ResetBoundSocketFD(ctx)
		return err
	}
	return nil
}
