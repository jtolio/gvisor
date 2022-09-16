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

// Package direct provides a filesystem implementation that directly accesses
// the host filesystem to service filesystem operations.
//
// Lock order:
//
//	regularFileFD/directoryFD.mu
//	  filesystem.renameMu
//	    dentry.cachingMu
//	      dentryCache.mu
//	      dentry.dirMu
//	        filesystem.syncMu
//	        dentry.metadataMu
//	          *** "memmap.Mappable locks" below this point
//	          dentry.mapsMu
//	            *** "memmap.Mappable locks taken by Translate" below this point
//	            dentry.handleMu
//	              dentry.dataMu
//	          filesystem.inoMu
//	specialFileFD.mu
//	  specialFileFD.bufMu
//
// Locking dentry.dirMu and dentry.metadataMu in multiple dentries requires that
// either ancestor dentries are locked before descendant dentries, or that
// filesystem.renameMu is locked for writing.
package direct

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	refs_vfs1 "gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/refsvfs2"
	fslock "gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
)

// Name is the default filesystem name.
const Name = "directfs"

// Mount option names for directfs.
const (
	moptSockFD                 = "sock_fd"
	moptCache                  = "cache"
	moptLimitHostFDTranslation = "limit_host_fd_translation"
	moptOverlayfsStaleRead     = "overlayfs_stale_read"
	moptHostUDS                = "host_uds"
)

// Valid values for the "cache" mount option.
const (
	cacheFSCache      = "fscache"
	cacheRevalidating = "host_revalidating"
)

const defaultMaxCachedDentries = 1000
const hostOpenFlags = unix.O_NOFOLLOW | unix.O_CLOEXEC

// UNIX_PATH_MAX as defined in include/uapi/linux/un.h.
const unixPathMax = 108

// +stateify savable
type dentryCache struct {
	// mu protects the below fields.
	mu sync.Mutex `state:"nosave"`
	// dentries contains all dentries with 0 references. Due to race conditions,
	// it may also contain dentries with non-zero references.
	dentries dentryList
	// dentriesLen is the number of dentries in dentries.
	dentriesLen uint64
	// maxCachedDentries is the maximum number of cachable dentries.
	maxCachedDentries uint64
}

// SetDentryCacheSize sets the size of the global directfs dentry cache.
func SetDentryCacheSize(size int) {
	if size < 0 {
		return
	}
	if globalDentryCache != nil {
		log.Warningf("Global dentry cache has already been initialized. Ignoring subsequent attempt.")
		return
	}
	globalDentryCache = &dentryCache{maxCachedDentries: uint64(size)}
}

// globalDentryCache is a global cache of dentries across all directfs mounts.
var globalDentryCache *dentryCache

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct{}

// filesystem implements vfs.FilesystemImpl.
//
// +stateify savable
type filesystem struct {
	vfsfs vfs.Filesystem

	// Immutable options.
	opts filesystemOptions

	// clock is a realtime clock used to set timestamps in file operations.
	clock ktime.Clock

	// devMinor is the filesystem's minor device number. devMinor is immutable.
	devMinor uint32

	// root is the root dentry. root is immutable.
	root *dentry

	// renameMu serves two purposes:
	//
	//	- It synchronizes path resolution with renaming initiated by this
	//		client.
	//
	//	- It is held by path resolution to ensure that reachable dentries remain
	//		valid. A dentry is reachable by path resolution if it has a non-zero
	//		reference count (such that it is usable as vfs.ResolvingPath.Start() or
	//		is reachable from its children), or if it is a child dentry (such that
	//		it is reachable from its parent).
	renameMu sync.RWMutex `state:"nosave"`

	dentryCache *dentryCache

	// syncableDentries contains all non-synthetic dentries. specialFileFDs
	// contains all open specialFileFDs. These fields are protected by syncMu.
	syncMu           sync.Mutex `state:"nosave"`
	syncableDentries dentryList
	specialFileFDs   specialFDList

	// inoByKey maps host device ID/inode numbers to client-internal inode
	// numbers. inoByKey is not preserved across checkpoint/restore because
	// same files may have different inode numbers across checkpoint/restore.
	// inoByKey is protected by inoMu.
	inoMu    sync.Mutex        `state:"nosave"`
	inoByKey map[inoKey]uint64 `state:"nosave"`

	// lastIno is the last inode number assigned to a file. lastIno is accessed
	// using atomic memory operations.
	lastIno atomicbitops.Uint64

	// released is nonzero once filesystem.Release has been called.
	released atomicbitops.Int32

	// procSelfFD is an open FD to /proc/self/fd directory, which will be used to
	// reopen file descriptors.
	procSelfFD *fd.FD
}

// +stateify savable
type filesystemOptions struct {
	// goferSock is this client's connection to the gofer. The other end of this
	// UDS is owned by the gofer process. Closing this indicates to the gofer
	// that it can cleanup and exit.
	goferSock *unet.Socket

	interop interopMode // derived from the "cache" mount option

	// If limitHostFDTranslation is true, apply maxFillRange() constraints to
	// host FD mappings returned by dentry.(memmap.Mappable).Translate(). This
	// makes memory accounting behavior more consistent between cases where
	// host FDs are / are not available, but may increase the frequency of
	// sentry-handled page faults on files for which a host FD is available.
	limitHostFDTranslation bool

	// If overlayfsStaleRead is true, O_RDONLY host FDs provided by the host
	// filesystem may not be coherent with writable host FDs opened later, so
	// all uses of the former must be replaced by uses of the latter. This is
	// usually only the case when the host filesystem is a Linux overlayfs
	// mount. (Prior to Linux 4.18, patch series centered on commit
	// d1d04ef8572b "ovl: stack file ops", both I/O and memory mappings were
	// incoherent between pre-copy-up and post-copy-up FDs; after that patch
	// series, only memory mappings are incoherent.)
	overlayfsStaleRead bool

	// If regularFilesUseSpecialFileFD is true, application FDs representing
	// regular files will use distinct file handles for each FD, in the same
	// way that application FDs representing "special files" such as sockets
	// do. This option may regress performance due to excessive openat(2) calls.
	// This option is not supported with overlayfsStaleRead for now.
	regularFilesUseSpecialFileFD bool

	// hostUDS dictates whether the sentry can create and connect to host unix
	// domain sockets.
	hostUDS bool
}

// interopMode controls the client's interaction with other host filesystem
// users.
//
// +stateify savable
type interopMode uint32

const (
	// InteropModeExclusive is appropriate when the filesystem client is the
	// only user of the host filesystem.
	//
	//	- The client may cache arbitrary filesystem state (file data, metadata,
	//		filesystem structure, etc.).
	//
	//	- Client changes to filesystem state may be sent to the host
	//		filesystem asynchronously.
	//
	//	- File timestamps are based on client clocks. This ensures that users of
	//		the client observe timestamps that are coherent with their own clocks
	//		and consistent with Linux's semantics (in particular, it is not always
	//		possible for clients to set arbitrary atimes and mtimes depending on the
	//		host filesystem implementation, and never possible for clients to set
	//		arbitrary ctimes.)
	InteropModeExclusive interopMode = iota

	// InteropModeShared is appropriate when there are users of the host
	// filesystem that may mutate its state other than the client.
	//
	//	- The client must verify ("revalidate") cached filesystem state before
	//		using it.
	//
	//	- Client changes to filesystem state must be sent to the host
	//		filesystem synchronously.
	//
	//	- File timestamps are based on host clocks. This is necessary to
	//		ensure that timestamp changes are synchronized between host filesystem
	//		users.
	InteropModeShared
)

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// Release implements vfs.FilesystemType.Release.
func (FilesystemType) Release(ctx context.Context) {}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fstype FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	mopts := vfs.GenericParseMountOptions(opts.Data)
	var fsopts filesystemOptions

	// Get the gofer socket.
	moSocketFD, ok := mopts[moptSockFD]
	if !ok {
		ctx.Warningf("direct.FilesystemType.GetFilesystem: mount option %s is required", moptSockFD)
		return nil, nil, linuxerr.EINVAL
	}
	delete(mopts, moptSockFD)
	socketFD, err := strconv.Atoi(moSocketFD)
	if err != nil {
		ctx.Warningf("direct.FilesystemType.GetFilesystem: invalid socket FD: %s=%s", moptSockFD, moSocketFD)
		return nil, nil, linuxerr.EINVAL
	}
	fsopts.goferSock, err = unet.NewSocket(socketFD)
	if err != nil {
		ctx.Warningf("direct.FilesystemType.GetFilesystem: NewSocket failed: %v", err)
		return nil, nil, linuxerr.EINVAL
	}

	// Parse the cache policy. For historical reasons, this defaults to the
	// least generally-applicable option, InteropModeExclusive.
	fsopts.interop = InteropModeExclusive
	if cache, ok := mopts[moptCache]; ok {
		delete(mopts, moptCache)
		switch cache {
		case cacheFSCache:
			fsopts.interop = InteropModeExclusive
		case cacheRevalidating:
			fsopts.interop = InteropModeShared
		default:
			ctx.Warningf("direct.FilesystemType.GetFilesystem: invalid cache policy: %s=%s", moptCache, cache)
			return nil, nil, linuxerr.EINVAL
		}
	}

	// Handle simple flags.
	if _, ok := mopts[moptLimitHostFDTranslation]; ok {
		delete(mopts, moptLimitHostFDTranslation)
		fsopts.limitHostFDTranslation = true
	}
	if _, ok := mopts[moptOverlayfsStaleRead]; ok {
		delete(mopts, moptOverlayfsStaleRead)
		fsopts.overlayfsStaleRead = true
	}
	if _, ok := mopts[moptHostUDS]; ok {
		delete(mopts, moptHostUDS)
		fsopts.hostUDS = true
	}

	// Check for unparsed options.
	if len(mopts) != 0 {
		ctx.Warningf("direct.FilesystemType.GetFilesystem: unknown options: %v", mopts)
		return nil, nil, linuxerr.EINVAL
	}

	// Validation.
	if fsopts.regularFilesUseSpecialFileFD && fsopts.overlayfsStaleRead {
		// These options are not supported together. To support this, when a dentry
		// is opened writably for the first time, we need to iterate over all the
		// specialFileFDs of that dentry that represent a regular file and call
		// fd.hostFileMapper.RegenerateMappings(writable_fd).
		ctx.Warningf("direct.FilesystemType.GetFilesystem: regularFilesUseSpecialFileFD and overlayfsStaleRead options are not supported together.")
		return nil, nil, linuxerr.EINVAL
	}

	procSelfHostFD, err := unix.Open("/proc/self/fd", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		ctx.Warningf("direct.FilesystemType.GetFilesystem: error opening /proc/self/fd: %v", err)
		return nil, nil, err
	}
	procSelfFD := fd.New(procSelfHostFD)

	// Construct the filesystem object.
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}
	fs := &filesystem{
		opts:       fsopts,
		clock:      ktime.RealtimeClockFromContext(ctx),
		devMinor:   devMinor,
		inoByKey:   make(map[inoKey]uint64),
		procSelfFD: procSelfFD,
	}

	// Did the user configure a global dentry cache?
	if globalDentryCache != nil {
		fs.dentryCache = globalDentryCache
	} else {
		fs.dentryCache = &dentryCache{maxCachedDentries: defaultMaxCachedDentries}
	}

	if err = fs.initRoot(); err != nil {
		return nil, nil, err
	}

	fs.vfsfs.Init(vfsObj, &fstype, fs)
	return &fs.vfsfs, &fs.root.vfsd, nil
}

func (fs *filesystem) initRoot() error {
	r := fs.opts.goferSock.Reader(true)
	r.EnableFDs(1)

	// The gofer sends one byte only, along with the donated host FD.
	var buf [1]byte
	if cur, err := r.ReadVec([][]byte{buf[:]}); err != nil && (err != io.EOF || cur == 0) {
		r.CloseFDs()
		return fmt.Errorf("ReadVec failed: %v", err)
	}
	fds, err := r.ExtractFDs()
	if err != nil {
		return fmt.Errorf("ExtractFDs failed: %v", err)
	}
	if len(fds) != 1 {
		return fmt.Errorf("expected 1 FD from gofer, got %d", len(fds))
	}

	fs.root, err = fs.newDentry(handle{fds[0]})
	if err != nil {
		return err
	}
	// Set the root's reference count to 2. One reference is returned to the
	// caller, and the other is held by fs to prevent the root from being "cached"
	// and subsequently evicted.
	fs.root.refs = atomicbitops.FromInt64(2)
	return nil
}

// tryOpen tries to open() with different modes as documented.
func tryOpen(open func(int) (int, error)) (handle, error) {
	// Attempt to open file in the following in order:
	//   1. RDONLY | NONBLOCK: for all files, directories, ro mounts, FIFOs.
	//      Use non-blocking to prevent getting stuck inside open(2) for
	//      FIFOs. This option has no effect on regular files.
	//   2. PATH: for symlinks, sockets.
	flags := []int{
		unix.O_RDONLY | unix.O_NONBLOCK,
		unix.O_PATH,
	}

	var (
		hostFD int
		err    error
	)
	for _, flag := range flags {
		hostFD, err = open(flag | hostOpenFlags)
		if err == nil {
			return handle{fd: hostFD}, nil
		}

		if err == unix.ENOENT {
			// File doesn't exist, no point in retrying.
			return handle{fd: -1}, err
		}
	}
	return handle{fd: -1}, err
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	fs.released.Store(1)

	fs.syncMu.Lock()
	for elem := fs.syncableDentries.Front(); elem != nil; elem = elem.Next() {
		d := elem.d
		d.handleMu.Lock()
		d.dataMu.Lock()

		// TODO(jamieliu): Do we need to flushf/fsync d?
		// if h := d.writeHandleLocked(); h.isOpen() {
		//   flush h?
		// }

		// Close host FDs if they exist.
		oldReadFD := d.readHandle.fd
		d.readHandle.close()
		if oldReadFD != d.writeHandle.fd {
			d.writeHandle.close()
		}
		d.mmapHandle = handle{-1}
		d.handleMu.Unlock()
	}
	// There can't be any specialFileFDs still using fs, since each such
	// FileDescription would hold a reference on a Mount holding a reference on
	// fs.
	fs.syncMu.Unlock()

	// If leak checking is enabled, release all outstanding references in the
	// filesystem. We deliberately avoid doing this outside of leak checking; we
	// have released all external resources above rather than relying on dentry
	// destructors. fs.root may be nil if creating the client or initializing the
	// root dentry failed in GetFilesystem.
	if refs_vfs1.GetLeakMode() != refs_vfs1.NoLeakChecking && fs.root != nil {
		fs.renameMu.Lock()
		fs.root.releaseSyntheticRecursiveLocked(ctx)
		fs.evictAllCachedDentriesLocked(ctx)
		fs.renameMu.Unlock()

		// An extra reference was held by the filesystem on the root to prevent it from
		// being cached/evicted.
		fs.root.DecRef(ctx)
	}

	fs.vfsfs.VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.opts.goferSock.Close()
}

// releaseSyntheticRecursiveLocked traverses the tree with root d and decrements
// the reference count on every synthetic dentry. Synthetic dentries have one
// reference for existence that should be dropped during filesystem.Release.
//
// Precondition: d.fs.renameMu is locked for writing.
func (d *dentry) releaseSyntheticRecursiveLocked(ctx context.Context) {
	if d.isSynthetic() {
		d.decRefNoCaching()
		d.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
	}
	if d.isDir() {
		var children []*dentry
		d.dirMu.Lock()
		for _, child := range d.children {
			children = append(children, child)
		}
		d.dirMu.Unlock()
		for _, child := range children {
			if child != nil {
				child.releaseSyntheticRecursiveLocked(ctx)
			}
		}
	}
}

// inoKey is the key used to identify the inode backed by this dentry.
//
// +stateify savable
type inoKey struct {
	ino uint64
	dev uint64
}

// dentry implements vfs.DentryImpl.
//
// +stateify savable
type dentry struct {
	vfsd vfs.Dentry

	// refs is the reference count. Each dentry holds a reference on its
	// parent, even if disowned. An additional reference is held on all
	// synthetic dentries until they are unlinked or invalidated. When refs
	// reaches 0, the dentry may be added to the cache or destroyed. If refs ==
	// -1, the dentry has already been destroyed. refs is accessed using atomic
	// memory operations.
	refs atomicbitops.Int64

	// fs is the owning filesystem. fs is immutable.
	fs *filesystem

	// parent is this dentry's parent directory. Each dentry holds a reference
	// on its parent. If this dentry is a filesystem root, parent is nil.
	// parent is protected by filesystem.renameMu.
	parent *dentry

	// name is the name of this dentry in its parent. If this dentry is a
	// filesystem root, name is the empty string. name is protected by
	// filesystem.renameMu.
	name string

	// inoKey is used to identify this dentry's host file.
	inoKey inoKey

	// controlHandle is the host FD to this file. controlFD is immutable.
	//
	// if controlHandle.fd < 0, this dentry represents a synthetic file, i.e. a
	// file that does not exist on the host filesystem. As of this writing, the
	// only files that can be synthetic are sockets, pipes, and directories.
	controlHandle handle

	// If deleted is non-zero, the file represented by this dentry has been
	// deleted is accessed using atomic memory operations.
	deleted atomicbitops.Uint32

	// cachingMu is used to synchronize concurrent dentry caching attempts on
	// this dentry.
	cachingMu sync.Mutex `state:"nosave"`

	// If cached is true, this dentry is part of filesystem.dentryCache. cached
	// is protected by cachingMu.
	cached bool

	// cacheEntry links dentry into filesystem.dentryCache.dentries. It is
	// protected by filesystem.dentryCache.mu.
	cacheEntry dentryListElem

	// syncableListEntry links dentry into filesystem.syncableDentries. It is
	// protected by filesystem.syncMu.
	syncableListEntry dentryListElem

	dirMu sync.Mutex `state:"nosave"`

	// If this dentry represents a directory, children contains:
	//
	//	- Mappings of child filenames to dentries representing those children.
	//
	//	- Mappings of child filenames that are known not to exist to nil
	//		dentries (only if InteropModeShared is not in effect and the directory
	//		is not synthetic).
	//
	// children is protected by dirMu.
	children map[string]*dentry

	// If this dentry represents a directory, syntheticChildren is the number
	// of child dentries for which dentry.isSynthetic() == true.
	// syntheticChildren is protected by dirMu.
	syntheticChildren int

	// If this dentry represents a directory,
	// dentry.cachedMetadataAuthoritative() == true, and dirents is not nil, it
	// is a cache of all entries in the directory, in the order they were
	// read from the host. childrenSet just stores the `Name` field of all
	// dirents in a set for fast query. dirents and childrenSet are protected by
	// dirMu and share the same lifecycle.
	dirents     []vfs.Dirent
	childrenSet map[string]struct{}

	// Cached metadata; protected by metadataMu.
	// To access:
	//   - In situations where consistency is not required (like stat), these
	//     can be accessed using atomic operations only (without locking).
	//   - Lock metadataMu and can access without atomic operations.
	// To mutate:
	//   - Lock metadataMu and use atomic operations to update because we might
	//     have atomic readers that don't hold the lock.
	metadataMu sync.Mutex          `state:"nosave"`
	ino        uint64              // immutable
	mode       atomicbitops.Uint32 // type is immutable, perms are mutable
	uid        atomicbitops.Uint32 // auth.KUID, but stored as raw uint32 for sync/atomic
	gid        atomicbitops.Uint32 // auth.KGID, but ...
	blockSize  atomicbitops.Uint32 // 0 if unknown
	// Timestamps, all nsecs from the Unix epoch.
	atime atomicbitops.Int64
	mtime atomicbitops.Int64
	ctime atomicbitops.Int64
	// File size, which differs from other metadata in two ways:
	//
	//	- We make a best-effort attempt to keep it up to date even if
	//		!dentry.cachedMetadataAuthoritative() for the sake of O_APPEND writes.
	//
	//	- size is protected by both metadataMu and dataMu (i.e. both must be
	//		locked to mutate it; locking either is sufficient to access it).
	size atomicbitops.Uint64
	// If this dentry does not represent a synthetic file, deleted is 0, and
	// atimeDirty/mtimeDirty are non-zero, atime/mtime may have diverged from the
	// host file's timestamps, which should be updated when this dentry is
	// evicted.
	atimeDirty atomicbitops.Uint32
	mtimeDirty atomicbitops.Uint32

	// nlink counts the number of hard links to this dentry. It's updated and
	// accessed using atomic operations. It's not protected by metadataMu like the
	// other metadata fields.
	nlink atomicbitops.Uint32

	mapsMu sync.Mutex `state:"nosave"`

	// If this dentry represents a regular file, mappings tracks mappings of
	// the file into memmap.MappingSpaces. mappings is protected by mapsMu.
	mappings memmap.MappingSet

	//	- If this dentry represents a regular file or directory, readHandle is
	//		used for reads by all regularFileFDs/directoryFDs representing
	//		this dentry.
	//
	//	- If this dentry represents a regular file, writeFile is
	//		used for writes by all regularFileFDs representing this dentry.
	//
	//	- If this dentry represents a regular file, mmapHandle is the host FD
	//		used for memory mappings.
	//
	// readHandle and writeHandle may or may not be the same. Once either of them
	// are opened (-1 => valid FD), it may be mutated with handleMu locked, but
	// cannot be closed until the dentry is destroyed.
	//
	// mmapHandle is always either nil or readHandle; if writeHandle >= 0
	// (the file has been opened for writing), it is additionally either nil or
	// writeHandle.
	handleMu    sync.RWMutex `state:"nosave"`
	readHandle  handle
	writeHandle handle
	mmapHandle  handle

	// dataMu protects filedata.
	dataMu sync.RWMutex `state:"nosave"`

	// pf implements platform.File for mappings of hostFD.
	pf dentryPlatformFile

	// If this dentry represents a symbolic link, target is the symlink target.
	// target is immutable after initialization. haveTarget indicates if target
	// has been initialized. These are protected by dataMu.
	haveTarget bool
	target     string

	// If this dentry represents a synthetic socket file, endpoint is the
	// transport endpoint bound to this file.
	endpoint transport.BoundEndpoint

	// If this dentry represents a synthetic named pipe, pipe is the pipe
	// endpoint bound to this file.
	pipe *pipe.VFSPipe

	locks vfs.FileLocks

	// Inotify watches for this dentry.
	//
	// Note that inotify may behave unexpectedly in the presence of hard links,
	// because dentries corresponding to the same file have separate inotify
	// watches when they should share the same set.
	watches vfs.Watches
}

// +stateify savable
type dentryListElem struct {
	// d is the dentry that this elem represents.
	d *dentry
	dentryEntry
}

// newDentry creates a new dentry representing the given file. The dentry
// initially has no references, but is not cached; it is the caller's
// responsibility to set the dentry's reference count and/or call
// dentry.checkCachingLocked() as appropriate.
func (fs *filesystem) newDentry(controlHandle handle) (*dentry, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(controlHandle.fd, &stat); err != nil {
		log.Warningf("failed to fstat(2) FD %d: %v", controlHandle.fd, err)
		return nil, err
	}
	d := &dentry{
		fs:            fs,
		controlHandle: controlHandle,
		inoKey:        inoKeyFromHost(&stat),
		ino:           fs.inoFromHost(&stat),
		mode:          atomicbitops.FromUint32(stat.Mode),
		blockSize:     atomicbitops.FromUint32(uint32(stat.Blksize)),
		readHandle:    handle{-1},
		writeHandle:   handle{-1},
		mmapHandle:    handle{-1},
		uid:           atomicbitops.FromUint32(stat.Uid),
		gid:           atomicbitops.FromUint32(stat.Gid),
		size:          atomicbitops.FromUint64(uint64(stat.Size)),
		atime:         atomicbitops.FromInt64(dentryTimestampFromTimespec(stat.Atim)),
		mtime:         atomicbitops.FromInt64(dentryTimestampFromTimespec(stat.Mtim)),
		ctime:         atomicbitops.FromInt64(dentryTimestampFromTimespec(stat.Ctim)),
		nlink:         atomicbitops.FromUint32(uint32(stat.Nlink)),
	}
	d.pf.dentry = d
	d.cacheEntry.d = d
	d.syncableListEntry.d = d
	d.vfsd.Init(d)
	refsvfs2.Register(d)
	fs.syncMu.Lock()
	fs.syncableDentries.PushBack(&d.syncableListEntry)
	fs.syncMu.Unlock()
	return d, nil
}

func inoKeyFromHost(stat *unix.Stat_t) inoKey {
	return inoKey{
		ino: stat.Ino,
		dev: stat.Dev,
	}
}

func (fs *filesystem) inoFromHost(stat *unix.Stat_t) uint64 {
	key := inoKeyFromHost(stat)
	fs.inoMu.Lock()
	defer fs.inoMu.Unlock()

	if ino, ok := fs.inoByKey[key]; ok {
		return ino
	}
	ino := fs.nextIno()
	fs.inoByKey[key] = ino
	return ino
}

func (fs *filesystem) nextIno() uint64 {
	return fs.lastIno.Add(1)
}

func (d *dentry) isSynthetic() bool {
	return !d.isControlFileOk()
}

func (d *dentry) cachedMetadataAuthoritative() bool {
	return d.fs.opts.interop != InteropModeShared || d.isSynthetic()
}

// Precondition: d.metadataMu must be locked.
// +checklocks:d.metadataMu
func (d *dentry) updateMetadataFromStatLocked(stat *unix.Stat_t) error {
	if got, want := stat.Mode&unix.S_IFMT, d.fileType(); got != want {
		panic(fmt.Sprintf("direct.dentry file type changed from %#o to %#o", want, got))
	}
	d.mode.Store(stat.Mode)
	d.uid.Store(stat.Uid)
	d.gid.Store(stat.Gid)
	d.blockSize.Store(uint32(stat.Blksize))
	// Don't override newer client-defined timestamps with old host-defined
	// ones.
	if d.atimeDirty.Load() == 0 {
		d.atime.Store(dentryTimestampFromTimespec(stat.Atim))
	}
	if d.mtimeDirty.Load() == 0 {
		d.mtime.Store(dentryTimestampFromTimespec(stat.Mtim))
	}
	d.ctime.Store(dentryTimestampFromTimespec(stat.Ctim))
	d.nlink.Store(uint32(stat.Nlink))
	d.updateSizeLocked(uint64(stat.Size))
	return nil
}

// Preconditions: !d.isSynthetic().
// Preconditions: d.metadataMu is locked.
// +checklocks:d.metadataMu
func (d *dentry) refreshSizeLocked(fd int) error {
	// Using statx(2) with a minimal mask is faster than fstat(2).
	var stat unix.Statx_t
	err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_SIZE, &stat)
	if err != nil {
		return err
	}
	d.updateSizeLocked(stat.Size)
	return nil
}

func (d *dentry) withSuitableFD(fn func(fd int) error) error {
	handleMuRLocked := false
	fd := -1
	// Use open FDs in preferenece to the control FD. Control FDs may be opened
	// with O_PATH. This may be significantly more efficient in some
	// implementations. Prefer a writable FD over a readable one since some
	// filesystem implementations may update a writable FD's metadata after
	// writes, without making metadata updates immediately visible to read-only
	// FDs representing the same file.
	d.handleMu.RLock()
	switch {
	case d.writeHandle.isOpen():
		fd = d.writeHandle.fd
		handleMuRLocked = true
	case d.readHandle.isOpen():
		fd = d.readHandle.fd
		handleMuRLocked = true
	default:
		fd = d.controlHandle.fd
		d.handleMu.RUnlock()
	}

	err := fn(fd)
	if handleMuRLocked {
		// handleMu must be released before updateFromLisaStatLocked().
		d.handleMu.RUnlock() // +checklocksforce: complex case.
	}
	return err
}

// updateMetadata is called to sync d's metadata with the host.
func (d *dentry) updateMetadata() error {
	d.metadataMu.Lock()
	defer d.metadataMu.Unlock()

	var stat unix.Stat_t
	if err := d.withSuitableFD(func(fd int) error {
		return unix.Fstat(fd, &stat)
	}); err != nil {
		return err
	}
	return d.updateMetadataFromStatLocked(&stat)
}

func (d *dentry) fileType() uint32 {
	return d.mode.Load() & linux.S_IFMT
}

func (d *dentry) statTo(stat *linux.Statx) {
	stat.Mask = linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_NLINK | linux.STATX_UID | linux.STATX_GID | linux.STATX_ATIME | linux.STATX_MTIME | linux.STATX_CTIME | linux.STATX_INO | linux.STATX_SIZE | linux.STATX_BLOCKS | linux.STATX_BTIME
	stat.Blksize = d.blockSize.Load()
	stat.Nlink = d.nlink.Load()
	if stat.Nlink == 0 {
		// The host filesystem doesn't support link count; just make
		// something up. This is consistent with Linux, where
		// fs/inode.c:inode_init_always() initializes link count to 1, and
		// fs/9p/vfs_inode_dotl.c:v9fs_stat2inode_dotl() doesn't touch it if
		// it's not provided by the host filesystem.
		stat.Nlink = 1
	}
	stat.UID = d.uid.Load()
	stat.GID = d.gid.Load()
	stat.Mode = uint16(d.mode.Load())
	stat.Ino = uint64(d.ino)
	stat.Size = d.size.Load()
	// This is consistent with regularFileFD.Seek(), which treats regular files
	// as having no holes.
	stat.Blocks = (stat.Size + 511) / 512
	stat.Atime = linux.NsecToStatxTimestamp(d.atime.Load())
	stat.Btime = linux.StatxTimestamp{} // btime is not supported yet.
	stat.Ctime = linux.NsecToStatxTimestamp(d.ctime.Load())
	stat.Mtime = linux.NsecToStatxTimestamp(d.mtime.Load())
	stat.DevMajor = linux.UNNAMED_MAJOR
	stat.DevMinor = d.fs.devMinor
}

// Precondition: fs.renameMu must be locked for at least reading.
func (d *dentry) setStat(ctx context.Context, creds *auth.Credentials, opts *vfs.SetStatOptions, mnt *vfs.Mount) error {
	stat := &opts.Stat
	if stat.Mask == 0 {
		return nil
	}
	if stat.Mask&^(linux.STATX_MODE|linux.STATX_UID|linux.STATX_GID|linux.STATX_ATIME|linux.STATX_MTIME|linux.STATX_SIZE) != 0 {
		return linuxerr.EPERM
	}
	mode := linux.FileMode(d.mode.Load())
	if err := vfs.CheckSetStat(ctx, creds, opts, mode, auth.KUID(d.uid.Load()), auth.KGID(d.gid.Load())); err != nil {
		return err
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()

	d.metadataMu.Lock()
	defer d.metadataMu.Unlock()

	// Update size first, because if this succeeds, it impacts how timestamps
	// are updated. If it fails, we won't change timestamps.
	if stat.Mask&linux.STATX_SIZE != 0 {
		// Reject attempts to truncate files other than regular files.
		switch mode.FileType() {
		case linux.S_IFREG:
			// ok
		case linux.S_IFDIR:
			return linuxerr.EISDIR
		default:
			return linuxerr.EINVAL
		}

		if d.isSynthetic() {
			d.updateSizeLocked(stat.Size)
		} else {
			if err := d.ensureSharedHandle(false /* read */, true /* write */, false /* trunc */); err != nil {
				return err
			}
			// d.dataMu must be held around the update to both the host
			// file's size and d.size to serialize with writeback (which
			// might otherwise write data back up to the old d.size after
			// the host file has been truncated).
			d.handleMu.RLock()
			d.dataMu.Lock()
			if err := unix.Ftruncate(d.writeHandle.fd, int64(stat.Size)); err != nil {
				d.dataMu.Unlock()
				d.handleMu.RUnlock()
				return err
			}
			// d.size should be kept up to date, and privatized
			// copy-on-write mappings of truncated pages need to be
			// invalidated, even if InteropModeShared is in effect.
			d.updateSizeAndUnlockDataMuLocked(stat.Size)
			d.handleMu.RUnlock()
		}
	}

	// Next, update timestamps. This must immediately follow after size update,
	// so no other intermediate attribute update failure will prevent this.
	var (
		now                         int64
		cachedMetadataAuthoritative bool = d.cachedMetadataAuthoritative()
	)
	if cachedMetadataAuthoritative {
		// Truncate updates mtime.
		if stat.Mask&(linux.STATX_SIZE|linux.STATX_MTIME) == linux.STATX_SIZE {
			stat.Mask |= linux.STATX_MTIME
			stat.Mtime = linux.StatxTimestamp{
				Nsec: linux.UTIME_NOW,
			}
		}

		// Use client clocks for timestamps.
		now = d.fs.clock.Now().Nanoseconds()
		if stat.Mask&linux.STATX_ATIME != 0 && stat.Atime.Nsec == linux.UTIME_NOW {
			stat.Atime = linux.NsecToStatxTimestamp(now)
		}
		if stat.Mask&linux.STATX_MTIME != 0 && stat.Mtime.Nsec == linux.UTIME_NOW {
			stat.Mtime = linux.NsecToStatxTimestamp(now)
		}
	}
	if stat.Mask&(linux.STATX_ATIME|linux.STATX_MTIME) != 0 {
		utimes := [2]unix.Timespec{
			{Sec: 0, Nsec: unix.UTIME_OMIT},
			{Sec: 0, Nsec: unix.UTIME_OMIT},
		}
		if stat.Mask&unix.STATX_ATIME != 0 {
			utimes[0].Sec = stat.Atime.Sec
			utimes[0].Nsec = int64(stat.Atime.Nsec)
		}
		if stat.Mask&unix.STATX_MTIME != 0 {
			utimes[1].Sec = stat.Mtime.Sec
			utimes[1].Nsec = int64(stat.Mtime.Nsec)
		}

		if !d.isSynthetic() {
			if d.isSymlink() {
				// utimensat operates different that other syscalls. To operate on a
				// symlink it *requires* AT_SYMLINK_NOFOLLOW with dirFD and a non-empty
				// name.
				if err := utimensat(d.parent.controlHandle.fd, d.name, utimes, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					return err
				}
			} else {
				hostFD := d.controlHandle.fd
				if d.isRegularFile() {
					// For regular files, utimensat(2) requires the FD to be open for
					// writing, see BUGS section.
					if err := d.ensureSharedHandle(false /* read */, true /* write */, false /* trunc */); err != nil {
						return err
					}
					d.handleMu.RLock()
					hostFD = d.writeHandle.fd
				}
				// Directories and regular files can operate directly on the fd
				// using empty name.
				err := utimensat(hostFD, "", utimes, 0)
				if d.isRegularFile() {
					d.handleMu.RUnlock()
				}
				if err != nil {
					return err
				}
			}
		}

		if cachedMetadataAuthoritative {
			// Note that stat.Atime.Nsec and stat.Mtime.Nsec can't be UTIME_NOW because
			// if cachedMetadataAuthoritative then we converted stat.Atime and
			// stat.Mtime to client-local timestamps above.
			if stat.Mask&linux.STATX_ATIME != 0 {
				d.atime.Store(stat.Atime.ToNsec())
				d.atimeDirty.Store(0)
			}
			if stat.Mask&linux.STATX_MTIME != 0 {
				d.mtime.Store(stat.Mtime.ToNsec())
				d.mtimeDirty.Store(0)
			}
		}
	}

	// Next, update mode.
	// As with Linux, if the UID, GID, or file size is changing, we have to
	// clear permission bits. Note that when set, clearSGID may cause
	// permissions to be updated.
	clearSGID := (stat.Mask&linux.STATX_UID != 0 && stat.UID != d.uid.Load()) ||
		(stat.Mask&linux.STATX_GID != 0 && stat.GID != d.gid.Load()) ||
		stat.Mask&linux.STATX_SIZE != 0
	if clearSGID {
		if stat.Mask&linux.STATX_MODE != 0 {
			stat.Mode = uint16(vfs.ClearSUIDAndSGID(uint32(stat.Mode)))
		} else {
			oldMode := d.mode.Load()
			if updatedMode := vfs.ClearSUIDAndSGID(oldMode); updatedMode != oldMode {
				stat.Mode = uint16(updatedMode)
				stat.Mask |= linux.STATX_MODE
			}
		}
	}
	if stat.Mask&linux.STATX_MODE != 0 {
		d.chmodLocked(uint32(stat.Mode))
	}

	// Finally, update UID/GID.
	if stat.Mask&(linux.STATX_UID|linux.STATX_GID) != 0 {
		// "If the owner or group is specified as -1, then that ID is not changed"
		// - chown(2)
		uid := -1
		if stat.Mask&linux.STATX_UID != 0 {
			uid = int(stat.UID)
		}
		gid := -1
		if stat.Mask&linux.STATX_GID != 0 {
			gid = int(stat.GID)
		}
		if !d.isSynthetic() {
			if err := fchown(d.controlHandle.fd, uid, gid); err != nil {
				return err
			}
		}
		if cachedMetadataAuthoritative && stat.Mask&linux.STATX_UID != 0 {
			d.uid.Store(stat.UID)
		}
		if cachedMetadataAuthoritative && stat.Mask&linux.STATX_GID != 0 {
			d.gid.Store(stat.GID)
		}
	}

	if cachedMetadataAuthoritative {
		d.ctime.Store(now)
	}
	return nil
}

// Preconditions:
// - d.fs.renameMu must be locked for at least reading.
// - d.metadataMu must be locked.
func (d *dentry) chmodLocked(mode uint32) error {
	if !d.isSynthetic() {
		if d.isSocket() && d.parent != nil {
			// A non-synthetic socket is only created on bind(2) in directfs.
			// fchmod(2) on it fails. We need to fchmodat(2) it from its parent.
			// Note that AT_SYMLINK_NOFOLLOW flag is not currently supported.
			if err := unix.Fchmodat(d.parent.controlHandle.fd, d.name, mode&^unix.S_IFMT, 0 /* flags */); err != nil {
				return err
			}
		} else {
			if err := unix.Fchmod(d.controlHandle.fd, mode&^unix.S_IFMT); err != nil {
				return err
			}
		}
	}
	if d.cachedMetadataAuthoritative() {
		d.mode.Store(d.fileType() | mode)
	}
	return nil
}

// doAllocate performs an allocate operation on d. Note that d.metadataMu will
// be held when allocate is called.
func (d *dentry) doAllocate(ctx context.Context, offset, length uint64, allocate func() error) error {
	d.metadataMu.Lock()
	defer d.metadataMu.Unlock()

	// Allocating a smaller size is a noop.
	size := offset + length
	if d.cachedMetadataAuthoritative() && size <= d.size.RacyLoad() {
		return nil
	}

	err := allocate()
	if err != nil {
		return err
	}
	d.updateSizeLocked(size)
	if d.cachedMetadataAuthoritative() {
		d.touchCMtimeLocked()
	}
	return nil
}

// Preconditions: d.metadataMu must be locked.
func (d *dentry) updateSizeLocked(newSize uint64) {
	d.dataMu.Lock()
	d.updateSizeAndUnlockDataMuLocked(newSize)
}

// Preconditions: d.metadataMu and d.dataMu must be locked.
//
// Postconditions: d.dataMu is unlocked.
// +checklocksrelease:d.dataMu
func (d *dentry) updateSizeAndUnlockDataMuLocked(newSize uint64) {
	oldSize := d.size.RacyLoad()
	d.size.Store(newSize)
	// d.dataMu must be unlocked to lock d.mapsMu and invalidate mappings
	// below. This allows concurrent calls to Read/Translate/etc. These
	// functions synchronize with truncation by refusing to use cache
	// contents beyond the new d.size. (We are still holding d.metadataMu,
	// so we can't race with Write or another truncate.)
	d.dataMu.Unlock()
	if newSize < oldSize {
		oldpgend, _ := hostarch.PageRoundUp(oldSize)
		newpgend, _ := hostarch.PageRoundUp(newSize)
		if oldpgend != newpgend {
			d.mapsMu.Lock()
			d.mappings.Invalidate(memmap.MappableRange{newpgend, oldpgend}, memmap.InvalidateOpts{
				// Compare Linux's mm/truncate.c:truncate_setsize() =>
				// truncate_pagecache() =>
				// mm/memory.c:unmap_mapping_range(evencows=1).
				InvalidatePrivate: true,
			})
			d.mapsMu.Unlock()
		}
	}
}

func (d *dentry) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes) error {
	return vfs.GenericCheckPermissions(creds, ats, linux.FileMode(d.mode.Load()), auth.KUID(d.uid.Load()), auth.KGID(d.gid.Load()))
}

func (d *dentry) checkXattrPermissions(creds *auth.Credentials, name string, ats vfs.AccessTypes) error {
	// Deny access to the "security" and "system" namespaces since applications
	// may expect these to affect kernel behavior in unimplemented ways
	// (b/148380782). Allow all other extended attributes to be passed through
	// to the host filesystem. This is inconsistent with Linux's 9p client,
	// but consistent with other filesystems (e.g. FUSE).
	//
	// NOTE(b/202533394): Also disallow "trusted" namespace for now. This is
	// consistent with the VFS1 gofer client.
	if strings.HasPrefix(name, linux.XATTR_SECURITY_PREFIX) || strings.HasPrefix(name, linux.XATTR_SYSTEM_PREFIX) || strings.HasPrefix(name, linux.XATTR_TRUSTED_PREFIX) {
		return linuxerr.EOPNOTSUPP
	}
	mode := linux.FileMode(d.mode.Load())
	kuid := auth.KUID(d.uid.Load())
	kgid := auth.KGID(d.gid.Load())
	if err := vfs.GenericCheckPermissions(creds, ats, mode, kuid, kgid); err != nil {
		return err
	}
	return vfs.CheckXattrPermissions(creds, ats, mode, kuid, name)
}

func (d *dentry) mayDelete(creds *auth.Credentials, child *dentry) error {
	return vfs.CheckDeleteSticky(
		creds,
		linux.FileMode(d.mode.Load()),
		auth.KUID(d.uid.Load()),
		auth.KUID(child.uid.Load()),
		auth.KGID(child.gid.Load()),
	)
}

// IncRef implements vfs.DentryImpl.IncRef.
func (d *dentry) IncRef() {
	// d.refs may be 0 if d.fs.renameMu is locked, which serializes against
	// d.checkCachingLocked().
	r := d.refs.Add(1)
	if d.LogRefs() {
		refsvfs2.LogIncRef(d, r)
	}
}

// TryIncRef implements vfs.DentryImpl.TryIncRef.
func (d *dentry) TryIncRef() bool {
	for {
		r := d.refs.Load()
		if r <= 0 {
			return false
		}
		if d.refs.CompareAndSwap(r, r+1) {
			if d.LogRefs() {
				refsvfs2.LogTryIncRef(d, r+1)
			}
			return true
		}
	}
}

// DecRef implements vfs.DentryImpl.DecRef.
func (d *dentry) DecRef(ctx context.Context) {
	if d.decRefNoCaching() == 0 {
		d.checkCachingLocked(ctx, false /* renameMuWriteLocked */)
	}
}

// decRefNoCaching decrements d's reference count without calling
// d.checkCachingLocked, even if d's reference count reaches 0; callers are
// responsible for ensuring that d.checkCachingLocked will be called later.
func (d *dentry) decRefNoCaching() int64 {
	r := d.refs.Add(-1)
	if d.LogRefs() {
		refsvfs2.LogDecRef(d, r)
	}
	if r < 0 {
		panic("direct.dentry.decRefNoCaching() called without holding a reference")
	}
	return r
}

// RefType implements refsvfs2.CheckedObject.Type.
func (d *dentry) RefType() string {
	return "direct.dentry"
}

// LeakMessage implements refsvfs2.CheckedObject.LeakMessage.
func (d *dentry) LeakMessage() string {
	return fmt.Sprintf("[direct.dentry %p] reference count of %d instead of -1", d, d.refs.Load())
}

// LogRefs implements refsvfs2.CheckedObject.LogRefs.
//
// This should only be set to true for debugging purposes, as it can generate an
// extremely large amount of output and drastically degrade performance.
func (d *dentry) LogRefs() bool {
	return false
}

// InotifyWithParent implements vfs.DentryImpl.InotifyWithParent.
func (d *dentry) InotifyWithParent(ctx context.Context, events, cookie uint32, et vfs.EventType) {
	if d.isDir() {
		events |= linux.IN_ISDIR
	}

	d.fs.renameMu.RLock()
	// The ordering below is important, Linux always notifies the parent first.
	if d.parent != nil {
		d.parent.watches.Notify(ctx, d.name, events, cookie, et, d.isDeleted())
	}
	d.watches.Notify(ctx, "", events, cookie, et, d.isDeleted())
	d.fs.renameMu.RUnlock()
}

// Watches implements vfs.DentryImpl.Watches.
func (d *dentry) Watches() *vfs.Watches {
	return &d.watches
}

// OnZeroWatches implements vfs.DentryImpl.OnZeroWatches.
//
// If no watches are left on this dentry and it has no references, cache it.
func (d *dentry) OnZeroWatches(ctx context.Context) {
	d.checkCachingLocked(ctx, false /* renameMuWriteLocked */)
}

// checkCachingLocked should be called after d's reference count becomes 0 or
// it becomes disowned.
//
// For performance, checkCachingLocked can also be called after d's reference
// count becomes non-zero, so that d can be removed from the LRU cache. This
// may help in reducing the size of the cache and hence reduce evictions. Note
// that this is not necessary for correctness.
//
// It may be called on a destroyed dentry. For example,
// renameMu[R]UnlockAndCheckCaching may call checkCachingLocked multiple times
// for the same dentry when the dentry is visited more than once in the same
// operation. One of the calls may destroy the dentry, so subsequent calls will
// do nothing.
//
// Preconditions: d.fs.renameMu must be locked for writing if
// renameMuWriteLocked is true; it may be temporarily unlocked.
func (d *dentry) checkCachingLocked(ctx context.Context, renameMuWriteLocked bool) {
	d.cachingMu.Lock()
	refs := d.refs.Load()
	if refs == -1 {
		// Dentry has already been destroyed.
		d.cachingMu.Unlock()
		return
	}
	if refs > 0 {
		// fs.dentryCache.dentries is permitted to contain dentries with non-zero
		// refs, which are skipped by fs.evictCachedDentryLocked() upon reaching
		// the end of the LRU. But it is still beneficial to remove d from the
		// cache as we are already holding d.cachingMu. Keeping a cleaner cache
		// also reduces the number of evictions (which is expensive as it acquires
		// fs.renameMu).
		d.removeFromCacheLocked()
		d.cachingMu.Unlock()
		return
	}
	// Deleted and invalidated dentries with zero references are no longer
	// reachable by path resolution and should be dropped immediately.
	if d.vfsd.IsDead() {
		d.removeFromCacheLocked()
		d.cachingMu.Unlock()
		if !renameMuWriteLocked {
			// Need to lock d.fs.renameMu for writing as needed by d.destroyLocked().
			d.fs.renameMu.Lock()
			defer d.fs.renameMu.Unlock()
			// Now that renameMu is locked for writing, no more refs can be taken on
			// d because path resolution requires renameMu for reading at least.
			if d.refs.Load() != 0 {
				// Destroy d only if its ref is still 0. If not, either someone took a
				// ref on it or it got destroyed before fs.renameMu could be acquired.
				return
			}
		}
		if d.isDeleted() {
			d.watches.HandleDeletion(ctx)
		}
		d.destroyLocked(ctx) // +checklocksforce: renameMu must be acquired at this point.
		return
	}
	if d.vfsd.IsEvictable() {
		d.cachingMu.Unlock()
		// Attempt to evict.
		if renameMuWriteLocked {
			d.evictLocked(ctx) // +checklocksforce: renameMu is locked in this case.
			return
		}
		d.evict(ctx)
		return
	}
	// If d still has inotify watches and it is not deleted or invalidated, it
	// can't be evicted. Otherwise, we will lose its watches, even if a new
	// dentry is created for the same file in the future. Note that the size of
	// d.watches cannot concurrently transition from zero to non-zero, because
	// adding a watch requires holding a reference on d.
	if d.watches.Size() > 0 {
		// As in the refs > 0 case, removing d is beneficial.
		d.removeFromCacheLocked()
		d.cachingMu.Unlock()
		return
	}

	if d.fs.released.Load() != 0 {
		d.cachingMu.Unlock()
		if !renameMuWriteLocked {
			// Need to lock d.fs.renameMu to access d.parent. Lock it for writing as
			// needed by d.destroyLocked() later.
			d.fs.renameMu.Lock()
			defer d.fs.renameMu.Unlock()
		}
		if d.parent != nil {
			d.parent.dirMu.Lock()
			delete(d.parent.children, d.name)
			d.parent.dirMu.Unlock()
		}
		d.destroyLocked(ctx) // +checklocksforce: see above.
		return
	}

	d.fs.dentryCache.mu.Lock()
	// If d is already cached, just move it to the front of the LRU.
	if d.cached {
		d.fs.dentryCache.dentries.Remove(&d.cacheEntry)
		d.fs.dentryCache.dentries.PushFront(&d.cacheEntry)
		d.fs.dentryCache.mu.Unlock()
		d.cachingMu.Unlock()
		return
	}
	// Cache the dentry, then evict the least recently used cached dentry if
	// the cache becomes over-full.
	d.fs.dentryCache.dentries.PushFront(&d.cacheEntry)
	d.fs.dentryCache.dentriesLen++
	d.cached = true
	shouldEvict := d.fs.dentryCache.dentriesLen > d.fs.dentryCache.maxCachedDentries
	d.fs.dentryCache.mu.Unlock()
	d.cachingMu.Unlock()

	if shouldEvict {
		if !renameMuWriteLocked {
			// Need to lock d.fs.renameMu for writing as needed by
			// d.evictCachedDentryLocked().
			d.fs.renameMu.Lock()
			defer d.fs.renameMu.Unlock()
		}
		d.fs.evictCachedDentryLocked(ctx) // +checklocksforce: see above.
	}
}

// Preconditions: d.cachingMu must be locked.
func (d *dentry) removeFromCacheLocked() {
	if d.cached {
		d.fs.dentryCache.mu.Lock()
		d.fs.dentryCache.dentries.Remove(&d.cacheEntry)
		d.fs.dentryCache.dentriesLen--
		d.fs.dentryCache.mu.Unlock()
		d.cached = false
	}
}

// Precondition: fs.renameMu must be locked for writing; it may be temporarily
// unlocked.
// +checklocks:fs.renameMu
func (fs *filesystem) evictAllCachedDentriesLocked(ctx context.Context) {
	for fs.dentryCache.dentriesLen != 0 {
		fs.evictCachedDentryLocked(ctx)
	}
}

// Preconditions:
//   - fs.renameMu must be locked for writing; it may be temporarily unlocked.
//
// +checklocks:fs.renameMu
func (fs *filesystem) evictCachedDentryLocked(ctx context.Context) {
	fs.dentryCache.mu.Lock()
	victim := fs.dentryCache.dentries.Back()
	fs.dentryCache.mu.Unlock()
	if victim == nil {
		// fs.dentryCache.dentries may have become empty between when it was
		// checked and when we locked fs.dentryCache.mu.
		return
	}

	if victim.d.fs == fs {
		victim.d.evictLocked(ctx) // +checklocksforce: owned as precondition, victim.fs == fs
		return
	}

	// The dentry cache is shared between all direct filesystems and the victim is
	// from another filesystem. Have that filesystem do the work. We unlock
	// fs.renameMu to prevent deadlock: two filesystems could otherwise wait on
	// each others' renameMu.
	fs.renameMu.Unlock()
	defer fs.renameMu.Lock()
	victim.d.evict(ctx)
}

// Preconditions:
//   - d.fs.renameMu must not be locked for writing.
func (d *dentry) evict(ctx context.Context) {
	d.fs.renameMu.Lock()
	defer d.fs.renameMu.Unlock()
	d.evictLocked(ctx)
}

// Preconditions:
//   - d.fs.renameMu must be locked for writing; it may be temporarily unlocked.
//
// +checklocks:d.fs.renameMu
func (d *dentry) evictLocked(ctx context.Context) {
	d.cachingMu.Lock()
	d.removeFromCacheLocked()
	// d.refs or d.watches.Size() may have become non-zero from an earlier path
	// resolution since it was inserted into fs.dentryCache.dentries.
	if d.refs.Load() != 0 || d.watches.Size() != 0 {
		d.cachingMu.Unlock()
		return
	}
	if d.parent != nil {
		d.parent.dirMu.Lock()
		if !d.vfsd.IsDead() {
			// Note that d can't be a mount point (in any mount namespace), since VFS
			// holds references on mount points.
			d.fs.vfsfs.VirtualFilesystem().InvalidateDentry(ctx, &d.vfsd)
			delete(d.parent.children, d.name)
			// We're only deleting the dentry, not the file it
			// represents, so we don't need to update
			// victim parent.dirents etc.
		}
		d.parent.dirMu.Unlock()
	}
	// Safe to unlock cachingMu now that d.vfsd.IsDead(). Henceforth any
	// concurrent caching attempts on d will attempt to destroy it and so will
	// try to acquire fs.renameMu (which we have already acquiredd). Hence,
	// fs.renameMu will synchronize the destroy attempts.
	d.cachingMu.Unlock()
	d.destroyLocked(ctx) // +checklocksforce: owned as precondition.
}

// destroyLocked destroys the dentry.
//
// Preconditions:
//   - d.fs.renameMu must be locked for writing; it may be temporarily unlocked.
//   - d.refs == 0.
//   - d.parent.children[d.name] != d, i.e. d is not reachable by path traversal
//     from its former parent dentry.
//
// +checklocks:d.fs.renameMu
func (d *dentry) destroyLocked(ctx context.Context) {
	switch d.refs.Load() {
	case 0:
		// Mark the dentry destroyed.
		d.refs.Store(-1)
	case -1:
		panic("dentry.destroyLocked() called on already destroyed dentry")
	default:
		panic("dentry.destroyLocked() called with references on the dentry")
	}

	// Allow the following to proceed without renameMu locked to improve
	// scalability.
	d.fs.renameMu.Unlock()

	d.handleMu.Lock()
	oldReadFD := d.readHandle.fd
	d.readHandle.close()
	if oldReadFD != d.writeHandle.fd {
		d.writeHandle.close()
	}
	d.mmapHandle = handle{-1}
	d.handleMu.Unlock()

	if !d.isSynthetic() {
		// Close the control FD.
		d.controlHandle.close()

		// Remove d from the set of syncable dentries.
		d.fs.syncMu.Lock()
		d.fs.syncableDentries.Remove(&d.syncableListEntry)
		d.fs.syncMu.Unlock()
	}

	d.fs.renameMu.Lock()

	// Drop the reference held by d on its parent without recursively locking
	// d.fs.renameMu.
	if d.parent != nil && d.parent.decRefNoCaching() == 0 {
		d.parent.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
	}
	refsvfs2.Unregister(d)
}

func (d *dentry) isDeleted() bool {
	return d.deleted.Load() != 0
}

func (d *dentry) setDeleted() {
	d.deleted.Store(1)
}

func (d *dentry) isControlFileOk() bool {
	return d.controlHandle.fd >= 0
}

func (d *dentry) listXattr(ctx context.Context, size uint64) ([]string, error) {
	if !d.isControlFileOk() {
		return nil, nil
	}
	// Consistent with runsc/fsgofer.
	return nil, linuxerr.EOPNOTSUPP
}

func (d *dentry) getXattr(ctx context.Context, creds *auth.Credentials, opts *vfs.GetXattrOptions) (string, error) {
	if !d.isControlFileOk() {
		return "", linuxerr.ENODATA
	}
	if err := d.checkXattrPermissions(creds, opts.Name, vfs.MayRead); err != nil {
		return "", err
	}
	// Consistent with runsc/fsgofer.
	return "", linuxerr.EOPNOTSUPP
}

func (d *dentry) setXattr(ctx context.Context, creds *auth.Credentials, opts *vfs.SetXattrOptions) error {
	if !d.isControlFileOk() {
		return linuxerr.EPERM
	}
	if err := d.checkXattrPermissions(creds, opts.Name, vfs.MayWrite); err != nil {
		return err
	}
	// Consistent with runsc/fsgofer.
	return linuxerr.EOPNOTSUPP
}

func (d *dentry) removeXattr(ctx context.Context, creds *auth.Credentials, name string) error {
	if !d.isControlFileOk() {
		return linuxerr.EPERM
	}
	if err := d.checkXattrPermissions(creds, name, vfs.MayWrite); err != nil {
		return err
	}
	// Consistent with runsc/fsgofer.
	return linuxerr.EOPNOTSUPP
}

// Preconditions:
//   - !d.isSynthetic().
//   - d.isRegularFile() || d.isDir().
func (d *dentry) ensureSharedHandle(read, write, trunc bool) error {
	// O_TRUNC unconditionally requires us to obtain a new handle (opened with
	// O_TRUNC).
	if !trunc {
		d.handleMu.RLock()
		canReuseCurHandle := (!read || d.readHandle.isOpen()) && (!write || d.writeHandle.isOpen())
		d.handleMu.RUnlock()
		if canReuseCurHandle {
			// Current handles are sufficient.
			return nil
		}
	}

	d.handleMu.Lock()
	needNewHandle := (read && !d.readHandle.isOpen()) || (write && !d.writeHandle.isOpen()) || trunc
	if !needNewHandle {
		d.handleMu.Unlock()
		return nil
	}

	var fdsToCloseArr [2]int
	fdsToClose := fdsToCloseArr[:0]
	invalidateTranslations := false
	// Get a new handle. If this file has been opened for both reading and
	// writing, try to get a single handle that is usable for both:
	//
	//	- Writable memory mappings of a host FD require that the host FD is
	//		opened for both reading and writing.
	//
	//	- NOTE(b/141991141): Some filesystems may not ensure coherence
	//		between multiple handles for the same file.
	openReadable := d.readHandle.isOpen() || read
	openWritable := d.writeHandle.isOpen() || write
	h, err := d.openHandle(openReadable, openWritable, trunc)
	if linuxerr.Equals(linuxerr.EACCES, err) && (openReadable != read || openWritable != write) {
		// It may not be possible to use a single handle for both
		// reading and writing, since permissions on the file may have
		// changed to e.g. disallow reading after previously being
		// opened for reading. In this case, we have no choice but to
		// use separate handles for reading and writing.
		log.Debugf("direct.dentry.ensureSharedHandle: bifurcating read/write handles for dentry %p", d)
		openReadable = read
		openWritable = write
		h, err = d.openHandle(openReadable, openWritable, trunc)
	}
	if err != nil {
		d.handleMu.Unlock()
		return err
	}

	// Update d.readHandle and d.writeHandle
	if openReadable && openWritable && (!d.readHandle.isOpen() || !d.writeHandle.isOpen() || d.readHandle.fd != d.writeHandle.fd) {
		// Replace existing FDs with this one.
		if d.readHandle.isOpen() {
			// We already have a readable FD that may be in use by
			// concurrent callers of d.pf.FD().
			if d.fs.opts.overlayfsStaleRead {
				// If overlayfsStaleRead is in effect, then the new FD
				// may not be coherent with the existing one, so we
				// have no choice but to switch to mappings of the new
				// FD in both the application and sentry.
				if err := d.pf.hostFileMapper.RegenerateMappings(int(h.fd)); err != nil {
					d.handleMu.Unlock()
					log.Warningf("direct.dentry.ensureSharedHandle: failed to replace sentry mappings of old FD with mappings of new FD: %v", err)
					h.close()
					return err
				}
				fdsToClose = append(fdsToClose, d.readHandle.fd)
				invalidateTranslations = true
				d.readHandle = h
			} else {
				// Otherwise, we want to avoid invalidating existing
				// memmap.Translations (which is expensive); instead, use
				// dup3 to make the old file descriptor refer to the new
				// file description, then close the new file descriptor
				// (which is no longer needed). Racing callers of d.pf.FD()
				// may use the old or new file description, but this
				// doesn't matter since they refer to the same file, and
				// any racing mappings must be read-only.
				if err := unix.Dup3(h.fd, d.readHandle.fd, unix.O_CLOEXEC); err != nil {
					oldFD := d.readHandle.fd
					d.handleMu.Unlock()
					log.Warningf("direct.dentry.ensureSharedHandle: failed to dup fd %d to fd %d: %v", h.fd, oldFD, err)
					h.close()
					return err
				}
				fdsToClose = append(fdsToClose, h.fd)
				h = d.readHandle
			}
		} else {
			d.readHandle = h
		}
		if d.writeHandle.fd != h.fd && d.writeHandle.isOpen() {
			fdsToClose = append(fdsToClose, d.writeHandle.fd)
		}
		d.writeHandle = h
		d.mmapHandle = d.writeHandle
	} else if openReadable && !d.readHandle.isOpen() {
		d.readHandle = h
		// If the file has not been opened for writing, the new FD may
		// be used for read-only memory mappings.
		if !d.writeHandle.isOpen() {
			d.mmapHandle = d.readHandle
		}
	} else if openWritable && !d.writeHandle.isOpen() {
		d.writeHandle = h
	} else {
		// The new FD is not useful.
		fdsToClose = append(fdsToClose, h.fd)
	}
	d.handleMu.Unlock()

	if invalidateTranslations {
		// Invalidate application mappings that may be using an old FD; they
		// will be replaced with mappings using the new FD after future calls
		// to d.Translate(). This requires holding d.mapsMu, which precedes
		// d.handleMu in the lock order.
		d.mapsMu.Lock()
		d.mappings.InvalidateAll(memmap.InvalidateOpts{})
		d.mapsMu.Unlock()
	}
	for _, fd := range fdsToClose {
		unix.Close(int(fd))
	}

	return nil
}

func (d *dentry) syncHostFile(ctx context.Context) error {
	d.handleMu.RLock()
	defer d.handleMu.RUnlock()
	return d.syncHostFileLocked(ctx)
}

// Preconditions: d.handleMu must be locked.
func (d *dentry) syncHostFileLocked(ctx context.Context) error {
	// Prefer syncing write handles over read handles, since some remote
	// filesystem implementations may not sync changes made through write
	// handles otherwise.
	if d.writeHandle.isOpen() {
		ctx.UninterruptibleSleepStart(false)
		err := unix.Fsync(d.writeHandle.fd)
		ctx.UninterruptibleSleepFinish(false)
		return err
	}
	if d.readHandle.isOpen() {
		ctx.UninterruptibleSleepStart(false)
		err := unix.Fsync(d.readHandle.fd)
		ctx.UninterruptibleSleepFinish(false)
		return err
	}
	return nil
}

func (d *dentry) syncfsHostFile(ctx context.Context) error {
	d.handleMu.RLock()
	defer d.handleMu.RUnlock()
	if err := d.syncHostFileLocked(ctx); err != nil {
		// Only return err if we can reasonably have expected sync to succeed
		// (d is a regular file and was opened for writing).
		if d.isRegularFile() && d.writeHandle.isOpen() {
			return err
		}
		ctx.Debugf("direct.dentry.syncCachedFile: syncing non-writable or non-regular-file dentry failed: %v", err)
	}
	return nil
}

// incLinks increments link count.
func (d *dentry) incLinks() {
	if d.nlink.Load() == 0 {
		// The host filesystem doesn't support link count.
		return
	}
	d.nlink.Add(1)
}

// decLinks decrements link count.
func (d *dentry) decLinks() {
	if d.nlink.Load() == 0 {
		// The host filesystem doesn't support link count.
		return
	}
	d.nlink.Add(^uint32(0))
}

// fileDescription is embedded by FD implementations of
// vfs.FileDescriptionImpl.
//
// +stateify savable
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	lockLogging sync.Once `state:"nosave"`
}

func (fd *fileDescription) filesystem() *filesystem {
	return fd.vfsfd.Mount().Filesystem().Impl().(*filesystem)
}

func (fd *fileDescription) dentry() *dentry {
	return fd.vfsfd.Dentry().Impl().(*dentry)
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *fileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	d := fd.dentry()
	const validMask = uint32(linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID | linux.STATX_ATIME | linux.STATX_MTIME | linux.STATX_CTIME | linux.STATX_SIZE | linux.STATX_BLOCKS | linux.STATX_BTIME)
	if !d.cachedMetadataAuthoritative() && opts.Mask&validMask != 0 && opts.Sync != linux.AT_STATX_DONT_SYNC {
		// Use specialFileFD.handle for the Stat if available, for the
		// same reason that we try to use open FD in withSuitableFD().
		if sffd, ok := fd.vfsfd.Impl().(*specialFileFD); ok {
			if err := sffd.updateMetadata(); err != nil {
				return linux.Statx{}, err
			}
		} else {
			if err := d.updateMetadata(); err != nil {
				return linux.Statx{}, err
			}
		}
	}
	var stat linux.Statx
	d.statTo(&stat)
	return stat, nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	fs := fd.filesystem()
	fs.renameMu.RLock()
	defer fs.renameMu.RUnlock()
	return fd.dentry().setStat(ctx, auth.CredentialsFromContext(ctx), &opts, fd.vfsfd.Mount())
}

// ListXattr implements vfs.FileDescriptionImpl.ListXattr.
func (fd *fileDescription) ListXattr(ctx context.Context, size uint64) ([]string, error) {
	return fd.dentry().listXattr(ctx, size)
}

// GetXattr implements vfs.FileDescriptionImpl.GetXattr.
func (fd *fileDescription) GetXattr(ctx context.Context, opts vfs.GetXattrOptions) (string, error) {
	return fd.dentry().getXattr(ctx, auth.CredentialsFromContext(ctx), &opts)
}

// SetXattr implements vfs.FileDescriptionImpl.SetXattr.
func (fd *fileDescription) SetXattr(ctx context.Context, opts vfs.SetXattrOptions) error {
	return fd.dentry().setXattr(ctx, auth.CredentialsFromContext(ctx), &opts)
}

// RemoveXattr implements vfs.FileDescriptionImpl.RemoveXattr.
func (fd *fileDescription) RemoveXattr(ctx context.Context, name string) error {
	return fd.dentry().removeXattr(ctx, auth.CredentialsFromContext(ctx), name)
}

// LockBSD implements vfs.FileDescriptionImpl.LockBSD.
func (fd *fileDescription) LockBSD(ctx context.Context, uid fslock.UniqueID, ownerPID int32, t fslock.LockType, block bool) error {
	fd.lockLogging.Do(func() {
		log.Infof("File lock using directfs file handled internally.")
	})
	return fd.LockFD.LockBSD(ctx, uid, ownerPID, t, block)
}

// LockPOSIX implements vfs.FileDescriptionImpl.LockPOSIX.
func (fd *fileDescription) LockPOSIX(ctx context.Context, uid fslock.UniqueID, ownerPID int32, t fslock.LockType, r fslock.LockRange, block bool) error {
	fd.lockLogging.Do(func() {
		log.Infof("Range lock using directfs file handled internally.")
	})
	return fd.Locks().LockPOSIX(ctx, uid, ownerPID, t, r, block)
}

// UnlockPOSIX implements vfs.FileDescriptionImpl.UnlockPOSIX.
func (fd *fileDescription) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, r fslock.LockRange) error {
	return fd.Locks().UnlockPOSIX(ctx, uid, r)
}
