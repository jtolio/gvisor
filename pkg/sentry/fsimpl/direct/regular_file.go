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
	"io"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/metric"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

func (d *dentry) isRegularFile() bool {
	return d.fileType() == linux.S_IFREG
}

// +stateify savable
type regularFileFD struct {
	fileDescription

	// off is the file offset. off is protected by mu.
	mu  sync.Mutex `state:"nosave"`
	off int64
}

func newRegularFileFD(mnt *vfs.Mount, d *dentry, flags uint32) (*regularFileFD, error) {
	fd := &regularFileFD{}
	fd.LockFD.Init(&d.locks)
	if err := fd.vfsfd.Init(fd, flags, mnt, &d.vfsd, &vfs.FileDescriptionOptions{
		AllowDirectIO: true,
	}); err != nil {
		return nil, err
	}
	if fd.vfsfd.IsWritable() && (d.mode.Load()&0111 != 0) {
		metric.SuspiciousOperationsMetric.Increment("opened_write_execute_file")
	}
	return fd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *regularFileFD) Release(context.Context) {
}

// OnClose implements vfs.FileDescriptionImpl.OnClose.
func (fd *regularFileFD) OnClose(ctx context.Context) error {
	return nil
}

// Allocate implements vfs.FileDescriptionImpl.Allocate.
func (fd *regularFileFD) Allocate(ctx context.Context, mode, offset, length uint64) error {
	d := fd.dentry()
	return d.doAllocate(ctx, offset, length, func() error {
		d.handleMu.RLock()
		defer d.handleMu.RUnlock()
		return unix.Fallocate(d.writeHandle.fd, uint32(mode), int64(offset), int64(length))
	})
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *regularFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}

	// Check that flags are supported.
	//
	// TODO(gvisor.dev/issue/2601): Support select preadv2 flags.
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, linuxerr.EOPNOTSUPP
	}

	// Check for reading at EOF before calling into MM (but not under
	// InteropModeShared, which makes d.size unreliable).
	d := fd.dentry()
	if d.cachedMetadataAuthoritative() && uint64(offset) >= d.size.Load() {
		return 0, io.EOF
	}

	var (
		n       int64
		readErr error
	)
	// Lock d.metadataMu for the rest of the read to prevent d.size from
	// changing.
	d.metadataMu.Lock()
	defer d.metadataMu.Unlock()
	rw := getDentryReadWriter(ctx, d, offset)
	n, readErr = dst.CopyOutFrom(ctx, rw)
	putDentryReadWriter(rw)
	if d.fs.opts.interop != InteropModeShared {
		// Compare Linux's mm/filemap.c:do_generic_file_read() => file_accessed().
		d.touchAtimeLocked(fd.vfsfd.Mount())
	}
	return n, readErr
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *regularFileFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	fd.mu.Lock()
	n, err := fd.PRead(ctx, dst, fd.off, opts)
	fd.off += n
	fd.mu.Unlock()
	return n, err
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *regularFileFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	n, _, err := fd.pwrite(ctx, src, offset, opts)
	return n, err
}

// pwrite returns the number of bytes written, final offset, error. The final
// offset should be ignored by PWrite.
func (fd *regularFileFD) pwrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (written, finalOff int64, err error) {
	if offset < 0 {
		return 0, offset, linuxerr.EINVAL
	}

	// Check that flags are supported.
	//
	// TODO(gvisor.dev/issue/2601): Support select pwritev2 flags.
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, offset, linuxerr.EOPNOTSUPP
	}

	d := fd.dentry()

	d.metadataMu.Lock()
	defer d.metadataMu.Unlock()

	// If the fd was opened with O_APPEND, make sure the file size is updated.
	// There is a possible race here if size is modified externally after
	// metadata cache is updated.
	if fd.vfsfd.StatusFlags()&linux.O_APPEND != 0 && !d.cachedMetadataAuthoritative() {
		d.handleMu.RLock()
		err := d.refreshSizeLocked(d.writeHandle.fd)
		d.handleMu.RUnlock()
		if err != nil {
			return 0, offset, err
		}
	}

	// Set offset to file size if the fd was opened with O_APPEND.
	if fd.vfsfd.StatusFlags()&linux.O_APPEND != 0 {
		// Holding d.metadataMu is sufficient for reading d.size.
		offset = int64(d.size.RacyLoad())
	}
	limit, err := vfs.CheckLimit(ctx, offset, src.NumBytes())
	if err != nil {
		return 0, offset, err
	}
	src = src.TakeFirst64(limit)

	if d.fs.opts.interop != InteropModeShared {
		// Compare Linux's mm/filemap.c:__generic_file_write_iter() =>
		// file_update_time(). This is d.touchCMtime(), but without locking
		// d.metadataMu (recursively).
		d.touchCMtimeLocked()
	}

	// handleReadWriter always writes to the host file. So O_DIRECT is
	// effectively always set. Invalidate pages in d.mappings that have been
	// written to.
	pgstart := hostarch.PageRoundDown(uint64(offset))
	pgend, ok := hostarch.PageRoundUp(uint64(offset + src.NumBytes()))
	if !ok {
		return 0, offset, linuxerr.EINVAL
	}
	mr := memmap.MappableRange{pgstart, pgend}
	d.mapsMu.Lock()
	d.mappings.Invalidate(mr, memmap.InvalidateOpts{})
	d.mapsMu.Unlock()

	rw := getDentryReadWriter(ctx, d, offset)
	n, err := src.CopyInTo(ctx, rw)
	putDentryReadWriter(rw)
	if err != nil {
		return n, offset + n, err
	}
	if n > 0 && fd.vfsfd.StatusFlags()&(linux.O_DSYNC|linux.O_SYNC) != 0 {
		// Note that if any of the following fail, then we can't guarantee that
		// any data was actually written with the semantics of O_DSYNC or
		// O_SYNC, so we return zero bytes written. Compare Linux's
		// mm/filemap.c:generic_file_write_iter() =>
		// include/linux/fs.h:generic_write_sync().
		if err := d.syncHostFile(ctx); err != nil {
			return 0, offset, err
		}
	}

	// As with Linux, writing clears the setuid and setgid bits.
	if n > 0 {
		oldMode := d.mode.Load()
		// If setuid or setgid were set, update d.mode and propagate
		// changes to the host.
		if newMode := vfs.ClearSUIDAndSGID(oldMode); newMode != oldMode {
			d.chmodLocked(newMode)
		}
	}

	return n, offset + n, nil
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *regularFileFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	fd.mu.Lock()
	n, off, err := fd.pwrite(ctx, src, fd.off, opts)
	fd.off = off
	fd.mu.Unlock()
	return n, err
}

type dentryReadWriter struct {
	ctx context.Context
	d   *dentry
	off uint64
}

var dentryReadWriterPool = sync.Pool{
	New: func() any {
		return &dentryReadWriter{}
	},
}

func getDentryReadWriter(ctx context.Context, d *dentry, offset int64) *dentryReadWriter {
	rw := dentryReadWriterPool.Get().(*dentryReadWriter)
	rw.ctx = ctx
	rw.d = d
	rw.off = uint64(offset)
	return rw
}

func putDentryReadWriter(rw *dentryReadWriter) {
	rw.ctx = nil
	rw.d = nil
	dentryReadWriterPool.Put(rw)
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
func (rw *dentryReadWriter) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	if dsts.IsEmpty() {
		return 0, nil
	}

	rw.d.handleMu.RLock()
	defer rw.d.handleMu.RUnlock()
	n, err := rw.d.readHandle.readToBlocksAt(rw.ctx, dsts, rw.off)
	rw.off += n
	return n, err
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
//
// Preconditions: rw.d.metadataMu must be locked.
func (rw *dentryReadWriter) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	if srcs.IsEmpty() {
		return 0, nil
	}

	rw.d.handleMu.RLock()
	n, err := rw.d.writeHandle.writeFromBlocksAt(rw.ctx, srcs, rw.off)
	rw.off += n
	rw.d.dataMu.Lock()
	if rw.off > rw.d.size.Load() {
		rw.d.size.Store(rw.off)
	}
	rw.d.dataMu.Unlock()
	rw.d.handleMu.RUnlock()
	return n, err
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *regularFileFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	newOffset, err := regularFileSeekLocked(ctx, fd.dentry(), fd.off, offset, whence)
	if err != nil {
		return 0, err
	}
	fd.off = newOffset
	return newOffset, nil
}

// Calculate the new offset for a seek operation on a regular file.
func regularFileSeekLocked(ctx context.Context, d *dentry, fdOffset, offset int64, whence int32) (int64, error) {
	switch whence {
	case linux.SEEK_SET:
		// Use offset as specified.
	case linux.SEEK_CUR:
		offset += fdOffset
	case linux.SEEK_END, linux.SEEK_DATA, linux.SEEK_HOLE:
		// Ensure file size is up to date.
		if !d.cachedMetadataAuthoritative() {
			if err := d.updateMetadata(); err != nil {
				return 0, err
			}
		}
		size := int64(d.size.Load())
		// For SEEK_DATA and SEEK_HOLE, treat the file as a single contiguous
		// block of data.
		switch whence {
		case linux.SEEK_END:
			offset += size
		case linux.SEEK_DATA:
			if offset > size {
				return 0, linuxerr.ENXIO
			}
			// Use offset as specified.
		case linux.SEEK_HOLE:
			if offset > size {
				return 0, linuxerr.ENXIO
			}
			offset = size
		}
	default:
		return 0, linuxerr.EINVAL
	}
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	return offset, nil
}

// Sync implements vfs.FileDescriptionImpl.Sync.
func (fd *regularFileFD) Sync(ctx context.Context) error {
	return fd.dentry().syncHostFile(ctx)
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *regularFileFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	d := fd.dentry()
	// All mappings require a host FD to be coherent with other
	// filesystem users.
	if !d.mmapHandle.isOpen() {
		return linuxerr.ENODEV
	}
	// After this point, d may be used as a memmap.Mappable.
	d.pf.hostFileMapperInitOnce.Do(d.pf.hostFileMapper.Init)
	return vfs.GenericConfigureMMap(&fd.vfsfd, d, opts)
}

// AddMapping implements memmap.Mappable.AddMapping.
func (d *dentry) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	d.mapsMu.Lock()
	mapped := d.mappings.AddMapping(ms, ar, offset, writable)
	// Do this unconditionally since whether we have a host FD can change
	// across save/restore.
	for _, r := range mapped {
		d.pf.hostFileMapper.IncRefOn(r)
	}
	d.mapsMu.Unlock()
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (d *dentry) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
	d.mapsMu.Lock()
	unmapped := d.mappings.RemoveMapping(ms, ar, offset, writable)
	for _, r := range unmapped {
		d.pf.hostFileMapper.DecRefOn(r)
	}
	d.mapsMu.Unlock()
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (d *dentry) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	return d.AddMapping(ctx, ms, dstAR, offset, writable)
}

// Translate implements memmap.Mappable.Translate.
func (d *dentry) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	mr := optional
	if d.fs.opts.limitHostFDTranslation {
		mr = maxFillRange(required, optional)
	}
	return []memmap.Translation{
		{
			Source: mr,
			File:   &d.pf,
			Offset: mr.Start,
			Perms:  hostarch.AnyAccess,
		},
	}, nil
}

func maxFillRange(required, optional memmap.MappableRange) memmap.MappableRange {
	const maxReadahead = 64 << 10 // 64 KB, chosen arbitrarily
	if required.Length() >= maxReadahead {
		return required
	}
	if optional.Length() <= maxReadahead {
		return optional
	}
	optional.Start = required.Start
	if optional.Length() <= maxReadahead {
		return optional
	}
	optional.End = optional.Start + maxReadahead
	return optional
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (d *dentry) InvalidateUnsavable(ctx context.Context) error {
	return nil
}

// dentryPlatformFile implements memmap.File. It exists solely because dentry
// cannot implement both vfs.DentryImpl.IncRef and memmap.File.IncRef.
//
// dentryPlatformFile is only used when a host FD representing the remote file
// is available (i.e. dentry.mmapFD >= 0), and that FD is used for application
// memory mappings (i.e. !filesystem.opts.forcePageCache).
//
// +stateify savable
type dentryPlatformFile struct {
	*dentry

	// fdRefs counts references on memmap.File offsets. fdRefs is protected
	// by dentry.dataMu.
	fdRefs fsutil.FrameRefSet

	// If this dentry represents a regular file, and dentry.mmapFD >= 0,
	// hostFileMapper caches mappings of dentry.mmapFD.
	hostFileMapper fsutil.HostFileMapper

	// hostFileMapperInitOnce is used to lazily initialize hostFileMapper.
	hostFileMapperInitOnce sync.Once `state:"nosave"`
}

// IncRef implements memmap.File.IncRef.
func (d *dentryPlatformFile) IncRef(fr memmap.FileRange) {
	d.dataMu.Lock()
	d.fdRefs.IncRefAndAccount(fr)
	d.dataMu.Unlock()
}

// DecRef implements memmap.File.DecRef.
func (d *dentryPlatformFile) DecRef(fr memmap.FileRange) {
	d.dataMu.Lock()
	d.fdRefs.DecRefAndAccount(fr)
	d.dataMu.Unlock()
}

// MapInternal implements memmap.File.MapInternal.
func (d *dentryPlatformFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	d.handleMu.RLock()
	defer d.handleMu.RUnlock()
	return d.hostFileMapper.MapInternal(fr, d.mmapHandle.fd, at.Write)
}

// FD implements memmap.File.FD.
func (d *dentryPlatformFile) FD() int {
	d.handleMu.RLock()
	defer d.handleMu.RUnlock()
	return d.mmapHandle.fd
}
