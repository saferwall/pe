// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import "io"

// peData is the internal abstraction for raw PE file bytes.
// It is backed either by an in-memory buffer (mmap or []byte via bufferData)
// or by an io.ReaderAt that reads on demand (readerAtData), so that callers
// never need to know how the underlying bytes are stored.
type peData interface {
	// slice returns bytes [offset, offset+size).
	// For bufferData this is zero-copy (returns a sub-slice).
	// For readerAtData this allocates a fresh buffer and fills it via ReadAt.
	slice(offset, size uint32) ([]byte, error)

	// dataSize returns the total number of accessible bytes.
	dataSize() uint32

	// readerAt returns an io.ReaderAt over the full data.
	// Used by AuthentihashExt and other range-reading code.
	readerAt() io.ReaderAt
}

// bufferData implements peData over an in-memory []byte.
// Used by NewFile (backing the mmap slice) and NewBytes.
type bufferData struct{ buf []byte }

func (b *bufferData) slice(offset, size uint32) ([]byte, error) {
	end := uint64(offset) + uint64(size)
	if end > uint64(len(b.buf)) {
		return nil, ErrOutsideBoundary
	}
	return b.buf[offset : offset+size], nil
}

func (b *bufferData) dataSize() uint32 { return uint32(len(b.buf)) }

func (b *bufferData) readerAt() io.ReaderAt { return &byteReaderAt{b.buf} }

// byteReaderAt wraps a []byte and implements io.ReaderAt without depending on
// bytes.Reader (which would require importing "bytes" here).
type byteReaderAt struct{ buf []byte }

func (r *byteReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(r.buf)) {
		return 0, io.EOF
	}
	n := copy(p, r.buf[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// readerAtData implements peData over an io.ReaderAt.
// Each slice call allocates a fresh buffer and fills it via ReadAt.
// Used by NewFileNoMmap to avoid memory-mapping (and the Windows file lock
// that mmap causes).
type readerAtData struct {
	ra io.ReaderAt
	sz uint32
}

func (r *readerAtData) slice(offset, size uint32) ([]byte, error) {
	if uint64(offset)+uint64(size) > uint64(r.sz) {
		return nil, ErrOutsideBoundary
	}
	buf := make([]byte, size)
	if _, err := r.ra.ReadAt(buf, int64(offset)); err != nil {
		return nil, err
	}
	return buf, nil
}

func (r *readerAtData) dataSize() uint32 { return r.sz }

func (r *readerAtData) readerAt() io.ReaderAt { return r.ra }
