package manager

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type DownloaderOptions struct {
	PartSize         int64
	ParallelNum      int
	EnableCheckpoint bool
	CheckpointDir    string
	VerifyData       bool
	UseTempFile      bool
	ClientOptions    []func(*s3.Options)
}

type DownloadResult struct {
	Written int64
}

type DownloadError struct {
	Err  error
	Path string
}

func (m *DownloadError) Error() string {
	var extra string
	if m.Err != nil {
		extra = fmt.Sprintf(", cause: %s", m.Err.Error())
	}
	return fmt.Sprintf("download failed %s", extra)
}

type Downloader struct {
	client  DownloadClient
	options DownloaderOptions
}

func (d *Downloader) newDelegate(ctx context.Context, request *s3.GetObjectInput, optFns ...func(*DownloaderOptions)) (*downloaderDelegate, error) {
	if request == nil {
		return nil, NewErrParamNull("request")
	}

	if !isValidBucketName(request.Bucket) {
		return nil, NewErrParamInvalid("request.Bucket")
	}

	if !isValidObjectName(request.Key) {
		return nil, NewErrParamInvalid("request.Key")
	}

	if request.Range != nil && !isValidRange(request.Range) {
		return nil, NewErrParamInvalid("request.Range")
	}

	delegate := downloaderDelegate{
		Downloader: *d,
		context:    ctx,
		request:    request,
	}

	for _, opt := range optFns {
		opt(&delegate.options)
	}

	if delegate.options.ParallelNum <= 0 {
		delegate.options.ParallelNum = DefaultParallel
	}
	if delegate.options.PartSize <= 0 {
		delegate.options.PartSize = DefaultPartSize
	}

	return &delegate, nil
}

func (d *Downloader) DownloadFile(ctx context.Context, request *s3.GetObjectInput, filePath string, optFns ...func(*DownloaderOptions)) (result *DownloadResult, err error) {
	// Downloader wrapper
	delegate, err := d.newDelegate(ctx, request, optFns...)
	if err != nil {
		return nil, err
	}

	// Source
	if err = delegate.checkSource(); err != nil {
		return nil, err
	}

	// Destination
	var file *os.File
	if file, err = delegate.checkDestination(filePath); err != nil {
		return nil, err
	}

	// Range
	if err = delegate.adjustRange(); err != nil {
		return nil, err
	}

	// Checkpoint
	if err = delegate.checkCheckpoint(); err != nil {
		return nil, err
	}

	// truncate to the right position
	if err = delegate.adjustWriter(file); err != nil {
		return nil, err
	}

	// CRC Part
	// delegate.updateCRCFlag()

	// download
	result, err = delegate.download()

	return result, delegate.closeWriter(file, err)
}

func NewDownloader(c DownloadClient, optFns ...func(*DownloaderOptions)) *Downloader {
	options := DownloaderOptions{
		PartSize:         DefaultPartSize,
		ParallelNum:      DefaultParallel,
		UseTempFile:      true,
		EnableCheckpoint: true,
		CheckpointDir:    DefaultCheckpointDir,
	}

	for _, fn := range optFns {
		fn(&options)
	}

	u := &Downloader{
		client:  c,
		options: options,
	}

	return u
}

type downloaderDelegate struct {
	Downloader
	context context.Context
	request *s3.GetObjectInput

	w       io.WriterAt
	rstart  int64
	pos     int64
	epos    int64
	written int64

	// Source's Info
	sizeInBytes int64
	etag        string
	modTime     string
	headers     http.Header

	//Destination's Info
	filePath     string
	tempFilePath string

	//crc
	// calcCRC  bool
	// checkCRC bool

	checkpoint *downloadCheckpoint
}

func (u *downloaderDelegate) wrapErr(err error) error {
	return &DownloadError{
		Path: fmt.Sprintf("oss://%s/%s", aws.ToString(u.request.Bucket), aws.ToString(u.request.Key)),
		Err:  err,
	}
}

func (d *downloaderDelegate) checkSource() error {
	var request = new(s3.HeadObjectInput)
	copyRequest(request, d.request)
	result, err := d.client.HeadObject(d.context, request, d.options.ClientOptions...)
	if err != nil {
		return err
	}
	d.sizeInBytes = aws.ToInt64(result.ContentLength)
	d.modTime = result.LastModified.String()
	d.etag = aws.ToString(result.ETag)
	var resHeader = make(http.Header)
	resHeader.Set("Content-Length", strconv.FormatInt(aws.ToInt64(result.ContentLength), 10))
	resHeader.Set("Last-Modified", d.modTime)
	resHeader.Set("ETag", d.etag)
	d.headers = resHeader
	return nil
}

func (d *downloaderDelegate) checkDestination(filePath string) (*os.File, error) {
	if filePath == "" {
		return nil, NewErrParamInvalid("filePath")
	}
	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, err
	}

	// use temporary file
	tempFilePath := absFilePath
	if d.options.UseTempFile {
		tempFilePath += TempFileSuffix
	}
	d.filePath = absFilePath
	d.tempFilePath = tempFilePath

	// use openfile to check the filepath is valid
	var file *os.File
	if file, err = os.OpenFile(tempFilePath, os.O_WRONLY|os.O_CREATE, FilePermMode); err != nil {
		return nil, err
	}

	return file, nil
}

func (d *downloaderDelegate) adjustWriter(file *os.File) error {
	if err := file.Truncate(d.pos - d.rstart); err != nil {
		return err
	}
	d.w = file
	return nil
}

func (d *downloaderDelegate) closeWriter(file *os.File, err error) error {
	if file != nil {
		file.Close()
	}

	if err != nil {
		if d.checkpoint == nil {
			os.Remove(d.tempFilePath)
		}
	} else {
		if d.tempFilePath != d.filePath {
			err = os.Rename(d.tempFilePath, d.filePath)
		}
		if err == nil && d.checkpoint != nil {
			d.checkpoint.remove()
		}
	}

	d.w = nil
	d.checkpoint = nil

	return err
}

func (d *downloaderDelegate) adjustRange() error {
	d.pos = 0
	d.rstart = 0
	d.epos = d.sizeInBytes
	if d.request.Range != nil {
		httpRange, _ := ParseRange(*d.request.Range)
		if httpRange.Offset >= d.sizeInBytes {
			return fmt.Errorf("invalid range, object size :%v, range: %v", d.sizeInBytes, aws.ToString(d.request.Range))
		}
		d.pos = httpRange.Offset
		d.rstart = d.pos
		if httpRange.Count > 0 {
			d.epos = min(httpRange.Offset+httpRange.Count, d.sizeInBytes)
		}
	}

	return nil
}

func (d *downloaderDelegate) checkCheckpoint() error {
	if d.options.EnableCheckpoint {
		d.checkpoint = newDownloadCheckpoint(d.request, d.tempFilePath, d.options.CheckpointDir, d.headers, d.options.PartSize)
		d.checkpoint.VerifyData = d.options.VerifyData
		if err := d.checkpoint.load(); err != nil {
			return err
		}

		if d.checkpoint.Loaded {
			d.pos = d.checkpoint.Info.Data.DownloadInfo.Offset
			d.written = d.pos - d.rstart
		} else {
			d.checkpoint.Info.Data.DownloadInfo.Offset = d.pos
		}
	}
	return nil
}

type downloaderChunk struct {
	w      io.WriterAt
	start  int64
	size   int64
	cur    int64
	rstart int64 //range start
}

func (c *downloaderChunk) Write(p []byte) (n int, err error) {
	if c.cur >= c.size {
		return 0, io.EOF
	}

	n, err = c.w.WriteAt(p, c.start+c.cur-c.rstart)
	c.cur += int64(n)
	return
}

type downloadedChunk struct {
	start int64
	size  int64
	// crc64 uint64
}

type ReaderRangeGetOutput struct {
	Body          io.ReadCloser
	ContentLength int64
	ContentRange  *string
	ETag          *string
	LastModified  *time.Time
}

type RangeReader struct {
	in     io.ReadCloser // Input reader
	closed bool          // whether we have closed the underlying stream

	//Range Getter
	rangeGet  ReaderRangeGetFn
	httpRange HTTPRange

	// For reader
	offset int64

	oriHttpRange HTTPRange

	context context.Context

	// Origin file pattern
	etag      string
	modTime   *time.Time
	totalSize int64
}

type LimitedReadCloser struct {
	*io.LimitedReader
	io.Closer
}

func NewLimitedReadCloser(rc io.ReadCloser, limit int64) io.ReadCloser {
	if limit < 0 {
		return rc
	}
	return &LimitedReadCloser{
		LimitedReader: &io.LimitedReader{R: rc, N: limit},
		Closer:        rc,
	}
}

func (r *RangeReader) Read(p []byte) (n int, err error) {
	defer func() {
		r.offset += int64(n)
		r.httpRange.Offset += int64(n)
	}()
	n, err = r.read(p)
	return
}

func (r *RangeReader) read(p []byte) (int, error) {
	if r.closed {
		return 0, fmt.Errorf("RangeReader is closed")
	}

	// open stream
	if r.in == nil {
		httpRangeRemains := r.httpRange
		if r.httpRange.Count > 0 {
			gotNum := r.httpRange.Offset - r.oriHttpRange.Offset
			if gotNum > 0 && r.httpRange.Count > gotNum {
				httpRangeRemains.Count = r.httpRange.Count - gotNum
			}
		}
		output, err := r.rangeGet(r.context, httpRangeRemains)
		if err == nil {
			etag := aws.ToString(output.ETag)
			if r.etag == "" {
				r.etag = etag
				r.modTime = output.LastModified
			}
			if etag != r.etag {
				err = fmt.Errorf("source file is changed, expect etag:%s ,got etag:%s", r.etag, etag)
			}

			// Partial Response check
			var off int64
			if output.ContentRange == nil {
				off = 0
				r.totalSize = output.ContentLength
			} else {
				off, _, r.totalSize, _ = ParseContentRange(*output.ContentRange)
			}
			if off != httpRangeRemains.Offset {
				err = fmt.Errorf("range get fail, expect offset:%v, got offset:%v", httpRangeRemains.Offset, off)
			}
		}
		if err != nil {
			if output != nil && output.Body != nil {
				output.Body.Close()
			}
			return 0, err
		}
		body := output.Body
		if httpRangeRemains.Count > 0 {
			body = NewLimitedReadCloser(output.Body, httpRangeRemains.Count)
		}
		r.in = body
	}

	// read from stream
	// ignore error when reading from stream
	n, err := r.in.Read(p)
	if err != nil && err != io.EOF {
		r.in.Close()
		r.in = nil
		err = nil
	}

	return n, err
}

func (r *RangeReader) Offset() int64 {
	return r.offset
}

func (r *RangeReader) Close() (err error) {
	if r.closed {
		return nil
	}
	r.closed = true

	if r.in != nil {
		err = r.in.Close()
	}
	return
}

type ReaderRangeGetFn func(context.Context, HTTPRange) (output *ReaderRangeGetOutput, err error)

// NewRangeReader returns a reader that will read from the Reader returued by getter from the given offset.
// The etag is used to identify the content of the object. If not set, the first ETag returned value will be used instead.
func NewRangeReader(ctx context.Context, rangeGet ReaderRangeGetFn, httpRange *HTTPRange, etag string) (*RangeReader, error) {
	if rangeGet == nil {
		return nil, errors.New("nil reader supplied")
	}

	range_ := HTTPRange{}
	if httpRange != nil {
		range_ = *httpRange
	}

	a := &RangeReader{
		rangeGet:     rangeGet,
		context:      ctx,
		httpRange:    range_,
		oriHttpRange: range_,
		offset:       range_.Offset,
		etag:         etag,
	}

	//fmt.Printf("NewRangeReader, range: %s, etag:%s\n", ToString(a.httpRange.FormatHTTPRange()), a.etag)

	return a, nil
}

func (d *downloaderDelegate) downloadChunk(chunk downloaderChunk /*, hash hash.Hash64*/) (downloadedChunk, error) {
	// Get the next byte range of data
	var request = new(s3.GetObjectInput)
	copyRequest(request, d.request)

	getFn := func(ctx context.Context, httpRange HTTPRange) (output *ReaderRangeGetOutput, err error) {
		// update range
		request.Range = nil
		rangeStr := httpRange.FormatHTTPRange()
		if rangeStr != nil {
			request.Range = rangeStr
		}

		result, err := d.client.GetObject(ctx, request, d.options.ClientOptions...)
		if err != nil {
			return nil, err
		}

		return &ReaderRangeGetOutput{
			Body:          result.Body,
			ETag:          result.ETag,
			ContentLength: aws.ToInt64(result.ContentLength),
			ContentRange:  result.ContentRange,
		}, nil
	}

	reader, _ := NewRangeReader(d.context, getFn, &HTTPRange{chunk.start, chunk.size}, d.etag)
	defer reader.Close()

	var (
		r io.Reader = reader
		// crc64 uint64    = 0
	)
	// if hash != nil {
	// 	hash.Reset()
	// 	r = io.TeeReader(reader, hash)
	// }

	n, err := io.Copy(&chunk, r)

	// if hash != nil {
	// 	crc64 = hash.Sum64()
	// }

	return downloadedChunk{
		start: chunk.start,
		size:  n,
		// crc64: crc64,
	}, err
}

func (d *downloaderDelegate) download() (*DownloadResult, error) {
	var (
		wg       sync.WaitGroup
		errValue atomic.Value
		cpCh     chan downloadedChunk
		cpWg     sync.WaitGroup
		cpChunks []downloadedChunk
		tracker  bool = /*d.calcCRC || */ d.checkpoint != nil
		// tCRC64   uint64 = 0
	)

	saveErrFn := func(e error) {
		errValue.Store(e)
	}

	getErrFn := func() error {
		v := errValue.Load()
		if v == nil {
			return nil
		}
		e, _ := v.(error)
		return e
	}

	// writeChunkFn runs in worker goroutines to pull chunks off of the ch channel
	writeChunkFn := func(ch chan downloaderChunk) {
		defer wg.Done()
		// var hash hash.Hash64
		// if d.calcCRC {
		// 	hash = NewCRC64(0)
		// }

		for {
			chunk, ok := <-ch
			if !ok {
				break
			}

			if getErrFn() != nil {
				continue
			}

			dchunk, derr := d.downloadChunk(chunk /*, hash*/)

			if derr != nil && derr != io.EOF {
				saveErrFn(derr)
			} else {
				// update tracker info
				if tracker {
					cpCh <- dchunk
				}
			}
		}
	}

	// trackerFn runs in worker goroutines to update checkpoint info or calc downloaded crc
	trackerFn := func(ch chan downloadedChunk) {
		defer cpWg.Done()
		var (
			tOffset int64 = 0
		)

		if d.checkpoint != nil {
			tOffset = d.checkpoint.Info.Data.DownloadInfo.Offset
			// tCRC64 = d.checkpoint.Info.Data.DownloadInfo.CRC64
		}

		for {
			chunk, ok := <-ch
			if !ok {
				break
			}
			cpChunks = append(cpChunks, chunk)
			sort.Slice(cpChunks, func(i, j int) bool {
				return cpChunks[i].start < cpChunks[j].start
			})
			newOffset := tOffset
			i := 0
			for ii := range cpChunks {
				if cpChunks[ii].start == newOffset {
					newOffset += cpChunks[ii].size
					i++
				} else {
					break
				}
			}
			if newOffset != tOffset {
				//remove updated chunk in cpChunks
				// if d.calcCRC {
				// 	tCRC64 = d.combineCRC(tCRC64, cpChunks[0:i])
				// }
				tOffset = newOffset
				cpChunks = cpChunks[i:]
				if d.checkpoint != nil {
					d.checkpoint.Info.Data.DownloadInfo.Offset = tOffset
					// d.checkpoint.Info.Data.DownloadInfo.CRC64 = tCRC64
					d.checkpoint.dump()
				}
			}
		}
	}

	// Start the download workers
	ch := make(chan downloaderChunk, d.options.ParallelNum)
	for i := 0; i < d.options.ParallelNum; i++ {
		wg.Add(1)
		go writeChunkFn(ch)
	}

	// Start tracker worker if need track downloaded chunk
	if tracker {
		cpCh = make(chan downloadedChunk, max(3, d.options.ParallelNum))
		cpWg.Add(1)
		go trackerFn(cpCh)
	}

	// Consume downloaded data
	// if d.request.ProgressFn != nil && d.written > 0 {
	// 	d.request.ProgressFn(d.written, d.written, d.sizeInBytes)
	// }

	// Queue the next range of bytes to read.
	for getErrFn() == nil {
		if d.pos >= d.epos {
			break
		}
		size := min(d.epos-d.pos, d.options.PartSize)
		ch <- downloaderChunk{w: d.w, start: d.pos, size: size, rstart: d.rstart}
		d.pos += size
	}

	// Waiting for parts download finished
	close(ch)
	wg.Wait()

	if tracker {
		close(cpCh)
		cpWg.Wait()
	}

	if err := getErrFn(); err != nil {
		return nil, d.wrapErr(err)
	}

	// if d.checkCRC {
	// 	if len(cpChunks) > 0 {
	// 		sort.Sort(cpChunks)
	// 	}
	// 	if derr := checkResponseHeaderCRC64(fmt.Sprint(d.combineCRC(tCRC64, cpChunks)), d.headers); derr != nil {
	// 		return nil, d.wrapErr(derr)
	// 	}
	// }

	return &DownloadResult{
		Written: d.written,
	}, nil
}
