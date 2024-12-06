package manager

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/schollz/progressbar/v3"
)

type UploaderOptions struct {
	PartSize          int64
	ParallelNum       int
	LeavePartsOnError bool
	EnableCheckpoint  bool
	CheckpointDir     string
	ClientOptions     []func(*s3.Options)
}

type Uploader struct {
	client  UploaderClient
	options UploaderOptions
}

func NewUploader(c UploaderClient, optFns ...func(*UploaderOptions)) *Uploader {
	options := UploaderOptions{
		PartSize:          DefaultPartSize,
		ParallelNum:       DefaultParallel,
		LeavePartsOnError: true,
		EnableCheckpoint:  true,
		CheckpointDir:     DefaultCheckpointDir,
	}
	for _, fn := range optFns {
		fn(&options)
	}
	u := &Uploader{
		client:  c,
		options: options,
	}
	return u
}

func (u *Uploader) newDelegate(ctx context.Context, request *s3.PutObjectInput, optFns ...func(*UploaderOptions)) (*uploaderDelegate, error) {
	if request == nil {
		return nil, NewErrParamNull("request")
	}
	if request.Bucket == nil {
		return nil, NewErrParamNull("request.Bucket")
	}
	if request.Key == nil {
		return nil, NewErrParamNull("request.Key")
	}
	d := uploaderDelegate{
		Uploader: *u,
		context:  ctx,
		request:  request,
	}
	for _, opt := range optFns {
		opt(&d.options)
	}
	if d.options.ParallelNum <= 0 {
		d.options.ParallelNum = DefaultParallel
	}
	if d.options.PartSize <= 0 {
		d.options.PartSize = DefaultPartSize
	}
	return &d, nil
}

func (u *Uploader) UploadFile(ctx context.Context, request *s3.PutObjectInput, filePath string, optFns ...func(*UploaderOptions)) (*UploadResult, error) {
	delegate, err := u.newDelegate(ctx, request, optFns...)
	if err != nil {
		return nil, err
	}

	if err = delegate.checkSource(filePath); err != nil {
		return nil, err
	}
	var file *os.File
	if file, err = delegate.openReader(); err != nil {
		return nil, err
	}
	delegate.body = file
	if err = delegate.applySource(); err != nil {
		return nil, err
	}
	if err = delegate.checkCheckpoint(); err != nil {
		return nil, err
	}
	if err = delegate.adjustSource(); err != nil {
		return nil, err
	}

	delegate.processBar = progressbar.DefaultBytes(delegate.totalSize, fmt.Sprintf("Uploading %v", delegate.fileInfo.Name()))
	result, err := delegate.upload()
	return result, delegate.closeReader(file, err)
}

type uploaderDelegate struct {
	Uploader
	context context.Context
	request *s3.PutObjectInput

	body interface {
		io.ReadSeeker
		io.ReaderAt
	}
	readerPos int64
	totalSize int64
	// hashCRC64   uint64
	transferred int64
	processBar  *progressbar.ProgressBar

	filePath string
	fileInfo os.FileInfo

	uploadId      string
	partNumber    int32
	uploadedParts []types.Part

	checkpoint *uploadCheckpoint
}

func (u *uploaderDelegate) checkSource(filePath string) error {
	if filePath == "" {
		return NewErrParamRequired("filePath")
	}

	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file not exists, %v", filePath)
		}
		return err
	}

	u.filePath = filePath
	u.fileInfo = info

	return nil
}

func (u *uploaderDelegate) applySource() error {
	totalSize, err := GetReaderLen(u.body)
	if err != nil {
		return NewErrParamNull("the body is null")
	}

	//Part Size
	partSize := u.options.PartSize
	if totalSize > 0 {
		for totalSize/partSize >= int64(MaxUploadParts) {
			partSize += u.options.PartSize
		}
	}

	u.totalSize = totalSize
	u.options.PartSize = partSize

	return nil
}

func (u *uploaderDelegate) adjustSource() error {
	// resume from upload id
	if u.uploadId != "" {
		// if the body supports seek
		r, ok := u.body.(io.Seeker)
		// not support
		if !ok {
			u.uploadId = ""
			return nil
		}
		// if upload id is valid
		paginator := s3.NewListPartsPaginator(u.client, &s3.ListPartsInput{
			Bucket:   u.request.Bucket,
			Key:      u.request.Key,
			UploadId: aws.String(u.uploadId),
		})

		// find consecutive sequence from min part number
		var (
			checkPartNumber int32 = 1
			/*updateCRC64     bool   = ((u.base.featureFlags & FeatureEnableCRC64CheckUpload) > 0)
			hashCRC64       uint64 = 0*/
			page          *s3.ListPartsOutput
			err           error
			uploadedParts []types.Part
		)
	outerLoop:

		for paginator.HasMorePages() {
			page, err = paginator.NextPage(u.context, u.options.ClientOptions...)
			if err != nil {
				u.uploadId = ""
				return nil
			}
			for _, p := range page.Parts {
				if aws.ToInt32(p.PartNumber) != checkPartNumber ||
					aws.ToInt64(p.Size) != u.options.PartSize {
					break outerLoop
				}
				checkPartNumber++
				uploadedParts = append(uploadedParts, p)
				/*if updateCRC64 && p.ChecksumCRC32 != nil {
					value, _ := strconv.ParseUint(aws.ToString(p.ChecksumCRC32), 10, 64)
					hashCRC64 = CRC64Combine(hashCRC64, value, uint64(aws.ToInt64(p.Size)))
				}*/
			}
		}

		partNumber := checkPartNumber - 1
		newOffset := int64(partNumber) * u.options.PartSize
		if _, err := r.Seek(newOffset, io.SeekStart); err != nil {
			u.uploadId = ""
			return nil
		}

		u.partNumber = partNumber
		u.readerPos = newOffset
		/*u.hashCRC64 = hashCRC64*/
		u.uploadedParts = uploadedParts
	}
	return nil
}

func (d *uploaderDelegate) checkCheckpoint() error {
	if d.options.EnableCheckpoint {
		d.checkpoint = newUploadCheckpoint(d.request, d.filePath, d.options.CheckpointDir, d.fileInfo, d.options.PartSize)
		if err := d.checkpoint.load(); err != nil {
			return err
		}

		if d.checkpoint.Loaded {
			d.uploadId = d.checkpoint.Info.Data.UploadInfo.UploadId
		}
		d.options.LeavePartsOnError = true
	}
	return nil
}

func (d *uploaderDelegate) openReader() (*os.File, error) {
	file, err := os.Open(d.filePath)
	if err != nil {
		return nil, err
	}

	d.body = file
	return file, nil
}

func (d *uploaderDelegate) closeReader(file *os.File, err error) error {
	if file != nil {
		file.Close()
	}

	if d.checkpoint != nil && err == nil {
		d.checkpoint.remove()
	}

	d.body = nil
	d.checkpoint = nil

	return err
}

type uploadIdInfo struct {
	uploadId string
	startNum int32
}

func (u *uploaderDelegate) getUploadId() (info uploadIdInfo, err error) {
	if u.uploadId != "" {
		return uploadIdInfo{
			uploadId: u.uploadId,
			startNum: u.partNumber,
		}, nil
	}

	// if not exist or fail, create a new upload id
	request := &s3.CreateMultipartUploadInput{}
	copyRequest(request, u.request)
	if request.ContentType == nil {
		request.ContentType = u.getContentType()
	}

	result, err := u.client.CreateMultipartUpload(u.context, request, u.options.ClientOptions...)
	if err != nil {
		return info, err
	}

	return uploadIdInfo{
		uploadId: *result.UploadId,
		startNum: 0,
	}, nil
}

func (u *uploaderDelegate) getContentType() *string {
	if u.filePath != "" {
		if contentType := TypeByExtension(u.filePath); contentType != "" {
			return aws.String(contentType)
		}
	}
	return nil
}

func (u *uploaderDelegate) wrapErr(uploadId string, err error) error {
	return &UploadError{
		UploadId: uploadId,
		Path:     fmt.Sprintf("oss://%s/%s", *u.request.Bucket, *u.request.Key),
		Err:      err}
}

type UploadResult struct {
	UploadId *string

	ETag *string

	VersionId *string

	// HashCRC64 *string

	ResultCommon
}

type UploadError struct {
	Err      error
	UploadId string
	Path     string
}

func (m *UploadError) Error() string {
	var extra string
	if m.Err != nil {
		extra = fmt.Sprintf(", cause: %s", m.Err.Error())
	}
	return fmt.Sprintf("upload failed, upload id: %s%s", m.UploadId, extra)
}

func (u *uploaderDelegate) upload() (*UploadResult, error) {
	if u.totalSize >= 0 && u.totalSize < u.options.PartSize {
		return u.singlePart()
	}
	return u.multiPart()
}

func (u *uploaderDelegate) singlePart() (*UploadResult, error) {
	request := &s3.PutObjectInput{}
	copyRequest(request, u.request)
	request.Body = u.body
	if request.ContentType == nil {
		request.ContentType = u.getContentType()
	}

	result, err := u.client.PutObject(u.context, request, u.options.ClientOptions...)

	if err != nil {
		return nil, u.wrapErr("", err)
	}

	return &UploadResult{
		ETag:      result.ETag,
		VersionId: result.VersionId,
		// HashCRC64:    result.HashCRC64,
		ResultCommon: ResultCommon{},
	}, nil
}

func (u *uploaderDelegate) nextReader() (io.ReadSeeker, int, func(), error) {
	var err error
	r := u.body
	n := u.options.PartSize
	if u.totalSize >= 0 {
		bytesLeft := u.totalSize - u.readerPos
		if bytesLeft <= u.options.PartSize {
			err = io.EOF
			n = bytesLeft
		}
	}

	reader := io.NewSectionReader(r, u.readerPos, n)
	cleanup := func() {}

	u.readerPos += n

	return reader, int(n), cleanup, err
}

type uploaderChunk struct {
	partNum int32
	size    int
	body    io.ReadSeeker
	cleanup func()
}

func (u *uploaderDelegate) multiPart() (*UploadResult, error) {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		parts    []types.CompletedPart
		errValue atomic.Value
		// crcParts uploadPartCRCs
		// enableCRC = (u.base.featureFlags & FeatureEnableCRC64CheckUpload) > 0
	)
	// Init the multipart
	uploadIdInfo, err := u.getUploadId()
	if err != nil {
		return nil, u.wrapErr("", err)
	}
	//fmt.Printf("getUploadId result: %v, %#v\n", uploadId, err)
	uploadId := uploadIdInfo.uploadId
	startPartNum := uploadIdInfo.startNum

	// Update Checkpoint
	if u.checkpoint != nil {
		u.checkpoint.Info.Data.UploadInfo.UploadId = uploadId
		u.checkpoint.dump()
	}

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

	// readChunk runs in worker goroutines to pull chunks off of the ch channel
	readChunkFn := func(ch chan uploaderChunk) {

		defer wg.Done()
		for {
			data, ok := <-ch
			if !ok {
				break
			}

			if getErrFn() == nil {
				upResult, err := u.client.UploadPart(
					u.context,
					&s3.UploadPartInput{
						Bucket:       u.request.Bucket,
						Key:          u.request.Key,
						UploadId:     aws.String(uploadId),
						PartNumber:   aws.Int32(data.partNum),
						Body:         data.body,
						RequestPayer: u.request.RequestPayer,
					},
					u.options.ClientOptions...)

				if err == nil {
					mu.Lock()
					parts = append(parts, types.CompletedPart{ETag: upResult.ETag, PartNumber: aws.Int32(data.partNum)})
					// if enableCRC {
					// 	crcParts = append(crcParts,
					// 		uploadPartCRC{partNumber: data.partNum, hashCRC64: upResult.HashCRC64, size: data.size})
					// }
					// if u.request.ProgressFn != nil {
					// 	u.transferred += int64(data.size)
					// 	u.request.ProgressFn(int64(data.size), u.transferred, u.totalSize)
					// }
					u.transferred += int64(data.size)
					u.processBar.Add64(int64(data.size))
					mu.Unlock()
				} else {
					saveErrFn(err)
				}
			}
			data.cleanup()
		}
	}

	ch := make(chan uploaderChunk, u.options.ParallelNum)
	for i := 0; i < u.options.ParallelNum; i++ {
		wg.Add(1)
		go readChunkFn(ch)
	}

	// Read and queue the parts
	var (
		qnum int32 = startPartNum
		qerr error = nil
	)

	// consume uploaded parts
	if u.readerPos > 0 {
		for _, p := range u.uploadedParts {
			parts = append(parts, types.CompletedPart{PartNumber: p.PartNumber, ETag: p.ETag})
		}
		// if u.request.ProgressFn != nil {
		// 	u.transferred = u.readerPos
		// 	u.request.ProgressFn(u.readerPos, u.transferred, u.totalSize)
		// }
		u.transferred = u.readerPos
		u.processBar.Set64(u.transferred)
	}

	for getErrFn() == nil && qerr == nil {
		var (
			reader       io.ReadSeeker
			nextChunkLen int
			cleanup      func()
		)

		reader, nextChunkLen, cleanup, qerr = u.nextReader()
		// check err
		if (qerr != nil && qerr != io.EOF) ||
			nextChunkLen == 0 {
			cleanup()
			saveErrFn(qerr)
			break
		}
		qnum++
		//fmt.Printf("send chunk: %d\n", qnum)
		ch <- uploaderChunk{body: reader, partNum: qnum, cleanup: cleanup, size: nextChunkLen}
	}

	// Close the channel, wait for workers
	close(ch)
	wg.Wait()

	// Complete upload
	var cmResult *s3.CompleteMultipartUploadOutput
	if err = getErrFn(); err == nil {
		sort.Slice(parts, func(i, j int) bool {
			return aws.ToInt32(parts[i].PartNumber) < aws.ToInt32(parts[j].PartNumber)
		})
		cmRequest := &s3.CompleteMultipartUploadInput{}
		copyRequest(cmRequest, u.request)
		cmRequest.UploadId = aws.String(uploadId)
		cmRequest.MultipartUpload = &types.CompletedMultipartUpload{Parts: parts}
		cmResult, err = u.client.CompleteMultipartUpload(u.context, cmRequest, u.options.ClientOptions...)
	}
	//fmt.Printf("CompleteMultipartUpload cmResult: %#v, %#v\n", cmResult, err)

	if err != nil {
		//Abort
		if !u.options.LeavePartsOnError {
			abortRequest := &s3.AbortMultipartUploadInput{}
			copyRequest(abortRequest, u.request)
			abortRequest.UploadId = aws.String(uploadId)
			_, _ = u.client.AbortMultipartUpload(u.context, abortRequest, u.options.ClientOptions...)
		}
		return nil, u.wrapErr(uploadId, err)
	}

	// if enableCRC {
	// 	caclCRC := fmt.Sprint(u.combineCRC(crcParts))
	// 	if err = checkResponseHeaderCRC64(caclCRC, cmResult.Headers); err != nil {
	// 		return nil, u.wrapErr(uploadId, err)
	// 	}
	// }

	return &UploadResult{
		UploadId:  aws.String(uploadId),
		ETag:      cmResult.ETag,
		VersionId: cmResult.VersionId,
		// HashCRC64:    cmResult.HashCRC64,
		ResultCommon: ResultCommon{},
	}, nil
}
