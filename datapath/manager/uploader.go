package manager

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type UploaderOptions struct {
	PartSize          int64
	ParallelNum       int
	LeavePartsOnError bool
	EnableCheckpoint  bool
	CheckpointDir     string
	ClientOptions     []func(*s3.Options)
}

type UploadResult struct {
	UploadId   *string
	ETag       *string
	VersionId  *string
	HashCRC64  *string
	Status     string
	StatusCode int
	Headers    http.Header
	OpMetadata OperationMetadata
}

type Uploader struct {
	client  *s3.Client
	options UploaderOptions
}

func NewUploader(c *s3.Client, optFns ...func(*UploaderOptions)) *Uploader {
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
