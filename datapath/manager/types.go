package manager

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type HTTPRange struct {
	Offset int64
	Count  int64
}

func (r HTTPRange) FormatHTTPRange() *string {
	if r.Offset == 0 && r.Count == 0 {
		return nil // No specified range
	}
	endOffset := "" // if count == CountToEnd (0)
	if r.Count > 0 {
		endOffset = strconv.FormatInt((r.Offset+r.Count)-1, 10)
	}
	dataRange := fmt.Sprintf("bytes=%v-%s", r.Offset, endOffset)
	return &dataRange
}

type UploaderClient interface {
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	CreateMultipartUpload(ctx context.Context, params *s3.CreateMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error)
	UploadPart(ctx context.Context, params *s3.UploadPartInput, optFns ...func(*s3.Options)) (*s3.UploadPartOutput, error)
	CompleteMultipartUpload(ctx context.Context, params *s3.CompleteMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error)
	AbortMultipartUpload(ctx context.Context, params *s3.AbortMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error)
	ListMultipartUploads(ctx context.Context, params *s3.ListMultipartUploadsInput, optFns ...func(*s3.Options)) (*s3.ListMultipartUploadsOutput, error)
	ListParts(context.Context, *s3.ListPartsInput, ...func(*s3.Options)) (*s3.ListPartsOutput, error)
}

type DownloadClient interface {
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

type OperationMetadata struct {
	values map[any][]any
}

func (m OperationMetadata) Get(key any) any {
	if m.values == nil {
		return nil
	}
	v := m.values[key]
	if len(v) == 0 {
		return nil
	}
	return v[0]
}

func (m OperationMetadata) Values(key any) []any {
	if m.values == nil {
		return nil
	}
	return m.values[key]
}

func (m *OperationMetadata) Add(key, value any) {
	if m.values == nil {
		m.values = map[any][]any{}
	}
	m.values[key] = append(m.values[key], value)
}

func (m *OperationMetadata) Set(key, value any) {
	if m.values == nil {
		m.values = map[any][]any{}
	}
	m.values[key] = []any{value}
}

func (m OperationMetadata) Has(key any) bool {
	if m.values == nil {
		return false
	}
	_, ok := m.values[key]
	return ok
}

func (m OperationMetadata) Clone() OperationMetadata {
	vs := make(map[any][]any, len(m.values))
	for k, v := range m.values {
		vv := make([]any, len(v))
		copy(vv, v)
		vs[k] = vv
	}
	return OperationMetadata{
		values: vs,
	}
}

type ResultCommon struct {
	Status     string
	StatusCode int
	Headers    http.Header
	OpMetadata OperationMetadata
}
