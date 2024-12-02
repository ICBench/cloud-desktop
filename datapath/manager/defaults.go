package manager

const (
	MaxUploadParts int32 = 10000

	MaxPartSize int64 = 5 * 1024 * 1024 * 1024

	MinPartSize int64 = 100 * 1024

	DefaultPartSize int64 = 6 * 1024 * 1024

	DefaultParallel = 3

	DefaultCheckpointDir = "~/.datapath"
)
