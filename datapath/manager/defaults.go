package manager

import "os"

const (
	MaxUploadParts int32 = 10000

	MaxPartSize int64 = 5 * 1024 * 1024 * 1024

	MinPartSize int64 = 100 * 1024

	DefaultPartSize int64 = 6 * 1024 * 1024

	DefaultParallel = 3

	DefaultCheckpointDir = "/home/shizhao/.datapath/"

	CheckpointFileSuffixDownloader = ".dcp"

	CheckpointFileSuffixUploader = ".ucp"

	CheckpointMagic = "92611BED-89E2-46B6-89E5-72F273D4B0A3"

	FilePermMode = os.FileMode(0664)
)
