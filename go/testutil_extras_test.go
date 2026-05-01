package lucairn

import (
	"os"
	"path/filepath"
)

// readFileFull is a narrow helper mirroring os.ReadFile behaviour through
// a consistent API shape used across tests. Kept in a separate file so
// it can be trivially retired in favour of os.ReadFile later.
func readFileFull(dir, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, name))
}
