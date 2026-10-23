//go:build !cgo

package authority

import "fmt"

func transientSQLite(error) bool { return false }

func checkCgoSupported() error {
	return fmt.Errorf("%w: CGO is disabled; protected authority requires native CGO SQLite", ErrUnavailable)
}
