//go:build !cgo

package authority

func transientSQLite(error) bool { return false }
