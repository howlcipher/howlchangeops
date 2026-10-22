package authority

import "os"

// Protected Windows ACL enrollment is not implemented. Refuse to infer trust
// from POSIX mode bits on Windows; legacy CLI cross-builds remain unaffected.
func owned(os.FileInfo) bool { return false }

func protectedAncestor(os.FileInfo, string) bool { return false }
