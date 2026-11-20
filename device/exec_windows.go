package main

import "context"

// Windows builds generate pairing certificates and run protocol tests only.
func execute(ctx context.Context, shell string, q request) result {
	return result{Code: 126, Stderr: []byte("device execution is Android/Linux only")}
}
