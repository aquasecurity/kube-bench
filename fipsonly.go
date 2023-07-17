//go:build fipsonly

package main

import (
	_ "crypto/tls/fipsonly"
)
