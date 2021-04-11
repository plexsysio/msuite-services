package utils

import (
	r "math/rand"
	"time"
)

// For generating random strings
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	r.Seed(time.Now().Unix() + time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[r.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}
