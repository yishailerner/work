// Package work provides a SHA256-based proof-of-work system.
package work

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sync"
)

// Generate generates a proof-of-work nonce which satisfies the given
// difficulty for data. workers specifies how many concurrent workers should
// try to find a valid nonce and will default to 1 if below it.
//
// The larger the difficulty, the more computationally expensive the nonce is
// to produce.
func Generate(data []byte, difficulty uint64, workers int) uint64 {
	if workers < 1 { // sanity check
		workers = 1
	}

	// work is distributed between workers so that each worker operates on a
	// different range. delta specifies the increment between them.
	delta := math.MaxUint64 / uint64(workers)

	// although unlikely for higher difficulties, all workers can potentially find
	// a valid nonce at the same time. since only the first result is taken, the
	// channel is buffered to avoid a deadlock.
	result := make(chan uint64, workers-1)
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		// determine nonce range
		start := uint64(i) * delta
		end := start + delta

		go func() {
			defer wg.Done()

			buf := make([]byte, len(data)+8)
			copy(buf, data)

			for nonce := start; nonce < end; nonce++ {
				select {
				case <-done:
					return
				default:
				}

				binary.BigEndian.PutUint64(buf[len(data):], nonce)

				hash := sha256.Sum256(buf)
				value := binary.BigEndian.Uint64(hash[:])
				if value >= difficulty {
					result <- nonce
					return
				}
			}
		}()
	}

	nonce := <-result
	close(done)
	wg.Wait()
	return nonce
}

// Verify returns whether nonce is a valid proof-of-work nonce for the given
// data and difficulty.
func Verify(data []byte, difficulty, nonce uint64) bool {
	return Difficulty(data, nonce) >= difficulty
}

// Difficulty returns the difficulty of the given nonce for data.
func Difficulty(data []byte, nonce uint64) uint64 {
	buf := make([]byte, len(data)+8)
	copy(buf, data)
	binary.BigEndian.PutUint64(buf[len(data):], nonce)

	hash := sha256.Sum256(buf)
	return binary.BigEndian.Uint64(hash[:])
}
