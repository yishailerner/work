package work_test

import (
	"crypto/rand"
	"fmt"
	"math"
	"runtime"
	"testing"

	"github.com/yishailerner/graph/pkg/work"
)

func TestGenerate(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		data       []byte
		difficulty uint64
		workers    int
	}{
		{nil, 0, 0},
		{nil, 0, 1},
		{nil, 0, runtime.NumCPU()},
		{nil, 0xff0fffc000000000, runtime.NumCPU()},
		{[]byte("so"), 0xf00fffc000000000, -5},
		{[]byte("very"), 0, 1},
		{[]byte("random"), 0, 50},
	} {
		nonce := work.Generate(tt.data, tt.difficulty, tt.workers)
		if !work.Verify(tt.data, tt.difficulty, nonce) {
			t.Errorf("Generate(%q, %x, %d) = invalid nonce %x", tt.data, tt.difficulty, tt.workers, nonce)
		}
	}
}

var goldenTests = []struct {
	valid      bool
	data       []byte
	nonce      uint64
	difficulty uint64
}{
	// edge-cases
	{true, nil, 0, 0},
	{false, nil, 0, 0xffffffc000000000},
	{true, []byte{93, 14, 57, 57}, 0, 0},
	{false, []byte{93, 14, 57, 57}, 0, 0xffffffc000000000},
	{false, []byte("zero nonce"), 0, 0xffffffc000000000},
	{false, []byte("max nonce"), math.MaxUint64, 0xffffffc000000000},
	{true, []byte("zero difficulty"), math.MaxUint64, 0},
	{false, []byte("max difficulty"), math.MaxUint64, 0xffffffc000000000},

	// validate that only the exact nonce is verified (statistically, of course)
	{false, []byte{1, 2, 3}, 147372694, 0xffffffc000000000},
	{true, []byte{1, 2, 3}, 147372695, 0xffffffc000000000},
	{false, []byte{1, 2, 3}, 147372696, 0xffffffc000000000},
	{false, nil, 3593661, 0xffffffc000000000},
	{true, nil, 3593662, 0xffffffc000000000},
	{false, nil, 3593663, 0xffffffc000000000},
}

func TestVerify(t *testing.T) {
	t.Parallel()

	for _, tt := range goldenTests {
		valid := work.Verify(tt.data, tt.difficulty, tt.nonce)
		if valid != tt.valid {
			t.Errorf("Verify(%q, %x, %x) = %t; want %t", tt.data, tt.difficulty, tt.nonce, valid, tt.valid)
		}
	}
}

func TestDifficulty(t *testing.T) {
	t.Parallel()

	for _, tt := range goldenTests {
		difficulty := work.Difficulty(tt.data, tt.nonce)
		valid := difficulty >= tt.difficulty
		if !valid && tt.valid {
			t.Errorf("Difficulty(%q, %x) = %x; want above or equal to %x", tt.data, tt.nonce, difficulty, tt.difficulty)
		} else if valid && !tt.valid {
			t.Errorf("Difficulty(%q, %x) = %x; want below %x", tt.data, tt.nonce, difficulty, tt.difficulty)
		}
	}
}

func BenchmarkGenerate(b *testing.B) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}

	nc := runtime.NumCPU()

	difficulties := []uint64{0, 0xfff0ffc000000000, 0xffffffc000000000}
	workers := []int{1, nc, nc * 2}

	b.ResetTimer()
	for _, w := range workers {
		for _, d := range difficulties {
			b.Run(fmt.Sprintf("%016x-%d", d, w), func(b *testing.B) {
				for n := 0; n < b.N; n++ {
					work.Generate(data, d, w)
				}
			})
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		work.Verify(data, 0xffffffc000000000, 123)
	}
}
