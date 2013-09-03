package main

import "testing"

func TestPublicHash(t *testing.T) {
	pairs := [...][2]string{
		{"", "3i42h3s6nnfq2msv"},
		{"herp derp", "im2xxvv3yyfccmu3"}}
	for _, pair := range pairs {
		in, out := pair[0], pair[1]
		if x := computePublicHash(in); x != out {
			t.Errorf("ComputePublicHash(%s) = %s, should be %s", in, x, out)
		}
	}
}
