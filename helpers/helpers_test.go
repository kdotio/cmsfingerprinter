package helpers

import (
	"fmt"
	"testing"
)

func TestSortRevs(t *testing.T) {
	cases := []struct {
		input []string
		want  []string
	}{
		{[]string{"1.7.9", "1.7.8", "1.7.7", "1.7.6", "1.7.5", "1.7.4", "1.7.3", "1.7.24", "1.7.2", "1.7.12", "1.7.10", "1.7.1", "1.7.0"},
			[]string{"1.7.24", "1.7.12", "1.7.10", "1.7.9", "1.7.8", "1.7.7", "1.7.6", "1.7.5", "1.7.4", "1.7.3", "1.7.2", "1.7.1", "1.7.0"}},
		{[]string{"5.6.0", "5.7", "5.7.1"}, []string{"5.7.1", "5.7", "5.6.0"}},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Log("Input:", tc.input)

			got := SortRevsAlphabeticallyDesc(tc.input)
			if len(tc.input) != len(got) {
				t.Fatal("length differs")
			}
			t.Log("Output:", got)

			for i := range tc.input {
				if tc.want[i] != got[i] {
					t.Errorf("order does not match (%d), expected '%s', got '%s'", i, tc.want[i], got[i])
				}
			}
		})
	}
}
