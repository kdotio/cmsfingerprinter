package helpers

import "testing"

func TestSortRevs(t *testing.T) {
	unsorted := []string{"1.7.9", "1.7.8", "1.7.7", "1.7.6", "1.7.5", "1.7.4", "1.7.3", "1.7.24", "1.7.2", "1.7.12", "1.7.10", "1.7.1", "1.7.0"}
	t.Log("Input:", unsorted)

	want := []string{"1.7.24", "1.7.12", "1.7.10", "1.7.9", "1.7.8", "1.7.7", "1.7.6", "1.7.5", "1.7.4", "1.7.3", "1.7.2", "1.7.1", "1.7.0"}

	got := SortRevsAlphabeticallyDesc(unsorted)
	if len(unsorted) != len(got) {
		t.Fatal("length differs")
	}
	t.Log("Output:", got)

	for i := range unsorted {
		if want[i] != got[i] {
			t.Errorf("order does not match (%d), expected '%s', got '%s'", i, want[i], got[i])
		}
	}
}
