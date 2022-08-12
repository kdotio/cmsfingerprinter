package uniquefinder

import (
	"fmt"
	"testing"

	"cms-fingerprinter/structs"
)

func TestParse(t *testing.T) {
	cases := []struct {
		input map[string]structs.Filehash
		want  map[string][]uniqueness
	}{
		{input: map[string]structs.Filehash{
			"laravel/css/style.css": {
				"2c77b0dec20ab616d1c213e2fc18281f": []string{"3.2.10", "3.2.9", "3.2.8", "3.2.7", "3.2.6", "3.2.5", "3.2.4", "3.2.3", "3.2.1"},
				"3e7890ce1d17033409efa1df4d1e2315": []string{"3.2.14", "3.2.13", "3.2.12", "3.2.11"},
				"f03ef4849bc6e724701475b36ca4cde1": []string{"3.2.0"},
			},
			"laravel/img/logoback.png": {
				"ab59c0ff93cfddf4b322336b98f657bf": []string{"3.2.14", "3.2.13", "3.2.12", "3.2.11", "3.2.10", "3.2.9", "3.2.8", "3.2.7", "3.2.6", "3.2.5", "3.2.4", "3.2.3", "3.2.1", "3.2.0"},
			}},
			want: map[string][]uniqueness{
				// 3.2.0 has a file with unique hash, thus allowing immediate identification
				"3.2.0":  {{1, "laravel/css/style.css"}, {14, "laravel/img/logoback.png"}},
				"3.2.1":  {{9, "laravel/css/style.css"}, {14, "laravel/img/logoback.png"}},
				"3.2.3":  {{9, "laravel/css/style.css"}, {14, "laravel/img/logoback.png"}},
				"3.2.4":  {{9, "laravel/css/style.css"}, {14, "laravel/img/logoback.png"}},
				"3.2.5":  {{9, "laravel/css/style.css"}, {14, "laravel/img/logoback.png"}},
				"3.2.6":  {{9, "laravel/css/style.css"}, {14, "laravel/img/logoback.png"}},
				"3.2.7":  {{9, "laravel/css/style.css"}, {14, "laravel/img/logoback.png"}},
				"3.2.8":  {{9, "laravel/css/style.css"}, {14, "laravel/img/logoback.png"}},
				"3.2.9":  {{9, "laravel/css/style.css"}, {14, "laravel/img/logoback.png"}},
				"3.2.10": {{9, "laravel/css/style.css"}, {14, "laravel/img/logoback.png"}},
				"3.2.11": {{4, "laravel/css/style.css"}, {14, "laravel/img/logoback.png"}},
				"3.2.12": {{4, "laravel/css/style.css"}, {14, "laravel/img/logoback.png"}},
				"3.2.13": {{4, "laravel/css/style.css"}, {14, "laravel/img/logoback.png"}},
				"3.2.14": {{4, "laravel/css/style.css"}, {14, "laravel/img/logoback.png"}},
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			got := parse(tc.input)

			if len(tc.want) != len(got) {
				t.Fatalf("len, expected %d, got %d", len(tc.want), len(got))
			}

			for tag, wt := range tc.want {
				gt, ok := got[tag]
				if !ok {
					t.Error("missing", tag)
					continue
				}

				for i := range wt {
					if wt[i] != gt[i] {
						t.Errorf("%s %d: expected %v, got %v", tag, i, wt[i], gt[i])
					}
				}
			}
		})
	}
}
