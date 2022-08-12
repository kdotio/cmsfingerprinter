package uniquefinder

import "testing"

func TestMostUniqueAcross(t *testing.T) {
	cases := []struct {
		want  string
		input map[string]uniqueness
	}{
		{"wp-content/themes/twentyten/style.css",
			map[string]uniqueness{
				"6.0":   {1, "wp-content/themes/twentyten/style.css"},
				"6.0.1": {1, "wp-content/themes/twentyten/style.css"},
			}},
		{"assets/tinymce4/js/langs/cs.js",
			map[string]uniqueness{
				"4.5.5":  {9, "assets/tinymce4/js/langs/es.js"},
				"4.5.6":  {9, "assets/tinymce4/js/langs/es.js"},
				"4.5.7":  {9, "assets/tinymce4/js/langs/es.js"},
				"4.5.8":  {9, "assets/tinymce4/js/langs/es.js"},
				"4.5.9":  {2, "assets/tinymce4/js/langs/cs.js"},
				"4.5.10": {2, "assets/tinymce4/js/langs/cs.js"},
				"4.4.15": {12, "assets/contao/css/form.css"},
				"4.4.16": {12, "assets/contao/css/form.css"},
				"4.4.17": {12, "assets/contao/css/form.css"},
				"4.4.18": {12, "assets/contao/css/form.css"},
				"4.4.19": {12, "assets/contao/css/form.css"},
				"4.4.20": {12, "assets/contao/css/form.css"},
			}},
	}

	for _, tc := range cases {
		got := getMostUniqueAcross(tc.input)

		if tc.want != got {
			t.Errorf("expected '%s', got '%s'", tc.want, got)
		}
	}
}

func TestSortByUniqueness(t *testing.T) {
	cases := []struct {
		input []uniqueness
		want  []uniqueness
	}{
		{input: []uniqueness{{120, "robots.txt"}, {3, "css/app.css"}, {10, "js/app.js"}},
			want: []uniqueness{{3, "css/app.css"}, {10, "js/app.js"}, {120, "robots.txt"}}},
	}

	for _, tc := range cases {
		got := sortByUniqueness(tc.input)

		if len(tc.want) != len(got) {
			t.Errorf("len, expected %d, got %d", len(tc.want), len(got))
			continue
		}

		for i := range tc.want {
			if tc.want[i] != got[i] {
				t.Errorf("expected %v, got %v", tc.want[i], got[i])
			}
		}
	}
}
