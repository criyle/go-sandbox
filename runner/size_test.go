package runner

import "testing"

func TestSizeSetRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{"", " ", "b", "k", "-1", "18446744073709551616", "18446744073709551616g"} {
		var s Size
		if err := s.Set(input); err == nil {
			t.Errorf("Size.Set(%q) succeeded, want error", input)
		}
	}
}

func TestSizeSet(t *testing.T) {
	for _, test := range []struct {
		input string
		want  Size
	}{
		{"1", 1},
		{"2K", 2 << 10},
		{"3mb", 3 << 20},
		{"4G", 4 << 30},
		{" 5k ", 5 << 10},
	} {
		var got Size
		if err := got.Set(test.input); err != nil {
			t.Fatalf("Size.Set(%q): %v", test.input, err)
		}
		if got != test.want {
			t.Errorf("Size.Set(%q) = %d, want %d", test.input, got, test.want)
		}
	}
}
