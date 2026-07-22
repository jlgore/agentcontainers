package identity

import "testing"

// OverrideBinding is a canonical hash: reordered object keys and added
// whitespace must not change it, distinct args must, and empty/absent args
// fold to one stable form. A mismatch here would reject legitimate overrides
// or (worse) let a different call collide onto the same binding.
func TestOverrideBindingCanonical(t *testing.T) {
	tool := "run_command"

	// Reordered keys + extra whitespace → identical binding.
	a := OverrideBinding(tool, []byte(`{"binary":"dd","extra_args":["x"]}`))
	b := OverrideBinding(tool, []byte(`{  "extra_args" : ["x"] ,  "binary":"dd" }`))
	if a != b {
		t.Errorf("key order/whitespace changed the binding:\n a=%s\n b=%s", a, b)
	}

	// Different args → different binding.
	if c := OverrideBinding(tool, []byte(`{"binary":"dd","extra_args":["y"]}`)); c == a {
		t.Errorf("distinct args collided onto the same binding: %s", c)
	}

	// Different tool → different binding.
	if c := OverrideBinding("exec_shell", []byte(`{"binary":"dd","extra_args":["x"]}`)); c == a {
		t.Errorf("distinct tool collided onto the same binding: %s", c)
	}

	// Large integer literal is preserved exactly (no float64 rounding), so two
	// distinct big ints do not collide.
	big1 := OverrideBinding(tool, []byte(`{"n":10000000000000001}`))
	big2 := OverrideBinding(tool, []byte(`{"n":10000000000000002}`))
	if big1 == big2 {
		t.Error("large integers collided — numeric precision lost in canonicalization")
	}

	// Absent and empty args fold to the same canonical form.
	if OverrideBinding(tool, nil) != OverrideBinding(tool, []byte("   ")) {
		t.Error("nil and blank args produced different bindings")
	}
}
