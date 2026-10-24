package probe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Blackman99/lotstamp/internal/advisory"
	"github.com/Blackman99/lotstamp/internal/testfix"
)

func opts() Options {
	a := advisory.Load()
	return Options{DecoderNames: a.DecoderNames, FixMarker: a.FixMarker}
}

func TestPrefixedTable(t *testing.T) {
	d := t.TempDir()
	for _, fixed := range []bool{false, true} {
		p := testfix.Write(t, d, "x", testfix.Spec{Table: true, Fixed: fixed})
		ev, err := File(p, opts())
		if err != nil {
			t.Fatal(err)
		}
		want := 16
		if fixed {
			want = 17
		}
		if ev.DecoderNames != want || ev.FixMarker != fixed || ev.Format != "elf" {
			t.Fatalf("fixed=%v: got names=%d marker=%v format=%s", fixed, ev.DecoderNames, ev.FixMarker, ev.Format)
		}
	}
}

// Brotli 1.0.x (Debian 12) stores bare names. The bookworm backport adds a bare BLOCK_SWITCH.
func TestBareTable(t *testing.T) {
	d := t.TempDir()
	for _, fixed := range []bool{false, true} {
		p := testfix.Write(t, d, "libbrotlidec.so.1.0.9", testfix.Spec{Table: true, Bare: true, Fixed: fixed})
		ev, _ := File(p, opts())
		if ev.FixMarker != fixed || ev.DecoderNames < 16 {
			t.Fatalf("bare fixed=%v: names=%d marker=%v", fixed, ev.DecoderNames, ev.FixMarker)
		}
	}
}

func TestVersions(t *testing.T) {
	d := t.TempDir()
	// Bun embeds a Node headers URL too: both must be read, the verdict decides who wins.
	p := testfix.Write(t, d, "bun", testfix.Spec{Table: true, Extra: "Bun/1.4.3\x00" + testfix.NodeHeaders("26.3.0") + "\x00Bun v1.4.3 (abc)"})
	ev, _ := File(p, opts())
	if len(ev.Bun) == 0 || ev.Bun[0] != "1.4.3" || len(ev.Node) == 0 || ev.Node[0] != "26.3.0" {
		t.Fatalf("bun=%v node=%v", ev.Bun, ev.Node)
	}
	p = testfix.Write(t, d, "code", testfix.Spec{Table: true, Fixed: true, Extra: testfix.NodeHeaders("24.19.0") + "\x00Electron/39.2.0 Chrome/150.0.7000.1\x00"})
	ev, _ = File(p, opts())
	if len(ev.Electron) == 0 || ev.Electron[0] != "39.2.0" || len(ev.Chrome) == 0 || !strings.HasPrefix(ev.Chrome[0], "150") {
		t.Fatalf("electron=%v chrome=%v", ev.Electron, ev.Chrome)
	}
}

// A marker split across the chunk boundary must still be found, and never counted twice.
func TestChunkBoundary(t *testing.T) {
	d := t.TempDir()
	for _, pad := range []int{chunk - 200, chunk - 100, chunk - 64, chunk - 20, chunk + 3} {
		p := testfix.Write(t, d, "big", testfix.Spec{Table: true, Fixed: true, Pad: pad})
		ev, _ := File(p, opts())
		if !ev.FixMarker || ev.DecoderNames != 17 {
			t.Fatalf("pad %d: names=%d marker=%v", pad, ev.DecoderNames, ev.FixMarker)
		}
	}
}

func TestAppImageAndMagic(t *testing.T) {
	d := t.TempDir()
	b := testfix.Bytes(testfix.Spec{})
	copy(b[8:], "AI\x02")
	p := filepath.Join(d, "Cursor.AppImage")
	os.WriteFile(p, b, 0o755)
	ev, _ := File(p, opts())
	if ev.Packed != "appimage" {
		t.Fatalf("packed=%q", ev.Packed)
	}
	for m, want := range map[string]string{"\x7fELF": "elf", "MZ": "pe", "\xcf\xfa\xed\xfe": "macho", "#!": "other"} {
		p := testfix.Write(t, d, "m", testfix.Spec{Magic: m})
		if got := Magic(p); got != want {
			t.Errorf("magic %q: got %s want %s", m, got, want)
		}
	}
}

func TestNoTable(t *testing.T) {
	d := t.TempDir()
	p := testfix.Write(t, d, "node", testfix.Spec{Extra: testfix.NodeHeaders("24.22.0")})
	ev, _ := File(p, opts())
	if ev.HasDecoder(12) {
		t.Fatal("no table should mean no decoder")
	}
}
