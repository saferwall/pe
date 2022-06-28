package pe

import (
	"crypto/md5"
	"encoding/hex"
	"testing"
)

type TestOverlay struct {
	overlayOffset int64
	overlayLength int64
	md5str        string
}

var overlayTests = []struct {
	in  string
	out TestOverlay
}{
	{getAbsoluteFilePath("test/putty.exe"),
		TestOverlay{
			overlayOffset: 1163264,
			overlayLength: 15760,
			md5str:        "1f46295a513e744895a6acf1029e136f",
		}},
}

func TestFile_NewOverlayReader(t *testing.T) {
	for _, tt := range overlayTests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, &Options{})
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}

			if err := file.Parse(); err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in, err)
			}
			if file.OverlayOffset != tt.out.overlayOffset {
				t.Errorf("overlayLength failed, got %d, want %d", file.OverlayOffset, tt.out.overlayOffset)
			}

			overlayLength := file.OverlayLength()
			if overlayLength != tt.out.overlayLength {
				t.Errorf("overlayOffset failed, got %d, want %d", overlayLength, tt.out.overlayLength)
			}

			overlay, _ := file.Overlay()
			h := md5.New()
			h.Write(overlay)
			md5str := hex.EncodeToString(h.Sum(nil))
			if md5str != tt.out.md5str {
				t.Errorf("overlayOffset failed, got %s, want %s", md5str, tt.out.md5str)
			}
		})
	}
}
