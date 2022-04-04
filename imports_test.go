// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import "testing"

func TestImpHash(t *testing.T) {
	for _, tt := range []struct {
		in  string
		out string
	}{
		{getAbsoluteFilePath("test/putty.exe"), "2e3215acc61253e5fa73a840384e9720"},
		{getAbsoluteFilePath("test/01008963d32f5cc17b64c31446386ee5b36a7eab6761df87a2989ba9394d8f3d"), "431cb9bbc479c64cb0d873043f4de547"},
		{getAbsoluteFilePath("test/0103daa751660333b7ae5f098795df58f07e3031563e042d2eb415bffa71fe7a"), "8b58a51c1fff9c4a944265c1fe0fab74"},
		{getAbsoluteFilePath("test/0585495341e0ffaae1734acb78708ff55cd3612d844672d37226ef63d12652d0"), "e4290fa6afc89d56616f34ebbd0b1f2c"},
	} {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, &Options{})
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}
			if err := file.Parse(); err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in, err)
			}
			imphash, err := file.ImpHash()
			if err != nil {
				t.Fatalf("ImpHash(%s) failed, reason: %v", tt.in, err)
			}
			if imphash != tt.out {
				t.Errorf("ImpHash(%s) got %v, want %v", tt.in, imphash, tt.out)
			}
		})
	}
}
