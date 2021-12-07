// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"fmt"
	"testing"
)

func TestAuthentihash(t *testing.T) {

	tests := []struct {
		in  string
		out string
	}{
		{getAbsoluteFilePath("test/putty"),
			"8be7d65593b0fff2e8b29004640261b8a0d4fcc651a14cd0b8b702b7928f8ee0"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, nil)
			if err != nil {
				t.Errorf("TestAuthentihash(%s) failed, reason: %v", tt.in, err)
				return
			}
			err = file.Parse()
			if err != nil {
				t.Errorf("TestAuthentihash(%s) failed, reason: %v", tt.in, err)
				return
			}

			hash := file.Authentihash()
			got := fmt.Sprintf("%x", hash)
			if string(got) != tt.out {
				t.Errorf("TestAuthentihash(%s) got %v, want %v", tt.in, got, tt.out)
			}

		})
	}
}
