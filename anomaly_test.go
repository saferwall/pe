// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"testing"
)

func TestGetAnomalies(t *testing.T) {

	tests := []struct {
		in      string
		out []string
	}{
		{
			getAbsoluteFilePath(
			"test/050708404553416d103652a7ca1f887ab81f533a019a0eeff0e6bb460a202cde"),
			[]string{AnoReservedDataDirectoryEntry},
		},
		{
			getAbsoluteFilePath(
			"test/0585495341e0ffaae1734acb78708ff55cd3612d844672d37226ef63d12652d0"),
			[]string{AnoAddressOfEntryPointNull, AnoMajorSubsystemVersion},
		},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, &Options{})
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}
			err = file.Parse()
			if err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in, err)
			}

			err = file.GetAnomalies()
			if err != nil {
				t.Fatalf("GetAnomalies(%s) failed, reason: %v", tt.in, err)
			}

			for _, ano := range tt.out {
				if !stringInSlice(ano, file.Anomalies) {
					t.Errorf("anomaly(%s) not found in anomalies, got: %v", ano, file.Anomalies)
				}
			}

		})
	}
}
