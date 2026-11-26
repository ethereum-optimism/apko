// Copyright 2025 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lock

import (
	"encoding/json"
	"strings"
	"testing"

	"chainguard.dev/apko/pkg/build/types"
)

func TestArch2LockedPackages(t *testing.T) {
	l := Lock{
		Contents: LockContents{
			Packages: []LockPkg{{
				Name:         "avx",
				Version:      "1.2.3",
				Architecture: "x86_64",
			}, {
				Name:         "sve",
				Version:      "2.3.4",
				Architecture: "aarch64",
			}},
		},
	}

	archs := []types.Architecture{types.ParseArchitecture("arm64")}
	if got, want := len(l.Arch2LockedPackages(archs)), 1; got != want {
		t.Errorf("wanted %d arch, got %d", want, got)
	}
}

func TestLockPkgJSON(t *testing.T) {
	tests := []struct {
		name string
		pkg  LockPkg
		want string
	}{{
		name: "local package",
		pkg:  LockPkg{Name: "tool", Version: "1.0-r0", Architecture: "x86_64", Local: true, URL: "./packages/x86_64/tool-1.0-r0.apk", Checksum: "Q1abc"},
		want: `{"name":"tool","version":"1.0-r0","architecture":"x86_64","local":true}`,
	}, {
		name: "remote package with sha256",
		pkg:  LockPkg{Name: "tool", URL: "https://example.com/x86_64/tool-1.0-r0.apk", Version: "1.0-r0", Architecture: "x86_64", Checksum: "Q1abc", SHA256: "sha256:00"},
		want: `{"name":"tool","url":"https://example.com/x86_64/tool-1.0-r0.apk","version":"1.0-r0","architecture":"x86_64","signature":{"range":"","checksum":""},"control":{"range":"","checksum":""},"data":{"range":"","checksum":""},"checksum":"Q1abc","sha256":"sha256:00"}`,
	}, {
		name: "remote package without sha256",
		pkg:  LockPkg{Name: "tool", URL: "https://example.com/x86_64/tool-1.0-r0.apk", Version: "1.0-r0", Architecture: "x86_64", Checksum: "Q1abc"},
		want: `{"name":"tool","url":"https://example.com/x86_64/tool-1.0-r0.apk","version":"1.0-r0","architecture":"x86_64","signature":{"range":"","checksum":""},"control":{"range":"","checksum":""},"data":{"range":"","checksum":""},"checksum":"Q1abc"}`,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.pkg)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("got = %s, wanted = %s", got, tt.want)
			}
			var back LockPkg
			if err := json.Unmarshal(got, &back); err != nil {
				t.Fatal(err)
			}
			if back.Local != tt.pkg.Local || back.Name != tt.pkg.Name || back.SHA256 != tt.pkg.SHA256 {
				t.Errorf("round trip: got = %+v, wanted = %+v", back, tt.pkg)
			}
		})
	}
}

func TestParseSHA256(t *testing.T) {
	valid := "sha256:" + strings.Repeat("ab", 32)
	tests := []struct {
		in      string
		wantErr string
	}{
		{in: valid},
		{in: strings.Repeat("ab", 32), wantErr: "does not start with"},
		{in: "sha256:zz", wantErr: "not hex encoded"},
		{in: "sha256:abab", wantErr: "has 2 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseSHA256(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, wanted %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if FormatSHA256(got) != tt.in {
				t.Errorf("FormatSHA256 = %s, wanted = %s", FormatSHA256(got), tt.in)
			}
		})
	}
}
