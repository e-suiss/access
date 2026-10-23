// Command cbor-crosscheck re-encodes every "cbor" vector with an independent encoder (OP-106 m.24).
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

type file struct {
	Cases []map[string]any `json:"cases"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: cbor-crosscheck <vectors dir>")
		os.Exit(2)
	}
	dec, err := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
		TagsMd:      cbor.TagsForbidden,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	checked, failed := 0, 0
	err = filepath.WalkDir(os.Args[1], func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var f file
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil
		}
		for _, c := range f.Cases {
			id, _ := c["id"].(string)
			for _, field := range []string{"cbor", "input", "decision"} {
				h, ok := c[field].(string)
				if !ok {
					continue
				}
				want, err := hex.DecodeString(h)
				if err != nil {
					return err
				}
				var v any
				if err := dec.Unmarshal(want, &v); err != nil {
					fmt.Printf("FAIL %s %s.%s: decode: %v\n", path, id, field, err)
					failed++
					continue
				}
				got, err := enc.Marshal(v)
				if err != nil || !bytes.Equal(got, want) {
					fmt.Printf("FAIL %s %s.%s: re-encoding differs\n", path, id, field)
					failed++
					continue
				}
				checked++
			}
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d vectors identical, %d failed\n", checked, failed)
	if failed > 0 {
		os.Exit(1)
	}
}
