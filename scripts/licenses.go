//go:build ignore

// Generate NOTICE from the Linux build's go-licenses inventory.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/google/go-licenses/v2/licenses"
)

func main() {
	if err := generate(); err != nil {
		log.Fatal(err)
	}
}

func generate() error {
	// Run the generator on the host, and load packages for the Linux build.
	if err := os.Setenv("GOOS", "linux"); err != nil {
		return err
	}
	classifier, err := licenses.NewClassifier()
	if err != nil {
		return err
	}
	libs, err := licenses.Libraries(context.Background(), classifier, false, []string{"github.com/Silo-Server/shunpike"}, "./...")
	if err != nil {
		return err
	}
	if len(libs) == 0 {
		return fmt.Errorf("Linux license inventory is empty")
	}
	modulePaths, err := exec.Command("go", "list", "-m", "-f", "{{.Path}}", "all").Output()
	if err != nil {
		return fmt.Errorf("list module paths: %w", err)
	}
	modules := strings.Fields(string(modulePaths))
	sort.Slice(modules, func(i, j int) bool { return len(modules[i]) > len(modules[j]) })
	sort.Slice(libs, func(i, j int) bool { return libs[i].Name() < libs[j].Name() })
	var notice bytes.Buffer
	notice.WriteString("Shunpike Third-Party Notices\n\nGenerated from the Linux build with the pinned go-licenses inventory.\nRegenerate from the module root: go run scripts/licenses.go > NOTICE\n")
	for _, lib := range libs {
		module := ""
		for _, path := range modules {
			if lib.Name() == path || strings.HasPrefix(lib.Name(), path+"/") {
				module = path
				break
			}
		}
		if module == "" || lib.LicenseFile == "" || len(lib.Licenses) == 0 {
			return fmt.Errorf("incomplete license inventory for %q", lib.Name())
		}
		text, err := os.ReadFile(lib.LicenseFile)
		if err != nil {
			return err
		}
		names := make([]string, 0, len(lib.Licenses))
		for _, license := range lib.Licenses {
			names = append(names, license.Name)
		}
		sort.Strings(names)
		fmt.Fprintf(&notice, "\n---\nModule: %s\nLicense: %s\n\n%s\n", module, strings.Join(names, ", "), strings.TrimSpace(string(text)))
	}
	_, err = os.Stdout.Write(notice.Bytes())
	return err
}
