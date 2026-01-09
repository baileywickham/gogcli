package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/steipete/gogcli/internal/config"
	"github.com/steipete/gogcli/internal/outfmt"
	"github.com/steipete/gogcli/internal/secrets"
	"github.com/steipete/gogcli/internal/ui"
)

func TestAuthKeyringSet_WritesConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv("GOG_KEYRING_BACKEND", "")

	var stdout, stderr bytes.Buffer
	u, err := ui.New(ui.Options{Stdout: &stdout, Stderr: &stderr, Color: "never"})
	if err != nil {
		t.Fatalf("ui new: %v", err)
	}
	ctx := ui.WithUI(context.Background(), u)
	ctx = outfmt.WithMode(ctx, outfmt.Mode{})

	if err = runKong(t, &AuthKeyringCmd{}, []string{"file"}, ctx, nil); err != nil {
		t.Fatalf("run: %v", err)
	}

	path, err := config.ConfigPath()
	if err != nil {
		t.Fatalf("config path: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !bytes.Contains(b, []byte(`"keyring_backend": "file"`)) {
		t.Fatalf("expected keyring_backend=file, got:\n%s", string(b))
	}

	info, err := secrets.ResolveKeyringBackendInfo()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if info.Value != "file" || info.Source != "config" {
		t.Fatalf("expected file/config, got %q/%q", info.Value, info.Source)
	}
}

func TestAuthKeyring_WritesConfig_Shorthand(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv("GOG_KEYRING_BACKEND", "")

	var stdout, stderr bytes.Buffer
	u, err := ui.New(ui.Options{Stdout: &stdout, Stderr: &stderr, Color: "never"})
	if err != nil {
		t.Fatalf("ui new: %v", err)
	}
	ctx := ui.WithUI(context.Background(), u)
	ctx = outfmt.WithMode(ctx, outfmt.Mode{})

	if err = runKong(t, &AuthKeyringCmd{}, []string{"set", "file"}, ctx, nil); err != nil {
		t.Fatalf("run: %v", err)
	}

	cfg, err := config.ReadConfig()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if cfg.KeyringBackend != "file" {
		t.Fatalf("expected file, got %q", cfg.KeyringBackend)
	}
}

func TestAuthKeyringSet_InvalidBackend(t *testing.T) {
	var stdout, stderr bytes.Buffer
	u, err := ui.New(ui.Options{Stdout: &stdout, Stderr: &stderr, Color: "never"})
	if err != nil {
		t.Fatalf("ui new: %v", err)
	}
	ctx := ui.WithUI(context.Background(), u)
	ctx = outfmt.WithMode(ctx, outfmt.Mode{})

	err = runKong(t, &AuthKeyringCmd{}, []string{"nope"}, ctx, nil)
	if err == nil {
		t.Fatalf("expected error")
	}

	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 2 {
		t.Fatalf("expected usage exit 2, got: %v", err)
	}
}
