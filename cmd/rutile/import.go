package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/Lercas/rutile/internal/protocol"
	"github.com/Lercas/rutile/internal/store"
)

const maxImportedIdentityFileLen = 2 << 20

func readLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("input is too large (max %d bytes)", max)
	}
	return b, nil
}

func normalizeImportedSecret(raw []byte) (string, error) {
	value := strings.TrimRight(string(raw), "\n")
	if err := store.ValidateSecretValue(value); err != nil {
		return "", err
	}
	return value, nil
}

func commandOutputLimited(cmd *exec.Cmd, max int64) ([]byte, error) {
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	out, readErr := readLimited(stdout, max)
	if readErr != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, readErr
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// sanitizeImportPath maps a foreign store path onto rutile's stricter
// path charset, replacing anything else with '-'.
func sanitizeImportPath(p string) string {
	var segs []string
	for _, seg := range strings.Split(p, "/") {
		var b strings.Builder
		for _, r := range seg {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
				r == '.', r == '_', r == '@', r == '-':
				b.WriteRune(r)
			default:
				b.WriteRune('-')
			}
		}
		s := strings.Trim(b.String(), ".")
		if s == "" || s == ".." {
			s = "_"
		}
		segs = append(segs, s)
	}
	return strings.Join(segs, "/")
}

// importSecrets stores each (path, value) pair, reporting per-item errors
// without aborting the whole run.
func importSecrets(pairs map[string]string, prefix string) error {
	if len(pairs) == 0 {
		return errors.New("ничего не найдено для импорта / nothing to import")
	}
	imported, failed := 0, 0
	for p, v := range pairs {
		dst := sanitizeImportPath(p)
		if prefix != "" {
			dst = strings.TrimSuffix(prefix, "/") + "/" + dst
		}
		if err := store.ValidatePath(dst); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", p, err)
			failed++
			continue
		}
		if err := store.ValidateSecretValue(v); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", p, err)
			failed++
			continue
		}
		if err := callUnlocked("put", protocol.PutParams{Path: dst, Value: v}, nil); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", p, err)
			failed++
			continue
		}
		fmt.Printf("  ✓ %s\n", dst)
		imported++
	}
	fmt.Printf("импортировано / imported: %d", imported)
	if failed > 0 {
		fmt.Printf(", ошибок / failed: %d", failed)
	}
	fmt.Println()
	if imported == 0 {
		return errors.New("nothing was imported")
	}
	return nil
}

// walkEncrypted collects relative secret paths with the given extension.
func walkEncrypted(root, ext string) (map[string]string, error) {
	files := map[string]string{} // secret path -> absolute file
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ext) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[strings.TrimSuffix(filepath.ToSlash(rel), ext)] = path
		return nil
	})
	return files, err
}

func cmdImport() *cobra.Command {
	c := &cobra.Command{
		Use:   "import",
		Short: "Импорт секретов из passage, pass или .env / import from passage, pass or dotenv",
	}
	c.AddCommand(importPassage(), importPass(), importEnv())
	return c
}

func importPassage() *cobra.Command {
	var storeDir, identFile, prefix string
	c := &cobra.Command{
		Use:   "passage",
		Short: "Импорт из passage (age)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			ids, err := loadPassageIdentities(identFile)
			if err != nil {
				return err
			}
			files, err := walkEncrypted(storeDir, ".age")
			if err != nil {
				return err
			}
			pairs := map[string]string{}
			for p, f := range files {
				ciphertext, err := os.Open(f)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", p, err)
					continue
				}
				data, err := readLimited(ciphertext, store.MaxSecretValueLen+64*1024)
				ciphertext.Close()
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", p, err)
					continue
				}
				r, err := age.Decrypt(bytes.NewReader(data), ids...)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ✗ %s: decrypt: %v\n", p, err)
					continue
				}
				pt, err := readLimited(r, store.MaxSecretValueLen)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", p, err)
					continue
				}
				value, err := normalizeImportedSecret(pt)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", p, err)
					continue
				}
				pairs[p] = value
			}
			return importSecrets(pairs, prefix)
		},
	}
	home, _ := os.UserHomeDir()
	c.Flags().StringVar(&storeDir, "store", filepath.Join(home, ".passage", "store"), "каталог store passage")
	c.Flags().StringVar(&identFile, "identities", filepath.Join(home, ".passage", "identities"), "файл age-identities")
	c.Flags().StringVar(&prefix, "prefix", "", "префикс путей в rutile")
	return c
}

// loadPassageIdentities reads a passage identities file, transparently
// handling the age-encrypted (passphrase-protected) variant.
func loadPassageIdentities(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := readLimited(f, maxImportedIdentityFileLen)
	if err != nil {
		return nil, err
	}
	encrypted := bytes.HasPrefix(data, []byte("age-encryption.org/v1")) ||
		bytes.Contains(data[:min(len(data), 64)], []byte("BEGIN AGE ENCRYPTED FILE"))
	if encrypted {
		pw, err := readPassphrase("Passphrase файла identities passage: ")
		if err != nil {
			return nil, err
		}
		sid, err := age.NewScryptIdentity(pw)
		if err != nil {
			return nil, err
		}
		r, err := age.Decrypt(bytes.NewReader(data), sid)
		if err != nil {
			return nil, fmt.Errorf("не удалось расшифровать identities: %w", err)
		}
		if data, err = readLimited(r, maxImportedIdentityFileLen); err != nil {
			return nil, err
		}
	}
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("разбор identities: %w", err)
	}
	return ids, nil
}

func importPass() *cobra.Command {
	var storeDir, prefix string
	c := &cobra.Command{
		Use:   "pass",
		Short: "Импорт из pass (gpg)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			if _, err := exec.LookPath("gpg"); err != nil {
				return errors.New("gpg не найден в PATH — он нужен для расшифровки pass-хранилища")
			}
			files, err := walkEncrypted(storeDir, ".gpg")
			if err != nil {
				return err
			}
			pairs := map[string]string{}
			for p, f := range files {
				out, err := commandOutputLimited(exec.Command("gpg", "--quiet", "--decrypt", f), store.MaxSecretValueLen)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ✗ %s: gpg: %v\n", p, err)
					continue
				}
				value, err := normalizeImportedSecret(out)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", p, err)
					continue
				}
				pairs[p] = value
			}
			return importSecrets(pairs, prefix)
		},
	}
	home, _ := os.UserHomeDir()
	c.Flags().StringVar(&storeDir, "store", filepath.Join(home, ".password-store"), "каталог password-store")
	c.Flags().StringVar(&prefix, "prefix", "", "префикс путей в rutile")
	return c
}

func importEnv() *cobra.Command {
	var prefix string
	c := &cobra.Command{
		Use:   "env <file>",
		Short: "Импорт из .env (dotenv)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			if prefix == "" {
				return errors.New("--prefix обязателен для env-импорта (например --prefix dev/myproject)")
			}
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			pairs := map[string]string{}
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 64*1024), store.MaxSecretValueLen+store.MaxPathLen+4096)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				line = strings.TrimPrefix(line, "export ")
				k, v, ok := strings.Cut(line, "=")
				if !ok {
					continue
				}
				k = strings.TrimSpace(k)
				v = strings.TrimSpace(v)
				if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
					v = v[1 : len(v)-1]
				}
				if k == "" || v == "" {
					continue
				}
				pairs[k] = v
			}
			if err := sc.Err(); err != nil {
				return err
			}
			return importSecrets(pairs, prefix)
		},
	}
	c.Flags().StringVar(&prefix, "prefix", "", "префикс путей в rutile (обязателен)")
	return c
}
