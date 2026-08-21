package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Lercas/rutile/internal/ipc"
	"github.com/Lercas/rutile/internal/paths"
	"github.com/Lercas/rutile/internal/protocol"
)

// placeholderRe matches {{rutile:dev/foo/bar}} in command arguments.
var placeholderRe = regexp.MustCompile(`\{\{rutile:([a-zA-Z0-9._@/-]+)\}\}`)
var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func optionalAgentAuth(agent, token string) (*protocol.AgentAuth, error) {
	if agent == "" && token == "" {
		return nil, nil
	}
	if agent == "" || token == "" {
		return nil, errors.New("RUTILE_AGENT and RUTILE_TOKEN must either both be set or both be absent; refusing to downgrade partial agent credentials to human mode")
	}
	return &protocol.AgentAuth{Agent: agent, Token: token}, nil
}

func validateArgvSecretOptIn(args []string, allowed bool) error {
	if allowed {
		return nil
	}
	for _, arg := range args {
		if placeholderRe.MatchString(arg) {
			return errors.New("secret placeholder in argv is disabled by default; prefer -e or pass --allow-argv-secrets after reviewing process-list/log exposure")
		}
	}
	return nil
}

// resolvePlaceholders substitutes every {{rutile:path}} in args.
func resolvePlaceholders(args []string, get func(string) (string, error)) ([]string, error) {
	out := make([]string, len(args))
	for i, a := range args {
		var firstErr error
		out[i] = placeholderRe.ReplaceAllStringFunc(a, func(m string) string {
			path := placeholderRe.FindStringSubmatch(m)[1]
			v, err := get(path)
			if err != nil && firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", path, err)
			}
			return v
		})
		if firstErr != nil {
			return nil, firstErr
		}
	}
	return out, nil
}

func cmdRun() *cobra.Command {
	var envMap []string
	var allowArgvSecrets bool
	c := &cobra.Command{
		Use:   "run -e ENV_VAR=secret/path [--] command [args...]",
		Short: "Запустить команду с policy-scoped секретами в env (argv — только opt-in)",
		Long: `Секреты подставляются в окружение дочернего процесса (-e), поэтому
rutile сам не печатает значение и оно не попадает в shell history. Дочерний
процесс всё ещё может вывести или залогировать свой env — проверяйте команду.

Подстановка {{rutile:path}} в argv по умолчанию запрещена: argv может быть
виден другим процессам и telemetry. Для осознанного исключения используйте
--allow-argv-secrets.

Если заданы RUTILE_AGENT и RUTILE_TOKEN, чтение идёт от имени агента
через его политику; иначе — от имени человека.`,
		Example: `  rutile run -e API_KEY=dev/svc/key -- sh -c 'curl -H "X-Key: $API_KEY" https://api.example.com'
  rutile run --allow-argv-secrets -- deploy --token {{rutile:deploy/token}}`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			auth, err := optionalAgentAuth(os.Getenv("RUTILE_AGENT"), os.Getenv("RUTILE_TOKEN"))
			if err != nil {
				return err
			}
			get := func(path string) (string, error) {
				var res protocol.GetResult
				var err error
				if auth != nil {
					err = ipc.Call("get", auth, protocol.GetParams{Path: path, Reason: "rutile run"}, &res)
				} else {
					err = callUnlocked("get", protocol.GetParams{Path: path, Reason: "rutile run"}, &res)
				}
				return res.Value, err
			}

			env := os.Environ()
			for _, kv := range envMap {
				name, path, ok := strings.Cut(kv, "=")
				if !ok || !envNameRe.MatchString(name) || path == "" {
					return fmt.Errorf("bad -e %q: ожидается ENV_VAR=secret/path", kv)
				}
				v, err := get(path)
				if err != nil {
					return fmt.Errorf("-e %s: %w", kv, err)
				}
				env = append(env, name+"="+v)
			}
			if err := validateArgvSecretOptIn(args, allowArgvSecrets); err != nil {
				return err
			}
			resolved, err := resolvePlaceholders(args, get)
			if err != nil {
				return err
			}

			ec := exec.Command(resolved[0], resolved[1:]...)
			ec.Env = env
			ec.Stdin, ec.Stdout, ec.Stderr = os.Stdin, os.Stdout, os.Stderr
			err = ec.Run()
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				os.Exit(exitErr.ExitCode())
			}
			return err
		},
	}
	c.Flags().StringArrayVarP(&envMap, "env", "e", nil, "ENV_VAR=secret/path (можно повторять)")
	c.Flags().BoolVar(&allowArgvSecrets, "allow-argv-secrets", false, "разрешить подстановку секрета в argv (может быть виден в ps/логах)")
	return c
}

func cmdRotate() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Ротация ключа: новый age-identity, перешифровка всех секретов",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			// make sure the store is unlocked before asking for the new passphrase
			if err := callUnlocked("status", nil, nil); err != nil {
				return err
			}
			var st protocol.StatusResult
			if err := ipc.Call("status", nil, nil, &st); err != nil {
				return err
			}
			if !st.Unlocked {
				pw, err := readPassphrase("Текущая passphrase: ")
				if err != nil {
					return err
				}
				if err := ipc.Call("unlock", nil, protocol.UnlockParams{Passphrase: pw}, nil); err != nil {
					return err
				}
			}
			p1, err := readPassphrase("Новая passphrase: ")
			if err != nil {
				return err
			}
			p2, err := readPassphrase("Повторите новую passphrase: ")
			if err != nil {
				return err
			}
			if p1 != p2 {
				return errors.New("passphrase не совпадают")
			}
			var res protocol.RotateResult
			if err := ipc.Call("rotate", nil, protocol.RotateParams{NewPassphrase: p1}, &res); err != nil {
				return err
			}
			backup := res.Backup
			if backup == "" { // compatibility with an older daemon
				backup = paths.IdentityFile() + ".bak"
			}
			fmt.Printf(`Ключ ротирован, перешифровано секретов: %d.
Старый ключ сохранён в %s — проверьте, что всё читается,
затем удалите recovery-копию осознанно.
`, res.Reencrypted, backup)
			return nil
		},
	}
}

func cmdBackup() *cobra.Command {
	return &cobra.Command{
		Use:   "backup <dir>",
		Short: "Скопировать ключ (identities.age + recipients.txt) в каталог",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			dst := args[0]
			if err := os.MkdirAll(dst, 0o700); err != nil {
				return err
			}
			if st, err := os.Stat(dst); err != nil {
				return err
			} else if !st.IsDir() || st.Mode().Perm()&0o077 != 0 {
				return fmt.Errorf("backup directory must be a private directory (mode 0700): %s has mode %03o", dst, st.Mode().Perm())
			}
			root, err := os.OpenRoot(dst)
			if err != nil {
				return err
			}
			defer root.Close()
			var files []backupFile
			for _, src := range []string{paths.IdentityFile(), paths.RecipientsFile()} {
				data, err := os.ReadFile(src)
				if err != nil {
					return err
				}
				files = append(files, backupFile{name: filepath.Base(src), data: data})
			}
			if err := writeBackupFiles(root, files); err != nil {
				return err
			}
			for _, file := range files {
				fmt.Println("скопировано:", filepath.Join(dst, file.name))
			}
			fmt.Println("Ключ зашифрован вашей passphrase — храните копию отдельно от неё.")
			return nil
		},
	}
}

type backupFile struct {
	name string
	data []byte
}

func writeBackupFiles(root *os.Root, files []backupFile) error {
	for _, file := range files {
		if _, err := root.Lstat(file.name); err == nil {
			return fmt.Errorf("refusing to overwrite backup file %s", file.name)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	created := make([]string, 0, len(files))
	cleanup := func() {
		for _, name := range created {
			_ = root.Remove(name)
		}
	}
	for _, file := range files {
		f, err := root.OpenFile(file.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			cleanup()
			return err
		}
		created = append(created, file.name)
		if _, err := f.Write(file.data); err != nil {
			f.Close()
			cleanup()
			return err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			cleanup()
			return err
		}
		if err := f.Close(); err != nil {
			cleanup()
			return err
		}
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func cmdDelegations() *cobra.Command {
	c := &cobra.Command{
		Use:   "delegations",
		Short: "Активные суб-токены, выпущенные агентами",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			var res protocol.DelegationListResult
			if err := ipc.Call("delegation_list", nil, nil, &res); err != nil {
				return err
			}
			if len(res.Delegations) == 0 {
				fmt.Println("(делегирований нет)")
				return nil
			}
			for _, d := range res.Delegations {
				fmt.Printf("%s  %s>%s  %v  до %s  (token %s…)\n",
					d.ID, d.Parent, d.Label, d.Patterns, d.ExpiresAt.Local().Format("15:04 02.01"), d.TokenPfx)
			}
			return nil
		},
	}
	revoke := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Отозвать суб-токен",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			if err := ipc.Call("delegation_revoke", nil, protocol.DelegationRevokeParams{ID: args[0]}, nil); err != nil {
				return err
			}
			fmt.Println("отозвано:", args[0])
			return nil
		},
	}
	c.AddCommand(revoke)
	return c
}
