// rutile — an AI-agent-oriented secrets manager: an age-encrypted
// pass-style store served by a background broker daemon, with per-agent
// access policies, an MCP server for AI tools and a tamper-evident audit log.
package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/Lercas/rutile/internal/ageio"
	"github.com/Lercas/rutile/internal/gitsync"
	"github.com/Lercas/rutile/internal/ipc"
	"github.com/Lercas/rutile/internal/paths"
	"github.com/Lercas/rutile/internal/protocol"
	"github.com/Lercas/rutile/internal/store"
)

// version is overridden at build time: -ldflags "-X main.version=..."
var version = "1.4.0"

func readSecretInput(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, store.MaxSecretValueLen+1))
	if err != nil {
		return "", err
	}
	value := strings.TrimRight(string(b), "\n")
	if err := store.ValidateSecretValue(value); err != nil {
		return "", err
	}
	return value, nil
}

func readInitPassphrase(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, ageio.MaxPassphraseLen+1))
	if err != nil {
		return "", err
	}
	pw := strings.TrimRight(string(b), "\n")
	if err := ageio.ValidatePassphrase(pw); err != nil {
		return "", err
	}
	return pw, nil
}

func writeInitialKeyMaterial(writeRecipients, writeIdentity func() error) error {
	// recipients.txt is public metadata and may be safely replaced on retry.
	// identities.age is the Initialized commit marker and must be written last.
	if err := writeRecipients(); err != nil {
		return err
	}
	return writeIdentity()
}

func validateGeneratedSecretLength(length int) error {
	if length <= 0 {
		return errors.New("длина пароля должна быть положительной")
	}
	if length > store.MaxSecretValueLen {
		return fmt.Errorf("длина пароля слишком велика (максимум %d)", store.MaxSecretValueLen)
	}
	return nil
}

func main() {
	root := &cobra.Command{
		Use:           "rutile",
		Short:         "Менеджер секретов для людей и AI-агентов (age + политики доступа + аудит)",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		cmdInit(), cmdAdd(), cmdShow(), cmdLs(), cmdRm(), cmdGenerate(), cmdEdit(),
		cmdUnlock(), cmdLock(), cmdStatus(),
		cmdAgent(), cmdAllow(), cmdDeny(), cmdPolicy(),
		cmdRequests(), cmdApprove(), cmdReject(), cmdDelegations(),
		cmdRun(), cmdRotate(), cmdBackup(), cmdImport(), cmdDoctor(),
		cmdAudit(), cmdGit(), cmdDaemon(), cmdMCP(),
	)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func requireInit() error {
	if !paths.Initialized() {
		return errors.New("хранилище не создано — выполните: rutile init")
	}
	return nil
}

func readPassphrase(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(pw), nil
}

// callUnlocked runs a daemon call, transparently prompting for the
// passphrase and retrying when the store is locked.
func callUnlocked(method string, params, out any) error {
	err := ipc.Call(method, nil, params, out)
	var rpcErr *protocol.RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != protocol.CodeLocked {
		return err
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return err
	}
	for i := 0; i < 3; i++ {
		pw, perr := readPassphrase("Passphrase: ")
		if perr != nil {
			return perr
		}
		uerr := ipc.Call("unlock", nil, protocol.UnlockParams{Passphrase: pw}, nil)
		if uerr == nil {
			return ipc.Call(method, nil, params, out)
		}
		fmt.Fprintln(os.Stderr, "Неверная passphrase, попробуйте ещё раз.")
	}
	return errors.New("не удалось разблокировать хранилище")
}

func cmdInit() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Создать хранилище (один раз): passphrase → готово",
		RunE: func(cmd *cobra.Command, args []string) error {
			if paths.Initialized() {
				return fmt.Errorf("хранилище уже существует: %s", paths.Dir())
			}
			if err := os.MkdirAll(paths.StoreDir(), 0o700); err != nil {
				return err
			}
			if err := os.MkdirAll(paths.AgentsDir(), 0o700); err != nil {
				return err
			}
			var pw string
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				// piped passphrase (tests/automation)
				piped, err := readInitPassphrase(os.Stdin)
				if err != nil {
					return err
				}
				pw = piped
			} else {
				p1, err := readPassphrase("Придумайте passphrase: ")
				if err != nil {
					return err
				}
				p2, err := readPassphrase("Повторите passphrase: ")
				if err != nil {
					return err
				}
				if p1 != p2 {
					return errors.New("passphrase не совпадают")
				}
				pw = p1
			}
			if err := ageio.ValidatePassphrase(pw); err != nil {
				return err
			}
			id, err := ageio.GenerateIdentity()
			if err != nil {
				return err
			}
			if err := writeInitialKeyMaterial(
				func() error { return ageio.SaveRecipients(paths.RecipientsFile(), id.Recipient()) },
				func() error { return ageio.SaveIdentityEncrypted(paths.IdentityFile(), id, pw) },
			); err != nil {
				return err
			}
			if err := gitsync.Init(paths.Dir()); err != nil {
				fmt.Fprintln(os.Stderr, "предупреждение: git недоступен:", err)
			}
			fmt.Printf(`Готово! Хранилище: %s

Дальше:
  rutile add dev/myproject/api-key     # сохранить секрет
  rutile show dev/myproject/api-key    # прочитать
  rutile agent add claude              # подключить AI-агента
`, paths.Dir())
			return nil
		},
	}
}

func cmdAdd() *cobra.Command {
	return &cobra.Command{
		Use:     "add <path>",
		Aliases: []string{"insert"},
		Short:   "Сохранить секрет (значение — со stdin или скрытым вводом)",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			var value string
			if term.IsTerminal(int(os.Stdin.Fd())) {
				v, err := readPassphrase("Значение секрета: ")
				if err != nil {
					return err
				}
				value = v
			} else {
				v, err := readSecretInput(os.Stdin)
				if err != nil {
					return err
				}
				value = v
			}
			if value == "" {
				return errors.New("пустое значение")
			}
			if err := store.ValidateSecretValue(value); err != nil {
				return err
			}
			if err := callUnlocked("put", protocol.PutParams{Path: args[0], Value: value}, nil); err != nil {
				return err
			}
			fmt.Println("сохранено:", args[0])
			return nil
		},
	}
}

func cmdShow() *cobra.Command {
	return &cobra.Command{
		Use:   "show <path>",
		Short: "Показать секрет",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			var res protocol.GetResult
			if err := callUnlocked("get", protocol.GetParams{Path: args[0]}, &res); err != nil {
				return err
			}
			fmt.Println(res.Value)
			return nil
		},
	}
}

func cmdLs() *cobra.Command {
	return &cobra.Command{
		Use:   "ls [prefix]",
		Short: "Список секретов",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			prefix := ""
			if len(args) == 1 {
				prefix = args[0]
			}
			var res protocol.ListResult
			if err := ipc.Call("list", nil, protocol.ListParams{Prefix: prefix}, &res); err != nil {
				return err
			}
			if len(res.Paths) == 0 {
				fmt.Println("(пусто)")
				return nil
			}
			for _, p := range res.Paths {
				fmt.Println(p)
			}
			return nil
		},
	}
}

func cmdRm() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <path>",
		Short: "Удалить секрет",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			if err := ipc.Call("del", nil, protocol.DelParams{Path: args[0]}, nil); err != nil {
				return err
			}
			fmt.Println("удалено:", args[0])
			return nil
		},
	}
}

func cmdGenerate() *cobra.Command {
	var length int
	c := &cobra.Command{
		Use:   "generate <path>",
		Short: "Сгенерировать и сохранить случайный пароль",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			if err := validateGeneratedSecretLength(length); err != nil {
				return err
			}
			const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.,!@#%^&*"
			b := make([]byte, length)
			for i := range b {
				n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
				if err != nil {
					return err
				}
				b[i] = charset[n.Int64()]
			}
			if err := callUnlocked("put", protocol.PutParams{Path: args[0], Value: string(b)}, nil); err != nil {
				return err
			}
			fmt.Println(string(b))
			return nil
		},
	}
	c.Flags().IntVarP(&length, "length", "n", 24, "длина пароля")
	return c
}

func cmdEdit() *cobra.Command {
	return &cobra.Command{
		Use:   "edit <path>",
		Short: "Отредактировать секрет в $EDITOR",
		Args:  cobra.ExactArgs(1),
		RunE:  runEdit,
	}
}

func cmdUnlock() *cobra.Command {
	return &cobra.Command{
		Use:   "unlock",
		Short: "Разблокировать хранилище (обычно происходит само)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			var st protocol.StatusResult
			if err := ipc.Call("status", nil, nil, &st); err != nil {
				return err
			}
			if st.Unlocked {
				fmt.Println("уже разблокировано")
				return nil
			}
			pw, err := readPassphrase("Passphrase: ")
			if err != nil {
				return err
			}
			if err := ipc.Call("unlock", nil, protocol.UnlockParams{Passphrase: pw}, nil); err != nil {
				return err
			}
			fmt.Println("разблокировано")
			return nil
		},
	}
}

func cmdLock() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Заблокировать хранилище (выгрузить ключ из памяти демона)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			if err := ipc.Call("lock", nil, nil, nil); err != nil {
				return err
			}
			fmt.Println("заблокировано")
			return nil
		},
	}
}

func cmdStatus() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Состояние демона и хранилища",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			var st protocol.StatusResult
			if err := ipc.Call("status", nil, nil, &st); err != nil {
				return err
			}
			state := "заблокировано"
			if st.Unlocked {
				state = "разблокировано"
			}
			fmt.Printf("хранилище: %s\nсостояние: %s\nсекретов: %d\n", st.StoreDir, state, st.SecretCount)
			if st.LocksAt != nil {
				fmt.Printf("авто-блокировка: %s\n", st.LocksAt.Local().Format("15:04:05"))
			}
			if st.PendingRequests > 0 {
				fmt.Printf("⚠ запросов от агентов: %d — rutile requests\n", st.PendingRequests)
			}
			return nil
		},
	}
}

func cmdGit() *cobra.Command {
	return &cobra.Command{
		Use:                "git [args...]",
		Short:              "Выполнить git-команду в каталоге хранилища",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			return gitsync.Passthrough(paths.Dir(), args)
		},
	}
}
