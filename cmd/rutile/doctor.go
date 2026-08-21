package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Lercas/rutile/internal/ageio"
	"github.com/Lercas/rutile/internal/audit"
	"github.com/Lercas/rutile/internal/ipc"
	"github.com/Lercas/rutile/internal/paths"
	"github.com/Lercas/rutile/internal/protocol"
)

func validateSecurePath(path string, wantMode os.FileMode, wantDir bool) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symbolic link is not allowed")
	}
	if wantDir {
		if !st.IsDir() {
			return fmt.Errorf("not a directory")
		}
	} else if !st.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	if st.Mode().Perm() != wantMode.Perm() {
		return fmt.Errorf("mode is %03o, want %03o", st.Mode().Perm(), wantMode.Perm())
	}
	return nil
}

func cmdDoctor() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Проверить здоровье установки / check installation health",
		RunE: func(cmd *cobra.Command, args []string) error {
			bad := 0
			ok := func(f string, a ...any) { fmt.Printf("  ✓ "+f+"\n", a...) }
			warn := func(f string, a ...any) { fmt.Printf("  ⚠ "+f+"\n", a...) }
			fail := func(f string, a ...any) { fmt.Printf("  ✗ "+f+"\n", a...); bad++ }

			fmt.Println("rutile doctor")

			if !paths.Initialized() {
				fail("хранилище не создано — rutile init")
				return fmt.Errorf("%d problem(s)", bad)
			}
			ok("хранилище: %s", paths.Dir())

			// Required filesystem boundary and key metadata.
			for _, check := range []struct {
				label   string
				path    string
				mode    os.FileMode
				wantDir bool
			}{
				{label: "каталог хранилища", path: paths.Dir(), mode: 0o700, wantDir: true},
				{label: "каталог секретов", path: paths.StoreDir(), mode: 0o700, wantDir: true},
				{label: "каталог агентов", path: paths.AgentsDir(), mode: 0o700, wantDir: true},
				{label: "identities.age", path: paths.IdentityFile(), mode: 0o600},
				{label: "recipients.txt", path: paths.RecipientsFile(), mode: 0o600},
			} {
				if err := validateSecurePath(check.path, check.mode, check.wantDir); err != nil {
					fail("%s (%s): %v", check.label, check.path, err)
				} else {
					ok("%s: %03o", check.label, check.mode)
				}
			}
			backups, err := filepath.Glob(paths.IdentityFile() + ".bak*")
			if err != nil {
				fail("не удалось перечислить recovery-копии identity: %v", err)
			}
			for _, backup := range backups {
				if modeErr := validateSecurePath(backup, 0o600, false); modeErr != nil {
					fail("recovery-копия %s небезопасна: %v", backup, modeErr)
				} else {
					warn("осталась recovery-копия %s после rotate — проверьте store и удалите её осознанно", backup)
				}
			}
			if recs, err := ageio.LoadRecipients(paths.RecipientsFile()); err != nil {
				fail("recipients.txt повреждён: %v", err)
			} else if len(recs) > 1 {
				fail("ротация не завершена: recipients.txt содержит %d ключа; исправьте причину сбоя и повторите rutile rotate", len(recs))
			} else if len(recs) != 1 {
				fail("recipients.txt не содержит активный ключ")
			}

			// daemon
			var st protocol.StatusResult
			if err := ipc.Call("status", nil, nil, &st); err != nil {
				fail("демон недоступен: %v", err)
			} else {
				state := "заблокировано (locked)"
				if st.Unlocked {
					state = "разблокировано (unlocked)"
				}
				ok("демон отвечает; %s; секретов: %d", state, st.SecretCount)
				if st.PendingRequests > 0 {
					warn("ожидают решения %d запросов агентов — rutile requests", st.PendingRequests)
				}
			}
			if sst, err := os.Lstat(paths.SocketPath()); err != nil {
				fail("socket %s недоступен: %v", paths.SocketPath(), err)
			} else if sst.Mode()&os.ModeSocket == 0 {
				fail("путь socket %s не является Unix socket", paths.SocketPath())
			} else {
				mode := sst.Mode().Perm()
				if mode != 0o600 && mode != 0o660 {
					fail("права сокета: %o — допустимы 600 или 660 в system mode", mode)
				} else if mode == 0o660 {
					ok("права сокета: 660 (system mode)")
				} else {
					ok("права сокета: 600")
				}
			}

			// audit chain
			if n, err := audit.Verify(paths.AuditFile()); err != nil {
				fail("audit-цепочка повреждена: %v", err)
			} else {
				ok("audit-цепочка целостна: %d записей", n)
			}

			// git
			if _, err := exec.LookPath("git"); err != nil {
				warn("git не найден — версионирование хранилища отключено")
			} else if _, err := os.Stat(paths.Dir() + "/.git"); err != nil {
				warn("хранилище не под git — история изменений не ведётся")
			} else {
				ok("git-версионирование активно")
			}

			if bad > 0 {
				return fmt.Errorf("проблем: %d", bad)
			}
			fmt.Println("всё в порядке / all good")
			return nil
		},
	}
}
