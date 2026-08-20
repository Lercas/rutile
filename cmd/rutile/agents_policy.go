package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lercas/rutile/internal/audit"
	"github.com/Lercas/rutile/internal/ipc"
	"github.com/Lercas/rutile/internal/paths"
	"github.com/Lercas/rutile/internal/protocol"
)

func cmdAgent() *cobra.Command {
	c := &cobra.Command{
		Use:   "agent",
		Short: "Управление AI-агентами (регистрация, список, отзыв)",
	}

	var desc, atype, expires string
	var localOnly bool
	add := &cobra.Command{
		Use:   "add <name>",
		Short: "Зарегистрировать агента и получить готовую команду подключения",
		Example: `  rutile agent add claude --type claude-code
  rutile agent add ci-runner --type ci --expires 30d --local-only`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			var res protocol.AgentAddResult
			p := protocol.AgentAddParams{Name: args[0], Description: desc, Type: atype, Expires: expires, LocalOnly: localOnly}
			if err := ipc.Call("agent_add", nil, p, &res); err != nil {
				return err
			}
			self, _ := os.Executable()
			fmt.Printf(`Агент %q зарегистрирован.

Токен (показывается ОДИН раз, сохраните его):
  %s

Подключение к Claude Code — выполните:
  claude mcp add %s -e RUTILE_AGENT=%s -e RUTILE_TOKEN=%s -- %s mcp

Затем разрешите доступ к нужным секретам:
  rutile allow %s "dev/**"
`, res.Name, res.Token, res.Name, res.Name, res.Token, self, res.Name)
			return nil
		},
	}
	add.Flags().StringVarP(&desc, "description", "d", "", "описание агента")
	add.Flags().StringVarP(&atype, "type", "t", "", "тип потребителя: claude-code, cursor, ci, framework, custom…")
	add.Flags().StringVar(&expires, "expires", "", "срок жизни токена: 30d, 12h; пусто — бессрочно")
	add.Flags().BoolVar(&localOnly, "local-only", false, "токен работает только локально (stdio), на HTTP отвергается")

	list := &cobra.Command{
		Use:   "list",
		Short: "Список агентов",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			var res protocol.AgentListResult
			if err := ipc.Call("agent_list", nil, nil, &res); err != nil {
				return err
			}
			if len(res.Agents) == 0 {
				fmt.Println("(нет агентов — rutile agent add <name>)")
				return nil
			}
			for _, a := range res.Agents {
				last := "никогда"
				if a.LastUsedAt != nil {
					last = a.LastUsedAt.Local().Format("2006-01-02 15:04")
				}
				extra := ""
				if a.Type != "" {
					extra += "  type=" + a.Type
				}
				if a.ExpiresAt != nil {
					state := "истекает " + a.ExpiresAt.Local().Format("2006-01-02 15:04")
					if time.Now().After(*a.ExpiresAt) {
						state = "ИСТЁК " + a.ExpiresAt.Local().Format("2006-01-02")
					}
					extra += "  " + state
				}
				if a.LocalOnly {
					extra += "  [local-only]"
				}
				fmt.Printf("%-20s token=%s...  создан=%s  активность=%s%s\n",
					a.Name, a.TokenPrefix, a.CreatedAt.Local().Format("2006-01-02"), last, extra)
			}
			return nil
		},
	}

	revoke := &cobra.Command{
		Use:   "revoke <name>",
		Short: "Отозвать агента (токен и все его правила)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			if err := ipc.Call("agent_revoke", nil, protocol.AgentRevokeParams{Name: args[0]}, nil); err != nil {
				return err
			}
			fmt.Println("агент отозван:", args[0])
			return nil
		},
	}

	c.AddCommand(add, list, revoke)
	return c
}

func cmdAllow() *cobra.Command {
	var forDur string
	var oneTime bool
	c := &cobra.Command{
		Use:   `allow <agent> <pattern>`,
		Short: `Разрешить агенту читать секреты (шаблон: "dev/**")`,
		Example: `  rutile allow claude "dev/**"
  rutile allow claude "prod/db-password" --for 1h
  rutile allow ci "deploy/token" --one-time`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			var res protocol.RuleInfo
			p := protocol.RuleAddParams{Agent: args[0], Pattern: args[1], For: forDur, OneTime: oneTime}
			if err := ipc.Call("rule_add", nil, p, &res); err != nil {
				return err
			}
			extra := ""
			if res.ExpiresAt != nil {
				extra += " до " + res.ExpiresAt.Local().Format("15:04 02.01")
			}
			if res.OneTime {
				extra += " (одноразово)"
			}
			fmt.Printf("разрешено: %s → %q%s\n", res.Agent, res.Pattern, extra)
			return nil
		},
	}
	c.Flags().StringVar(&forDur, "for", "", "срок действия (например 1h, 30m); без флага — бессрочно")
	c.Flags().BoolVar(&oneTime, "one-time", false, "правило сгорает после первого чтения")
	return c
}

func cmdDeny() *cobra.Command {
	return &cobra.Command{
		Use:   "deny <agent> [pattern]",
		Short: "Убрать доступ (без шаблона — все правила агента)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			p := protocol.RuleDelParams{Agent: args[0]}
			if len(args) == 2 {
				p.Pattern = args[1]
			}
			var res protocol.RuleDelResult
			if err := ipc.Call("rule_del", nil, p, &res); err != nil {
				return err
			}
			fmt.Printf("удалено правил: %d\n", res.Removed)
			return nil
		},
	}
}

func cmdPolicy() *cobra.Command {
	return &cobra.Command{
		Use:   "policy",
		Short: "Показать все правила доступа",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			var res protocol.RuleListResult
			if err := ipc.Call("rule_list", nil, nil, &res); err != nil {
				return err
			}
			if len(res.Rules) == 0 {
				fmt.Println("(правил нет — агентам всё запрещено по умолчанию)")
				return nil
			}
			now := time.Now()
			for _, r := range res.Rules {
				state := "активно"
				if r.OneTime && r.Consumed {
					state = "использовано"
				} else if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
					state = "истекло"
				} else if r.ExpiresAt != nil {
					state = "до " + r.ExpiresAt.Local().Format("15:04 02.01")
				}
				flags := ""
				if r.OneTime {
					flags = " [one-time]"
				}
				fmt.Printf("%-20s %-30q %s%s\n", r.Agent, r.Pattern, state, flags)
			}
			return nil
		},
	}
}

// sanitizeTerm strips control characters from agent-supplied strings so a
// hostile agent cannot inject ANSI escape sequences into the human's
// terminal via reasons/notes.
func sanitizeTerm(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '·'
		}
		return r
	}, s)
}

func cmdRequests() *cobra.Command {
	return &cobra.Command{
		Use:   "requests",
		Short: "Запросы доступа от агентов, ждущие вашего решения",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			var res protocol.RequestListResult
			if err := ipc.Call("request_list", nil, nil, &res); err != nil {
				return err
			}
			if len(res.Requests) == 0 {
				fmt.Println("(запросов нет)")
				return nil
			}
			for _, r := range res.Requests {
				reason := ""
				if r.Reason != "" {
					reason = " — " + sanitizeTerm(r.Reason)
				}
				fmt.Printf("%s  %s → %q%s  (%s)\n", r.ID, r.Agent, r.Path, reason, r.CreatedAt.Local().Format("15:04 02.01"))
			}
			fmt.Println("\nrutile approve <id> [--for 1h] [--one-time]  |  rutile reject <id>")
			return nil
		},
	}
}

func cmdApprove() *cobra.Command {
	var forDur string
	var oneTime bool
	c := &cobra.Command{
		Use:   "approve <id>",
		Short: "Одобрить запрос агента (создаёт правило доступа)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			var res protocol.RequestResolveResult
			p := protocol.RequestResolveParams{ID: args[0], Approve: true, For: forDur, OneTime: oneTime}
			if err := ipc.Call("request_resolve", nil, p, &res); err != nil {
				return err
			}
			fmt.Printf("одобрено: %s → %q\n", res.Rule.Agent, res.Rule.Pattern)
			return nil
		},
	}
	c.Flags().StringVar(&forDur, "for", "", "срок действия (например 1h)")
	c.Flags().BoolVar(&oneTime, "one-time", false, "одноразовый доступ")
	return c
}

func cmdReject() *cobra.Command {
	return &cobra.Command{
		Use:   "reject <id>",
		Short: "Отклонить запрос агента",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			var res protocol.RequestResolveResult
			if err := ipc.Call("request_resolve", nil, protocol.RequestResolveParams{ID: args[0]}, &res); err != nil {
				return err
			}
			fmt.Println("отклонено:", res.ID)
			return nil
		},
	}
}

func cmdAudit() *cobra.Command {
	var n int
	c := &cobra.Command{
		Use:   "audit",
		Short: "Журнал доступа (кто, что, когда)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			entries, err := audit.Tail(paths.AuditFile(), n)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				fmt.Println("(журнал пуст)")
				return nil
			}
			for _, e := range entries {
				mark := "✓"
				if e.Result != "granted" {
					mark = "✗"
				}
				path := e.Path
				if path != "" {
					path = " " + path
				}
				reason := ""
				if e.Reason != "" {
					reason = " (" + sanitizeTerm(e.Reason) + ")"
				}
				note := ""
				if e.Note != "" {
					note = " — «" + sanitizeTerm(e.Note) + "»"
				}
				fmt.Printf("%s %s %s/%s %s%s%s%s\n",
					e.TS.Local().Format("2006-01-02 15:04:05"), mark, e.ActorType, e.Actor, e.Action, path, reason, note)
			}
			return nil
		},
	}
	c.Flags().IntVarP(&n, "lines", "n", 30, "сколько последних записей показать")

	verify := &cobra.Command{
		Use:   "verify",
		Short: "Проверить целостность журнала (hash-цепочку)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			count, err := audit.Verify(paths.AuditFile())
			if err != nil {
				return fmt.Errorf("журнал повреждён после записи %d: %w", count, err)
			}
			fmt.Printf("журнал целостен: %d записей\n", count)
			return nil
		},
	}
	rotate := &cobra.Command{
		Use:   "rotate",
		Short: "Архивировать журнал и начать новую цепочку (checkpoint связывает их)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireInit(); err != nil {
				return err
			}
			var res protocol.AuditRotateResult
			if err := ipc.Call("audit_rotate", nil, nil, &res); err != nil {
				return err
			}
			fmt.Printf("архив: %s (%d записей); новая цепочка начата с checkpoint\n", res.Archive, res.Entries)
			return nil
		},
	}
	c.AddCommand(verify, rotate)
	return c
}
