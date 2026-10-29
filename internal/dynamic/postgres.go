package dynamic

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
)

var identifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)

type Postgres struct {
	URL    string
	Prefix string
	Run    func(context.Context, string, ...string) error
}
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (p *Postgres) Issue(ctx context.Context, leaseID string) (Credential, error) {
	if p.URL == "" && p.Run == nil {
		return Credential{}, errors.New("postgres provider is not configured")
	}
	prefix := p.Prefix
	if prefix == "" {
		prefix = "ds"
	}
	username := fmt.Sprintf("%s_%s", prefix, leaseID[:12])
	if !identifier.MatchString(username) {
		return Credential{}, errors.New("generated role name is invalid")
	}
	password, err := randomPassword()
	if err != nil {
		return Credential{}, err
	}
	err = p.execute(ctx, fmt.Sprintf(`CREATE ROLE "%s" LOGIN PASSWORD '%s'`, username, password))
	return Credential{Username: username, Password: password}, err
}
func (p *Postgres) Revoke(ctx context.Context, username string) error {
	if !identifier.MatchString(username) {
		return errors.New("invalid role name")
	}
	return p.execute(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS "%s"`, username))
}
func (p *Postgres) Rotate(ctx context.Context, username, password string) error {
	if !identifier.MatchString(username) {
		return errors.New("invalid role name")
	}
	return p.execute(ctx, fmt.Sprintf(`ALTER ROLE "%s" PASSWORD '%s'`, username, password))
}
func (p *Postgres) execute(ctx context.Context, statement string) error {
	if p.Run != nil {
		return p.Run(ctx, statement)
	}
	command := exec.CommandContext(ctx, "psql", p.URL, "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--command", statement)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("psql: %w: %s", err, output)
	}
	return nil
}
func randomPassword() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
