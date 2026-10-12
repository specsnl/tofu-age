package cmd_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func (k sshKey) publicKey(t *testing.T) ssh.PublicKey {
	t.Helper()

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.public))
	if err != nil {
		t.Fatalf("parse the SSH public key: %v", err)
	}

	return pub
}

// fingerprint is how check names an SSH key.
func (k sshKey) fingerprint(t *testing.T) string {
	t.Helper()

	return k.publicKey(t).Type() + " " + ssh.FingerprintSHA256(k.publicKey(t))
}

// runCheck runs `tofu-age check` with identity in TOFU_AGE_IDENTITY, and fails
// the test if any output repeats it.
func runCheck(t *testing.T, identity, recipients string) (string, error) {
	t.Helper()

	t.Setenv(envIdentity, identity)

	stdout, stderr, err := run(t, "check", recipients)

	if stderr != "" {
		t.Errorf("stderr = %q, want nothing; main owns the single print", stderr)
	}

	if identity == "" {
		return stdout, err
	}

	for line := range strings.SplitSeq(identity, "\n") {
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-----") {
			continue
		}

		if strings.Contains(stdout, line) || (err != nil && strings.Contains(err.Error(), line)) {
			t.Errorf("stdout = %q, error = %v, want neither to repeat %s", stdout, err, envIdentity)
		}
	}

	return stdout, err
}

func TestCheck_PassesForAListedIdentity(t *testing.T) {
	classic, pq := newIdentity(t), newHybridIdentity(t)
	ed, rsaKey := newSSHKey(t, "ed25519", ""), newSSHKey(t, "rsa", "")

	for _, tc := range []struct {
		name       string
		recipients string
		identity   string
		want       string
	}{
		{"classic", recipientsFile(t, newIdentity(t).Recipient(), classic.Recipient()), keyFile(classic, classic.Recipient()), classic.Recipient().String()},
		{"post-quantum", recipientsFile(t, pq.Recipient()), keyFile(pq, pq.Recipient()), pq.Recipient().String()[:32] + "…"},
		{"SSH ed25519", recipientsFile(t, ed, classic.Recipient()), ed.private, ed.fingerprint(t)},
		{"SSH RSA", recipientsFile(t, rsaKey), rsaKey.private, rsaKey.fingerprint(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, err := runCheck(t, tc.identity, tc.recipients)
			if err != nil {
				t.Fatalf("check: %v", err)
			}

			if want := "in " + tc.recipients + ":     " + tc.want + "\n"; stdout != want {
				t.Errorf("stdout = %q, want %q", stdout, want)
			}
		})
	}
}

// While switching to post-quantum keys a developer holds both, and only one is
// listed. That passes, and names the other.
func TestCheck_NamesTheUnlistedIdentities(t *testing.T) {
	classic, pq := newIdentity(t), newHybridIdentity(t)
	recipients := recipientsFile(t, pq.Recipient())

	stdout, err := runCheck(t, keyFile(classic, classic.Recipient())+keyFile(pq, pq.Recipient()), recipients)
	if err != nil {
		t.Fatalf("check: %v", err)
	}

	want := "in " + recipients + ":     " + pq.Recipient().String()[:32] + "…\n" +
		"not in " + recipients + ": " + classic.Recipient().String() + "\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

func TestCheck_FailsWhenNoIdentityIsListed(t *testing.T) {
	c1, c2 := newIdentity(t), newIdentity(t)
	ed := newSSHKey(t, "ed25519", "")
	recipients := recipientsFile(t, newIdentity(t).Recipient(), newSSHKey(t, "ed25519", ""))

	for _, tc := range []struct {
		name     string
		identity string
		want     []string
	}{
		{"age keys", keyFile(c1, c1.Recipient()) + keyFile(c2, c2.Recipient()), []string{c1.Recipient().String(), c2.Recipient().String()}},
		{"an SSH key", ed.private, []string{ed.fingerprint(t)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, err := runCheck(t, tc.identity, recipients)
			if err == nil {
				t.Fatal("want an error, got none")
			}

			for _, want := range append([]string{"check: ", "is in the recipients file " + recipients}, tc.want...) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to say %q", err, want)
				}
			}

			if stdout != "" {
				t.Errorf("stdout = %q, want nothing", stdout)
			}
		})
	}
}

// A protected key fails whatever the recipients file holds, even when there is
// none.
func TestCheck_RefusesAPassphraseProtectedSSHKeyBeforeTheFile(t *testing.T) {
	key := newSSHKey(t, "ed25519", "correct horse battery staple")

	for name, recipients := range map[string]string{
		"listed":  recipientsFile(t, key),
		"no file": filepath.Join(t.TempDir(), "absent.txt"),
	} {
		t.Run(name, func(t *testing.T) {
			stdout, err := runCheck(t, key.private, recipients)
			if err == nil {
				t.Fatal("want an error, got none")
			}

			for _, want := range []string{"check: ", "protected by a passphrase", ssh.FingerprintSHA256(key.publicKey(t))} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to say %q", err, want)
				}
			}

			if stdout != "" {
				t.Errorf("stdout = %q, want nothing", stdout)
			}
		})
	}
}

func TestCheck_RejectsTheIdentity(t *testing.T) {
	id := newIdentity(t)
	recipients := recipientsFile(t, id.Recipient())

	for _, tc := range []struct {
		name     string
		identity string
		want     string
	}{
		{"unset", "", envIdentity + " is unset or empty"},
		{"empty", "", envIdentity + " is unset or empty"},
		{"malformed", "AGE-SECRET-KEY-1NOTAKEY\n", "parse " + envIdentity},
		{"a recipient instead of an identity", id.Recipient().String() + "\n", "unknown identity type"},
		{"a malformed SSH key", "-----BEGIN OPENSSH PRIVATE KEY-----\nnotakey\n-----END OPENSSH PRIVATE KEY-----\n", "as an SSH private key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envIdentity, tc.identity)

			if tc.name == "unset" {
				if err := os.Unsetenv(envIdentity); err != nil {
					t.Fatalf("unset %s: %v", envIdentity, err)
				}
			}

			stdout, _, err := run(t, "check", recipients)
			if err == nil {
				t.Fatal("want an error, got none")
			}

			if !strings.HasPrefix(err.Error(), "check: ") || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name the command and say %q", err, tc.want)
			}

			if stdout != "" {
				t.Errorf("stdout = %q, want nothing", stdout)
			}
		})
	}
}

// check reads the recipients file as encrypt does, so it refuses what encrypt
// refuses.
func TestCheck_RejectsTheRecipientsFile(t *testing.T) {
	id := newIdentity(t)
	identity := keyFile(id, id.Recipient())

	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{"missing", filepath.Join(t.TempDir(), "absent.txt"), "no such file"},
		{"comments only", writeFile(t, "# alice (laptop)\n"), "no recipients found"},
		{"malformed", writeFile(t, "age1notakey\n"), "line 1"},
		{"classic and post-quantum mixed", recipientsFile(t, id.Recipient(), newHybridIdentity(t).Recipient()), "can't mix post-quantum and classic recipients"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, err := runCheck(t, identity, tc.path)
			if err == nil {
				t.Fatal("want an error, got none")
			}

			if !strings.HasPrefix(err.Error(), "check: ") || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name the command and say %q", err, tc.want)
			}

			if stdout != "" {
				t.Errorf("stdout = %q, want nothing", stdout)
			}
		})
	}
}
