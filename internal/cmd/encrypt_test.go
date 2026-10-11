package cmd_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate an identity: %v", err)
	}

	return id
}

func newHybridIdentity(t *testing.T) *age.HybridIdentity {
	t.Helper()

	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatalf("generate a post-quantum identity: %v", err)
	}

	return id
}

// sshKey is an SSH keypair as ssh-keygen writes it. As a fmt.Stringer it is
// its public half, the line that goes into a recipients file.
type sshKey struct {
	public  string
	private string
}

func (k sshKey) String() string { return k.public }

// newSSHKey generates an "ed25519" or "rsa" SSH key, protected by passphrase
// unless that is empty.
func newSSHKey(t *testing.T, kind, passphrase string) sshKey {
	t.Helper()

	var (
		key crypto.Signer
		err error
	)

	switch kind {
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		t.Fatalf("unknown SSH key kind %q", kind)
	}

	if err != nil {
		t.Fatalf("generate an %s SSH key: %v", kind, err)
	}

	pub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		t.Fatalf("encode the %s SSH public key: %v", kind, err)
	}

	const comment = "dev@laptop"

	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(key, comment)
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, comment, []byte(passphrase))
	}

	if err != nil {
		t.Fatalf("encode the %s SSH private key: %v", kind, err)
	}

	return sshKey{
		public:  strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + comment,
		private: string(pem.EncodeToMemory(block)),
	}
}

func (k sshKey) identity(t *testing.T) age.Identity {
	t.Helper()

	id, err := agessh.ParseIdentity([]byte(k.private))
	if err != nil {
		t.Fatalf("parse the SSH private key: %v", err)
	}

	return id
}

// writeFile writes content to a file in a fresh temporary directory and
// returns its path.
func writeFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "age-recipients.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}

	return path
}

// recipientsFile writes a recipients file the way the design lays one out: a
// comment naming each key's holder, and blank lines between them.
func recipientsFile(t *testing.T, recipients ...fmt.Stringer) string {
	t.Helper()

	var content strings.Builder
	for i, r := range recipients {
		fmt.Fprintf(&content, "# holder %d\n%s\n\n", i, r)
	}

	return writeFile(t, content.String())
}

// encryptPayload runs `tofu-age encrypt` on payload and returns the
// ciphertext from its output.
func encryptPayload(t *testing.T, recipients string, payload []byte) []byte {
	t.Helper()

	stdout, stderr, err := runWithInput(t, inputFor(t, payload), "encrypt", recipients)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if stderr != "" {
		t.Errorf("stderr = %q, want nothing", stderr)
	}

	return outputOf(t, stdout)
}

// The ciphertext is checked with age itself rather than with `tofu-age
// decrypt`, so a fault shared by both commands cannot hide here.
func TestEncrypt_EveryRecipientCanDecrypt(t *testing.T) {
	c1, c2, c3 := newIdentity(t), newIdentity(t), newIdentity(t)
	pq1, pq2 := newHybridIdentity(t), newHybridIdentity(t)
	ed, rsaKey := newSSHKey(t, "ed25519", ""), newSSHKey(t, "rsa", "")
	plaintext := []byte(`{"version":4,"resources":[]}`)

	for _, tc := range []struct {
		name       string
		recipients string
		ids        []age.Identity
		outsider   age.Identity
	}{
		{"classic", recipientsFile(t, c1.Recipient(), c2.Recipient(), c3.Recipient()), []age.Identity{c1, c2, c3}, newIdentity(t)},
		{"post-quantum", recipientsFile(t, pq1.Recipient(), pq2.Recipient()), []age.Identity{pq1, pq2}, newHybridIdentity(t)},
		{"SSH beside classic", recipientsFile(t, ed, rsaKey, c1.Recipient()), []age.Identity{ed.identity(t), rsaKey.identity(t), c1}, newSSHKey(t, "ed25519", "").identity(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext := encryptPayload(t, tc.recipients, plaintext)

			if !bytes.HasPrefix(ciphertext, []byte("age-encryption.org/v1\n")) {
				t.Fatalf("ciphertext = %q, want an age file", ciphertext)
			}

			for i, id := range tc.ids {
				r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
				if err != nil {
					t.Fatalf("identity %d: %v", i, err)
				}

				got, err := io.ReadAll(r)
				if err != nil {
					t.Fatalf("identity %d: read: %v", i, err)
				}

				if !bytes.Equal(got, plaintext) {
					t.Errorf("identity %d: plaintext = %q, want %q", i, got, plaintext)
				}
			}

			if _, err := age.Decrypt(bytes.NewReader(ciphertext), tc.outsider); err == nil {
				t.Error("an identity outside the recipients file decrypted the payload")
			}
		})
	}
}

// age draws a fresh file key on every write, so the same state never encrypts
// to the same bytes twice.
func TestEncrypt_FreshKeyPerWrite(t *testing.T) {
	recipients := recipientsFile(t, newIdentity(t).Recipient())
	plaintext := []byte("the same state")

	if bytes.Equal(encryptPayload(t, recipients, plaintext), encryptPayload(t, recipients, plaintext)) {
		t.Error("two writes of the same payload produced the same ciphertext")
	}
}

func TestEncrypt_RejectsTheRecipientsFile(t *testing.T) {
	secret := newIdentity(t).String()
	mixed := recipientsFile(t, newIdentity(t).Recipient(), newHybridIdentity(t).Recipient())
	mixedSSH := recipientsFile(t, newSSHKey(t, "ed25519", ""), newHybridIdentity(t).Recipient())

	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{"missing", filepath.Join(t.TempDir(), "absent.txt"), "no such file"},
		{"unreadable", t.TempDir(), "is a directory"},
		{"empty", writeFile(t, ""), "no recipients found"},
		{"comments only", writeFile(t, "# alice (laptop)\n\n# bob\n"), "no recipients found"},
		{"malformed", writeFile(t, "age1notakey\n"), "line 1"},
		{"an identity instead of a recipient", writeFile(t, "# oops\n"+secret+"\n"), "unknown recipient type"},
		{"classic and post-quantum mixed", mixed, "can't mix post-quantum and classic recipients"},
		{"SSH and post-quantum mixed", mixedSSH, "can't mix post-quantum and classic recipients"},
		{"a malformed SSH key", writeFile(t, "ssh-ed25519 AAAAnotakey dev@laptop\n"), "malformed SSH recipient"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, err := runWithInput(t, inputFor(t, []byte("state")), "encrypt", tc.path)
			if err == nil {
				t.Fatal("want an error, got none")
			}

			if !strings.HasPrefix(err.Error(), "encrypt: ") || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name the command and say %q", err, tc.want)
			}

			if strings.Contains(err.Error(), secret) {
				t.Errorf("error = %q, want it not to repeat the private key", err)
			}

			if stdout != header {
				t.Errorf("stdout = %q, want only the header", stdout)
			}

			if stderr != "" {
				t.Errorf("stderr = %q, want nothing; main owns the single print", stderr)
			}
		})
	}
}
