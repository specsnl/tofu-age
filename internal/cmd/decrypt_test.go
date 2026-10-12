package cmd_test

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
)

const envIdentity = "TOFU_AGE_IDENTITY"

// keyFile is what age-keygen writes, and so what a secrets manager hands over:
// comments around the one private key.
func keyFile(identity, recipient fmt.Stringer) string {
	return fmt.Sprintf("# created: 2026-10-12T00:00:00Z\n# public key: %s\n%s\n", recipient, identity)
}

// decryptPayload runs `tofu-age decrypt` on ciphertext and returns the
// plaintext from its output. The caller sets TOFU_AGE_IDENTITY.
func decryptPayload(t *testing.T, ciphertext []byte) []byte {
	t.Helper()

	stdout, stderr, err := runWithInput(t, inputFor(t, ciphertext), "decrypt")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if stderr != "" {
		t.Errorf("stderr = %q, want nothing", stderr)
	}

	return outputOf(t, stdout)
}

func TestRoundTrip(t *testing.T) {
	classic, pq := newIdentity(t), newHybridIdentity(t)
	ed, rsaKey := newSSHKey(t, "ed25519", ""), newSSHKey(t, "rsa", "")

	// age encrypts in 64 KiB chunks, so the large payload spans several.
	large := bytes.Repeat([]byte("0123456789abcdef"), 20_000)

	for _, keys := range []struct {
		name       string
		recipients string
		identity   string
	}{
		{"classic", recipientsFile(t, classic.Recipient()), keyFile(classic, classic.Recipient())},
		{"post-quantum", recipientsFile(t, pq.Recipient()), keyFile(pq, pq.Recipient())},
		{"SSH ed25519", recipientsFile(t, ed), ed.private},
		{"SSH RSA", recipientsFile(t, rsaKey), rsaKey.private},
	} {
		for _, tc := range []struct {
			name    string
			payload []byte
		}{
			{"empty", []byte{}},
			{"state", []byte(`{"version":4,"resources":[]}`)},
			{"binary", []byte{0x00, 0xff, 0x0a, 0x0d, 0x22}},
			{"several chunks", large},
		} {
			t.Run(keys.name+"/"+tc.name, func(t *testing.T) {
				t.Setenv(envIdentity, keys.identity)

				ciphertext := encryptPayload(t, keys.recipients, tc.payload)

				if got := decryptPayload(t, ciphertext); !bytes.Equal(got, tc.payload) {
					t.Errorf("round trip = %d bytes, want the %d bytes put in", len(got), len(tc.payload))
				}
			})
		}
	}
}

func TestDecrypt_AnyOneRecipient(t *testing.T) {
	ids := []*age.X25519Identity{newIdentity(t), newIdentity(t), newIdentity(t)}
	plaintext := []byte("shared state")
	ciphertext := encryptPayload(t, recipientsFile(t, ids[0].Recipient(), ids[1].Recipient(), ids[2].Recipient()), plaintext)

	for i, id := range ids {
		t.Setenv(envIdentity, keyFile(id, id.Recipient()))

		if got := decryptPayload(t, ciphertext); !bytes.Equal(got, plaintext) {
			t.Errorf("identity %d: plaintext = %q, want %q", i, got, plaintext)
		}
	}
}

// TOFU_AGE_IDENTITY may hold several identities; one matching is enough.
func TestDecrypt_AnyOneIdentity(t *testing.T) {
	id := newIdentity(t)
	plaintext := []byte("state")
	ciphertext := encryptPayload(t, recipientsFile(t, id.Recipient()), plaintext)

	other := newIdentity(t)
	t.Setenv(envIdentity, keyFile(other, other.Recipient())+keyFile(id, id.Recipient()))

	if got := decryptPayload(t, ciphertext); !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext = %q, want %q", got, plaintext)
	}
}

// While a team switches to post-quantum keys, state written before and after
// the switch coexists. Holding both identities reads both.
func TestDecrypt_ClassicAndPostQuantumSideBySide(t *testing.T) {
	classic, pq := newIdentity(t), newHybridIdentity(t)
	t.Setenv(envIdentity, keyFile(classic, classic.Recipient())+keyFile(pq, pq.Recipient()))

	for name, recipients := range map[string]string{
		"classic":      recipientsFile(t, classic.Recipient()),
		"post-quantum": recipientsFile(t, pq.Recipient()),
	} {
		plaintext := []byte(name + " state")

		if got := decryptPayload(t, encryptPayload(t, recipients, plaintext)); !bytes.Equal(got, plaintext) {
			t.Errorf("%s: plaintext = %q, want %q", name, got, plaintext)
		}
	}
}

func TestDecrypt_RejectsTheIdentity(t *testing.T) {
	id := newIdentity(t)
	ciphertext := encryptPayload(t, recipientsFile(t, id.Recipient()), []byte("state"))
	wrong := newIdentity(t)

	for _, tc := range []struct {
		name     string
		identity string
		want     string
	}{
		{"unset", "", envIdentity + " is unset or empty"},
		{"empty", "", envIdentity + " is unset or empty"},
		{"comments only", "# created: 2026-10-12T00:00:00Z\n", "no identities found"},
		{"malformed", "AGE-SECRET-KEY-1NOTAKEY\n", "parse " + envIdentity},
		{"a recipient instead of an identity", id.Recipient().String() + "\n", "unknown identity type"},
		{"a plugin identity", "AGE-PLUGIN-YUBIKEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQ\n", "unknown identity type"},
		{"the wrong identity", keyFile(wrong, wrong.Recipient()), "did not match any of the recipients"},
		{"a post-quantum identity for a classic file", newHybridIdentity(t).String() + "\n", "did not match any of the recipients"},
		{"the wrong SSH key", newSSHKey(t, "ed25519", "").private, "did not match any of the recipients"},
		{"a malformed SSH key", "-----BEGIN OPENSSH PRIVATE KEY-----\nnotakey\n-----END OPENSSH PRIVATE KEY-----\n", "as an SSH private key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv first, so the variable is restored after the test.
			t.Setenv(envIdentity, tc.identity)

			if tc.name == "unset" {
				if err := os.Unsetenv(envIdentity); err != nil {
					t.Fatalf("unset %s: %v", envIdentity, err)
				}
			}

			stdout, stderr, err := runWithInput(t, inputFor(t, ciphertext), "decrypt")
			if err == nil {
				t.Fatal("want an error, got none")
			}

			if !strings.HasPrefix(err.Error(), "decrypt: ") || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name the command and say %q", err, tc.want)
			}

			if tc.identity != "" && strings.Contains(err.Error(), strings.TrimSpace(tc.identity)) {
				t.Errorf("error = %q, want it not to repeat %s", err, envIdentity)
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

// The public half of an SSH key does not tell whether the private half has a
// passphrase, so encrypt cannot refuse a protected key. decrypt refuses it, and
// says which key it is.
func TestDecrypt_RefusesAPassphraseProtectedSSHKey(t *testing.T) {
	key := newSSHKey(t, "ed25519", "correct horse battery staple")
	ciphertext := encryptPayload(t, recipientsFile(t, key), []byte("state"))

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key.public))
	if err != nil {
		t.Fatalf("parse the SSH public key: %v", err)
	}

	t.Setenv(envIdentity, key.private)

	stdout, stderr, err := runWithInput(t, inputFor(t, ciphertext), "decrypt")
	if err == nil {
		t.Fatal("want an error, got none")
	}

	for _, want := range []string{"decrypt: ", "protected by a passphrase", ssh.FingerprintSHA256(pub)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to say %q", err, want)
		}
	}

	if stdout != header {
		t.Errorf("stdout = %q, want only the header", stdout)
	}

	if stderr != "" {
		t.Errorf("stderr = %q, want nothing; main owns the single print", stderr)
	}
}

func TestDecrypt_RejectsADamagedCiphertext(t *testing.T) {
	id := newIdentity(t)
	t.Setenv(envIdentity, keyFile(id, id.Recipient()))

	// Two full chunks and a bit, so a cut can fall exactly between chunks.
	const chunk = 64 * 1024

	ciphertext := encryptPayload(t, recipientsFile(t, id.Recipient()), bytes.Repeat([]byte("s"), 2*chunk+100))

	// The payload starts after the header's closing "--- <mac>" line and a
	// 16-byte nonce; each chunk carries a 16-byte tag.
	mac := bytes.Index(ciphertext, []byte("\n--- "))
	if mac < 0 {
		t.Fatalf("ciphertext has no header MAC line: %q", ciphertext[:min(len(ciphertext), 200)])
	}

	payloadStart := mac + 1 + bytes.IndexByte(ciphertext[mac+1:], '\n') + 1 + 16

	flip := func(i int) []byte {
		c := bytes.Clone(ciphertext)
		c[i] ^= 0x01

		return c
	}

	for _, tc := range []struct {
		name       string
		ciphertext []byte
	}{
		{"empty", []byte{}},
		{"not age", []byte("plaintext state")},
		{"cut inside the header", ciphertext[:mac]},
		{"cut after the header", ciphertext[:payloadStart]},
		{"cut between chunks", ciphertext[:payloadStart+chunk+16]},
		{"missing its last byte", ciphertext[:len(ciphertext)-1]},
		{"a tampered header", flip(len("age-encryption.org/v1\n-> X25519 "))},
		{"a tampered nonce", flip(payloadStart - 1)},
		{"a tampered first chunk", flip(payloadStart)},
		{"a tampered last tag", flip(len(ciphertext) - 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, err := runWithInput(t, inputFor(t, tc.ciphertext), "decrypt")
			if err == nil {
				t.Fatal("want an error, got none")
			}

			if !strings.HasPrefix(err.Error(), "decrypt: ") {
				t.Errorf("error = %q, want it to name the command", err)
			}

			if stdout != header {
				t.Errorf("stdout = %q, want only the header: nothing of the plaintext may leak", stdout)
			}

			if stderr != "" {
				t.Errorf("stderr = %q, want nothing; main owns the single print", stderr)
			}
		})
	}
}
