package credentials

import "testing"

func TestCredentials(t *testing.T) {
	t.Run("New", func(t *testing.T) {
		creds := NewProvider("a", "b", "c")

		val, err := creds.Retrieve()
		if err != nil {
			t.Fatalf("Unable to retrieve credentials: %v", err)
		}
		if val.AccessKeyID != "a" {
			t.Fatalf("Incorrect access key: %v", val.AccessKeyID)
		}
	})

	t.Run("Expired", func(t *testing.T) {
		creds := NewProvider("a", "b", "c")

		if creds.IsExpired() != false {
			t.Fatalf("Credentials should never expire")
		}
	})
}

func TestSessionFromCredentialsProvider(t *testing.T) {
	t.Run("Happy Path", func(t *testing.T) {
		creds := NewProvider("a", "b", "c")
		sess := SessionFromCredentialsProvider(creds)

		if sess == nil {
			t.Fatalf("Unable to create session")
		}
	})
}
