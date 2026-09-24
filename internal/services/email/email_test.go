package email

import (
	"bufio"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/synnfluxx/TrustMeBroID/internal/config"
	discardHandler "github.com/synnfluxx/TrustMeBroID/internal/lib/logger/handlers/discardHandler"
)

// fakeSMTP is a single-connection SMTP server that accepts everything and hands
// back the message it received. It lets the whole send path run without a relay.
func fakeSMTP(t *testing.T) (port int, received <-chan string) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	messages := make(chan string, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)
		say := func(line string) {
			_, _ = writer.WriteString(line + "\r\n")
			_ = writer.Flush()
		}

		say("220 fake ESMTP")

		var body strings.Builder
		inData := false
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if strings.TrimRight(line, "\r\n") == "." {
					inData = false
					say("250 OK")
					messages <- body.String()
					continue
				}
				body.WriteString(line)
				continue
			}

			cmd := strings.ToUpper(strings.TrimRight(line, "\r\n"))
			switch {
			case strings.HasPrefix(cmd, "EHLO"):
				say("250-fake")
				say("250-AUTH PLAIN LOGIN")
				say("250 OK")
			case strings.HasPrefix(cmd, "AUTH"):
				say("235 authenticated")
			case strings.HasPrefix(cmd, "DATA"):
				say("354 send it")
				inData = true
			case strings.HasPrefix(cmd, "QUIT"):
				say("221 bye")
				return
			default:
				say("250 OK")
			}
		}
	}()

	return listener.Addr().(*net.TCPAddr).Port, messages
}

func newService(host string, port int) *EmailService {
	return NewEmailService(discardHandler.NewDiscardLogger(), &config.SMTPConfig{
		Host:     host,
		Port:     port,
		Username: "noreply@auralift.test",
		Password: "pw",
	})
}

func headersOf(message string) map[string]string {
	headers := map[string]string{}
	for _, line := range strings.Split(message, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break
		}
		if key, value, ok := strings.Cut(line, ": "); ok {
			headers[key] = value
		}
	}
	return headers
}

func TestSendVerificationEmail_DeliversAWellFormedMessage(t *testing.T) {
	port, received := fakeSMTP(t)

	err := newService("127.0.0.1", port).
		SendVerificationEmail("user@example.test", "tok-123", "https://app.test")

	require.NoError(t, err)

	message := <-received
	headers := headersOf(message)
	require.Equal(t, "user@example.test", headers["To"])
	require.Equal(t, "noreply@auralift.test", headers["From"])
	require.Equal(t, "1.0", headers["MIME-Version"])
	require.Contains(t, headers["Content-Type"], "text/html")
	require.NotEmpty(t, headers["Subject"])
}

func TestSendVerificationEmail_LinkCarriesTokenAndAddress(t *testing.T) {
	port, received := fakeSMTP(t)

	require.NoError(t, newService("127.0.0.1", port).
		SendVerificationEmail("user@example.test", "tok-123", "https://app.test"))

	message := <-received
	require.Contains(t, message, "https://app.test/auth/verify?token=tok-123&email=user@example.test")
}

// The template renders the address into the body, so a crafted address is
// interpolated into HTML unescaped. text/template is used where html/template
// is required.
func TestSendVerificationEmail_AddressIsNotHTMLEscaped(t *testing.T) {
	port, received := fakeSMTP(t)

	require.NoError(t, newService("127.0.0.1", port).
		SendVerificationEmail(`a<script>alert(1)</script>@example.test`, "tok", "https://app.test"))

	message := <-received
	require.Contains(t, message, "<script>alert(1)</script>",
		"text/template does not escape; switching to html/template would fix this")
}

// RFC 5322 requires a Date header and net/smtp does not add one. Its absence
// costs deliverability with most providers.
func TestSendVerificationEmail_HasNoDateHeader(t *testing.T) {
	port, received := fakeSMTP(t)

	require.NoError(t, newService("127.0.0.1", port).
		SendVerificationEmail("user@example.test", "tok", "https://app.test"))

	_, hasDate := headersOf(<-received)["Date"]
	require.False(t, hasDate, "no Date header is emitted today")
}

// The subject is non-ASCII and is written raw rather than RFC 2047 encoded.
func TestSendVerificationEmail_SubjectIsNotMIMEEncoded(t *testing.T) {
	port, received := fakeSMTP(t)

	require.NoError(t, newService("127.0.0.1", port).
		SendVerificationEmail("user@example.test", "tok", "https://app.test"))

	subject := headersOf(<-received)["Subject"]
	require.NotContains(t, subject, "=?UTF-8?", "subject is sent as raw UTF-8")
}

func TestSendVerificationEmail_RefusesWhenSMTPUnconfigured(t *testing.T) {
	for _, tc := range []struct {
		name string
		host string
		port int
	}{
		{"no host", "", 587},
		{"no port", "smtp.test", 0},
		{"neither", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := newService(tc.host, tc.port).
				SendVerificationEmail("user@example.test", "tok", "https://app.test")

			require.Error(t, err)
			require.Contains(t, err.Error(), "smtp is not configured")
		})
	}
}

func TestSendVerificationEmail_UnreachableRelay(t *testing.T) {
	// Port 1 is reserved and never listening.
	err := newService("127.0.0.1", 1).
		SendVerificationEmail("user@example.test", "tok", "https://app.test")

	require.Error(t, err)
}

// An empty base URL produces a relative link that no mail client can open. The
// send still succeeds, so only the log would reveal it.
func TestSendVerificationEmail_EmptyBaseURLStillSends(t *testing.T) {
	port, received := fakeSMTP(t)

	require.NoError(t, newService("127.0.0.1", port).
		SendVerificationEmail("user@example.test", "tok", ""))

	require.Contains(t, <-received, "/auth/verify?token=tok")
}

func TestSMTPFailureHint(t *testing.T) {
	cases := []struct {
		name string
		port int
		err  error
		want string
	}{
		{"implicit tls port", 465, errors.New("EOF"), "port 465"},
		{"no starttls", 587, errors.New("unencrypted connection"), "STARTTLS"},
		{"bad credentials", 587, errors.New("535 authentication failed"), "SMTP_USERNAME"},
		{"dns", 587, errors.New("dial tcp: lookup smtp: no such host"), "does not resolve"},
		{"refused", 587, errors.New("connection refused"), "unreachable"},
		{"relay rejection", 587, errors.New("550 mailbox unavailable"), "rejected the sender"},
		{"unknown", 587, errors.New("something odd"), "unclassified"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Contains(t, smtpFailureHint(tc.port, tc.err), tc.want)
		})
	}
}
