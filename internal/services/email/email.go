package email

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/synnfluxx/TrustMeBroID/internal/config"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
)

const emailTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Код подтверждения AuraLift</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f7; color: #51545e; margin: 0; padding: 0; }
        .wrapper { width: 100%; table-layout: fixed; background-color: #f4f4f7; padding: 40px 0; }
        .card { max-width: 570px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); padding: 40px; }
        h1 { color: #333333; font-size: 24px; font-weight: bold; margin-top: 0; text-align: left; }
        p { font-size: 16px; line-height: 1.5; color: #51545e; }
        .footer { margin-top: 30px; border-top: 1px solid #e8e8f0; padding-top: 20px; font-size: 14px; color: #a8a9ad; }
    </style>
</head>
<body>
    <!-- Скрытый текст предпросмотра (Preheader) -->
    <div style="display:none; max-height:0px; overflow:hidden;">
        Ваш код подтверждения AuraLift: {{.VerificationCode}}
    </div>

    <div class="wrapper">
        <div class="card">
            <h1>Здравствуйте, {{.Name}}!</h1>
            <p>Спасибо за регистрацию в <strong>AuraLift</strong>. Мы рады, что вы с нами!</p>
            <p>Чтобы подтвердить адрес электронной почты, введите этот код подтверждения в приложении:</p>

            <!-- Таблица, а не div: Outlook не поддерживает отступы на блоках.
                 Стили инлайновые, потому что часть клиентов вырезает <style>. -->
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin: 32px 0;">
                <tr>
                    <td align="center" style="background-color: #f6f3ff; border: 1px solid #e3d9ff; border-radius: 8px; padding: 28px 20px;">
                        <div style="font-family: Arial, sans-serif; font-size: 13px; color: #8b8b96; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 12px;">
                            Код подтверждения
                        </div>
                        <div style="font-family: 'Courier New', Courier, monospace; font-size: 38px; font-weight: bold; color: #7c3aed; letter-spacing: 10px; line-height: 1.1;">
                            {{.VerificationCode}}
                        </div>
                    </td>
                </tr>
            </table>

            <p><em>Код действует 15 минут и может быть использован один раз.</em></p>
            <p>Если вы не регистрировались в AuraLift, просто проигнорируйте это письмо — без кода никто не получит доступ к аккаунту.</p>

            <div class="footer">
                С уважением,<br>
                <strong>Команда AuraLift</strong><br>
                <small>support@auralift.com</small>
            </div>
        </div>
    </div>
</body>
</html>
`

type EmailData struct {
	Name             string
	VerificationCode string
}

type EmailService struct {
	Log        *slog.Logger
	SMTPConfig *config.SMTPConfig
}

func NewEmailService(log *slog.Logger, smtpConfig *config.SMTPConfig) *EmailService {
	return &EmailService{
		Log:        log,
		SMTPConfig: smtpConfig,
	}
}

func (e *EmailService) SendVerificationEmail(to, verificationCode string) error {
	const op = "email.SendVerificationEmail"
	start := time.Now()

	addr := net.JoinHostPort(e.SMTPConfig.Host, strconv.Itoa(e.SMTPConfig.Port))
	log := e.Log.With(
		slog.String(logger.KeyOp, op),
		sl.Email(to),
		slog.String("smtp_addr", addr),
		sl.Email2("smtp_from", e.SMTPConfig.Username),
	)

	if e.SMTPConfig.Host == "" || e.SMTPConfig.Port == 0 {
		err := fmt.Errorf("smtp is not configured: host=%q port=%d", e.SMTPConfig.Host, e.SMTPConfig.Port)
		log.Error("cannot send verification email: smtp is not configured",
			slog.String("remedy", "set smtp.host and smtp.port in the service config"),
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return err
	}

	data := EmailData{
		Name:             to,
		VerificationCode: verificationCode,
	}

	tmpl, err := template.New("emailTemplate").Parse(emailTemplate)
	if err != nil {
		log.Error("cannot send verification email: template does not parse",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return err
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		log.Error("cannot send verification email: template does not render",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return err
	}

	header := make(map[string]string)
	header["From"] = e.SMTPConfig.Username
	header["To"] = to
	header["Subject"] = "Добро пожаловать в AuraLifting! Подтвердите ваш email"
	header["MIME-Version"] = "1.0"
	header["Content-Type"] = `text/html; charset="UTF-8"`

	var msg bytes.Buffer
	for k, v := range header {
		fmt.Fprintf(&msg, "%s: %s\r\n", k, v)
	}
	msg.WriteString("\r\n")
	msg.Write(body.Bytes())

	log.Debug("sending verification email",
		sl.Token("verification", verificationCode),
		slog.Int("message_bytes", msg.Len()))

	var auth smtp.Auth
	if !e.SMTPConfig.NoAuth {
		auth = smtp.PlainAuth("", e.SMTPConfig.Username, e.SMTPConfig.Password, e.SMTPConfig.Host)
	}

	if err := smtp.SendMail(addr, auth, e.SMTPConfig.Username, []string{to}, msg.Bytes()); err != nil {
		// net/smtp errors are terse and the usual causes are configuration, not code.
		log.Error("verification email was not delivered to the smtp server",
			slog.String("likely_cause", smtpFailureHint(e.SMTPConfig.Port, err)),
			slog.String(logger.KeyOutcome, logger.OutcomeFailed),
			sl.Err(err), sl.Since(start))
		return err
	}

	// Handover to the relay only.
	log.Info("verification email handed to the smtp server",
		sl.Token("verification", verificationCode),
		slog.String(logger.KeyOutcome, logger.OutcomeSuccess),
		sl.Since(start))
	return nil
}

// smtpFailureHint maps the common net/smtp failures onto their usual cause.
func smtpFailureHint(port int, err error) string {
	text := strings.ToLower(err.Error())

	switch {
	case strings.Contains(text, "unencrypted connection"):
		return "the server did not offer STARTTLS; net/smtp refuses to send a password in the clear"
	case port == 465:
		return "port 465 expects implicit TLS, which net/smtp does not speak; use 587 with STARTTLS"
	case strings.Contains(text, "authentication failed"), strings.Contains(text, "535"):
		return "SMTP_USERNAME or SMTP_PASSWORD rejected by the server"
	case strings.Contains(text, "no such host"):
		return "smtp.host does not resolve from inside the container"
	case strings.Contains(text, "connection refused"), strings.Contains(text, "i/o timeout"):
		return "smtp host or port unreachable from this network"
	case strings.Contains(text, "550"), strings.Contains(text, "553"):
		return "the relay rejected the sender or the recipient address"
	default:
		return "unclassified smtp failure"
	}
}
