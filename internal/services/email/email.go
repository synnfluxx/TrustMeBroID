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
    <title>Добро пожаловать в AuraLift!</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f7; color: #51545e; margin: 0; padding: 0; }
        .wrapper { width: 100%; table-layout: fixed; background-color: #f4f4f7; padding: 40px 0; }
        .card { max-width: 570px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); padding: 40px; }
        h1 { color: #333333; font-size: 24px; font-weight: bold; margin-top: 0; text-align: left; }
        p { font-size: 16px; line-height: 1.5; color: #51545e; }
        .btn-container { text-align: center; margin: 30px 0; }
        .btn { background-color: #7c3aed; color: #ffffff !important; display: inline-block; padding: 12px 30px; font-size: 16px; font-weight: bold; text-decoration: none; border-radius: 6px; }
        .footer { margin-top: 30px; border-top: 1px solid #e8e8f0; padding-top: 20px; font-size: 14px; color: #a8a9ad; }
        .link { color: #7c3aed; word-break: break-all; }
    </style>
</head>
<body>
    <!-- Скрытый текст предпросмотра (Preheader) -->
    <div style="display:none; max-height:0px; overflow:hidden;">
        Остался всего один шаг, чтобы активировать ваш аккаунт AuraLift.
    </div>

    <div class="wrapper">
        <div class="card">
            <h1>Здравствуйте, {{.Name}}!</h1>
            <p>Спасибо за регистрацию в <strong>AuraLift</strong>. Мы рады, что вы с нами!</p>
            <p>Чтобы активировать ваш аккаунт и получить доступ ко всем возможностям платформы, пожалуйста, подтвердите ваш адрес электронной почты.</p>
            
            <div class="btn-container">
                <a href="{{.VerificationURL}}" class="btn" target="_blank">Подтвердить email</a>
            </div>
            
            <p>Если кнопка выше не работает, скопируйте эту ссылку и вставьте её в адресную строку браузера:</p>
            <p><a href="{{.VerificationURL}}" class="link">{{.VerificationURL}}</a></p>
            
            <p><em>Ссылка действительна в течение 24 часов.</em></p>
            <p>Если вы не регистрировались на нашем сайте, просто проигнорируйте это письмо.</p>
            
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
	Name            string
	VerificationURL string
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

func (e *EmailService) SendVerificationEmail(to, verificationToken, URL string) error {
	const op = "email.SendVerificationEmail"
	start := time.Now()

	addr := net.JoinHostPort(e.SMTPConfig.Host, strconv.Itoa(e.SMTPConfig.Port))
	log := e.Log.With(
		slog.String(logger.KeyOp, op),
		sl.Email(to),
		slog.String("smtp_addr", addr),
		sl.Email2("smtp_from", e.SMTPConfig.Username),
	)

	// Config problems here surface from net/smtp as a bare "dial tcp :0:
	// connect: connection refused", which does not say that the cause is an
	// empty config block. Name it up front instead.
	if e.SMTPConfig.Host == "" || e.SMTPConfig.Port == 0 {
		err := fmt.Errorf("smtp is not configured: host=%q port=%d", e.SMTPConfig.Host, e.SMTPConfig.Port)
		log.Error("cannot send verification email: smtp is not configured",
			slog.String("remedy", "set smtp.host and smtp.port in the service config"),
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return err
	}
	if URL == "" {
		// An empty base makes the link relative, so it is unclickable in every
		// mail client. Silent until a user complains; loud here.
		log.Error("verification link has an empty base url",
			slog.String("impact", "the link in the email will be relative and unusable"),
			slog.String("remedy", "check the redirect_uri registered for this application"))
	}

	url := fmt.Sprintf("%s/auth/verify?token=%s&email=%s", URL, verificationToken, to)

	data := EmailData{
		Name:            to,
		VerificationURL: url,
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
		msg.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	msg.WriteString("\r\n")
	msg.Write(body.Bytes())

	log.Debug("sending verification email",
		sl.Token("verification", verificationToken),
		slog.String("link_base", URL),
		slog.Int("message_bytes", msg.Len()))

	auth := smtp.PlainAuth("", e.SMTPConfig.Username, e.SMTPConfig.Password, e.SMTPConfig.Host)

	if err := smtp.SendMail(addr, auth, e.SMTPConfig.Username, []string{to}, msg.Bytes()); err != nil {
		// net/smtp errors are terse and the usual causes are configuration,
		// not code. Attaching the likely cause turns a five-minute guess into
		// a one-line read.
		log.Error("verification email was not delivered to the smtp server",
			slog.String("likely_cause", smtpFailureHint(e.SMTPConfig.Port, err)),
			slog.String(logger.KeyOutcome, logger.OutcomeFailed),
			sl.Err(err), sl.Since(start))
		return err
	}

	// Handover to the relay only. Whether the mailbox accepted it is not
	// observable from here, and the message must not imply otherwise.
	log.Info("verification email handed to the smtp server",
		sl.Token("verification", verificationToken),
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
