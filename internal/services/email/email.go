package email

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/smtp"
	"text/template"

	"github.com/synnfluxx/TrustMeBroID/internal/config"
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
	url := fmt.Sprintf("%s/auth/verify?token=%s&email=%s", URL, verificationToken, to)

	data := EmailData{
		Name:            to,
		VerificationURL: url,
	}

	tmpl, err := template.New("emailTemplate").Parse(emailTemplate)
	if err != nil {
		e.Log.Error("failed to parse email template", sl.Err(err))
		return err
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		e.Log.Error("failed to execute email template", sl.Err(err))
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

	auth := smtp.PlainAuth("", e.SMTPConfig.Username, e.SMTPConfig.Password, e.SMTPConfig.Host)

	err = smtp.SendMail(fmt.Sprintf("%s:%d", e.SMTPConfig.Host, e.SMTPConfig.Port), auth, e.SMTPConfig.Username, []string{to}, msg.Bytes())
	if err != nil {
		e.Log.Error("failed to send email", sl.Err(err))
		return err
	}

	e.Log.Info("verification email sent successfully", "to", to)
	return nil
}
