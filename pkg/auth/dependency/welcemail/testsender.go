package welcemail

import (
	"github.com/skygeario/skygear-server/pkg/auth/dependency/userprofile"
	"github.com/skygeario/skygear-server/pkg/core/config"
	"github.com/skygeario/skygear-server/pkg/core/mail"
	"github.com/skygeario/skygear-server/pkg/core/template"
)

type TestSender interface {
	Send(
		email string,
		textTemplate string,
		htmlTemplate string,
		subject string,
		sender string,
		replyTo string,
	) error
}

type DefaultTestSender struct {
	AppName string
	Config  config.WelcomeEmailConfiguration
	Sender  mail.Sender
}

func NewDefaultTestSender(config config.TenantConfiguration, sender mail.Sender) TestSender {
	return &DefaultTestSender{
		AppName: config.AppName,
		Config:  config.UserConfig.WelcomeEmail,
		Sender:  sender,
	}
}

func (d *DefaultTestSender) Send(
	email string,
	textTemplate string,
	htmlTemplate string,
	subject string,
	sender string,
	replyTo string,
) (err error) {
	check := func(test, a, b string) string {
		if test != "" {
			return a
		}

		return b
	}

	userProfile := userprofile.UserProfile{
		ID: "dummy-id",
	}
	context := map[string]interface{}{
		"appname":    d.AppName,
		"email":      userProfile.Data["email"],
		"user_id":    userProfile.ID,
		"user":       userProfile,
		"url_prefix": d.Config.URLPrefix,
	}

	var textBody string
	if textBody, err = template.ParseTextTemplate(textTemplate, context); err != nil {
		return
	}

	var htmlBody string
	if htmlBody, err = template.ParseHTMLTemplate(htmlTemplate, context); err != nil {
		return
	}

	err = d.Sender.Send(mail.SendOptions{
		Sender:    check(sender, sender, d.Config.Sender),
		Recipient: email,
		Subject:   check(subject, subject, d.Config.Subject),
		ReplyTo:   check(replyTo, replyTo, d.Config.ReplyTo),
		TextBody:  textBody,
		HTMLBody:  htmlBody,
	})

	return
}
