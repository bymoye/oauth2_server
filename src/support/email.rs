//! 邮件投递封装。

use std::time::Duration;

use anyhow::{Context, bail};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
};

use crate::domain::{EmailDelivery, Settings, SmtpEmailSettings, SmtpTlsMode};

pub(crate) fn parse_email_recipient(raw: &str) -> anyhow::Result<Mailbox> {
    raw.parse::<Mailbox>()
        .context("recipient email address is invalid")
}

pub(crate) fn email_delivery_configured(settings: &Settings) -> bool {
    matches!(&settings.email.delivery, EmailDelivery::Smtp(_))
}

pub(crate) async fn send_verification_email(
    settings: &Settings,
    recipient: Mailbox,
    code: &str,
) -> anyhow::Result<()> {
    let EmailDelivery::Smtp(smtp) = &settings.email.delivery else {
        bail!("email delivery is disabled");
    };

    let message = Message::builder()
        .from(smtp.from.clone())
        .to(recipient)
        .subject("Nazo OAuth 注册验证码")
        .header(ContentType::TEXT_PLAIN)
        .body(format!(
            "你的 Nazo OAuth 注册验证码是：{code}\n\n验证码将在 {} 秒后失效。如非本人操作，请忽略这封邮件。",
            settings.email.code_ttl_seconds
        ))
        .context("failed to build verification email")?;

    build_smtp_transport(smtp)?
        .send(message)
        .await
        .context("failed to send verification email")?;
    Ok(())
}

fn build_smtp_transport(
    smtp: &SmtpEmailSettings,
) -> anyhow::Result<AsyncSmtpTransport<Tokio1Executor>> {
    let tls_parameters =
        || TlsParameters::new(smtp.host.clone()).context("failed to build SMTP TLS parameters");

    let tls = match smtp.tls {
        SmtpTlsMode::StartTls => Tls::Required(tls_parameters()?),
        SmtpTlsMode::ImplicitTls => Tls::Wrapper(tls_parameters()?),
        SmtpTlsMode::None => Tls::None,
    };

    let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp.host)
        .port(smtp.port)
        .tls(tls)
        .timeout(Some(Duration::from_secs(30)));

    if let (Some(username), Some(password)) = (&smtp.username, &smtp.password) {
        builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
    }

    Ok(builder.build())
}
