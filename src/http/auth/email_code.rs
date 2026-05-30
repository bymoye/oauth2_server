//! 邮箱验证码发送端点。
use crate::http::prelude::*;

#[derive(Deserialize)]
pub(crate) struct SendCodeRequest {
    email: String,
}

/// 生成并保存注册邮箱验证码。
pub(crate) async fn send_code(
    state: Data<AppState>,
    Json(payload): Json<SendCodeRequest>,
) -> HttpResponse {
    let email = payload.email.trim().to_lowercase();
    let Ok(recipient) = parse_email_recipient(&email) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "邮箱格式无效.");
    };
    if !email_delivery_configured(&state.settings) {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "邮件发送未配置.",
        );
    }

    let code = random_numeric_code();
    let Ok(code_hash) = hash_password(&code) else {
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "验证码生成失败.",
        );
    };
    let key = format!("oauth:email_verify:code:{email}");
    if valkey_set_ex(
        &state.valkey,
        &key,
        code_hash,
        state.settings.email.code_ttl_seconds,
    )
    .await
    .is_err()
    {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "验证码生成失败.",
        );
    }

    if let Err(error) = send_verification_email(&state.settings, recipient, &code).await {
        let _ = valkey_del(&state.valkey, &key).await;
        tracing::warn!(%error, "failed to send verification email");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "验证码发送失败.",
        );
    }

    let mut body = json!({"success": true, "message": "如果邮箱尚未注册，验证码将会发送。"});
    if cfg!(debug_assertions) && state.settings.email_code_dev_response_enabled {
        body["verification_code"] = json!(code);
    }
    json_response(body)
}

fn random_numeric_code() -> String {
    let value = u32::from_be_bytes(rand::random::<[u8; 4]>()) % 1_000_000;
    format!("{value:06}")
}
