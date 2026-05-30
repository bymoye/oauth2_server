//! 邮箱验证码发送端点。
// 当前端点负责生成和保存验证码；邮件投递可由独立投递服务接入。
use crate::http::prelude::*;

const EMAIL_CODE_TTL_SECONDS: u64 = 900;

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
    if !email.contains('@') {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "邮箱格式无效.");
    }

    let code = random_numeric_code();
    let key = format!("oauth:email_verify:code:{email}");
    if valkey_set_ex(&state.valkey, key, blake3_hex(&code), EMAIL_CODE_TTL_SECONDS)
        .await
        .is_err()
    {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "验证码生成失败.",
        );
    }

    // TODO: 接入正式邮件投递服务后在这里发送验证码。
    // 当前只记录到 debug 日志，避免 HTTP 响应泄露验证码。
    tracing::debug!(email = %email, verification_code = %code, "generated registration verification code");
    json_response(json!({"success": true, "message": "如果邮箱尚未注册，验证码将会发送。"}))
}

fn random_numeric_code() -> String {
    let value = u32::from_be_bytes(rand::random::<[u8; 4]>()) % 1_000_000;
    format!("{value:06}")
}
