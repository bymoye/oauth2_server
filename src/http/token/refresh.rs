//! refresh_token grant 处理。
// 只处理 refresh token 轮换、复用检测和 family 撤销。
use super::{TokenForm, issue_token_response};
use crate::http::prelude::*;

async fn mark_token_family_reuse(state: &AppState, token_family_id: Uuid) {
    let Ok(mut conn) = get_conn(&state.diesel_db).await else {
        return;
    };
    let _ = diesel::update(
        oauth_tokens::table.filter(oauth_tokens::token_family_id.eq(token_family_id)),
    )
    .set(oauth_tokens::reuse_detected_at.eq(diesel_now))
    .execute(&mut conn)
    .await;
    let _ = diesel::update(
        oauth_tokens::table
            .filter(oauth_tokens::token_family_id.eq(token_family_id))
            .filter(oauth_tokens::revoked_at.is_null()),
    )
    .set(oauth_tokens::revoked_at.eq(diesel_now))
    .execute(&mut conn)
    .await;
}

pub(crate) async fn token_refresh(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
) -> HttpResponse {
    let Some(refresh_token) = &form.refresh_token else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 refresh_token.",
        );
    };
    let hash = blake3_hex(refresh_token);
    let token = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => oauth_tokens::table
            .filter(oauth_tokens::refresh_token_blake3.eq(hash))
            .select(TokenRow::as_select())
            .first::<TokenRow>(&mut conn)
            .await
            .optional()
            .ok()
            .flatten(),
        Err(_) => None,
    };
    let Some(token) = token else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token 无效.",
        );
    };
    let dpop_jkt = match validate_dpop_proof(state, req, None, token.dpop_jkt.as_deref()).await {
        Ok(value) => token.dpop_jkt.clone().or(value),
        Err(error) => return dpop_error_response(error),
    };
    if token.client_id != client.id || token.expires_at <= Utc::now() || token.revoked_at.is_some()
    {
        mark_token_family_reuse(state, token.token_family_id).await;
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token 无效或已撤销.",
        );
    }
    let rotated = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => diesel::update(
            oauth_tokens::table
                .filter(oauth_tokens::id.eq(token.id))
                .filter(oauth_tokens::revoked_at.is_null()),
        )
        .set(oauth_tokens::revoked_at.eq(diesel_now))
        .execute(&mut conn)
        .await
        .unwrap_or(0),
        Err(_) => 0,
    };
    if rotated == 0 {
        mark_token_family_reuse(state, token.token_family_id).await;
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token 无效或已撤销.",
        );
    }
    let audience = form
        .audience
        .clone()
        .unwrap_or_else(|| state.settings.default_audience.clone());
    if !audience_allowed(client, &audience) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
        );
    }
    issue_token_response(
        state,
        client,
        TokenIssue {
            user_id: token.user_id,
            subject: token.subject,
            scopes: json_array_to_strings(&token.scopes),
            audience,
            nonce: None,
            include_refresh: true,
            rotation: Some((token.token_family_id, Some(token.id))),
            dpop_jkt,
        },
    )
    .await
}
