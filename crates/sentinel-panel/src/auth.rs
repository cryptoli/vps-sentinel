use super::*;

pub(super) fn verify_panel_role(
    state: &AppState,
    headers: &HeaderMap,
    minimum: PanelRole,
) -> Result<PanelRole, PanelApiError> {
    let role = resolve_panel_role(state, headers)?;
    if role < minimum {
        return Err(PanelApiError::new(
            StatusCode::FORBIDDEN,
            "insufficient_panel_role",
        ));
    }
    Ok(role)
}

pub(super) fn verify_panel_page_role(
    state: &AppState,
    headers: &HeaderMap,
    page_id: &str,
    default_minimum: PanelRole,
) -> Result<PanelRole, PanelApiError> {
    let minimum = if state.public_pages.contains(page_id) {
        PanelRole::Public
    } else {
        default_minimum
    };
    verify_panel_role(state, headers, minimum)
}

#[cfg(test)]
pub(super) fn verify_view_auth(state: &AppState, headers: &HeaderMap) -> Result<(), PanelApiError> {
    verify_panel_role(state, headers, PanelRole::Operator).map(|_| ())
}

pub(super) fn resolve_panel_role(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<PanelRole, PanelApiError> {
    if state.view_token.is_none()
        && state.operator_token.is_none()
        && state.admin_token.is_none()
        && !panel_public_access_enabled(state)
    {
        return Err(PanelApiError::new(
            StatusCode::FORBIDDEN,
            "panel_view_token_not_configured",
        ));
    };
    let Some(actual) = view_token_from_headers(headers) else {
        if panel_public_access_enabled(state) {
            return Ok(PanelRole::Public);
        }
        return Err(PanelApiError::new(
            StatusCode::UNAUTHORIZED,
            "missing_view_token",
        ));
    };
    let admin_match = state
        .admin_token
        .as_deref()
        .is_some_and(|expected| constant_time_eq(expected, actual));
    if admin_match {
        return Ok(PanelRole::Admin);
    }
    let operator_match = state
        .operator_token
        .as_deref()
        .is_some_and(|expected| constant_time_eq(expected, actual));
    let view_match = state
        .view_token
        .as_deref()
        .is_some_and(|expected| constant_time_eq(expected, actual));
    if operator_match || view_match {
        return Ok(PanelRole::Operator);
    }
    if panel_public_access_enabled(state) {
        return Ok(PanelRole::Public);
    }
    Err(PanelApiError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_view_token",
    ))
}

pub(super) fn panel_public_access_enabled(state: &AppState) -> bool {
    state.public_enabled || !state.public_pages.is_empty()
}

pub(super) fn parse_public_pages(value: &str) -> BTreeSet<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|page| !page.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

pub(super) fn normalize_panel_path(value: &str) -> String {
    let trimmed = value.trim();
    let path = if trimmed.is_empty() {
        DEFAULT_ADMIN_PATH
    } else {
        trimmed
    };
    let with_slash = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    let normalized = with_slash.trim_end_matches('/').to_string();
    if normalized.is_empty() {
        DEFAULT_ADMIN_PATH.to_string()
    } else {
        normalized
    }
}

pub(super) fn random_panel_admin_path() -> String {
    let id = Uuid::new_v4().simple().to_string();
    format!("/{}", &id[..12])
}

pub(super) fn parse_panel_themes(value: &str) -> Vec<PanelThemeOption> {
    let mut seen = BTreeSet::new();
    let mut themes = value
        .split(',')
        .filter_map(|entry| {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                return None;
            }
            let (id, label) = trimmed
                .split_once(':')
                .map(|(id, label)| (id.trim(), label.trim()))
                .unwrap_or((trimmed, trimmed));
            let id = sanitize_theme_id(id);
            if id.is_empty() || !seen.insert(id.clone()) {
                return None;
            }
            Some(PanelThemeOption {
                label: if label.is_empty() {
                    id.clone()
                } else {
                    label.to_string()
                },
                id,
            })
        })
        .collect::<Vec<_>>();
    if themes.is_empty() {
        themes.push(PanelThemeOption {
            id: "default".to_string(),
            label: "Default".to_string(),
        });
    }
    themes
}

fn sanitize_theme_id(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(*ch, '-' | '_'))
        .collect::<String>()
}

pub(super) fn verify_admin_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), PanelApiError> {
    if state.admin_token.is_none() {
        return Err(PanelApiError::new(
            StatusCode::FORBIDDEN,
            "panel_admin_token_not_configured",
        ));
    }
    verify_panel_role(state, headers, PanelRole::Admin).map(|_| ())
}

pub(super) fn view_token_from_headers(headers: &HeaderMap) -> Option<&str> {
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token)
    {
        return Some(value);
    }
    headers
        .get("x-vps-sentinel-view-token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn bearer_token(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        let token = token.trim();
        if !token.is_empty() {
            return Some(token);
        }
    }
    None
}
