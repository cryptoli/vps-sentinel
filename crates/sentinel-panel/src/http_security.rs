use super::*;

pub(super) async fn security_headers(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    headers.insert(header::CONTENT_SECURITY_POLICY, state.csp_header);
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );
    response
}

pub(super) fn panel_csp_header(web_dir: &Path) -> HeaderValue {
    let mut policy = String::from("default-src 'self'; script-src 'self'");
    for hash in inline_script_hashes(web_dir) {
        policy.push_str(" 'sha256-");
        policy.push_str(&hash);
        policy.push('\'');
    }
    policy.push_str(
        "; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    );
    HeaderValue::from_str(&policy).unwrap_or_else(|error| {
        warn!(%error, "failed to build panel CSP header; falling back to strict script policy");
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
    })
}

fn inline_script_hashes(web_dir: &Path) -> BTreeSet<String> {
    let index_path = web_dir.join("index.html");
    let Ok(html) = fs::read_to_string(&index_path) else {
        warn!(path = %index_path.display(), "panel index.html is not readable; inline scripts will be blocked by CSP");
        return BTreeSet::new();
    };
    let mut hashes = BTreeSet::new();
    let mut rest = html.as_str();
    while let Some(script_offset) = rest.find("<script") {
        rest = &rest[script_offset..];
        let Some(tag_end) = rest.find('>') else {
            break;
        };
        let tag = &rest[..=tag_end];
        rest = &rest[tag_end + 1..];
        let Some(close_offset) = rest.find("</script>") else {
            break;
        };
        let body = &rest[..close_offset];
        rest = &rest[close_offset + "</script>".len()..];
        let tag_lower = tag.to_ascii_lowercase();
        if tag_lower.contains(" src=")
            || tag_lower.contains(" src\t")
            || tag_lower.contains(" src\n")
        {
            continue;
        }
        if body.trim().is_empty() {
            continue;
        }
        let digest = Sha256::digest(body.as_bytes());
        hashes.insert(BASE64_STANDARD.encode(digest));
    }
    hashes
}
