use crate::collectors::{CollectContext, Collector};
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use std::fs;
use std::path::Path;

pub struct UserCollector;

#[async_trait]
impl Collector for UserCollector {
    fn name(&self) -> &'static str {
        "users"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        let passwd_path = ctx.resolve(Path::new("/etc/passwd"));
        if !passwd_path.exists() {
            return Ok(Vec::new());
        }
        let text = fs::read_to_string(&passwd_path)
            .map_err(|err| sentinel_core::SentinelError::io(&passwd_path, err))?;
        Ok(parse_passwd(&text))
    }
}

/// Parse `/etc/passwd` content into user facts.
pub fn parse_passwd(text: &str) -> Vec<RawEvent> {
    text.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .filter_map(parse_passwd_line)
        .collect()
}

fn parse_passwd_line(line: &str) -> Option<RawEvent> {
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 7 {
        return None;
    }
    Some(
        RawEvent::new("users", "user_account")
            .with_field("name", parts[0])
            .with_field("uid", parts[2])
            .with_field("gid", parts[3])
            .with_field("home", parts[5])
            .with_field("shell", parts[6]),
    )
}

#[cfg(test)]
mod tests {
    use super::parse_passwd;

    #[test]
    fn parses_uid_zero_user() {
        let users =
            parse_passwd("root:x:0:0:root:/root:/bin/bash\napp:x:1000:1000::/home/app:/bin/bash");
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].field("name"), Some("root"));
        assert_eq!(users[0].field("uid"), Some("0"));
    }
}
