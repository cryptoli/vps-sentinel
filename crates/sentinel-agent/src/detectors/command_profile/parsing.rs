pub(super) fn normalize_text(command: &str) -> String {
    command
        .to_ascii_lowercase()
        .replace('\t', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

pub(super) fn split_shell_like(command: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;

    for ch in command.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if matches!(quote, Some(active) if active == ch) {
            quote = None;
            continue;
        }
        if quote.is_none() && (ch == '\'' || ch == '"') {
            quote = Some(ch);
            continue;
        }
        if quote.is_none() && ch.is_whitespace() {
            if !current.is_empty() {
                args.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(ch);
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

pub(super) fn contains_ipv4_literal(command: &str) -> bool {
    command
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .filter(|part| part.contains('.'))
        .any(is_ipv4_literal)
}

fn is_ipv4_literal(value: &str) -> bool {
    let mut count = 0;
    for part in value.split('.') {
        count += 1;
        if part.is_empty() || part.len() > 3 {
            return false;
        }
        let Ok(number) = part.parse::<u16>() else {
            return false;
        };
        if number > 255 {
            return false;
        }
    }
    count == 4
}
