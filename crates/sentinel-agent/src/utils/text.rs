pub fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    const TRUNCATION_MARKER: &str = "...[truncated]";
    if max_bytes <= TRUNCATION_MARKER.len() {
        return utf8_prefix(value, max_bytes).to_string();
    }
    let prefix_budget = max_bytes - TRUNCATION_MARKER.len();
    format!("{}{}", utf8_prefix(value, prefix_budget), TRUNCATION_MARKER)
}

fn utf8_prefix(value: &str, max_bytes: usize) -> &str {
    let mut end = 0;
    for (index, ch) in value.char_indices() {
        let next = index + ch.len_utf8();
        if next > max_bytes {
            break;
        }
        end = next;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use super::truncate_utf8;

    #[test]
    fn truncates_without_splitting_utf8() {
        let truncated = truncate_utf8("安全安全安全安全安全", 24);
        assert!(truncated.starts_with("安全"));
        assert!(truncated.contains("truncated"));
        assert!(truncated.len() <= 24);

        let tiny = truncate_utf8("安全安全", 5);
        assert_eq!(tiny, "安");
    }
}
