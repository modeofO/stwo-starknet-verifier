//! The from-line convention: an OPTIONAL first plaintext line
//! `from: <handle>` a burner sender may include so the recipient can
//! reply to the real identity. Rides inside AES-GCM — only the
//! recipient ever sees it. A convention, not a protocol: any client may
//! ignore it (the CLI prints it as ordinary text).

/// Prepends the from-line. Caller gates on the compose checkbox.
pub fn apply_from_line(text: &str, reply_handle: &str) -> String {
    format!("from: {reply_handle}\n{text}")
}

/// Parses a leading `from: <handle>` line into `(handle, body)`.
/// Handle must look like a registered handle: ASCII, 1-31 chars, no
/// whitespace. Anything else is ordinary text.
pub fn split_from_line(text: &str) -> Option<(&str, &str)> {
    let rest = text.strip_prefix("from: ")?;
    let (handle, body) = rest.split_once('\n')?;
    let ok = !handle.is_empty()
        && handle.len() <= 31
        && handle.is_ascii()
        && !handle.contains(char::is_whitespace);
    ok.then_some((handle, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_prepends_one_line() {
        assert_eq!(apply_from_line("hi bob", "alice"), "from: alice\nhi bob");
    }

    #[test]
    fn split_parses_only_wellformed_first_lines() {
        assert_eq!(split_from_line("from: alice\nhi"), Some(("alice", "hi")));
        // Round-trips apply.
        assert_eq!(
            split_from_line(&apply_from_line("hi", "burner-peer")),
            Some(("burner-peer", "hi"))
        );
        // Not a from-line: plain text, mid-text markers, empty handle,
        // over-long handle, embedded whitespace, no body separator.
        assert_eq!(split_from_line("hello from: alice"), None);
        assert_eq!(split_from_line("from: \nhi"), None);
        assert_eq!(split_from_line(&format!("from: {}\nhi", "x".repeat(32))), None);
        assert_eq!(split_from_line("from: two words\nhi"), None);
        assert_eq!(split_from_line("from: alice"), None); // no newline -> no body
        assert_eq!(split_from_line(""), None);
    }
}
