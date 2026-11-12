//! Text from a remote peer, made safe to put in a log line.

/// `text` with every character that could break or restyle a line written
/// out, cut to at most `max_bytes` bytes.
///
/// Text a remote server sends (an error body, a relay's message) reaches this
/// node's logs and error messages. There a raw line break would start what
/// reads as a log line of its own, and an ESC would start an ANSI sequence that
/// recolors, moves the cursor in or clears a terminal. So every control
/// character (`char::is_control`: C0, DEL and C1) and the Unicode line and
/// paragraph separators U+2028/U+2029, which some viewers break lines at, are
/// written as Rust escapes: `\n`, `\r` and `\t`, and `\u{1b}` for the rest.
/// Everything else passes through unchanged, quotes and backslashes included.
///
/// The cap is applied to the escaped text, and never cuts a character or an
/// escape in two. The walk stops at the cap, so a large body costs no more
/// than the text it keeps.
pub fn one_line(text: &str, max_bytes: usize) -> String {
    let mut written = String::with_capacity(text.len().min(max_bytes));
    for c in text.chars() {
        if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') {
            let escaped = c.escape_default();
            if written.len() + escaped.len() > max_bytes {
                break;
            }
            written.extend(escaped);
        } else {
            if written.len() + c.len_utf8() > max_bytes {
                break;
            }
            written.push(c);
        }
    }
    written
}

#[cfg(test)]
mod tests {
    use super::one_line;

    #[test]
    fn control_characters_and_line_separators_are_written_out() {
        let text = "\x1b[31mred\x1b[0m\ttab\x07bell\u{85}nel\u{2028}ls\u{2029}ps \"q\" \\ ok\r\n";
        assert_eq!(
            one_line(text, 1024),
            r#"\u{1b}[31mred\u{1b}[0m\ttab\u{7}bell\u{85}nel\u{2028}ls\u{2029}ps "q" \ ok\r\n"#
        );
    }

    #[test]
    fn the_cap_never_cuts_an_escape_in_two() {
        // 1020 bytes, then a six-byte escape that would end past the cap.
        let text = format!("{}\x1b", "x".repeat(1020));
        assert_eq!(one_line(&text, 1024), "x".repeat(1020));
        let text = format!("{}\x1b", "x".repeat(1018));
        assert_eq!(
            one_line(&text, 1024),
            format!("{}\\u{{1b}}", "x".repeat(1018))
        );
    }

    #[test]
    fn the_cap_never_cuts_a_character_in_two() {
        // 'é' is two bytes, so 1024 bytes hold 512 of them and no half.
        let text = "é".repeat(1024);
        let written = one_line(&text, 1023);
        assert_eq!(written, "é".repeat(511));
        assert_eq!(one_line("short", 1024), "short");
    }
}
