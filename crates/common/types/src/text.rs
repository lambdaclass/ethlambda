//! Text from a remote peer, made safe to put in a log line.

/// What a cut text ends in.
const CUT: &str = "...";

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
/// escape in two. A text that does not fit ends in `...`, within the cap, so
/// a cut one does not read as all that was sent; one that fits exactly is
/// left unmarked. The walk stops at the cap, so a large body costs no more
/// than the text it keeps.
pub fn one_line(text: &str, max_bytes: usize) -> String {
    let mut written = String::with_capacity(text.len().min(max_bytes));
    // What `written` is cut back to if the text does not fit: the longest
    // part of it that leaves room for the marker.
    let mut kept_if_cut = 0;
    for c in text.chars() {
        let breaks_the_line = c.is_control() || matches!(c, '\u{2028}' | '\u{2029}');
        let escaped = breaks_the_line.then(|| c.escape_default());
        let len = escaped
            .as_ref()
            .map_or(c.len_utf8(), ExactSizeIterator::len);
        if written.len() + len > max_bytes {
            written.truncate(kept_if_cut);
            // All of the marker, unless the cap is smaller than the marker.
            let room = max_bytes - kept_if_cut;
            written.push_str(&CUT[..room.min(CUT.len())]);
            break;
        }
        match escaped {
            Some(escaped) => written.extend(escaped),
            None => written.push(c),
        }
        if written.len() + CUT.len() <= max_bytes {
            kept_if_cut = written.len();
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

    /// A cut text ends in the marker, counted within the cap; a text that
    /// fits exactly is not marked.
    #[test]
    fn a_cut_text_ends_in_the_marker() {
        let text = "x".repeat(1024);
        assert_eq!(one_line(&text, 1024), text);
        let text = "x".repeat(1025);
        assert_eq!(one_line(&text, 1024), format!("{}...", "x".repeat(1021)));
        assert_eq!(one_line("short", 1024), "short");
        // A cap smaller than the marker keeps as much of it as fits.
        assert_eq!(one_line("abcdef", 2), "..");
    }

    #[test]
    fn the_cap_never_cuts_an_escape_in_two() {
        // 1018 bytes, then a six-byte escape that ends right at the cap.
        let text = format!("{}\x1b", "x".repeat(1018));
        assert_eq!(
            one_line(&text, 1024),
            format!("{}\\u{{1b}}", "x".repeat(1018))
        );
        // A byte more and the escape does not fit: it is left out whole, not
        // cut to `\u{` ahead of the marker.
        let text = format!("{}\x1b", "x".repeat(1019));
        assert_eq!(one_line(&text, 1024), format!("{}...", "x".repeat(1019)));
        // The escape fits but leaves the marker no room once the next
        // character does not: the cut backs up over the whole escape.
        let text = format!("{}\x1by", "x".repeat(1018));
        assert_eq!(one_line(&text, 1024), format!("{}...", "x".repeat(1018)));
    }

    #[test]
    fn the_cap_never_cuts_a_character_in_two() {
        // 'é' is two bytes. 1023 bytes hold 510 of them and the marker, and
        // never half of a 511th.
        let text = "é".repeat(1024);
        assert_eq!(one_line(&text, 1023), format!("{}...", "é".repeat(510)));
    }
}
