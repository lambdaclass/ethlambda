//! The startup banner, in one of two encodings.

use std::ffi::OsString;

/// The logo, drawn with block characters from the code page 437 set.
const UTF8: &str = include_str!("../assets/ethlambda_banner.txt");

/// The wordmark in plain ASCII, for terminals that cannot decode `UTF8`.
const ASCII: &str = include_str!("../assets/ethlambda_banner_ascii.txt");

/// The banner this process's terminal can display.
///
/// A terminal's encoding is not something a process can query, so this reads
/// the locale, which is how terminals and their shells advertise it.
pub fn for_locale() -> &'static str {
    if locale_is_utf8(|name| std::env::var_os(name)) {
        UTF8
    } else {
        ASCII
    }
}

/// Whether the locale's character encoding is UTF-8.
///
/// Follows POSIX precedence: the first of `LC_ALL`, `LC_CTYPE` and `LANG` that
/// is set and non-empty decides. With none of them set the locale is `C`, whose
/// encoding is ASCII.
///
/// Values are read as `OsString` because a variable holding bytes that are not
/// valid Unicode is still set: `env::var` would report it as absent, handing the
/// decision to a variable POSIX ranks below it.
fn locale_is_utf8(var: impl Fn(&str) -> Option<OsString>) -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .into_iter()
        .find_map(|name| var(name).filter(|value| !value.is_empty()))
        .is_some_and(|locale| {
            let locale = locale.to_string_lossy().to_ascii_lowercase();
            locale.contains("utf-8") || locale.contains("utf8")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(vars: &'a [(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        |name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        }
    }

    #[test]
    fn a_utf8_lang_selects_utf8() {
        assert!(locale_is_utf8(env(&[("LANG", "en_US.UTF-8")])));
        assert!(locale_is_utf8(env(&[("LANG", "C.utf8")])));
    }

    #[test]
    fn no_locale_is_ascii() {
        assert!(!locale_is_utf8(env(&[])));
    }

    #[test]
    fn a_non_utf8_encoding_is_ascii() {
        assert!(!locale_is_utf8(env(&[("LANG", "en_US.ISO-8859-1")])));
        assert!(!locale_is_utf8(env(&[("LANG", "C")])));
    }

    #[test]
    fn lc_all_overrides_everything() {
        let vars = [
            ("LC_ALL", "C"),
            ("LC_CTYPE", "en_US.UTF-8"),
            ("LANG", "en_US.UTF-8"),
        ];
        assert!(!locale_is_utf8(env(&vars)));
    }

    #[test]
    fn lc_ctype_overrides_lang() {
        let utf8_ctype = [("LC_CTYPE", "en_US.UTF-8"), ("LANG", "C")];
        assert!(locale_is_utf8(env(&utf8_ctype)));
        let c_ctype = [("LC_CTYPE", "C"), ("LANG", "en_US.UTF-8")];
        assert!(!locale_is_utf8(env(&c_ctype)));
    }

    #[test]
    fn an_empty_variable_counts_as_unset() {
        let vars = [("LC_ALL", ""), ("LANG", "en_US.UTF-8")];
        assert!(locale_is_utf8(env(&vars)));
    }

    #[cfg(unix)]
    #[test]
    fn a_non_unicode_value_still_takes_precedence() {
        use std::os::unix::ffi::OsStrExt;

        let var = |name: &str| match name {
            "LC_ALL" => Some(std::ffi::OsStr::from_bytes(b"\xff").to_os_string()),
            "LANG" => Some(OsString::from("en_US.UTF-8")),
            _ => None,
        };
        assert!(!locale_is_utf8(var));
    }

    #[test]
    fn the_fallback_is_ascii() {
        assert!(ASCII.is_ascii());
    }
}
