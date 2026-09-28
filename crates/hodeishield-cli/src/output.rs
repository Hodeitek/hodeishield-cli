//! Rendering: tables and detail views for people, the API's own JSON for programs.
//!
//! Everything printed for people passes through [`clean`]: vendor names, alert titles and the like
//! come from outside, and a control character in them must not reach the terminal.

use comfy_table::{ContentArrangement, Table, presets};
use serde_json::Value;
use std::io::Write;

/// Replaces control characters (escape sequences, carriage returns, …) with `�`.
pub fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if is_unsafe(c) { '\u{fffd}' } else { c })
        .collect()
}

/// Control characters (C0, DEL, C1) and the invisible or direction-changing format characters that
/// can make text display as something it is not.
fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00ad}'
                | '\u{061c}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
        )
}

/// An optional text cell: `-` when absent.
pub fn cell(value: Option<&str>) -> String {
    value.map_or_else(|| "-".to_owned(), clean)
}

/// `2026-01-31T09:05:00.000Z` → `2026-01-31 09:05Z`. Anything else is shown as is.
pub fn short_time(value: Option<&str>) -> String {
    let Some(value) = value else {
        return "-".to_owned();
    };
    let bytes = value.as_bytes();
    let digits = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    let looks_rfc3339 = value.is_ascii()
        && bytes.len() >= 17
        && digits(0..4)
        && bytes[4] == b'-'
        && digits(5..7)
        && bytes[7] == b'-'
        && digits(8..10)
        && (bytes[10] == b'T' || bytes[10] == b't')
        && digits(11..13)
        && bytes[13] == b':'
        && digits(14..16);
    if looks_rfc3339 && value.ends_with(['Z', 'z']) {
        format!("{} {}Z", &value[..10], &value[11..16])
    } else {
        clean(value)
    }
}

pub fn table(headers: &[&str], rows: Vec<Vec<String>>) -> Table {
    let mut table = Table::new();
    table
        .load_style(presets::NOTHING)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(headers.iter().copied());
    for row in rows {
        table.add_row(row);
    }
    for column in table.column_iter_mut() {
        column.set_padding((0, 2));
    }
    table
}

pub fn print_table(out: &mut dyn Write, table: &Table) -> std::io::Result<()> {
    for line in table.lines() {
        writeln!(out, "{}", line.trim_end())?;
    }
    Ok(())
}

/// The value as pretty JSON. serde_json escapes only C0 controls; DEL, C1 controls and the
/// characters [`clean`] replaces are escaped here as `\uXXXX` too, which encodes the same string, so
/// the JSON value is unchanged but nothing in it can drive the terminal.
pub fn print_json(out: &mut dyn Write, value: &Value) -> std::io::Result<()> {
    let text = serde_json::to_string_pretty(value).map_err(std::io::Error::other)?;
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        // Below U+007F, serde_json has already escaped everything inside strings; what is left is
        // the layout's own newlines and spaces.
        if u32::from(c) >= 0x7f && is_unsafe(c) {
            let mut units = [0_u16; 2];
            for unit in c.encode_utf16(&mut units) {
                escaped.push_str(&format!("\\u{unit:04x}"));
            }
        } else {
            escaped.push(c);
        }
    }
    writeln!(out, "{escaped}")
}

/// A scalar value as text, for detail views.
fn scalar(value: &Value) -> String {
    match value {
        Value::Null => "-".to_owned(),
        Value::String(s) => clean(s),
        Value::Array(items) if items.is_empty() => "-".to_owned(),
        Value::Array(items) => items.iter().map(scalar).collect::<Vec<_>>().join(", "),
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| format!("{}={}", clean(k), scalar(v)))
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

/// `key  value` lines, keys aligned, in the order the fields are declared.
pub fn print_detail(out: &mut dyn Write, value: &Value) -> std::io::Result<()> {
    let Value::Object(map) = value else {
        return writeln!(out, "{}", scalar(value));
    };
    let width = map.keys().map(|k| k.chars().count()).max().unwrap_or(0);
    for (key, value) in map {
        let text = scalar(value);
        let mut lines = text.lines();
        writeln!(out, "{:width$}  {}", clean(key), lines.next().unwrap_or(""))?;
        for line in lines {
            writeln!(out, "{:width$}  {line}", "")?;
        }
    }
    Ok(())
}

/// Formats Unix seconds as RFC 3339 UTC, without a date library.
pub fn unix_to_rfc3339(seconds: u64) -> String {
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    let rem = seconds % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_never_reach_the_terminal() {
        assert_eq!(
            clean("ok\u{1b}[31mred\r\n"),
            "ok\u{fffd}[31mred\u{fffd}\u{fffd}"
        );
        assert_eq!(cell(None), "-");
    }

    #[test]
    fn invisible_and_bidi_characters_are_replaced() {
        assert_eq!(
            clean("a\u{202e}b\u{200b}c\u{9b}d"),
            "a\u{fffd}b\u{fffd}c\u{fffd}d"
        );
    }

    #[test]
    fn json_escapes_what_could_drive_the_terminal_without_changing_the_value() {
        let value = serde_json::json!({"name": "a\u{9b}31m\u{7f}\u{202e}b\u{1b}"});
        let mut out = Vec::new();
        print_json(&mut out, &value).expect("print");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.chars().all(|c| !is_unsafe(c) || c == '\n'), "{text:?}");
        let back: Value = serde_json::from_str(&text).expect("still JSON");
        assert_eq!(back, value);
    }

    #[test]
    fn crafted_timestamps_neither_panic_nor_pass_unfiltered() {
        assert_eq!(
            short_time(Some("2026-01-31T09:0\u{20ac}Z")),
            "2026-01-31T09:0\u{20ac}Z"
        );
        assert!(!short_time(Some("\u{1b}[2J-\u{1b}[-abT\u{1b}[:0\u{1b}Z")).contains('\u{1b}'));
    }

    #[test]
    fn times() {
        assert_eq!(
            short_time(Some("2026-01-31T09:05:07.123Z")),
            "2026-01-31 09:05Z"
        );
        assert_eq!(
            short_time(Some("2026-01-31T09:05:07+02:00")),
            "2026-01-31T09:05:07+02:00"
        );
        assert_eq!(short_time(None), "-");
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_rfc3339(1_790_000_000), "2026-09-21T14:13:20Z");
        assert_eq!(unix_to_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn detail_aligns_and_flattens() {
        let mut out = Vec::new();
        print_detail(
            &mut out,
            &serde_json::json!({"id": "x", "control_codes": ["A.1", "A.2"], "by_status": {"ok": 2}, "none": null}),
        )
        .expect("print");
        let text = String::from_utf8(out).expect("utf8");
        assert_eq!(
            text,
            "id             x\ncontrol_codes  A.1, A.2\nby_status      ok=2\nnone           -\n"
        );
    }

    #[test]
    fn tables_have_no_trailing_spaces() {
        let t = table(
            &["ID", "NAME"],
            vec![vec!["1".into(), "a".into()], vec!["22".into(), "bb".into()]],
        );
        let mut out = Vec::new();
        print_table(&mut out, &t).expect("print");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.lines().all(|l| !l.ends_with(' ')), "{text:?}");
        assert!(text.starts_with("ID"), "{text:?}");
    }
}
