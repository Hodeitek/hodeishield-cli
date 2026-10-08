// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! The values the API document lists for a filter (`x-hs-known-values`): shown in `--help` and
//! checked before a request. The lists are open vocabularies, so a value that is not listed is
//! warned about and sent exactly as typed; nothing here refuses a value or rewrites it.

use crate::output::clean;
use hodeishield_api::Operation;

/// The help text of a filter flag: `base`, plus the values the document lists for `param`, when it
/// lists any. Without a list the help is `base` unchanged.
pub fn help(base: &str, operation: &Operation, param: &str) -> String {
    match operation.known_values(param) {
        Some(values) if !values.is_empty() => {
            format!("{base} Known values: {}.", values.join(", "))
        }
        _ => base.to_owned(),
    }
}

/// The legacy values of the alert `severity` filter and their current names.
///
/// The API is moving alert severity from a legacy Spanish scale to an English vocabulary, and
/// for a transition period its filter accepts both. A legacy value typed by the user is still
/// sent exactly as typed (the server accepts it); this table only lets the CLI say what to use
/// instead. It applies to the alert severity filter alone and can be removed, with
/// [`legacy_hint`], after [`LEGACY_SEVERITY_END`].
const LEGACY_SEVERITY: &[(&str, &str)] = &[
    ("critico", "critical"),
    ("alto", "high"),
    ("medio", "medium"),
    ("bajo", "low"),
    ("info", "info"),
];

/// The last day the API accepts the legacy severity values.
const LEGACY_SEVERITY_END: &str = "2027-01-14";

/// The specific hint for a legacy severity value, or `None` when the generic warning applies.
///
/// It fires only when the API document lists the English values, so only once the server has
/// switched. Until then the API still returns the legacy scale and the legacy values are the
/// working spelling; telling users to move away from them would send them to values that match
/// nothing. A document without a list stays silent, like every other filter.
fn legacy_hint(operation: &Operation, param: &str, value: &str, known: &[&str]) -> Option<String> {
    if operation.id != "listAlerts" || param != "severity" {
        return None;
    }
    let (_, current) = LEGACY_SEVERITY
        .iter()
        .find(|(legacy, _)| legacy.eq_ignore_ascii_case(value))?;
    if !known.contains(current) {
        return None;
    }
    Some(format!(
        "warning: `{}` is a legacy severity value, accepted by the API until \
         {LEGACY_SEVERITY_END}; use `{current}`. Sending it as typed.",
        clean(value),
    ))
}

/// The warnings for the `(parameter, value)` pairs the user gave, one per value that is not in the
/// list the document publishes for that parameter. A parameter without a list never warns. The
/// match is exact and case-sensitive, as the API is; a value that differs only by case also gets
/// the listed spelling as a hint.
pub fn warnings(operation: &Operation, filters: &[(&str, Option<&str>)]) -> Vec<String> {
    filters
        .iter()
        .filter_map(|&(param, value)| {
            let value = value?;
            let known = operation.known_values(param).filter(|v| !v.is_empty())?;
            if known.contains(&value) {
                return None;
            }
            if let Some(hint) = legacy_hint(operation, param, value, known) {
                return Some(hint);
            }
            let tail = known
                .iter()
                .find(|k| k.eq_ignore_ascii_case(value))
                .map_or_else(
                    || "sending it anyway.".to_owned(),
                    |k| format!("did you mean `{k}`? Sending it anyway."),
                );
            Some(format!(
                "warning: `{}` is not one of the values the API lists for --{} ({}); {tail}",
                clean(value),
                param.replace('_', "-"),
                known.join(", "),
            ))
        })
        .collect()
}

/// Prints [`warnings`] to stderr.
pub fn warn_unknown(operation: &Operation, filters: &[(&str, Option<&str>)]) {
    for warning in warnings(operation, filters) {
        eprintln!("{warning}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WITH_LISTS: Operation = Operation {
        id: "listAlerts",
        method: "GET",
        path: "/v1/alerts",
        summary: "List alerts",
        scopes: &[],
        known_values: &[("severity", &["critical", "high", "medium", "low"])],
    };

    const WITHOUT_LISTS: Operation = Operation {
        known_values: &[],
        ..WITH_LISTS
    };

    #[test]
    fn an_unlisted_value_warns_and_names_the_options() {
        assert_eq!(
            warnings(&WITH_LISTS, &[("severity", Some("urgent"))]),
            [
                "warning: `urgent` is not one of the values the API lists for --severity \
              (critical, high, medium, low); sending it anyway."
            ]
        );
    }

    #[test]
    fn a_listed_value_or_no_value_is_silent() {
        assert!(warnings(&WITH_LISTS, &[("severity", Some("high"))]).is_empty());
        assert!(warnings(&WITH_LISTS, &[("severity", None)]).is_empty());
    }

    #[test]
    fn a_difference_only_in_case_suggests_the_listed_spelling() {
        assert_eq!(
            warnings(&WITH_LISTS, &[("severity", Some("High"))]),
            [
                "warning: `High` is not one of the values the API lists for --severity \
              (critical, high, medium, low); did you mean `high`? Sending it anyway."
            ]
        );
    }

    #[test]
    fn a_parameter_without_a_list_never_warns() {
        assert!(warnings(&WITH_LISTS, &[("category", Some("anything"))]).is_empty());
        assert!(warnings(&WITHOUT_LISTS, &[("severity", Some("urgent"))]).is_empty());
    }

    const ENGLISH: Operation = Operation {
        known_values: &[("severity", &["critical", "high", "medium", "low", "info"])],
        ..WITH_LISTS
    };

    #[test]
    fn a_legacy_severity_points_to_its_new_name() {
        assert_eq!(
            warnings(&ENGLISH, &[("severity", Some("alto"))]),
            [
                "warning: `alto` is a legacy severity value, accepted by the API until \
                 2027-01-14; use `high`. Sending it as typed."
            ]
        );
        for (legacy, current) in [
            ("critico", "critical"),
            ("medio", "medium"),
            ("bajo", "low"),
        ] {
            let out = warnings(&ENGLISH, &[("severity", Some(legacy))]);
            assert!(out[0].contains(&format!("use `{current}`")), "{out:?}");
        }
    }

    #[test]
    fn a_legacy_severity_is_matched_without_regard_to_case() {
        let out = warnings(&ENGLISH, &[("severity", Some("ALTO"))]);
        assert_eq!(out.len(), 1);
        assert!(out[0].starts_with("warning: `ALTO` is a legacy severity value"));
        assert!(out[0].contains("use `high`"), "{out:?}");
    }

    #[test]
    fn a_current_severity_is_silent() {
        for value in ["critical", "high", "medium", "low", "info"] {
            assert!(warnings(&ENGLISH, &[("severity", Some(value))]).is_empty());
        }
    }

    #[test]
    fn an_unrelated_severity_keeps_the_generic_warning() {
        let out = warnings(&ENGLISH, &[("severity", Some("urgent"))]);
        assert!(
            out[0].contains("is not one of the values the API lists"),
            "{out:?}"
        );
    }

    #[test]
    fn the_legacy_hint_waits_for_the_english_list() {
        // No list yet: the API still speaks the legacy scale, so say nothing.
        assert!(warnings(&WITHOUT_LISTS, &[("severity", Some("alto"))]).is_empty());
        // A list without the new name: nothing to point to, so the generic warning stays.
        let other_list = Operation {
            known_values: &[("severity", &["urgent"])],
            ..WITH_LISTS
        };
        let out = warnings(&other_list, &[("severity", Some("bajo"))]);
        assert!(
            out[0].contains("is not one of the values the API lists"),
            "{out:?}"
        );
    }

    #[test]
    fn the_legacy_hint_is_scoped_to_the_alert_severity_filter() {
        let other = Operation {
            id: "listRisks",
            known_values: &[("severity", &["high"])],
            ..WITH_LISTS
        };
        let out = warnings(&other, &[("severity", Some("alto"))]);
        assert!(
            out[0].contains("is not one of the values the API lists"),
            "{out:?}"
        );
    }

    #[test]
    fn control_characters_in_the_value_are_not_echoed() {
        let out = warnings(&WITH_LISTS, &[("severity", Some("a\u{1b}[31mb"))]);
        assert!(!out[0].contains('\u{1b}'), "{out:?}");
    }

    #[test]
    fn help_lists_the_values_only_when_the_document_does() {
        assert_eq!(
            help("Exact severity.", &WITH_LISTS, "severity"),
            "Exact severity. Known values: critical, high, medium, low."
        );
        assert_eq!(
            help("Exact severity.", &WITHOUT_LISTS, "severity"),
            "Exact severity."
        );
        assert_eq!(
            help("Exact category.", &WITH_LISTS, "category"),
            "Exact category."
        );
    }
}
