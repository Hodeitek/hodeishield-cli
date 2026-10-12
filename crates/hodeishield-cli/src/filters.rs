// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! The values the API document lists for a filter (`x-hs-known-values`): shown in `--help` and
//! checked before a request. The lists are open vocabularies, so a value that is not listed is
//! warned about and sent exactly as typed; nothing here refuses a value or rewrites it.
//!
//! The document may also mark values as deprecated (`x-hs-deprecated-values`, with the last day
//! they are accepted in `x-hs-deprecated-values-sunset`). Such a value gets its own warning, which
//! points to the listed values, and is still sent exactly as typed.

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

/// Replacements for the deprecated values of the alert `severity` filter.
///
/// This table exists only because the API document lists the deprecated values without their
/// replacements. Remove it, and its use in [`deprecated_hint`], after the sunset, 2027-01-14.
const SEVERITY_REPLACEMENTS: &[(&str, &str)] = &[
    ("critico", "critical"),
    ("alto", "high"),
    ("medio", "medium"),
    ("bajo", "low"),
];

/// The listed value that replaces the deprecated `value`, when [`SEVERITY_REPLACEMENTS`] knows one
/// and the document lists it.
fn replacement(operation: &Operation, param: &str, value: &str) -> Option<&'static str> {
    if operation.id != "listAlerts" || param != "severity" {
        return None;
    }
    let (_, current) = SEVERITY_REPLACEMENTS
        .iter()
        .find(|(deprecated, _)| deprecated.eq_ignore_ascii_case(value))?;
    operation
        .known_values(param)
        .is_some_and(|known| known.contains(current))
        .then_some(*current)
}

/// The warning for a value the document marks as deprecated for `param` (matched without regard
/// to case), or `None` when it does not.
fn deprecated_hint(operation: &Operation, param: &str, value: &str) -> Option<String> {
    let deprecated = operation.deprecated_values(param)?;
    if !deprecated
        .values
        .iter()
        .any(|d| d.eq_ignore_ascii_case(value))
    {
        return None;
    }
    let until = deprecated.sunset.map_or_else(String::new, |date| {
        format!(", accepted by the API until {date}")
    });
    let known = operation.known_values(param).filter(|v| !v.is_empty());
    let advice = match (replacement(operation, param, value), known) {
        (Some(current), _) => format!("; use `{current}`"),
        (None, Some(known)) => format!("; use one of the listed values ({})", known.join(", ")),
        (None, None) => String::new(),
    };
    Some(format!(
        "warning: `{}` is a deprecated value for --{}{until}{advice}. Sending it as typed.",
        clean(value),
        param.replace('_', "-"),
    ))
}

/// The warnings for the `(parameter, value)` pairs the user gave: one per value the document marks
/// as deprecated for that parameter, and one per value that is not in the list it publishes. A
/// parameter without either list never warns. The match against the list is exact and
/// case-sensitive, as the API is; a value that differs only by case also gets the listed spelling
/// as a hint.
pub fn warnings(operation: &Operation, filters: &[(&str, Option<&str>)]) -> Vec<String> {
    filters
        .iter()
        .filter_map(|&(param, value)| {
            let value = value?;
            let known = operation.known_values(param).filter(|v| !v.is_empty());
            if known.is_some_and(|known| known.contains(&value)) {
                return None;
            }
            if let Some(hint) = deprecated_hint(operation, param, value) {
                return Some(hint);
            }
            let known = known?;
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
    use hodeishield_api::DeprecatedValues;

    const WITH_LISTS: Operation = Operation {
        id: "listAlerts",
        method: "GET",
        path: "/v1/alerts",
        summary: "List alerts",
        scopes: &[],
        known_values: &[("severity", &["critical", "high", "medium", "low"])],
        deprecated_values: &[],
        tenant_scoped: true,
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

    const ALERTS: Operation = Operation {
        known_values: &[("severity", &["critical", "high", "medium", "low", "info"])],
        deprecated_values: &[DeprecatedValues {
            param: "severity",
            values: &["critico", "alto", "medio", "bajo", "urgente"],
            sunset: Some("2027-01-14"),
        }],
        ..WITH_LISTS
    };

    #[test]
    fn a_deprecated_value_with_a_replacement_points_to_it() {
        assert_eq!(
            warnings(&ALERTS, &[("severity", Some("alto"))]),
            [
                "warning: `alto` is a deprecated value for --severity, accepted by the API until \
                 2027-01-14; use `high`. Sending it as typed."
            ]
        );
        for (deprecated, current) in [
            ("critico", "critical"),
            ("medio", "medium"),
            ("bajo", "low"),
        ] {
            let out = warnings(&ALERTS, &[("severity", Some(deprecated))]);
            assert!(out[0].contains(&format!("use `{current}`")), "{out:?}");
        }
    }

    #[test]
    fn a_deprecated_value_is_matched_without_regard_to_case() {
        let out = warnings(&ALERTS, &[("severity", Some("ALTO"))]);
        assert_eq!(out.len(), 1);
        assert!(out[0].starts_with("warning: `ALTO` is a deprecated value for --severity"));
        assert!(out[0].contains("use `high`"), "{out:?}");
    }

    #[test]
    fn a_deprecated_value_without_a_replacement_points_to_the_listed_values() {
        assert_eq!(
            warnings(&ALERTS, &[("severity", Some("urgente"))]),
            [
                "warning: `urgente` is a deprecated value for --severity, accepted by the API \
                 until 2027-01-14; use one of the listed values (critical, high, medium, low, \
                 info). Sending it as typed."
            ]
        );
        // A replacement the document does not list is not offered.
        let unlisted = Operation {
            known_values: &[("severity", &["urgent"])],
            ..ALERTS
        };
        let out = warnings(&unlisted, &[("severity", Some("alto"))]);
        assert!(
            out[0].ends_with("use one of the listed values (urgent). Sending it as typed."),
            "{out:?}"
        );
    }

    #[test]
    fn a_deprecated_value_without_a_sunset_or_a_list() {
        let no_sunset = Operation {
            id: "listRisks",
            known_values: &[("min_score", &["low", "high"])],
            deprecated_values: &[DeprecatedValues {
                param: "min_score",
                values: &["bajo"],
                sunset: None,
            }],
            ..WITH_LISTS
        };
        assert_eq!(
            warnings(&no_sunset, &[("min_score", Some("bajo"))]),
            [
                "warning: `bajo` is a deprecated value for --min-score; use one of the listed \
                 values (low, high). Sending it as typed."
            ]
        );
        let no_list = Operation {
            known_values: &[],
            ..no_sunset
        };
        assert_eq!(
            warnings(&no_list, &[("min_score", Some("bajo"))]),
            ["warning: `bajo` is a deprecated value for --min-score. Sending it as typed."]
        );
    }

    #[test]
    fn the_replacements_apply_to_the_alert_severity_filter_only() {
        let other = Operation {
            id: "listRisks",
            ..ALERTS
        };
        let out = warnings(&other, &[("severity", Some("alto"))]);
        assert!(out[0].contains("use one of the listed values"), "{out:?}");
    }

    #[test]
    fn a_current_severity_is_silent() {
        for value in ["critical", "high", "medium", "low", "info"] {
            assert!(warnings(&ALERTS, &[("severity", Some(value))]).is_empty());
        }
    }

    #[test]
    fn an_unrelated_severity_keeps_the_generic_warning() {
        let out = warnings(&ALERTS, &[("severity", Some("urgent"))]);
        assert!(
            out[0].contains("is not one of the values the API lists"),
            "{out:?}"
        );
    }

    /// Fails when the document adds or removes a deprecated severity, so the table above follows
    /// it, and when a replacement is not a listed value.
    #[test]
    fn the_replacements_match_the_generated_alert_severity_filter() {
        let operation = hodeishield_api::v1::operations::LIST_ALERTS;
        let deprecated = operation
            .deprecated_values("severity")
            .expect("the document deprecates severity values");
        let mut listed: Vec<&str> = deprecated.values.to_vec();
        listed.sort_unstable();
        let mut mapped: Vec<&str> = SEVERITY_REPLACEMENTS.iter().map(|(d, _)| *d).collect();
        mapped.sort_unstable();
        assert_eq!(mapped, listed);
        let known = operation.known_values("severity").expect("listed values");
        for (_, current) in SEVERITY_REPLACEMENTS {
            assert!(known.contains(current), "{current}");
        }
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
