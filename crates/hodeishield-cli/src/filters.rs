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
