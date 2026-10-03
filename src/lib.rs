//! Deterministic, fail-closed checks for JSON candidates.

#![forbid(unsafe_code)]

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// A versioned collection of hard predicates.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: String,
    pub rules: Vec<Rule>,
}

/// One named predicate evaluated at an RFC 6901 JSON Pointer.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub pointer: String,
    pub check: Check,
}

/// Supported deterministic predicates.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Check {
    Exists,
    Absent,
    Equals {
        value: Value,
    },
    OneOf {
        values: Vec<Value>,
    },
    NumberRange {
        min: Option<f64>,
        max: Option<f64>,
    },
    StringLength {
        min: Option<usize>,
        max: Option<usize>,
    },
    StringPattern {
        pattern: String,
    },
    ArrayLength {
        min: Option<usize>,
        max: Option<usize>,
    },
}

/// The final admission result.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
}

/// Result of one rule, retained even when another rule has already failed.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleResult {
    pub id: String,
    pub pointer: String,
    pub passed: bool,
    pub reason: String,
}

/// Reproducible evidence binding the policy, candidate, and rule results.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema_version: u32,
    pub policy_version: String,
    pub policy_sha256: String,
    pub candidate_sha256: String,
    pub decision: Decision,
    pub results: Vec<RuleResult>,
}

#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("policy version must not be empty")]
    EmptyVersion,
    #[error("rule id must not be empty")]
    EmptyRuleId,
    #[error("duplicate rule id: {0}")]
    DuplicateRuleId(String),
    #[error("rule {rule}: JSON Pointer must be empty or begin with '/': {pointer}")]
    InvalidPointer { rule: String, pointer: String },
    #[error("rule {rule}: minimum {min} is greater than maximum {max}")]
    InvalidRange {
        rule: String,
        min: String,
        max: String,
    },
    #[error("rule {rule}: at least one bound is required")]
    MissingBounds { rule: String },
    #[error("rule {rule}: one_of requires at least one value")]
    EmptyOneOf { rule: String },
    #[error("rule {rule}: invalid regex: {source}")]
    InvalidRegex {
        rule: String,
        #[source]
        source: regex::Error,
    },
    #[error("receipt does not match a fresh evaluation")]
    ReceiptMismatch,
    #[error("cannot serialize canonical JSON: {0}")]
    CanonicalJson(#[from] serde_json::Error),
}

impl Policy {
    /// Validate structural invariants before evaluating any candidate.
    pub fn validate(&self) -> Result<(), GateError> {
        if self.version.trim().is_empty() {
            return Err(GateError::EmptyVersion);
        }

        let mut ids = HashSet::new();
        for rule in &self.rules {
            if rule.id.trim().is_empty() {
                return Err(GateError::EmptyRuleId);
            }
            if !ids.insert(rule.id.as_str()) {
                return Err(GateError::DuplicateRuleId(rule.id.clone()));
            }
            if !rule.pointer.is_empty() && !rule.pointer.starts_with('/') {
                return Err(GateError::InvalidPointer {
                    rule: rule.id.clone(),
                    pointer: rule.pointer.clone(),
                });
            }
            validate_check(rule)?;
        }
        Ok(())
    }
}

fn validate_check(rule: &Rule) -> Result<(), GateError> {
    match &rule.check {
        Check::OneOf { values } if values.is_empty() => Err(GateError::EmptyOneOf {
            rule: rule.id.clone(),
        }),
        Check::NumberRange { min, max } => validate_bounds(&rule.id, *min, *max),
        Check::StringLength { min, max } | Check::ArrayLength { min, max } => {
            validate_bounds(&rule.id, *min, *max)
        }
        Check::StringPattern { pattern } => {
            Regex::new(pattern)
                .map(|_| ())
                .map_err(|source| GateError::InvalidRegex {
                    rule: rule.id.clone(),
                    source,
                })
        }
        _ => Ok(()),
    }
}

fn validate_bounds<T>(rule: &str, min: Option<T>, max: Option<T>) -> Result<(), GateError>
where
    T: PartialOrd + std::fmt::Display,
{
    match (min, max) {
        (None, None) => Err(GateError::MissingBounds {
            rule: rule.to_owned(),
        }),
        (Some(min), Some(max)) if min > max => Err(GateError::InvalidRange {
            rule: rule.to_owned(),
            min: min.to_string(),
            max: max.to_string(),
        }),
        _ => Ok(()),
    }
}

/// Evaluate all predicates and return a deterministic receipt.
pub fn evaluate(
    policy: &Policy,
    policy_json: &Value,
    candidate: &Value,
) -> Result<Receipt, GateError> {
    policy.validate()?;

    let results = policy
        .rules
        .iter()
        .map(|rule| evaluate_rule(rule, candidate))
        .collect::<Vec<_>>();
    let decision = if results.iter().all(|result| result.passed) {
        Decision::Allow
    } else {
        Decision::Deny
    };

    Ok(Receipt {
        schema_version: 1,
        policy_version: policy.version.clone(),
        policy_sha256: canonical_sha256(policy_json)?,
        candidate_sha256: canonical_sha256(candidate)?,
        decision,
        results,
    })
}

/// Re-evaluate the inputs and require the supplied receipt to match exactly.
pub fn verify_receipt(
    policy: &Policy,
    policy_json: &Value,
    candidate: &Value,
    receipt: &Receipt,
) -> Result<(), GateError> {
    let expected = evaluate(policy, policy_json, candidate)?;
    if &expected == receipt {
        Ok(())
    } else {
        Err(GateError::ReceiptMismatch)
    }
}

/// Hash JSON after recursively sorting object keys. Whitespace and key order do not affect it.
pub fn canonical_sha256(value: &Value) -> Result<String, GateError> {
    let canonical = canonicalize(value);
    let bytes = serde_json::to_vec(&canonical)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let object = keys
                .into_iter()
                .map(|key| (key.clone(), canonicalize(&values[key])))
                .collect();
            Value::Object(object)
        }
        scalar => scalar.clone(),
    }
}

fn evaluate_rule(rule: &Rule, candidate: &Value) -> RuleResult {
    let actual = candidate.pointer(&rule.pointer);
    let (passed, reason) = match &rule.check {
        Check::Exists => (
            actual.is_some(),
            if actual.is_some() {
                "value exists"
            } else {
                "value is missing"
            }
            .to_owned(),
        ),
        Check::Absent => (
            actual.is_none(),
            if actual.is_none() {
                "value is absent"
            } else {
                "value must be absent"
            }
            .to_owned(),
        ),
        check => match actual {
            None => (false, "value is missing".to_owned()),
            Some(value) => evaluate_value(check, value),
        },
    };

    RuleResult {
        id: rule.id.clone(),
        pointer: rule.pointer.clone(),
        passed,
        reason,
    }
}

fn evaluate_value(check: &Check, value: &Value) -> (bool, String) {
    match check {
        Check::Equals { value: expected } => verdict(
            value == expected,
            "value equals expected",
            "value differs from expected",
        ),
        Check::OneOf { values } => verdict(
            values.contains(value),
            "value is in the allowed set",
            "value is not in the allowed set",
        ),
        Check::NumberRange { min, max } => match value.as_f64() {
            Some(number) if number.is_finite() => range_verdict(number, *min, *max, "number"),
            _ => (false, "value is not a finite JSON number".to_owned()),
        },
        Check::StringLength { min, max } => match value.as_str() {
            Some(text) => range_verdict(text.chars().count(), *min, *max, "string length"),
            None => (false, "value is not a string".to_owned()),
        },
        Check::StringPattern { pattern } => match value.as_str() {
            Some(text) => {
                let matched = Regex::new(pattern).is_ok_and(|regex| regex.is_match(text));
                verdict(
                    matched,
                    "string matches pattern",
                    "string does not match pattern",
                )
            }
            None => (false, "value is not a string".to_owned()),
        },
        Check::ArrayLength { min, max } => match value.as_array() {
            Some(items) => range_verdict(items.len(), *min, *max, "array length"),
            None => (false, "value is not an array".to_owned()),
        },
        Check::Exists | Check::Absent => unreachable!("handled before value evaluation"),
    }
}

fn range_verdict<T>(value: T, min: Option<T>, max: Option<T>, label: &str) -> (bool, String)
where
    T: PartialOrd + Copy,
{
    let above_min = min.is_none_or(|minimum| value >= minimum);
    let below_max = max.is_none_or(|maximum| value <= maximum);
    verdict(
        above_min && below_max,
        &format!("{label} is within bounds"),
        &format!("{label} is outside bounds"),
    )
}

fn verdict(passed: bool, pass: &str, fail: &str) -> (bool, String) {
    (passed, if passed { pass } else { fail }.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_policy() -> (Policy, Value) {
        let json = json!({
            "version": "transfer-v1",
            "rules": [
                {"id": "currency", "pointer": "/currency", "check": {"type": "one_of", "values": ["CAD", "USD"]}},
                {"id": "amount", "pointer": "/amount", "check": {"type": "number_range", "min": 0.01, "max": 5000.0}},
                {"id": "memo", "pointer": "/memo", "check": {"type": "string_length", "max": 40}},
                {"id": "no_override", "pointer": "/admin_override", "check": {"type": "absent"}}
            ]
        });
        (serde_json::from_value(json.clone()).unwrap(), json)
    }

    #[test]
    fn allows_candidate_when_every_rule_passes() {
        let (policy, policy_json) = sample_policy();
        let receipt = evaluate(
            &policy,
            &policy_json,
            &json!({"currency": "CAD", "amount": 125.50, "memo": "invoice-42"}),
        )
        .unwrap();

        assert_eq!(receipt.decision, Decision::Allow);
        assert!(receipt.results.iter().all(|result| result.passed));
    }

    #[test]
    fn denies_and_reports_every_failure() {
        let (policy, policy_json) = sample_policy();
        let receipt = evaluate(
            &policy,
            &policy_json,
            &json!({"currency": "EUR", "amount": 9000, "admin_override": true}),
        )
        .unwrap();

        assert_eq!(receipt.decision, Decision::Deny);
        assert_eq!(
            receipt
                .results
                .iter()
                .filter(|result| !result.passed)
                .count(),
            4
        );
    }

    #[test]
    fn canonical_hash_ignores_object_key_order() {
        let left: Value = serde_json::from_str(r#"{"a":1,"b":{"x":2,"y":3}}"#).unwrap();
        let right: Value = serde_json::from_str(r#"{"b":{"y":3,"x":2},"a":1}"#).unwrap();
        assert_eq!(
            canonical_sha256(&left).unwrap(),
            canonical_sha256(&right).unwrap()
        );
    }

    #[test]
    fn verification_detects_a_modified_receipt() {
        let (policy, policy_json) = sample_policy();
        let candidate = json!({"currency": "CAD", "amount": 125.50, "memo": "invoice-42"});
        let mut receipt = evaluate(&policy, &policy_json, &candidate).unwrap();
        receipt.candidate_sha256 = "00".repeat(32);

        assert!(matches!(
            verify_receipt(&policy, &policy_json, &candidate, &receipt),
            Err(GateError::ReceiptMismatch)
        ));
    }

    #[test]
    fn rejects_invalid_policy_before_evaluation() {
        let policy_json = json!({
            "version": "bad-v1",
            "rules": [{"id": "amount", "pointer": "/amount", "check": {"type": "number_range", "min": 10, "max": 1}}]
        });
        let policy: Policy = serde_json::from_value(policy_json.clone()).unwrap();

        assert!(matches!(
            evaluate(&policy, &policy_json, &json!({"amount": 5})),
            Err(GateError::InvalidRange { .. })
        ));
    }

    #[test]
    fn supports_each_predicate_and_escaped_json_pointers() {
        let policy_json = json!({
            "version": "complete-v1",
            "rules": [
                {"id": "present", "pointer": "/nested/value", "check": {"type": "exists"}},
                {"id": "equal", "pointer": "/mode", "check": {"type": "equals", "value": "strict"}},
                {"id": "pattern", "pointer": "/ticket", "check": {"type": "string_pattern", "pattern": "^INC-[0-9]{4}$"}},
                {"id": "array", "pointer": "/reviewers", "check": {"type": "array_length", "min": 1, "max": 2}},
                {"id": "escaped", "pointer": "/a~1b/~0key", "check": {"type": "equals", "value": true}}
            ]
        });
        let policy: Policy = serde_json::from_value(policy_json.clone()).unwrap();
        let candidate = json!({
            "nested": {"value": null},
            "mode": "strict",
            "ticket": "INC-0042",
            "reviewers": ["alice"],
            "a/b": {"~key": true}
        });

        let receipt = evaluate(&policy, &policy_json, &candidate).unwrap();
        assert_eq!(receipt.decision, Decision::Allow);
        assert_eq!(receipt.results.len(), 5);
    }
}
