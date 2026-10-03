use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

#[test]
fn check_and_verify_round_trip() {
    let directory = tempdir().unwrap();
    let receipt = directory.path().join("receipt.json");

    let output = Command::cargo_bin("predicate-receipt")
        .unwrap()
        .args([
            "check",
            "--policy",
            "examples/transfer-policy.json",
            "--input",
            "examples/allowed-transfer.json",
            "--receipt",
        ])
        .arg(&receipt)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(parsed["decision"], "allow");
    assert!(receipt.exists());

    Command::cargo_bin("predicate-receipt")
        .unwrap()
        .args([
            "verify",
            "--policy",
            "examples/transfer-policy.json",
            "--input",
            "examples/allowed-transfer.json",
            "--receipt",
        ])
        .arg(&receipt)
        .assert()
        .success()
        .stdout(predicate::str::contains("receipt verified"));
}

#[test]
fn denied_candidate_uses_distinct_exit_code_and_still_emits_receipt() {
    Command::cargo_bin("predicate-receipt")
        .unwrap()
        .args([
            "check",
            "--policy",
            "examples/transfer-policy.json",
            "--input",
            "examples/denied-transfer.json",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains(r#""decision": "deny""#));
}

#[test]
fn verify_rejects_tampered_candidate() {
    let directory = tempdir().unwrap();
    let receipt = directory.path().join("receipt.json");
    let candidate = directory.path().join("candidate.json");
    fs::copy("examples/allowed-transfer.json", &candidate).unwrap();

    Command::cargo_bin("predicate-receipt")
        .unwrap()
        .args([
            "check",
            "--policy",
            "examples/transfer-policy.json",
            "--input",
        ])
        .arg(&candidate)
        .arg("--receipt")
        .arg(&receipt)
        .assert()
        .success();

    fs::write(
        &candidate,
        r#"{"currency":"CAD","amount":999,"memo":"changed"}"#,
    )
    .unwrap();

    Command::cargo_bin("predicate-receipt")
        .unwrap()
        .args([
            "verify",
            "--policy",
            "examples/transfer-policy.json",
            "--input",
        ])
        .arg(&candidate)
        .arg("--receipt")
        .arg(&receipt)
        .assert()
        .failure()
        .stderr(predicate::str::contains("receipt does not match"));
}
