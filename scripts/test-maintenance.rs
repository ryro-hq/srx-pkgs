use super::*;
fn policy() -> Policy {
    serde_json::from_str(include_str!("fixtures/maintenance-policy.json")).unwrap()
}
fn inventory() -> Inventory {
    serde_json::from_str(include_str!("../maintenance.json")).unwrap()
}
fn exports() -> Vec<String> {
    vec!["bootstrap".into(), "glibc".into(), "hello".into()]
}
#[test]
fn declared_owners_never_grant_authority() {
    let base = inventory();
    let mut proposed = inventory();
    proposed.packages[0].owners.push("human-declaration".into());
    let report = reconcile(exports(), &policy(), &base, &proposed).unwrap();
    assert!(report.inventory_consistent);
    assert!(!report.authorized && !report.promotion_ready);
    assert_eq!(report.membership_verification, "pending");
    assert_eq!(report.ownership_declared, vec!["bootstrap"]);
    assert_eq!(report.needs_owner, vec!["glibc", "hello"]);
}
#[test]
fn removed_records_and_tests_cannot_shrink_baseline() {
    let base = inventory();
    let mut proposed = inventory();
    proposed.packages.pop();
    proposed.packages[1]
        .tests
        .retain(|t| t != "hello-offline-consumption");
    let r = reconcile(exports(), &policy(), &base, &proposed).unwrap();
    assert!(r.blocked.contains(&"removed-base-record:hello".into()));
    assert!(
        r.blocked
            .contains(&"removed-base-test:glibc:hello-offline-consumption".into())
    );
    assert!(!r.inventory_consistent);
}
#[test]
fn new_export_and_stale_record_block_and_order_is_canonical() {
    let base = inventory();
    let mut changed = exports();
    changed.retain(|s| s != "hello");
    changed.push("new".into());
    let first = reconcile(changed.clone(), &policy(), &base, &inventory()).unwrap();
    changed.reverse();
    assert!(first.blocked.contains(&"missing-record:new".into()));
    assert!(first.blocked.contains(&"stale-record:hello".into()));
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&reconcile(changed, &policy(), &base, &inventory()).unwrap()).unwrap()
    );
}
#[test]
fn schemas_duplicates_empty_policy_and_changed_roles_fail_closed() {
    assert!(
        serde_json::from_str::<Policy>(
            r#"{"version":1,"version":1,"roles":[],"required_tests":[]}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<Policy>(
            r#"{"version":1,"roles":[],"required_tests":[],"approve":true}"#
        )
        .is_err()
    );
    let mut proposed = inventory();
    proposed.packages[1].export = "bootstrap".into();
    assert!(reconcile(exports(), &policy(), &inventory(), &proposed).is_err());
    let mut p = policy();
    p.required_tests.clear();
    assert!(reconcile(exports(), &p, &inventory(), &inventory()).is_err());
    let mut proposed = inventory();
    proposed.packages[1].roles.retain(|r| r != "toolchain");
    assert!(
        reconcile(exports(), &policy(), &inventory(), &proposed)
            .unwrap()
            .blocked
            .contains(&"removed-base-role:glibc:toolchain".into())
    );
}
#[test]
fn document_pin_bounds_and_symlinks_are_checked() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("policy.json");
    std::fs::write(&file, b"{}").unwrap();
    assert_eq!(
        pinned(&file, &ContentDigest::sha256(b"{}").to_string()).unwrap(),
        b"{}"
    );
    assert!(pinned(&file, &ContentDigest::sha256(b"changed").to_string()).is_err());
    assert!(pinned(&file, "invalid").is_err());
    std::os::unix::fs::symlink(&file, dir.path().join("alias")).unwrap();
    assert!(
        pinned(
            &dir.path().join("alias"),
            &ContentDigest::sha256(b"{}").to_string()
        )
        .is_err()
    );
    OpenOptions::new()
        .write(true)
        .open(&file)
        .unwrap()
        .set_len(MAX_BYTES as u64 + 1)
        .unwrap();
    assert!(pinned(&file, &ContentDigest::sha256(b"{}").to_string()).is_err());
}
#[test]
fn locked_discovery_does_not_execute_failing_factory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("main.srx"),
        r#"
 mod factories {
     mod never_evaluate {
         pub fn recipe() -> std::Recipe { recipe() }
     }
 }
 pub publish(factories, recipe): std::Recipe;
 "#,
    )
    .unwrap();
    syrox_engine::project::lock_project_with(dir.path(), &checks()).unwrap();
    let project = open_locked_project_with(dir.path(), &checks()).unwrap();
    let pin = project
        .lock_digest()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(discover(dir.path(), &pin).unwrap(), vec!["never_evaluate"]);
    assert!(discover(dir.path(), &"0".repeat(64)).is_err());
}
