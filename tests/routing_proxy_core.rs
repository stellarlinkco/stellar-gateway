use stellar_gateway::routing::is_wildcard_host_match;

#[test]
fn is_wildcard_host_match_should_match_case_insensitive_and_ignore_port() {
    assert!(is_wildcard_host_match(
        "Foo.PaGe.HdD.InK:443",
        "page.hdd.ink"
    ));
}

#[test]
fn is_wildcard_host_match_should_not_match_apex_suffix() {
    assert!(!is_wildcard_host_match("page.hdd.ink", "page.hdd.ink"));
}

#[test]
fn is_wildcard_host_match_should_not_match_outside_host() {
    assert!(!is_wildcard_host_match("example.com", "page.hdd.ink"));
}

#[test]
fn is_wildcard_host_match_should_match_multiple_labels_before_suffix() {
    assert!(is_wildcard_host_match("a.b.page.hdd.ink", "page.hdd.ink"));
}

#[test]
fn is_wildcard_host_match_should_not_match_when_label_is_missing() {
    assert!(!is_wildcard_host_match(".page.hdd.ink", "page.hdd.ink"));
}
