//! PROTO-01: shared manifest byte fixtures — the same cases.tsv is
//! consumed by the Worker parser test (syncd/test/manifest-fixtures.test.mjs),
//! so the two relays can never drift on accept/reject for a given input.
//! Regenerate fixtures: `node syncd/test/gen-manifest-fixtures.mjs`.

use mpm_core::Manifest;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

#[test]
fn shared_manifest_fixtures() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/manifest/cases.tsv"
    );
    let data = std::fs::read_to_string(path).expect("run gen-manifest-fixtures.mjs first");
    let mut n = 0;
    for line in data.lines() {
        if line.is_empty() {
            continue;
        }
        let mut f = line.split('\t');
        let name = f.next().unwrap();
        let expect = f.next().unwrap();
        let bytes = unhex(f.next().unwrap().trim());
        let res = Manifest::from_file(&bytes);
        let ok = res.is_ok();
        assert_eq!(ok, expect == "ok", "fixture {name}: {res:?}");
        n += 1;
    }
    assert!(n >= 30, "fixture file looks truncated ({n} cases)");
}
