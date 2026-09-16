//! End-to-end: init vault → add items → reopen → verify + decrypt.
//! Exercises manifest signing, wrap slots, op chain, both AEAD layers,
//! tamper detection, and wrong-password rejection.

use mpm_core::item::{tag, Item, ItemKind};
use mpm_core::manifest::{WrapSlot, SLOT_PASSWORD, SLOT_RECOVERY};
use mpm_core::{recovery, Manifest, Vault};
use mpm_crypto::kdf::{self, KdfParams};
use mpm_crypto::keys::{DeviceKey, KeyBundle};

const FAST: KdfParams = KdfParams { m_kib: 1024, t: 1, p: 1 };

fn tmpdir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "mpm-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Create vault on disk; returns (device key, seed, recovery code).
fn init(dir: &std::path::Path, pw: &[u8]) -> (DeviceKey, [u8; 32], [u8; 16]) {
    mpm_store::init_dir(dir).unwrap();
    let mut salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut salt);
    let kek = kdf::derive_kek(pw, &salt, &FAST).unwrap();

    let bundle = KeyBundle::generate();
    let device = DeviceKey::generate();
    let seed = *device.seed_bytes();

    let mut m = Manifest::new(FAST, salt, bundle.owner_verifying_key());
    m.wrap_slots.push(WrapSlot {
        slot_type: SLOT_PASSWORD,
        kdf: Some((FAST, salt)),
        blob: bundle.wrap(&kek, &mpm_core::aad::wrap_slot(SLOT_PASSWORD)).unwrap(),
    });

    let raw_code = recovery::generate_code();
    let mut rsalt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut rsalt);
    let rkek = kdf::derive_kek(&raw_code, &rsalt, &FAST).unwrap();
    m.wrap_slots.push(WrapSlot {
        slot_type: SLOT_RECOVERY,
        kdf: Some((FAST, rsalt)),
        blob: bundle.wrap(&rkek, &mpm_core::aad::wrap_slot(SLOT_RECOVERY)).unwrap(),
    });

    m.devices.push(mpm_core::DeviceEntry {
        id: device.id,
        vk: device.verifying_key(),
        name: "test".into(),
        active: true,
        enrolled_at: 0,
    });
    let sk = bundle.owner_signing_key();
    let bytes = m.to_file(&sk);
    mpm_store::write_manifest(dir, &bytes).unwrap();
    (device, seed, raw_code)
}

fn reopen(dir: &std::path::Path, pw: &[u8], seed: &[u8; 32], dev_id: [u8; 16]) -> Vault {
    let m = mpm_store::load_manifest(dir).unwrap();
    let (params, salt) = m.wrap_slots[0].kdf.unwrap();
    let kek = kdf::derive_kek(pw, &salt, &params).unwrap();
    let bundle =
        KeyBundle::unwrap(&kek, &mpm_core::aad::wrap_slot(SLOT_PASSWORD), &m.wrap_slots[0].blob)
            .expect("unwrap");
    let mut v = Vault::new(m, bundle, DeviceKey::from_bytes(seed, dev_id)).unwrap();
    for op in &mpm_store::read_ops(dir, &dev_id).unwrap() {
        v.apply_own_op(op).unwrap();
    }
    v
}

fn login(name: &str, user: &str, pass: &str) -> Item {
    let mut i = Item::default();
    i.set(tag::NAME, name.as_bytes().to_vec());
    i.set(tag::USERNAME, user.as_bytes().to_vec());
    i.set(tag::PASSWORD, pass.as_bytes().to_vec());
    i
}

#[test]
fn roundtrip_add_reopen_decrypt() {
    let dir = tmpdir();
    let pw = b"correct horse battery staple";
    let (device, seed, _code) = init(&dir, pw);
    let dev_id = device.id;

    let m = mpm_store::load_manifest(&dir).unwrap();
    let (params, salt) = m.wrap_slots[0].kdf.unwrap();
    let kek = kdf::derive_kek(pw, &salt, &params).unwrap();
    let bundle =
        KeyBundle::unwrap(&kek, &mpm_core::aad::wrap_slot(SLOT_PASSWORD), &m.wrap_slots[0].blob)
            .unwrap();
    let mut vault = Vault::new(m, bundle, device).unwrap();

    let (op, rid) = vault.make_upsert(ItemKind::Login, login("github", "chus", "hunter2")).unwrap();
    mpm_store::append_op(&dir, &dev_id, &op).unwrap();
    vault.commit(&op).unwrap();

    let mut card = Item::default();
    card.set(tag::NAME, b"amex".to_vec());
    card.set(tag::CARD_NUMBER, b"370000000000000".to_vec());
    card.set(tag::CARD_CVV, b"1234".to_vec());
    let (op2, _rid2) = vault.make_upsert(ItemKind::Card, card).unwrap();
    mpm_store::append_op(&dir, &dev_id, &op2).unwrap();
    vault.commit(&op2).unwrap();

    // full reopen path
    let v2 = reopen(&dir, pw, &seed, dev_id);
    assert_eq!(v2.records().count(), 2);
    let found = v2.find("github").expect("find by name");
    assert_eq!(found, rid);
    let item = v2.item(&found).unwrap();
    assert_eq!(item.get_str(tag::PASSWORD), Some("hunter2"));
    assert_eq!(item.get_str(tag::USERNAME), Some("chus"));
}

#[test]
fn tombstone_hides_item() {
    let dir = tmpdir();
    let pw = b"pw";
    let (device, seed, _code) = init(&dir, pw);
    let dev_id = device.id;

    let m = mpm_store::load_manifest(&dir).unwrap();
    let (params, salt) = m.wrap_slots[0].kdf.unwrap();
    let kek = kdf::derive_kek(pw, &salt, &params).unwrap();
    let bundle =
        KeyBundle::unwrap(&kek, &mpm_core::aad::wrap_slot(SLOT_PASSWORD), &m.wrap_slots[0].blob)
            .unwrap();
    let mut vault = Vault::new(m, bundle, device).unwrap();

    let (op, rid) = vault.make_upsert(ItemKind::Secret, {
        let mut i = Item::default();
        i.set(tag::NAME, b"tmp".to_vec());
        i.set(tag::TEXT, b"x".to_vec());
        i
    }).unwrap();
    mpm_store::append_op(&dir, &dev_id, &op).unwrap();
    vault.commit(&op).unwrap();

    let tomb = vault.make_tombstone(&rid).unwrap();
    mpm_store::append_op(&dir, &dev_id, &tomb).unwrap();
    vault.commit(&tomb).unwrap();

    let v2 = reopen(&dir, pw, &seed, dev_id);
    assert_eq!(v2.records().count(), 0);
    assert!(v2.item(&rid).is_err());
}

#[test]
fn tampered_op_rejected() {
    let dir = tmpdir();
    let pw = b"pw";
    let (device, seed, _code) = init(&dir, pw);
    let dev_id = device.id;

    let m = mpm_store::load_manifest(&dir).unwrap();
    let (params, salt) = m.wrap_slots[0].kdf.unwrap();
    let kek = kdf::derive_kek(pw, &salt, &params).unwrap();
    let bundle =
        KeyBundle::unwrap(&kek, &mpm_core::aad::wrap_slot(SLOT_PASSWORD), &m.wrap_slots[0].blob)
            .unwrap();
    let mut vault = Vault::new(m, bundle, device).unwrap();

    let (op, _rid) = vault.make_upsert(ItemKind::Login, login("a", "b", "c")).unwrap();
    mpm_store::append_op(&dir, &dev_id, &op).unwrap();
    vault.commit(&op).unwrap();

    // flip a ciphertext byte on disk → AEAD must reject on reopen
    let path = mpm_store::log_path(&dir, &dev_id);
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();

    let m2 = mpm_store::load_manifest(&dir).unwrap();
    let (p2, s2) = m2.wrap_slots[0].kdf.unwrap();
    let kek2 = kdf::derive_kek(pw, &s2, &p2).unwrap();
    let b2 = KeyBundle::unwrap(&kek2, &mpm_core::aad::wrap_slot(SLOT_PASSWORD), &m2.wrap_slots[0].blob).unwrap();
    let mut v2 = Vault::new(m2, b2, DeviceKey::from_bytes(&seed, dev_id)).unwrap();
    let ops = mpm_store::read_ops(&dir, &dev_id).unwrap();
    assert!(v2.apply_own_op(&ops[0]).is_err(), "tampered op must not verify");
}

#[test]
fn recovery_code_unlocks_and_parses() {
    let dir = tmpdir();
    let (device, seed, code) = init(&dir, b"pw");
    let dev_id = device.id;

    // format → parse roundtrip, including typo-tolerance (o→0, l→1)
    let formatted = recovery::format_code(&code);
    assert_eq!(recovery::parse_code(&formatted).unwrap(), code);

    // unlock via the RECOVERY slot with the raw code
    let m = mpm_store::load_manifest(&dir).unwrap();
    let slot = m
        .wrap_slots
        .iter()
        .find(|s| s.slot_type == SLOT_RECOVERY)
        .unwrap()
        .clone();
    let (params, salt) = slot.kdf.unwrap();
    let kek = kdf::derive_kek(&code, &salt, &params).unwrap();
    let bundle =
        KeyBundle::unwrap(&kek, &mpm_core::aad::wrap_slot(SLOT_RECOVERY), &slot.blob).unwrap();
    assert!(Vault::new(m, bundle, DeviceKey::from_bytes(&seed, dev_id)).is_ok());

    // a wrong code must not unwrap the recovery slot
    let mut bad = code;
    bad[0] ^= 0xff;
    let kek_bad = kdf::derive_kek(&bad, &salt, &params).unwrap();
    assert!(KeyBundle::unwrap(&kek_bad, &mpm_core::aad::wrap_slot(SLOT_RECOVERY), &slot.blob).is_err());
}

#[test]
fn wrong_password_fails() {
    let dir = tmpdir();
    init(&dir, b"right");
    let m = mpm_store::load_manifest(&dir).unwrap();
    let (params, salt) = m.wrap_slots[0].kdf.unwrap();
    let kek = kdf::derive_kek(b"wrong", &salt, &params).unwrap();
    assert!(
        KeyBundle::unwrap(&kek, &mpm_core::aad::wrap_slot(SLOT_PASSWORD), &m.wrap_slots[0].blob)
            .is_err()
    );
}
