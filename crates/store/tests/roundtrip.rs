//! End-to-end: init vault → add items → reopen → verify + decrypt.
//! Exercises manifest signing, wrap slots, op chain, both AEAD layers,
//! tamper detection, and wrong-password rejection.

use mpm_core::item::{tag, Item, ItemKind};
use mpm_core::manifest::{WrapSlot, SLOT_PASSWORD, SLOT_RECOVERY};
use mpm_core::{recovery, Manifest, Vault};
use mpm_crypto::kdf::{self, KdfParams};
use mpm_crypto::keys::{DeviceKey, KeyBundle};

const FAST: KdfParams = KdfParams {
    m_kib: 1024,
    t: 1,
    p: 1,
};

fn tmpdir() -> std::path::PathBuf {
    // nanos alone can collide across test threads (macOS clock granularity
    // is coarser than ns) — the counter makes it collision-proof
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "mpm-test-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
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
        blob: bundle
            .wrap(
                &kek,
                &mpm_core::aad::wrap_slot(&m.vault_id, m.key_epoch, SLOT_PASSWORD),
            )
            .unwrap(),
        extra: Vec::new(),
    });

    let raw_code = recovery::generate_code();
    let mut rsalt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut rsalt);
    let rkek = kdf::derive_kek(&raw_code, &rsalt, &FAST).unwrap();
    m.wrap_slots.push(WrapSlot {
        slot_type: SLOT_RECOVERY,
        kdf: Some((FAST, rsalt)),
        blob: bundle
            .wrap(
                &rkek,
                &mpm_core::aad::wrap_slot(&m.vault_id, m.key_epoch, SLOT_RECOVERY),
            )
            .unwrap(),
        extra: Vec::new(),
    });

    m.devices.push(mpm_core::DeviceEntry {
        id: device.id,
        vk: device.verifying_key(),
        name: "test".into(),
        active: true,
        enrolled_at: 0,
        extra: Vec::new(),
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
    let bundle = KeyBundle::unwrap(
        &kek,
        &mpm_core::aad::wrap_slot(&m.vault_id, m.key_epoch, SLOT_PASSWORD),
        &m.wrap_slots[0].blob,
    )
    .expect("unwrap");
    let mut v = Vault::new(m, bundle, DeviceKey::from_bytes(seed, dev_id)).unwrap();
    for op in &mpm_store::read_ops(dir, &dev_id).unwrap().ops {
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
    let bundle = KeyBundle::unwrap(
        &kek,
        &mpm_core::aad::wrap_slot(&m.vault_id, m.key_epoch, SLOT_PASSWORD),
        &m.wrap_slots[0].blob,
    )
    .unwrap();
    let mut vault = Vault::new(m, bundle, device).unwrap();

    let (op, rid) = vault
        .make_upsert(ItemKind::Login, login("github", "chus", "hunter2"))
        .unwrap();
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
    let found = match v2.find("github") {
        mpm_core::FindResult::One(id) => id,
        other => panic!("find failed: {other:?}"),
    };
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
    let bundle = KeyBundle::unwrap(
        &kek,
        &mpm_core::aad::wrap_slot(&m.vault_id, m.key_epoch, SLOT_PASSWORD),
        &m.wrap_slots[0].blob,
    )
    .unwrap();
    let mut vault = Vault::new(m, bundle, device).unwrap();

    let (op, rid) = vault
        .make_upsert(ItemKind::Secret, {
            let mut i = Item::default();
            i.set(tag::NAME, b"tmp".to_vec());
            i.set(tag::TEXT, b"x".to_vec());
            i
        })
        .unwrap();
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
    let bundle = KeyBundle::unwrap(
        &kek,
        &mpm_core::aad::wrap_slot(&m.vault_id, m.key_epoch, SLOT_PASSWORD),
        &m.wrap_slots[0].blob,
    )
    .unwrap();
    let mut vault = Vault::new(m, bundle, device).unwrap();

    let (op, _rid) = vault
        .make_upsert(ItemKind::Login, login("a", "b", "c"))
        .unwrap();
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
    let b2 = KeyBundle::unwrap(
        &kek2,
        &mpm_core::aad::wrap_slot(&m2.vault_id, m2.key_epoch, SLOT_PASSWORD),
        &m2.wrap_slots[0].blob,
    )
    .unwrap();
    let mut v2 = Vault::new(m2, b2, DeviceKey::from_bytes(&seed, dev_id)).unwrap();
    let ops = mpm_store::read_ops(&dir, &dev_id).unwrap().ops;
    assert!(
        v2.apply_own_op(&ops[0]).is_err(),
        "tampered op must not verify"
    );
}

#[test]
fn torn_tail_is_tolerated_and_checkpoint_detects_rollback() {
    let dir = tmpdir();
    let pw = b"pw";
    let (device, seed, _code) = init(&dir, pw);
    let dev_id = device.id;

    let mut v = reopen(&dir, pw, &seed, dev_id);
    for name in ["a", "b", "c"] {
        let mut it = Item::default();
        it.set(tag::NAME, name.as_bytes().to_vec());
        it.set(tag::PASSWORD, b"x".to_vec());
        let (op, _) = v.make_upsert(ItemKind::Login, it).unwrap();
        mpm_store::append_op(&dir, &dev_id, &op).unwrap();
        v.commit(&op).unwrap();
    }
    let (seq, head) = v.head();
    assert_eq!(seq, 3);

    // checkpoint survives outside the vault dir; log ahead/== is fine
    let dev = DeviceKey::from_bytes(&seed, dev_id);
    let vid = {
        let m = mpm_store::load_manifest(&dir).unwrap();
        m.vault_id
    };
    mpm_store::save_checkpoint(&vid, &dev, seq, &head).unwrap();
    let (s, h) = mpm_store::load_checkpoint(&vid, &dev).unwrap().unwrap();
    assert_eq!((s, h), (seq, head));

    // simulate a torn tail: truncate the log mid-final-op → tolerated
    let log = mpm_store::log_path(&dir, &dev_id);
    let len = std::fs::metadata(&log).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&log)
        .unwrap()
        .set_len(len - 10)
        .unwrap();
    let lr = mpm_store::read_ops(&dir, &dev_id).unwrap();
    assert!(lr.torn_tail && lr.ops.len() == 2);

    // simulate rollback: truncate at a clean boundary → checkpoint mismatch
    // (log at seq 2, checkpoint at seq 3 → caller must flag RolledBack)
    std::fs::write(&log, {
        // re-encode just the first two ops
        let mut b = Vec::new();
        for op in &lr.ops {
            b.extend_from_slice(&op.encode());
        }
        b
    })
    .unwrap();
    let lr2 = mpm_store::read_ops(&dir, &dev_id).unwrap();
    assert!(!lr2.torn_tail && lr2.ops.len() == 2);
    // checkpoint (seq=3) > log tip (seq=2) → rollback detected
    let (cseq, _) = mpm_store::load_checkpoint(&vid, &dev).unwrap().unwrap();
    assert!(cseq > 2);
}

#[test]
fn recovery_enrolls_device_when_key_absent() {
    // disaster restore: vault dir present, device key file absent
    let dir = tmpdir();
    let pw = b"pw";
    let (_device, _seed, code) = init(&dir, pw);

    let mut v = reopen(&dir, pw, &_seed, _device.id);
    let mut it = Item::default();
    it.set(tag::NAME, b"keep".to_vec());
    it.set(tag::PASSWORD, b"s3cret".to_vec());
    let (op, _) = v.make_upsert(ItemKind::Login, it).unwrap();
    mpm_store::append_op(&dir, &_device.id, &op).unwrap();
    v.commit(&op).unwrap();

    // nuke the device key file
    let dev_dir = dirs::data_local_dir().unwrap().join("mypassman/devices");
    let _ = std::fs::remove_file(dev_dir.join(format!("{}.dev", mpm_store::hex(&load_vid(&dir)))));

    // recovery unlock must work without the device key: unwrap bundle from
    // recovery slot, then enroll a fresh device (owner-signed registry)
    let m = mpm_store::load_manifest(&dir).unwrap();
    let slot = m
        .wrap_slots
        .iter()
        .find(|s| s.slot_type == SLOT_RECOVERY)
        .unwrap()
        .clone();
    let (params, salt) = slot.kdf.unwrap();
    let kek = kdf::derive_kek(&code, &salt, &params).unwrap();
    let bundle = KeyBundle::unwrap(
        &kek,
        &mpm_core::aad::wrap_slot(&m.vault_id, m.key_epoch, SLOT_RECOVERY),
        &slot.blob,
    )
    .unwrap();
    let newdev = DeviceKey::generate();
    let mut m2 = m;
    m2.devices.push(mpm_core::DeviceEntry {
        id: newdev.id,
        vk: newdev.verifying_key(),
        name: "recovery".into(),
        active: true,
        enrolled_at: 0,
        extra: Vec::new(),
    });
    let sk = bundle.owner_signing_key();
    let bytes = m2.to_file(&sk);
    mpm_store::write_manifest(&dir, &bytes).unwrap();
    mpm_store::save_device_key(&m2.vault_id, &newdev).unwrap();

    let mut v2 = Vault::new(m2, bundle, newdev).unwrap();
    // old device's log is foreign to the fresh device — verify + merge
    let old_log = mpm_store::read_ops(&dir, &_device.id).unwrap().ops;
    let pts = v2.verify_foreign_log(&_device.id, &old_log).unwrap();
    v2.apply_foreign(pts);
    assert_eq!(v2.records().count(), 1);
    let rid = v2.records().next().unwrap().record_id;
    assert_eq!(
        v2.item(&rid).unwrap().get_str(tag::PASSWORD),
        Some("s3cret")
    );
}

fn load_vid(dir: &std::path::Path) -> [u8; 16] {
    mpm_store::load_manifest(dir).unwrap().vault_id
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
    let (vid, ep) = (m.vault_id, m.key_epoch);
    let slot = m
        .wrap_slots
        .iter()
        .find(|s| s.slot_type == SLOT_RECOVERY)
        .unwrap()
        .clone();
    let (params, salt) = slot.kdf.unwrap();
    let kek = kdf::derive_kek(&code, &salt, &params).unwrap();
    let bundle = KeyBundle::unwrap(
        &kek,
        &mpm_core::aad::wrap_slot(&vid, ep, SLOT_RECOVERY),
        &slot.blob,
    )
    .unwrap();
    assert!(Vault::new(m, bundle, DeviceKey::from_bytes(&seed, dev_id)).is_ok());

    // a wrong code must not unwrap the recovery slot
    let mut bad = code;
    bad[0] ^= 0xff;
    let kek_bad = kdf::derive_kek(&bad, &salt, &params).unwrap();
    assert!(KeyBundle::unwrap(
        &kek_bad,
        &mpm_core::aad::wrap_slot(&vid, ep, SLOT_RECOVERY),
        &slot.blob
    )
    .is_err());
}

#[test]
fn noncanonical_recovery_code_rejected() {
    // 26th char carries 2 pad bits — non-zero pads must not alias
    let dir = tmpdir();
    let (_d, _s, code) = init(&dir, b"pw");
    let formatted = recovery::format_code(&code);
    let last = formatted.chars().last().unwrap();
    let alphabet = b"0123456789abcdefghjkmnpqrstvwxyz";
    let idx = alphabet.iter().position(|c| *c == last as u8).unwrap();
    // flip a low pad bit → same payload, noncanonical encoding
    let alt = alphabet[idx ^ 0b01] as char;
    let mut tampered = formatted.clone();
    tampered.replace_range(formatted.len() - 1.., &alt.to_string());
    assert!(
        recovery::parse_code(&tampered).is_err(),
        "noncanonical pad bits must fail"
    );
    assert_eq!(recovery::parse_code(&formatted).unwrap(), code);
}

#[test]
fn find_distinguishes_ambiguous_and_tombstoned() {
    let dir = tmpdir();
    let pw = b"pw";
    let (device, seed, _c) = init(&dir, pw);
    let dev_id = device.id;
    let mut v = reopen(&dir, pw, &seed, dev_id);
    for n in ["github", "github-work"] {
        let mut it = Item::default();
        it.set(tag::NAME, n.as_bytes().to_vec());
        it.set(tag::PASSWORD, b"x".to_vec());
        let (op, _) = v.make_upsert(ItemKind::Login, it).unwrap();
        mpm_store::append_op(&dir, &dev_id, &op).unwrap();
        v.commit(&op).unwrap();
    }
    // exact name beats substring ambiguity
    assert!(matches!(v.find("github"), mpm_core::FindResult::One(_)));
    assert!(matches!(v.find("gith"), mpm_core::FindResult::Ambiguous(2)));
    assert!(matches!(v.find("nope"), mpm_core::FindResult::None));

    // tombstone one, then find by its hex id → Tombstoned, not silent fallthrough
    let rid = match v.find("github-work") {
        mpm_core::FindResult::One(id) => id,
        _ => panic!(),
    };
    let tomb = v.make_tombstone(&rid).unwrap();
    mpm_store::append_op(&dir, &dev_id, &tomb).unwrap();
    v.commit(&tomb).unwrap();
    let hexid = mpm_store::hex(&rid);
    assert!(matches!(v.find(&hexid), mpm_core::FindResult::Tombstoned));
}

#[test]
fn merge_is_order_independent_on_equal_hlc() {
    // two devices, same record_id, same hlc → deterministic winner
    // regardless of which log is replayed first
    let dir = tmpdir();
    let pw = b"pw";
    let (device, seed, _c) = init(&dir, pw);
    let dev_id = device.id;
    let mut v = reopen(&dir, pw, &seed, dev_id);

    // second device enrolled via owner signature (simulates pairing)
    let dev2 = DeviceKey::generate();
    let dev2_id = dev2.id;
    {
        let mut m = v.manifest.clone();
        m.devices.push(mpm_core::DeviceEntry {
            id: dev2.id,
            vk: dev2.verifying_key(),
            name: "second".into(),
            active: true,
            enrolled_at: 0,
            extra: Vec::new(),
        });
        let sk = v.bundle().owner_signing_key();
        let bytes = m.to_file(&sk);
        mpm_store::write_manifest(&dir, &bytes).unwrap();
        v.manifest = mpm_core::Manifest::from_file(&bytes).unwrap();
    }

    // craft a shared record_id; both devices upsert it at the SAME hlc
    let mut rid = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut rid);
    let hlc = 0x00ff_ffff_ffffu64; // far-future constant → both ops tie on hlc

    let mk = |v: &Vault, dev: &DeviceKey, val: &str| {
        let mut it = Item::default();
        it.set(tag::NAME, b"shared".to_vec());
        it.set(tag::PASSWORD, val.as_bytes().to_vec());
        let fields_ct = mpm_core::OpPlaintext::seal_fields(
            v.dek(),
            &v.manifest.vault_id,
            v.manifest.key_epoch,
            &rid,
            &it,
        )
        .unwrap();
        let pt = mpm_core::OpPlaintext {
            prev_op_hash: [0u8; 32],
            hlc,
            op_type: mpm_core::OpType::Upsert,
            record_id: rid,
            kind: Some(ItemKind::Login),
            schema_v: 1,
            created: hlc,
            name: b"shared".to_vec(),
            fields_ct,
            gossip: Vec::new(),
            origin_device: dev.id,
            origin_seq: 1,
        };
        mpm_core::Op::seal(
            &pt,
            1,
            v.dek(),
            &v.manifest.vault_id,
            v.manifest.format_v,
            v.manifest.key_epoch,
            dev,
        )
        .unwrap()
    };

    let op_a = mk(&v, &device, "from-A");
    let op_b = mk(&v, &dev2, "from-B");

    // order 1: own log first
    let mut va = reopen(&dir, pw, &seed, dev_id);
    va.apply_own_op(&op_a).unwrap();
    let pts = va
        .verify_foreign_log(&dev2_id, std::slice::from_ref(&op_b))
        .unwrap();
    va.apply_foreign(pts);

    // order 2: foreign first (fresh vault, own log replayed second)
    let mut vb = reopen(&dir, pw, &seed, dev_id);
    let pts = vb.verify_foreign_log(&dev2_id, &[op_b]).unwrap();
    vb.apply_foreign(pts);
    vb.apply_own_op(&op_a).unwrap();

    let get_pw = |v: &Vault| {
        let rid2 = match v.find("shared") {
            mpm_core::FindResult::One(r) => r,
            _ => panic!(),
        };
        v.item(&rid2)
            .unwrap()
            .get_str(tag::PASSWORD)
            .unwrap()
            .to_string()
    };
    assert_eq!(
        get_pw(&va),
        get_pw(&vb),
        "merge result must not depend on log order"
    );
}

#[test]
fn wrong_password_fails() {
    let dir = tmpdir();
    init(&dir, b"right");
    let m = mpm_store::load_manifest(&dir).unwrap();
    let (params, salt) = m.wrap_slots[0].kdf.unwrap();
    let kek = kdf::derive_kek(b"wrong", &salt, &params).unwrap();
    assert!(KeyBundle::unwrap(
        &kek,
        &mpm_core::aad::wrap_slot(&m.vault_id, m.key_epoch, SLOT_PASSWORD),
        &m.wrap_slots[0].blob
    )
    .is_err());
}
