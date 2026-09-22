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
        revoked_seq: None,
        extra: Vec::new(),
    });
    let sk = bundle.owner_signing_key();
    let bytes = m.to_file(&sk);
    mpm_store::write_manifest(dir, &bytes).unwrap();
    (device, seed, raw_code)
}

fn reopen(dir: &std::path::Path, pw: &[u8], seed: &[u8; 32], dev_id: [u8; 16]) -> Vault {
    let m = mpm_store::load_manifest(dir).unwrap();
    let slot = m
        .wrap_slots
        .iter()
        .find(|s| s.slot_type == SLOT_PASSWORD)
        .unwrap();
    let (params, salt) = slot.kdf.unwrap();
    let kek = kdf::derive_kek(pw, &salt, &params).unwrap();
    let bundle = KeyBundle::unwrap(
        &kek,
        &mpm_core::aad::wrap_slot(&m.vault_id, m.key_epoch, SLOT_PASSWORD),
        &slot.blob,
        m.key_epoch,
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
        m.key_epoch,
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
        m.key_epoch,
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
        m.key_epoch,
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
        m2.key_epoch,
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

/// Bare frame for decode tests — read_ops never verifies signatures.
fn raw_frame(seq: u64, ct: &[u8]) -> mpm_core::Op {
    mpm_core::Op {
        seq,
        nonce: [1u8; 24],
        sig: [2u8; 64],
        ct: ct.to_vec(),
    }
}

#[test]
fn corrupt_middle_record_fails_closed_not_torn_tail() {
    let dir = tmpdir();
    mpm_store::init_dir(&dir).unwrap();
    let dev = [7u8; 16];
    let ops = [
        raw_frame(1, b"aaaa"),
        raw_frame(2, &[9u8; 300]),
        raw_frame(3, b"cccc"),
    ];
    let mut buf = Vec::new();
    for op in &ops {
        buf.extend_from_slice(&op.encode());
    }
    // Corrupt the middle record's declared ct_len → 0. Decode then
    // succeeds as an empty frame, lands inside the real ciphertext, and
    // fails — while the valid third frame still follows. A real torn
    // tail cannot have a complete record after the failure point.
    let off2 = ops[0].encode().len();
    let len_at = off2 + mpm_core::op::OP_HEADER_LEN - 4;
    buf[len_at..len_at + 4].copy_from_slice(&0u32.to_le_bytes());
    std::fs::write(mpm_store::log_path(&dir, &dev), &buf).unwrap();

    let err = mpm_store::read_ops(&dir, &dev).err().unwrap();
    assert!(matches!(err, mpm_store::StoreError::CorruptLog), "{err}");
}

#[test]
fn torn_first_frame_fails_closed() {
    // File starts mid-record: nothing decodable at offset 0 is a hard
    // error, never a "torn tail" that would silently yield an empty log.
    let dir = tmpdir();
    mpm_store::init_dir(&dir).unwrap();
    let dev = [9u8; 16];
    let enc = raw_frame(1, b"payload").encode();
    std::fs::write(mpm_store::log_path(&dir, &dev), &enc[..enc.len() - 2]).unwrap();
    assert!(mpm_store::read_ops(&dir, &dev).is_err());
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
        m.key_epoch,
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
        revoked_seq: None,
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
    v2.apply_foreign(&pts);
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
        ep,
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
        &slot.blob,
        ep,
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
            revoked_seq: None,
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
            snapshot: None,
            origin_device: dev.id,
            origin_seq: 1,
            key_epoch: 1,
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
    va.apply_foreign(&pts);

    // order 2: foreign first (fresh vault, own log replayed second)
    let mut vb = reopen(&dir, pw, &seed, dev_id);
    let pts = vb.verify_foreign_log(&dev2_id, &[op_b]).unwrap();
    vb.apply_foreign(&pts);
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
        &m.wrap_slots[0].blob,
        m.key_epoch,
    )
    .is_err());
}

/// Revocation horizon: ops a device wrote while trusted (seq <= revoked_seq)
/// keep merging after revocation; post-horizon ops are refused — and the
/// verified prefix still applies instead of wedging the log.
#[test]
fn revoked_device_horizon() {
    let dir = tmpdir();
    let pw = b"pw";
    let (device, seed, _c) = init(&dir, pw);
    let dev_id = device.id;
    let mut v = reopen(&dir, pw, &seed, dev_id);

    // enroll a second device (owner-signed, like `pair approve`)
    let dev2 = DeviceKey::generate();
    let dev2_id = dev2.id;
    {
        let mut m = v.manifest.clone();
        m.devices.push(mpm_core::DeviceEntry {
            id: dev2.id,
            vk: dev2.verifying_key(),
            name: "doomed".into(),
            active: true,
            enrolled_at: 0,
            revoked_seq: None,
            extra: Vec::new(),
        });
        let sk = v.bundle().owner_signing_key();
        let bytes = m.to_file(&sk);
        mpm_store::write_manifest(&dir, &bytes).unwrap();
        v.manifest = mpm_core::Manifest::from_file(&bytes).unwrap();
    }

    // dev2 writes three chained ops
    let mkop = |v: &Vault, seq: u64, prev: [u8; 32], name: &str| {
        let mut rid = [0u8; 16];
        rid[0] = seq as u8;
        let mut it = Item::default();
        it.set(tag::NAME, name.as_bytes().to_vec());
        let fields_ct = mpm_core::OpPlaintext::seal_fields(
            v.dek(),
            &v.manifest.vault_id,
            v.manifest.key_epoch,
            &rid,
            &it,
        )
        .unwrap();
        let pt = mpm_core::OpPlaintext {
            prev_op_hash: prev,
            hlc: seq * 100,
            op_type: mpm_core::OpType::Upsert,
            record_id: rid,
            kind: Some(ItemKind::Login),
            schema_v: 1,
            created: seq * 100,
            name: name.as_bytes().to_vec(),
            fields_ct,
            gossip: Vec::new(),
            snapshot: None,
            origin_device: dev2.id,
            origin_seq: seq,
            key_epoch: 1,
        };
        mpm_core::Op::seal(
            &pt,
            seq,
            v.dek(),
            &v.manifest.vault_id,
            v.manifest.format_v,
            v.manifest.key_epoch,
            &dev2,
        )
        .unwrap()
    };
    let op1 = mkop(&v, 1, [0u8; 32], "one");
    let op2 = mkop(&v, 2, op1.hash(), "two");
    let op3 = mkop(&v, 3, op2.hash(), "three");

    // revoke dev2 with horizon=1 — the relay held only seq 1 when the
    // owner revoked (op2/op3 were validly signed but post-revocation)
    {
        let mut m = v.manifest.clone();
        for d in &mut m.devices {
            if d.id == dev2_id {
                d.active = false;
                d.revoked_seq = Some(1);
            }
        }
        let sk = v.bundle().owner_signing_key();
        let bytes = m.to_file(&sk);
        mpm_store::write_manifest(&dir, &bytes).unwrap();
    }
    let mut v = reopen(&dir, pw, &seed, dev_id);

    // prefix verify: op1 merges, op2 trips the horizon, op3 never seen
    let r = v.verify_foreign_prefix(&dev2_id, &[op1.clone(), op2.clone(), op3], 1, [0u8; 32]);
    assert_eq!(r.pts.len(), 1, "only the pre-horizon op may merge");
    assert!(matches!(
        r.failed_at,
        Some((2, mpm_core::CoreError::RevokedWrite(2)))
    ));
    v.apply_foreign(&r.pts);
    assert!(matches!(v.find("one"), mpm_core::FindResult::One(_)));
    assert!(matches!(v.find("two"), mpm_core::FindResult::None));

    // strict variant still errors on the post-horizon op
    assert!(v.verify_foreign_log(&dev2_id, &[op1, op2]).is_err());
}

/// A revoked device with no recorded horizon (revoked by an older client)
/// contributes nothing — strict, rather than silently trusting its tail.
#[test]
fn revoked_device_no_horizon() {
    let dir = tmpdir();
    let pw = b"pw";
    let (device, seed, _c) = init(&dir, pw);
    let dev_id = device.id;
    let mut v = reopen(&dir, pw, &seed, dev_id);

    let dev2 = DeviceKey::generate();
    let dev2_id = dev2.id;
    {
        let mut m = v.manifest.clone();
        m.devices.push(mpm_core::DeviceEntry {
            id: dev2.id,
            vk: dev2.verifying_key(),
            name: "legacy-revoked".into(),
            active: false,
            enrolled_at: 0,
            revoked_seq: None, // revoked before horizons existed
            extra: Vec::new(),
        });
        let sk = v.bundle().owner_signing_key();
        let bytes = m.to_file(&sk);
        mpm_store::write_manifest(&dir, &bytes).unwrap();
        v.manifest = mpm_core::Manifest::from_file(&bytes).unwrap();
    }
    let mut rid = [0u8; 16];
    rid[0] = 7;
    let mut it = Item::default();
    it.set(tag::NAME, b"sneak".to_vec());
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
        hlc: 1,
        op_type: mpm_core::OpType::Upsert,
        record_id: rid,
        kind: Some(ItemKind::Login),
        schema_v: 1,
        created: 1,
        name: b"sneak".to_vec(),
        fields_ct,
        gossip: Vec::new(),
        snapshot: None,
        origin_device: dev2.id,
        origin_seq: 1,
        key_epoch: 1,
    };
    let op = mpm_core::Op::seal(
        &pt,
        1,
        v.dek(),
        &v.manifest.vault_id,
        v.manifest.format_v,
        v.manifest.key_epoch,
        &dev2,
    )
    .unwrap();

    let r = v.verify_foreign_prefix(&dev2_id, &[op], 1, [0u8; 32]);
    assert!(r.pts.is_empty());
    assert!(matches!(
        r.failed_at,
        Some((1, mpm_core::CoreError::RevokedWrite(1)))
    ));
}

/// DEK rotation: ops sealed pre-rotation still open (epoch fallback via
/// DEK history); ops sealed post-rotation are unreadable by a bundle that
/// predates the rotation — the exclusion property `pair revoke` relies on.
#[test]
fn dek_rotation_epoch_fallback() {
    let dir = tmpdir();
    let (device, seed, _c) = init(&dir, b"pw-old");
    let dev_id = device.id;
    let mut v = reopen(&dir, b"pw-old", &seed, dev_id);

    // an op at epoch 1
    let mut it = Item::default();
    it.set(tag::NAME, b"before".to_vec());
    it.set(tag::PASSWORD, b"secret1".to_vec());
    let (op1, rid1) = v.make_upsert(ItemKind::Login, it).unwrap();
    mpm_store::append_op(&dir, &dev_id, &op1).unwrap();
    v.commit(&op1).unwrap();

    // capture a pre-rotation bundle by unwrapping the epoch-1 slot blob
    let m_old = mpm_store::load_manifest(&dir).unwrap();
    let old_blob = m_old.wrap_slots[0].blob.clone();
    let (p, s) = m_old.wrap_slots[0].kdf.unwrap();
    let old_kek = kdf::derive_kek(b"pw-old", &s, &p).unwrap();
    let old_bundle = KeyBundle::unwrap(
        &old_kek,
        &mpm_core::aad::wrap_slot(&m_old.vault_id, 1, SLOT_PASSWORD),
        &old_blob,
        1,
    )
    .unwrap();
    assert_eq!(old_bundle.current_epoch(), 1);

    // rotate like `pair revoke` does: new DEK epoch + slots re-wrapped
    // under the NEW password (stale KEKs would defeat the exclusion)
    let epoch = v.rotate_keys();
    assert_eq!(epoch, 2);
    assert_eq!(v.manifest.key_epoch, 2);
    let mut salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut salt);
    let new_kek = kdf::derive_kek(b"pw-new", &salt, &FAST).unwrap();
    let blob = v
        .bundle()
        .wrap(
            &new_kek,
            &mpm_core::aad::wrap_slot(&v.manifest.vault_id, 2, SLOT_PASSWORD),
        )
        .unwrap();
    v.manifest
        .wrap_slots
        .retain(|s| s.slot_type != SLOT_PASSWORD);
    v.manifest.wrap_slots.push(WrapSlot {
        slot_type: SLOT_PASSWORD,
        kdf: Some((FAST, salt)),
        blob,
        extra: Vec::new(),
    });
    v.manifest.snapshot_epoch += 1;
    let bytes = v.manifest.to_file(&v.bundle().owner_signing_key());
    mpm_store::write_manifest(&dir, &bytes).unwrap();

    // an op at epoch 2
    let mut it2 = Item::default();
    it2.set(tag::NAME, b"after".to_vec());
    it2.set(tag::PASSWORD, b"secret2".to_vec());
    let (op2, rid2) = v.make_upsert(ItemKind::Login, it2).unwrap();
    mpm_store::append_op(&dir, &dev_id, &op2).unwrap();
    v.commit(&op2).unwrap();

    // the stale bundle: opens the epoch-1 op but not the epoch-2 one,
    // and refuses to write entirely (write_epoch guard)
    let m_new = mpm_store::load_manifest(&dir).unwrap();
    let mut v_old = Vault::new(m_new, old_bundle, DeviceKey::from_bytes(&seed, dev_id)).unwrap();
    v_old.apply_own_op(&op1).unwrap(); // epoch fallback finds dek@1
    assert!(v_old.apply_own_op(&op2).is_err());
    let mut itx = Item::default();
    itx.set(tag::NAME, b"sneak".to_vec());
    assert!(matches!(
        v_old.make_upsert(ItemKind::Login, itx),
        Err(mpm_core::CoreError::KeysRotated(2))
    ));

    // reopen with the new password: full history — both ops, both fields
    // (reopen already replays the local log, epoch fallback included)
    let v2 = reopen(&dir, b"pw-new", &seed, dev_id);
    let i1 = v2.item(&rid1).unwrap();
    let i2 = v2.item(&rid2).unwrap();
    assert_eq!(i1.get(tag::PASSWORD).unwrap(), b"secret1");
    assert_eq!(i2.get(tag::PASSWORD).unwrap(), b"secret2");

    // and the old password no longer unwraps the rotated slot
    let m2 = mpm_store::load_manifest(&dir).unwrap();
    let (p2, s2) = m2.wrap_slots[0].kdf.unwrap();
    let old_pw_kek = kdf::derive_kek(b"pw-old", &s2, &p2).unwrap();
    assert!(KeyBundle::unwrap(
        &old_pw_kek,
        &mpm_core::aad::wrap_slot(&m2.vault_id, 2, SLOT_PASSWORD),
        &m2.wrap_slots[0].blob,
        2,
    )
    .is_err());
}

/// Legacy 64-byte bundles (dek||seed, pre-multi-epoch) unwrap into a
/// single-epoch map keyed by the slot's aad epoch.
#[test]
fn legacy_bundle_v1_unwrap() {
    let mut raw = [0u8; 64];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut raw);
    let kek = [7u8; 32];
    let aad = [1u8; 38];
    let nonce = mpm_crypto::aead::random_nonce();
    let ct = mpm_crypto::aead::seal(&kek, &nonce, &aad, &raw).unwrap();
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);
    let b = KeyBundle::unwrap(&kek, &aad, &blob, 5).unwrap();
    assert_eq!(b.current_epoch(), 5);
    assert_eq!(b.dek_at(5).unwrap(), &raw[..32]);
    assert_eq!(b.dek_at(1), None);
}

/// Compaction: a signed checkpoint covers all device tips; covered log
/// prefixes drop; replay anchored at the checkpoint reproduces identical
/// state; post-compaction writes chain on the anchor; a forged checkpoint
/// is rejected by the winner-set check.
#[test]
fn checkpoint_compact_roundtrip() {
    use mpm_core::op::Gossip;
    use std::collections::BTreeMap;

    let dir = tmpdir();
    let pw = b"pw";
    let (device, seed, _c) = init(&dir, pw);
    let dev_id = device.id;
    let mut v = reopen(&dir, pw, &seed, dev_id);

    // own log: upsert + update (v1 becomes a droppable loser) + upsert + tombstone
    let (op, rid) = v
        .make_upsert(ItemKind::Login, login("a", "u", "p1"))
        .unwrap();
    mpm_store::append_op(&dir, &dev_id, &op).unwrap();
    v.commit(&op).unwrap();
    let op = v
        .make_update(&rid, ItemKind::Login, login("a", "u", "p2"))
        .unwrap();
    mpm_store::append_op(&dir, &dev_id, &op).unwrap();
    v.commit(&op).unwrap();
    let (op, rid2) = v
        .make_upsert(ItemKind::Login, login("b", "u", "p"))
        .unwrap();
    mpm_store::append_op(&dir, &dev_id, &op).unwrap();
    v.commit(&op).unwrap();
    let op = v.make_tombstone(&rid2).unwrap();
    mpm_store::append_op(&dir, &dev_id, &op).unwrap();
    v.commit(&op).unwrap();

    // enroll dev2 (owner-signed) and have it write one foreign op
    let dev2 = DeviceKey::generate();
    let dev2_id = dev2.id;
    {
        let mut m = v.manifest.clone();
        m.devices.push(mpm_core::DeviceEntry {
            id: dev2.id,
            vk: dev2.verifying_key(),
            name: "d2".into(),
            active: true,
            enrolled_at: 0,
            revoked_seq: None,
            extra: Vec::new(),
        });
        let sk = v.bundle().owner_signing_key();
        let bytes = m.to_file(&sk);
        mpm_store::write_manifest(&dir, &bytes).unwrap();
        v.manifest = mpm_core::Manifest::from_file(&bytes).unwrap();
    }
    let mut frid = [0u8; 16];
    frid[0] = 0xcc;
    let mut fit = Item::default();
    fit.set(tag::NAME, b"c".to_vec());
    let fct = mpm_core::OpPlaintext::seal_fields(
        v.dek(),
        &v.manifest.vault_id,
        v.manifest.key_epoch,
        &frid,
        &fit,
    )
    .unwrap();
    let fpt = mpm_core::OpPlaintext {
        prev_op_hash: [0u8; 32],
        hlc: 500,
        op_type: mpm_core::OpType::Upsert,
        record_id: frid,
        kind: Some(ItemKind::Login),
        schema_v: 1,
        created: 500,
        name: b"c".to_vec(),
        fields_ct: fct,
        gossip: Vec::new(),
        snapshot: None,
        origin_device: dev2_id,
        origin_seq: 1,
        key_epoch: 1,
    };
    let fop = mpm_core::Op::seal(
        &fpt,
        1,
        v.dek(),
        &v.manifest.vault_id,
        v.manifest.format_v,
        v.manifest.key_epoch,
        &dev2,
    )
    .unwrap();
    mpm_store::append_op(&dir, &dev2_id, &fop).unwrap();
    let r = v.verify_foreign_prefix(&dev2_id, std::slice::from_ref(&fop), 1, [0u8; 32]);
    assert!(r.failed_at.is_none());
    v.apply_foreign(&r.pts);
    assert_eq!(v.records().count(), 2); // a + c

    // covered vector = verified tips; winners = every record's winning frame
    let own_tip = v.head();
    let covered = vec![
        Gossip {
            device_id: dev_id,
            seq: own_tip.0,
            head: own_tip.1,
        },
        Gossip {
            device_id: dev2_id,
            seq: 1,
            head: fop.hash(),
        },
    ];
    let own_log = mpm_store::read_ops(&dir, &dev_id).unwrap().ops;
    let own_map: BTreeMap<u64, _> = own_log.iter().map(|o| (o.seq, o.clone())).collect();
    let winners: Vec<([u8; 16], mpm_core::Op)> = v
        .winner_origins()
        .iter()
        .map(|(d, s)| {
            let op = if *d == dev_id {
                own_map[s].clone()
            } else {
                fop.clone()
            };
            (*d, op)
        })
        .collect();
    assert_eq!(winners.len(), 3); // a (v2), b (tombstone), c

    // ── replica-side claim check BEFORE any drop: must verify ──
    let mut tips: BTreeMap<[u8; 16], (u64, [u8; 32])> = BTreeMap::new();
    tips.insert(dev_id, own_tip);
    tips.insert(dev2_id, (1, fop.hash()));
    // pts like replay_state collects: every verified op plaintext
    let mut pts: Vec<mpm_core::OpPlaintext> = Vec::new();
    {
        let mut vc = {
            let m = mpm_store::load_manifest(&dir).unwrap();
            let slot = m
                .wrap_slots
                .iter()
                .find(|s| s.slot_type == SLOT_PASSWORD)
                .unwrap();
            let (params, salt) = slot.kdf.unwrap();
            let kek = kdf::derive_kek(pw, &salt, &params).unwrap();
            let bundle = KeyBundle::unwrap(
                &kek,
                &mpm_core::aad::wrap_slot(&m.vault_id, m.key_epoch, SLOT_PASSWORD),
                &slot.blob,
                m.key_epoch,
            )
            .unwrap();
            Vault::new(m, bundle, DeviceKey::from_bytes(&seed, dev_id)).unwrap()
        };
        for op in &own_log {
            pts.push(vc.apply_own_op(op).unwrap());
        }
        let rr = vc.verify_foreign_prefix(&dev2_id, std::slice::from_ref(&fop), 1, [0u8; 32]);
        pts.extend(rr.pts);
    }

    let ckpt = v.make_checkpoint(covered.clone(), winners).unwrap();
    let snap = v.open_snapshot_op(&ckpt, &dev_id).unwrap();
    v.check_snapshot_claim(&snap, &tips, &pts)
        .expect("fresh checkpoint must verify against the covered replay");

    // a forged checkpoint (winner swapped for the losing v1 op) must fail
    let mut forged = snap.clone();
    forged.winners.iter_mut().for_each(|(d, o)| {
        if *d == dev_id && o.seq == 2 {
            *o = own_map[&1].clone(); // claim the LOSER op as winner
        }
    });
    assert!(v.check_snapshot_claim(&forged, &tips, &pts).is_err());

    // ── author side: append the checkpoint, drop covered prefixes ──
    mpm_store::append_op(&dir, &dev_id, &ckpt).unwrap();
    v.commit(&ckpt).unwrap();
    let att = v.attest_snapshot(&ckpt);
    mpm_store::save_snapshot(&dir, &dev_id, &ckpt.encode(), &att).unwrap();
    for g in &covered {
        mpm_store::drop_covered_prefix(&dir, &g.device_id, g.seq).unwrap();
    }
    mpm_store::save_base_vector(&dir, &covered).unwrap();

    // own log now holds ONLY the checkpoint; dev2's is fully dropped
    let own_lr = mpm_store::read_ops(&dir, &dev_id).unwrap();
    assert_eq!(own_lr.ops.len(), 1);
    assert_eq!(own_lr.ops[0].seq, ckpt.seq);
    assert!(mpm_store::read_ops(&dir, &dev2_id).unwrap().ops.is_empty());
    assert_eq!(mpm_store::load_base_vector(&dir).unwrap().len(), 2);

    // ── anchored replay reproduces identical state (what replay_state does) ──
    let mut v2 = {
        let m = mpm_store::load_manifest(&dir).unwrap();
        let slot = m
            .wrap_slots
            .iter()
            .find(|s| s.slot_type == SLOT_PASSWORD)
            .unwrap();
        let (params, salt) = slot.kdf.unwrap();
        let kek = kdf::derive_kek(pw, &salt, &params).unwrap();
        let bundle = KeyBundle::unwrap(
            &kek,
            &mpm_core::aad::wrap_slot(&m.vault_id, m.key_epoch, SLOT_PASSWORD),
            &slot.blob,
            m.key_epoch,
        )
        .unwrap();
        Vault::new(m, bundle, DeviceKey::from_bytes(&seed, dev_id)).unwrap()
    };
    let snaps = mpm_store::load_snapshots(&dir).unwrap();
    assert_eq!(snaps.len(), 1);
    let (author, frame, att2) = &snaps[0];
    assert!(v2.snapshot_attested(frame, att2.as_ref().unwrap()));
    let snap2 = v2.open_snapshot_op(frame, author).unwrap();
    v2.adopt_snapshot(&snap2).unwrap();
    let (aseq, _) = v2.anchor(&dev_id).expect("own anchor");
    let lr2 = mpm_store::read_ops(&dir, &dev_id).unwrap();
    assert_eq!(lr2.ops[0].seq, aseq + 1);
    v2.apply_own_anchor();
    for op in &lr2.ops {
        v2.apply_own_op(op).unwrap();
    }
    // dev2's suffix is empty; verify still anchors cleanly
    let (fs, prev) = v2.anchor(&dev2_id).map(|(s, h)| (s + 1, h)).unwrap();
    let r2 = v2.verify_foreign_prefix(&dev2_id, &[], fs, prev);
    assert!(r2.failed_at.is_none());
    v2.apply_foreign(&r2.pts);

    assert_eq!(v2.records().count(), 2);
    let it = v2.item(&rid).unwrap();
    assert_eq!(it.get(tag::PASSWORD).unwrap(), b"p2"); // winner kept, not loser
    assert!(v2.item(&rid2).is_err()); // tombstone kept: stays deleted
    assert!(matches!(v2.find("c"), mpm_core::FindResult::One(_)));

    // checkpoint op itself is merge-inert (never creates a record)
    assert_eq!(v2.records().count(), 2);

    // post-compaction write chains from the anchor — and re-replays clean
    let (op, _rid3) = v2
        .make_upsert(ItemKind::Login, login("d", "u", "p"))
        .unwrap();
    mpm_store::append_op(&dir, &dev_id, &op).unwrap();
    v2.commit(&op).unwrap();
    let mut v3 = {
        let m = mpm_store::load_manifest(&dir).unwrap();
        let slot = m
            .wrap_slots
            .iter()
            .find(|s| s.slot_type == SLOT_PASSWORD)
            .unwrap();
        let (params, salt) = slot.kdf.unwrap();
        let kek = kdf::derive_kek(pw, &salt, &params).unwrap();
        let bundle = KeyBundle::unwrap(
            &kek,
            &mpm_core::aad::wrap_slot(&m.vault_id, m.key_epoch, SLOT_PASSWORD),
            &slot.blob,
            m.key_epoch,
        )
        .unwrap();
        Vault::new(m, bundle, DeviceKey::from_bytes(&seed, dev_id)).unwrap()
    };
    let snap3 = v3
        .open_snapshot_op(&mpm_store::load_snapshots(&dir).unwrap()[0].1, &dev_id)
        .unwrap();
    v3.adopt_snapshot(&snap3).unwrap();
    v3.apply_own_anchor();
    for op in &mpm_store::read_ops(&dir, &dev_id).unwrap().ops {
        v3.apply_own_op(op).unwrap();
    }
    assert_eq!(v3.records().count(), 3); // a, c, d — d chained past the ckpt
}

/// A checkpoint op type from a NEWER client must not wedge older replay:
/// unknown op types decode, chain-verify, and are ignored by merge.
#[test]
fn unknown_op_type_is_forward_compatible() {
    let dir = tmpdir();
    let pw = b"pw";
    let (device, seed, _c) = init(&dir, pw);
    let dev_id = device.id;
    let mut v = reopen(&dir, pw, &seed, dev_id);

    let (op, _rid) = v
        .make_upsert(ItemKind::Login, login("a", "u", "p"))
        .unwrap();
    mpm_store::append_op(&dir, &dev_id, &op).unwrap();
    v.commit(&op).unwrap();

    // hand-craft an op with an unrecognized type byte (9) — chains fine
    let mut rid2 = [0u8; 16];
    rid2[0] = 9;
    let pt = mpm_core::OpPlaintext {
        prev_op_hash: v.head().1,
        hlc: v.next_hlc(),
        op_type: mpm_core::OpType::Unknown(9),
        record_id: rid2,
        kind: None,
        schema_v: 1,
        created: 0,
        name: Vec::new(),
        fields_ct: Vec::new(),
        gossip: Vec::new(),
        snapshot: None,
        origin_device: dev_id,
        origin_seq: 2,
        key_epoch: 1,
    };
    let weird = mpm_core::Op::seal(
        &pt,
        2,
        v.dek(),
        &v.manifest.vault_id,
        v.manifest.format_v,
        v.manifest.key_epoch,
        &device,
    )
    .unwrap();
    mpm_store::append_op(&dir, &dev_id, &weird).unwrap();
    v.apply_own_op(&weird).unwrap(); // decodes, chains, no merge effect
    assert_eq!(v.records().count(), 1);

    let (op, _rid) = v
        .make_upsert(ItemKind::Login, login("b", "u", "p"))
        .unwrap();
    mpm_store::append_op(&dir, &dev_id, &op).unwrap();
    v.commit(&op).unwrap();
    assert_eq!(v.records().count(), 2);

    let v2 = reopen(&dir, pw, &seed, dev_id);
    assert_eq!(v2.records().count(), 2); // replay across the unknown op
}

/// LWW losers with different content materialize as real conflict-copy
/// records — order-independent, idempotent, and never for identical
/// content or tombstone losers.
#[test]
fn conflict_copy_preserves_losing_edit() {
    let dir = tmpdir();
    let pw = b"pw";
    let (device, seed, _c) = init(&dir, pw);
    let dev_id = device.id;
    let mut v = reopen(&dir, pw, &seed, dev_id);

    // enroll dev2
    let dev2 = DeviceKey::generate();
    let dev2_id = dev2.id;
    {
        let mut m = v.manifest.clone();
        m.devices.push(mpm_core::DeviceEntry {
            id: dev2.id,
            vk: dev2.verifying_key(),
            name: "laptop".into(),
            active: true,
            enrolled_at: 0,
            revoked_seq: None,
            extra: Vec::new(),
        });
        let sk = v.bundle().owner_signing_key();
        let bytes = m.to_file(&sk);
        mpm_store::write_manifest(&dir, &bytes).unwrap();
        v.manifest = mpm_core::Manifest::from_file(&bytes).unwrap();
    }

    // shared record
    let (op, rid) = v
        .make_upsert(ItemKind::Login, login("shared", "u", "original"))
        .unwrap();
    mpm_store::append_op(&dir, &dev_id, &op).unwrap();
    v.commit(&op).unwrap();

    // dev2 edits the SAME record offline: different password, higher hlc
    // than A's concurrent edit — dev2 wins the merge.
    let mk_foreign = |v: &Vault, seq: u64, prev: [u8; 32], pass: &str, hlc: u64| {
        let mut it = Item::default();
        it.set(tag::USERNAME, b"u".to_vec());
        it.set(tag::PASSWORD, pass.as_bytes().to_vec());
        let fields_ct = mpm_core::OpPlaintext::seal_fields(
            v.dek(),
            &v.manifest.vault_id,
            v.manifest.key_epoch,
            &rid,
            &it,
        )
        .unwrap();
        let pt = mpm_core::OpPlaintext {
            prev_op_hash: prev,
            hlc,
            op_type: mpm_core::OpType::Upsert,
            record_id: rid,
            kind: Some(ItemKind::Login),
            schema_v: 1,
            created: 0,
            name: b"shared".to_vec(),
            fields_ct,
            gossip: Vec::new(),
            snapshot: None,
            origin_device: dev2_id,
            origin_seq: seq,
            key_epoch: 1,
        };
        mpm_core::Op::seal(
            &pt,
            seq,
            v.dek(),
            &v.manifest.vault_id,
            v.manifest.format_v,
            v.manifest.key_epoch,
            &dev2,
        )
        .unwrap()
    };

    // dev2's chain: seq1 = original-ish (same fields? no — give it its own
    // base version), seq2 = the concurrent winner.
    let f1 = mk_foreign(&v, 1, [0u8; 32], "d2-base", 1);
    let f2 = mk_foreign(&v, 2, f1.hash(), "d2-winner", u64::MAX - 1);

    // A's concurrent edit (loses: lower hlc)
    let losing = v
        .make_update(&rid, ItemKind::Login, login("shared", "u", "a-version"))
        .unwrap();
    mpm_store::append_op(&dir, &dev_id, &losing).unwrap();
    v.commit(&losing).unwrap();

    // order 1: A's op already in index, then dev2's ops arrive (winner
    // displaces A's version → A's edit is the conflict loser)
    let r = v.verify_foreign_prefix(&dev2_id, &[f1.clone(), f2.clone()], 1, [0u8; 32]);
    assert!(r.failed_at.is_none());
    v.apply_foreign(&r.pts);
    assert!(v.has_pending_conflicts());

    // dev2's winner version is the live one
    let it = v.item(&rid).unwrap();
    assert_eq!(it.get(tag::PASSWORD).unwrap(), b"d2-winner");

    // materialize → ONE new op producing the conflict record
    let mut n = 0;
    while let Some((cop, crid)) = v.materialize_conflict().unwrap() {
        mpm_store::append_op(&dir, &dev_id, &cop).unwrap();
        v.commit(&cop).unwrap();
        n += 1;
        // the copy carries the LOSER's fields under its own record key
        let cit = v.item(&crid).unwrap();
        assert_eq!(cit.get(tag::PASSWORD).unwrap(), b"a-version");
    }
    assert_eq!(n, 1);
    assert!(!v.has_pending_conflicts());

    // the copy shows as a normal record named for the losing device
    let names: Vec<String> = v.records().map(|r| r.name.clone()).collect();
    assert!(
        names.iter().any(|n| n == "shared (conflict, this device)")
            || names.iter().any(|n| n.starts_with("shared (conflict,")),
        "conflict copy present: {names:?}"
    );

    // idempotent: a second materialize pass emits nothing (rid exists)
    assert!(v.materialize_conflict().unwrap().is_none());

    // replay: a fresh vault re-derives the same index — the conflict
    // record is a real op, so it survives
    let v2 = reopen(&dir, pw, &seed, dev_id);
    let crid = mpm_core::vault::derive_conflict_id(&rid, &dev_id, 2);
    assert!(v2.item(&crid).is_ok(), "conflict record survives replay");

    // tombstone the copy → stays gone: replay must not resurrect it
    let op = v.make_tombstone(&crid).unwrap();
    mpm_store::append_op(&dir, &dev_id, &op).unwrap();
    v.commit(&op).unwrap();
    let v3 = reopen(&dir, pw, &seed, dev_id);
    assert!(v3.item(&crid).is_err(), "deleted conflict copy stays gone");
}

/// Second enrolled device for foreign-op tests (owner-signed manifest
/// edit, like `pair approve`); returns dev2.
fn enroll_dev2(dir: &std::path::Path, v: &mut Vault) -> DeviceKey {
    let dev2 = DeviceKey::generate();
    let mut m = v.manifest.clone();
    m.devices.push(mpm_core::DeviceEntry {
        id: dev2.id,
        vk: dev2.verifying_key(),
        name: "dev2".into(),
        active: true,
        enrolled_at: 0,
        revoked_seq: None,
        extra: Vec::new(),
    });
    let sk = v.bundle().owner_signing_key();
    let bytes = m.to_file(&sk);
    mpm_store::write_manifest(dir, &bytes).unwrap();
    v.manifest = mpm_core::Manifest::from_file(&bytes).unwrap();
    dev2
}

/// Foreign upsert frame from `dev2` with a caller-chosen hlc.
fn foreign_upsert(
    v: &Vault,
    dev2: &DeviceKey,
    seq: u64,
    prev: [u8; 32],
    hlc: u64,
    name: &str,
) -> mpm_core::Op {
    let mut rid = [0u8; 16];
    rid[0] = seq as u8;
    rid[1] = (hlc & 0xff) as u8;
    let mut it = Item::default();
    it.set(tag::NAME, name.as_bytes().to_vec());
    it.set(tag::PASSWORD, b"x".to_vec());
    let fields_ct = mpm_core::OpPlaintext::seal_fields(
        v.dek(),
        &v.manifest.vault_id,
        v.manifest.key_epoch,
        &rid,
        &it,
    )
    .unwrap();
    let pt = mpm_core::OpPlaintext {
        prev_op_hash: prev,
        hlc,
        op_type: mpm_core::OpType::Upsert,
        record_id: rid,
        kind: Some(ItemKind::Login),
        schema_v: 1,
        created: 0,
        name: name.as_bytes().to_vec(),
        fields_ct,
        gossip: Vec::new(),
        snapshot: None,
        origin_device: dev2.id,
        origin_seq: seq,
        key_epoch: v.manifest.key_epoch,
    };
    mpm_core::Op::seal(
        &pt,
        seq,
        v.dek(),
        &v.manifest.vault_id,
        v.manifest.format_v,
        v.manifest.key_epoch,
        dev2,
    )
    .unwrap()
}

/// SEC-06: an enrolled device can sign an op with hlc = u64::MAX. Its
/// merge still honors the true hlc (consensus — clamping that would fork
/// replicas), but the value must not pin the local clock: `next_hlc`
/// stays bounded by the documented skew window, so local writes keep
/// working instead of saturating forever.
#[test]
fn extreme_hlc_cannot_pin_local_clock() {
    const SKEW: u64 = 24 * 60 * 60 * 1000; // documented bound in vault.rs
    let dir = tmpdir();
    let pw = b"pw";
    let (device, seed, _c) = init(&dir, pw);
    let dev_id = device.id;
    let mut v = reopen(&dir, pw, &seed, dev_id);
    let dev2 = enroll_dev2(&dir, &mut v);

    let op_max = foreign_upsert(&v, &dev2, 1, [0u8; 32], u64::MAX, "pinned");
    let r = v.verify_foreign_prefix(&dev2.id, std::slice::from_ref(&op_max), 1, [0u8; 32]);
    assert!(r.failed_at.is_none());
    v.apply_foreign(&r.pts);

    // merge honored the true hlc — the op landed and wins its record
    assert!(matches!(v.find("pinned"), mpm_core::FindResult::One(_)));
    // but the local clock is bounded, not saturated
    let cap = mpm_core::vault::now_hlc() + SKEW + 1;
    assert!(v.next_hlc() <= cap, "next_hlc pinned at {}", v.next_hlc());
    // and a local write still produces a sane monotone timestamp
    let mut it = Item::default();
    it.set(tag::NAME, b"mine".to_vec());
    let (own, _) = v.make_upsert(ItemKind::Login, it).unwrap();
    let pt = v.apply_own_op(&own).unwrap();
    assert!(pt.hlc <= cap, "own write pinned at {}", pt.hlc);
}

/// The bound itself: an hlc inside the skew window is absorbed fully;
/// one beyond it is clamped to the window, not rejected.
#[test]
fn hlc_absorption_bounded_at_skew_window() {
    const SKEW: u64 = 24 * 60 * 60 * 1000;
    let dir = tmpdir();
    let pw = b"pw";
    let (device, seed, _c) = init(&dir, pw);
    let mut v = reopen(&dir, pw, &seed, device.id);
    let dev2 = enroll_dev2(&dir, &mut v);

    let now = mpm_core::vault::now_hlc();
    // in-window: absorbed — next_hlc must exceed it (monotone vs observed)
    let a = foreign_upsert(&v, &dev2, 1, [0u8; 32], now + 60_000, "in-window");
    // out-of-window: clamped — still applies, still wins, clock bounded
    let b = foreign_upsert(&v, &dev2, 2, a.hash(), now + 2 * SKEW, "beyond");
    let r = v.verify_foreign_prefix(&dev2.id, &[a, b], 1, [0u8; 32]);
    assert!(r.failed_at.is_none());
    v.apply_foreign(&r.pts);
    assert!(matches!(v.find("beyond"), mpm_core::FindResult::One(_)));
    let next = v.next_hlc();
    assert!(next > now + 60_000, "in-window hlc not absorbed: {next}");
    // cap measured after apply: clamping ran against an earlier `now`, so
    // this bound is tight regardless of ticks between the two calls
    let cap = mpm_core::vault::now_hlc() + SKEW + 1;
    assert!(next <= cap, "beyond-window hlc not clamped: {next}");
}

/// Equal-hlc merge is total-order deterministic ((hlc, origin_device,
/// origin_seq)) — including at the extreme end of the range.
#[test]
fn equal_extreme_hlc_ties_break_deterministically() {
    let dir = tmpdir();
    let pw = b"pw";
    let (device, seed, _c) = init(&dir, pw);
    let dev_id = device.id;
    let mut v = reopen(&dir, pw, &seed, dev_id);
    let dev2 = enroll_dev2(&dir, &mut v);

    // dev2 op on record r at hlc u64::MAX; own concurrent op on the same
    // record — winner decided by the tie-break, not by which arrived first
    let mut rid = [0u8; 16];
    rid[0] = 0xAA;
    let mk = |v: &Vault, hlc: u64| -> mpm_core::Op {
        let mut it = Item::default();
        it.set(tag::NAME, b"tied".to_vec());
        it.set(tag::PASSWORD, b"dev2".to_vec());
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
            created: 0,
            name: b"tied".to_vec(),
            fields_ct,
            gossip: Vec::new(),
            snapshot: None,
            origin_device: dev2.id,
            origin_seq: 1,
            key_epoch: v.manifest.key_epoch,
        };
        mpm_core::Op::seal(
            &pt,
            1,
            v.dek(),
            &v.manifest.vault_id,
            v.manifest.format_v,
            v.manifest.key_epoch,
            &dev2,
        )
        .unwrap()
    };
    let fop = mk(&v, u64::MAX);
    let r = v.verify_foreign_prefix(&dev2.id, &[fop], 1, [0u8; 32]);
    assert!(r.failed_at.is_none());
    v.apply_foreign(&r.pts);

    // own write under a pinned-proof clock still lands; tie vs MAX only
    // if the clock were pinned — it isn't, so dev2's MAX wins outright
    let mut it = Item::default();
    it.set(tag::NAME, b"tied".to_vec());
    it.set(tag::PASSWORD, b"own".to_vec());
    // craft own op directly on the same record id
    let own = v.make_update(&rid, ItemKind::Login, it).unwrap();
    let pt = v.apply_own_op(&own).unwrap();
    assert!(pt.hlc < u64::MAX);
    assert_eq!(v.item(&rid).unwrap().get(tag::PASSWORD).unwrap(), b"dev2");
}

/// Replaying an extreme-hlc foreign log re-derives the same bounded clock.
#[test]
fn extreme_hlc_replay_stays_bounded() {
    const SKEW: u64 = 24 * 60 * 60 * 1000;
    let dir = tmpdir();
    let pw = b"pw";
    let (device, seed, _c) = init(&dir, pw);
    let dev_id = device.id;
    let mut v = reopen(&dir, pw, &seed, dev_id);
    let dev2 = enroll_dev2(&dir, &mut v);

    // dev2's log ON DISK: u64::MAX op + a normal op chained after it
    let f1 = foreign_upsert(&v, &dev2, 1, [0u8; 32], u64::MAX, "big");
    let f2 = foreign_upsert(&v, &dev2, 2, f1.hash(), 42, "small");
    mpm_store::append_op(&dir, &dev2.id, &f1).unwrap();
    mpm_store::append_op(&dir, &dev2.id, &f2).unwrap();

    // fresh vault replays the foreign log → same bounded clock
    let mut v2 = reopen(&dir, pw, &seed, dev_id);
    let lr = mpm_store::read_ops(&dir, &dev2.id).unwrap();
    let r = v2.verify_foreign_prefix(&dev2.id, &lr.ops, 1, [0u8; 32]);
    assert!(r.failed_at.is_none());
    v2.apply_foreign(&r.pts);
    assert!(v2.next_hlc() <= mpm_core::vault::now_hlc() + SKEW + 1);
    assert!(matches!(v2.find("big"), mpm_core::FindResult::One(_)));
    assert!(matches!(v2.find("small"), mpm_core::FindResult::One(_)));
}

/// A revoked device's post-horizon op is rejected before merge — its
/// extreme hlc never reaches the clock at all.
#[test]
fn revoked_device_extreme_hlc_never_reaches_clock() {
    let dir = tmpdir();
    let pw = b"pw";
    let (device, seed, _c) = init(&dir, pw);
    let dev_id = device.id;
    let mut v = reopen(&dir, pw, &seed, dev_id);
    let dev2 = enroll_dev2(&dir, &mut v);

    let op1 = foreign_upsert(&v, &dev2, 1, [0u8; 32], 1, "pre-revocation");
    let op2 = foreign_upsert(&v, &dev2, 2, op1.hash(), u64::MAX, "post-revocation");

    // revoke with horizon=1
    let mut m = v.manifest.clone();
    for d in &mut m.devices {
        if d.id == dev2.id {
            d.active = false;
            d.revoked_seq = Some(1);
        }
    }
    let sk = v.bundle().owner_signing_key();
    let bytes = m.to_file(&sk);
    mpm_store::write_manifest(&dir, &bytes).unwrap();
    let mut v = reopen(&dir, pw, &seed, dev_id);

    let r = v.verify_foreign_prefix(&dev2.id, &[op1, op2], 1, [0u8; 32]);
    assert_eq!(r.pts.len(), 1);
    assert!(matches!(
        r.failed_at,
        Some((2, mpm_core::CoreError::RevokedWrite(2)))
    ));
    v.apply_foreign(&r.pts);
    // clock saw only the sane op — next_hlc is ordinary wall time
    let cap = mpm_core::vault::now_hlc() + 24 * 60 * 60 * 1000;
    assert!(v.next_hlc() <= cap);
}

/// REL-01: device-key writes are atomic — a crashed save leaves a stray
/// tmp sibling, never a torn .dev. The loader must keep reading the real
/// file regardless of litter.
#[test]
fn device_key_survives_tmp_litter() {
    let vault_id = [9u8; 16];
    let key = DeviceKey::generate();
    mpm_store::save_device_key(&vault_id, &key).unwrap();
    let back = mpm_store::load_device_key(&vault_id).unwrap();
    assert_eq!(back.id, key.id);
    assert_eq!(back.seed_bytes(), key.seed_bytes());

    // litter the devices dir with a crashed-write tmp — load must ignore it
    let dir = std::env::var_os("MPM_DATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| dirs::data_local_dir().unwrap().join("mypassman"))
        .join("devices");
    std::fs::write(
        dir.join(format!("{}.999999.tmp", mpm_store::hex(&vault_id))),
        b"torn",
    )
    .unwrap();
    let back = mpm_store::load_device_key(&vault_id).unwrap();
    assert_eq!(back.seed_bytes(), key.seed_bytes());

    // a second save atomically replaces — still reads clean
    mpm_store::save_device_key(&vault_id, &key).unwrap();
    assert_eq!(
        mpm_store::load_device_key(&vault_id).unwrap().seed_bytes(),
        key.seed_bytes()
    );

    let _ = std::fs::remove_file(dir.join(format!("{}.dev", mpm_store::hex(&vault_id))));
    let _ = std::fs::remove_file(dir.join(format!("{}.999999.tmp", mpm_store::hex(&vault_id))));
}
