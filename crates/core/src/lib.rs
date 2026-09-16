//! mypassman core: vault format, ops, manifest, merge.
//! All secrets live behind handle-style APIs — callers get plaintext only
//! at the last possible moment (DESIGN.md §3).

pub mod aad;
pub mod error;
pub mod gen;
pub mod item;
pub mod manifest;
pub mod op;
pub mod recovery;
pub mod tlv;
pub mod vault;

pub use error::{CoreError, Result};
pub use item::{Item, ItemKind};
pub use manifest::{DeviceEntry, Manifest, WrapSlot, SLOT_BIOMETRIC, SLOT_PASSWORD, SLOT_RECOVERY};
pub use op::{Op, OpPlaintext, OpType, OP_HEADER_LEN};
pub use vault::{RecordSummary, Vault};

pub const FORMAT_VERSION: u16 = 1;
pub const MIN_READER_VERSION: u16 = 1;
pub const RECORD_ID_LEN: usize = 16;
pub const DEVICE_ID_LEN: usize = 16;
pub const VAULT_ID_LEN: usize = 16;
pub const HASH_LEN: usize = 32;
