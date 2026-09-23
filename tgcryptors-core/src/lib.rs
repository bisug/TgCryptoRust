//! Core AES-256 primitives and Telegram-specific block modes.
//!
//! The crate exposes the AES-256 block cipher plus the modes Telegram relies on:
//! - `ige256` for MTProto message encryption
//! - `ctr256` for CDN file encryption
//! - `cbc256` for passport credentials
//!
//! On x86 and x86_64, the `aesni` feature enables runtime AES-NI dispatch.
//! Other targets use the software fallback.
//!
//! # Security Notice
//!
//! The software fallback uses table lookups, which are not constant-time on
//! all CPUs. If hardware AES acceleration is unavailable, evaluate that risk
//! against your deployment model. No ARM NEON backend exists yet; ARM targets
//! always use the software fallback.

pub mod aes256;
pub mod cbc256;
pub mod ctr256;
pub mod ige256;

/// Whether the crate was compiled with the AES-NI feature enabled.
///
/// Compile-time only: it does NOT mean AES-NI is usable on this CPU.
/// Use [`aesni_active`] for the runtime probe.
pub const AESNI_FEATURE_ENABLED: bool = cfg!(feature = "aesni");

/// AES block size in bytes (16).
pub const AES_BLOCK_SIZE: usize = aes256::AES_BLOCK_SIZE;

/// Decode a hex string (test helper for known-answer vectors).
#[cfg(test)]
pub(crate) fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Re-export the main APIs for convenience.
pub use aes256::{aesni_active, ExpandedKey};
pub use cbc256::{cbc256_decrypt, cbc256_decrypt_into, cbc256_encrypt, cbc256_encrypt_into};
pub use ctr256::{ctr256_decrypt, ctr256_encrypt, ctr256_encrypt_into, ctr256_encrypt_into_ek};
pub use ige256::{
    ige256_decrypt, ige256_decrypt_into, ige256_decrypt_into_ek, ige256_encrypt,
    ige256_encrypt_into, ige256_encrypt_into_ek,
};
