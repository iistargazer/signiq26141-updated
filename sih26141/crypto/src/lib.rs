use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 tag binding the message to the QKD-derived shared secret.
pub fn compute_message_hmac(
    shared_secret_hex: &str,
    message: &[u8],
) -> Result<String, &'static str> {
    let key_bytes = hex::decode(shared_secret_hex).map_err(|_| "Invalid hex secret key")?;
    let mut mac = HmacSha256::new_from_slice(&key_bytes)
        .map_err(|_| "HMAC initialization failed with key length")?;
    mac.update(message);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Constant-time tag verification. Case-insensitive via hex decode.
pub fn verify_message_hmac(
    shared_secret_hex: &str,
    message: &[u8],
    expected_tag_hex: &str,
) -> Result<bool, &'static str> {
    let key_bytes = hex::decode(shared_secret_hex).map_err(|_| "Invalid hex secret key")?;
    let expected_tag = hex::decode(expected_tag_hex).map_err(|_| "Invalid hex authentication tag")?;
    let mut mac = HmacSha256::new_from_slice(&key_bytes)
        .map_err(|_| "HMAC initialization failed with key length")?;
    mac.update(message);
    Ok(mac.verify_slice(&expected_tag).is_ok())
}
