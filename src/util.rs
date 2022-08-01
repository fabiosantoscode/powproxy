use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

/** Turns 8-byte array into a u64 */
pub fn quick_be_u64(bytes: &[u8]) -> Option<u64> {
    let bytes = <[u8; 8]>::try_from(bytes).ok()?;

    Some(u64::from_be_bytes(bytes))
}

/** Round the time such that there's only one challenge every 30 seconds */
pub fn round_time() -> SystemTime {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let more_than_30 = seconds % 30;
    UNIX_EPOCH + Duration::from_secs(seconds - more_than_30)
}
