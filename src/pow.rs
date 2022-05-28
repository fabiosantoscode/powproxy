use bitvec::prelude::*;
use sha2::{Sha256, Digest};

/**
 * Proof of work stuff
 */
pub fn validate_work(challenge: &[u8], magic: u32, difficulty: usize) -> bool {
    let mut hasher = Sha256::new();

    hasher.update([&magic.to_be_bytes(), challenge].concat());

    let hash = hasher.finalize();

    return has_leading_zeroes(hash.as_bits::<Lsb0>(), difficulty);
}

fn has_leading_zeroes(bits: &BitSlice<u8>, zero_count: usize) -> bool {
    bits
        .iter()
        .take(zero_count)
        .all(|bit| bit == false)
}

#[test]
fn test_work_zero_difficulty() {
    assert_eq!(validate_work(&hex::decode("ffff").unwrap(), 1, 0), true);
}

#[test]
fn test_work_real() {
    // challenge: 31643765326531336538313264666462326532346536363934653766633534666462623562646334396363643335356631306130353130613035303139346436663963313339336565323162383837353663356366363366
    // whole buf: 00009f4031643765326531336538313264666462326532346536363934653766633534666462623562646334396363643335356631306130353130613035303139346436663963313339336565323162383837353663356366363366
    // good hash: 0000f58f738a9bb77fcae4c4c5eaff277c92a8ba46262b3877560d448a374733
    // magic number: 40768 (0x00009f40)
    assert_eq!(40768_u32.to_be_bytes(), [0, 0, 0x9f, 0x40]);
    assert_eq!(
        validate_work(
            &hex::decode("31643765326531336538313264666462326532346536363934653766633534666462623562646334396363643335356631306130353130613035303139346436663963313339336565323162383837353663356366363366").unwrap(),
            40768,
            16
        ),
        true
    )
}

#[allow(unused)]
fn test_hex(inp: &str) -> Vec<u8> {
    hex::decode(inp).unwrap()
}

#[test]
fn test_leading_zeroes() {
    // sanity check
    assert_eq!(
        test_hex("02"),
        [2]
    );
    assert_eq!(has_leading_zeroes(test_hex("ff").as_bits::<Lsb0>(), 0), true);
    assert_eq!(has_leading_zeroes(test_hex("00").as_bits::<Lsb0>(), 0), true);

    assert_eq!(has_leading_zeroes(test_hex("00ff").as_bits::<Lsb0>(), 8), true);
    assert_eq!(has_leading_zeroes(test_hex("00ff").as_bits::<Lsb0>(), 9), false);

    assert_eq!(has_leading_zeroes(test_hex("0000ff").as_bits::<Lsb0>(), 16), true);
    assert_eq!(has_leading_zeroes(test_hex("0000ff").as_bits::<Lsb0>(), 17), false);
}
