use std::cmp;

use crate::primitives::sha256::DIGEST_LEN;
pub use crate::primitives::sha256::{sha256, Digest, Sha256};

const BLOCK_LENGTH: usize = 64;

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Digest {
    let key = match key.len().cmp(&BLOCK_LENGTH) {
        cmp::Ordering::Less => {
            let mut extended = key.to_vec();
            extended.extend(vec![0; BLOCK_LENGTH - key.len()]);
            extended
        }
        cmp::Ordering::Equal => key.to_vec(),
        cmp::Ordering::Greater => {
            let mut extended = sha256(key).to_bytes().to_vec();
            extended.extend(vec![0; BLOCK_LENGTH - DIGEST_LEN]);
            extended
        },
    };
    let o_key_pad: Vec<u8> = key.iter().map(|byte| byte ^ 0x5c).collect();
    let i_key_pad: Vec<u8> = key.iter().map(|byte| byte ^ 0x36).collect();

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&i_key_pad);
    inner_hasher.update(message);

    let inner_digest = inner_hasher.finalize().to_bytes();
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&o_key_pad);
    outer_hasher.update(&inner_digest);
    outer_hasher.finalize()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_case_1() {
        let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let message = b"Hi There";
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        let digest = hmac_sha256(&key, message);
        assert_eq!(digest.to_hex(), expected);
    }

    #[test]
    fn test_case_2() {
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        let digest = hmac_sha256(key, message);
        assert_eq!(digest.to_hex(), expected);
    }

    #[test]
    fn test_case_3() {
        let key = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let message = hex::decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap();
        let expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";
        let digest = hmac_sha256(&key, &message);
        assert_eq!(digest.to_hex(), expected);
    }

    #[test]
    fn test_case_4() {
        let key = hex::decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap();
        let message = hex::decode("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd").unwrap();
        let expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";
        let digest = hmac_sha256(&key, &message);
        assert_eq!(digest.to_hex(), expected);
    }

    #[test]
    fn test_case_5() {
        let key = hex::decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c").unwrap();
        let message = b"Test With Truncation";
        let expected_prefix = "a3b6167473100ee06e0c796c2955552b";
        let digest = hmac_sha256(&key, message).to_hex();
        assert!(digest.starts_with(expected_prefix));
    }

    #[test]
    fn test_case_6() {
        let key = vec![0xaa; 131];
        let message = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";
        let digest = hmac_sha256(&key, message);
        assert_eq!(digest.to_hex(), expected);
    }

    #[test]
    fn test_case_7() {
        let key = vec![0xaa; 131];
        let message = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let expected = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";
        let digest = hmac_sha256(&key, message);
        assert_eq!(digest.to_hex(), expected);
    }
}
