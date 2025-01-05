use primitives::sha256::DIGEST_LEN;

pub mod primitives;

mod hmac;

pub struct HkdfLabel {
    length: u16,
    label: Vec<u8>,
    context: Vec<u8>,
}

impl HkdfLabel {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + 1 + self.label.len() + 1 + self.context.len());
        bytes.extend(&(self.length).to_be_bytes());
        bytes.extend(&self.label);
        bytes.extend(&self.context);
        bytes
    }
}

/// HKDF-Expand-Label(PRK, label, context, L) with sha256
///
/// Panics if `length` is greater than 255 * 32.
pub fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
    assert!(length <= 255 * 32);
    let mut label_ = Vec::with_capacity(b"tls13 ".len() + label.len());
    label_.extend_from_slice(b"tls13 ");
    label_.extend_from_slice(label);
    let hkdf_label = HkdfLabel {
        length: length as u16,
        label: label_,
        context: context.to_vec(),
    };
    hkdf_expand(secret, &hkdf_label.to_bytes(), length as u16)
}

/// HKDF-Extract(salt, IKM) with sha256
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> primitives::sha256::Digest {
    hmac::hmac_sha256(salt, ikm)
}

/// HKDF-Expand(PRK, info, L) with sha256
///
/// Panics if `length` is greater than 255 * 32.
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: u16) -> Vec<u8> {
    assert!(prk.len() >= DIGEST_LEN);
    assert!(length <= 255 * 32);

    let mut t = None;
    let mut okm = Vec::new();
    let mut i: u8 = 0;
    while okm.len() < length as usize {
        i = i.checked_add(1).expect("HKDF-Expand can only produce 255 * 32 bytes");
        let mut t_ = t.map(|t: [u8; 32]| t.to_vec()).unwrap_or_default();
        t_.extend(info.iter());
        t_.extend([i]);
        let new_t = hmac::hmac_sha256(prk, &t_);
        println!("new_t: {:?}", new_t.to_hex());
        let new_t = new_t.to_bytes();
        okm.extend_from_slice(&new_t);
        t = Some(new_t);
    }
    okm.truncate(length as usize);
    okm
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hkdf_vector1() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let length = 42;
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(prk.to_hex(), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let okm = hkdf_expand(&prk.to_bytes(), &info, length);
        assert_eq!(
            hex::encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn test_hkdf_vector2() {
        let info = hex::decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
                                c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
                                d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
                                e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
                                f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let length = 82;
        let prk = hex::decode("06a6b88c5853361a06104c9ceb35b45c\
                                  ef760014904671014a193f40c15fc244").unwrap();
        let okm = hkdf_expand(&prk, &info, length);
        assert_eq!(
            hex::encode(&okm),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");
        }
}
