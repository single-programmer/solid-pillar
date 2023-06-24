//! SHA-256 hashing implementation.
//!
//! # Example
//! ```rust
//! use solid_pillar::sha256::Sha256;
//!
//! let mut hasher = Sha256::new();
//! hasher.update(b"Hello, ");
//! hasher.update(b"world!");
//! let result = hasher.finalize();
//! assert_eq!(result.to_hex(), "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3");
//! ```

use std::mem::swap;

const H0: u32 = 0x6a09e667;
const H1: u32 = 0xbb67ae85;
const H2: u32 = 0x3c6ef372;
const H3: u32 = 0xa54ff53a;
const H4: u32 = 0x510e527f;
const H5: u32 = 0x9b05688c;
const H6: u32 = 0x1f83d9ab;
const H7: u32 = 0x5be0cd19;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

pub struct Sha256 {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    h5: u32,
    h6: u32,
    h7: u32,
    msgbytelen: usize,
    rest: [u8; CHUNK_LEN],
    restlen: usize,
}

const CHUNK_LEN_BITS: usize = 512;
const CHUNK_LEN: usize = CHUNK_LEN_BITS / 8;
const DIGEST_LEN: usize = 256 / 8;

impl Sha256 {
    pub fn new() -> Self {
        Self {
            h0: H0,
            h1: H1,
            h2: H2,
            h3: H3,
            h4: H4,
            h5: H5,
            h6: H6,
            h7: H7,
            msgbytelen: 0,
            rest: [0; CHUNK_LEN],
            restlen: 0,
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.msgbytelen += bytes.len();

        if self.restlen + bytes.len() < CHUNK_LEN {
            self.rest[self.restlen..(self.restlen + bytes.len())].copy_from_slice(bytes);
            self.restlen += bytes.len();
            return;
        }
        let mut bytes = bytes;

        let (left, right) = bytes.split_at(CHUNK_LEN - self.restlen);
        self.rest[self.restlen..].copy_from_slice(left);
        self.restlen = 0;

        bytes = right;
        self.chunk_rest();
        if bytes.len() < CHUNK_LEN {
            self.rest[..bytes.len()].copy_from_slice(bytes);
            self.restlen = bytes.len();
            return;
        }

        loop {
            let (left, right) = bytes.split_at(CHUNK_LEN);
            debug_assert_eq!(left.len(), CHUNK_LEN);

            self.chunk_round(left);

            if right.len() < CHUNK_LEN {
                self.rest[0..right.len()].copy_from_slice(right);
                self.restlen = right.len();
                return;
            }
            bytes = right;
        }
    }

    pub fn finalize(mut self) -> Digest {
        self.rest[self.restlen] = 0x80;
        self.restlen += 1;
        for byte in &mut self.rest[self.restlen..CHUNK_LEN] {
            *byte = 0;
        }
        if self.restlen + 16 > CHUNK_LEN {
            let mut rest2 = [0; CHUNK_LEN];
            rest2[CHUNK_LEN - 16..CHUNK_LEN]
                .copy_from_slice(&(self.msgbytelen as u128 * 8).to_be_bytes());
            self.chunk_rest();
            self.chunk_round(&rest2);
        } else {
            self.rest[CHUNK_LEN - 16..CHUNK_LEN]
                .copy_from_slice(&(self.msgbytelen as u128 * 8).to_be_bytes());
            self.chunk_rest();
        }
        let mut digest = [0; DIGEST_LEN];
        digest[0..4].copy_from_slice(&self.h0.to_be_bytes());
        digest[4..8].copy_from_slice(&self.h1.to_be_bytes());
        digest[8..12].copy_from_slice(&self.h2.to_be_bytes());
        digest[12..16].copy_from_slice(&self.h3.to_be_bytes());
        digest[16..20].copy_from_slice(&self.h4.to_be_bytes());
        digest[20..24].copy_from_slice(&self.h5.to_be_bytes());
        digest[24..28].copy_from_slice(&self.h6.to_be_bytes());
        digest[28..32].copy_from_slice(&self.h7.to_be_bytes());
        Digest { digest }
    }

    fn chunk_rest(&mut self) {
        let mut rest = [0; CHUNK_LEN];
        swap(&mut self.rest, &mut rest);
        self.chunk_round(&rest);
        swap(&mut self.rest, &mut rest);
    }

    fn chunk_round(&mut self, chunk: &[u8]) {
        let mut w = [0u32; 80];
        for (i, w) in &mut w[0..16].iter_mut().enumerate() {
            let i = i * 4;
            *w = u32::from_be_bytes([
                chunk[i],
                chunk[i + 1],
                chunk[i + 2],
                chunk[i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = (w[i - 15].rotate_right(7)) ^ (w[i - 15].rotate_right(18)) ^ (w[i - 15] >> 3);
            let s1 = (w[i - 2].rotate_right(17)) ^ (w[i - 2].rotate_right(19)) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.h0;
        let mut b = self.h1;
        let mut c = self.h2;
        let mut d = self.h3;
        let mut e = self.h4;
        let mut f = self.h5;
        let mut g = self.h6;
        let mut h = self.h7;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.h0 = self.h0.wrapping_add(a);
        self.h1 = self.h1.wrapping_add(b);
        self.h2 = self.h2.wrapping_add(c);
        self.h3 = self.h3.wrapping_add(d);
        self.h4 = self.h4.wrapping_add(e);
        self.h5 = self.h5.wrapping_add(f);
        self.h6 = self.h6.wrapping_add(g);
        self.h7 = self.h7.wrapping_add(h);
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Digest {
    digest: [u8; DIGEST_LEN],
}

impl Digest {
    pub fn to_hex(&self) -> String {
        let mut hex = String::with_capacity(DIGEST_LEN * 2);
        for byte in &self.digest {
            hex.push_str(&format!("{:02x}", byte));
        }
        hex
    }
    pub fn to_bytes(&self) -> [u8; DIGEST_LEN] {
        self.digest
    }
}

#[cfg(test)]
mod tests {
    use crate::sha256::CHUNK_LEN;

    #[test]
    fn empty() {
        let digest = super::Sha256::new().finalize();
        assert_eq!(
            digest.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn boef() {
        let mut hasher = super::Sha256::new();
        hasher.update(b"boef");
        let digest = hasher.finalize();
        assert_eq!(digest.to_hex(), "f7c43761f480a2f143927021124dab8809af52f7cf5aafee97c44b320411f763")
    }

    #[test]
    fn multiple_updates() {
        let mut hasher = super::Sha256::new();
        hasher.update(b"b");
        hasher.update(b"o");
        hasher.update(b"e");
        hasher.update(b"f");
        let digest = hasher.finalize();
        assert_eq!(digest.to_hex(), "f7c43761f480a2f143927021124dab8809af52f7cf5aafee97c44b320411f763")
    }

    #[test]
    fn large_string() {
        let mut hasher = super::Sha256::new();
        hasher.update(b"b".repeat(40000).as_slice());
        let digest = hasher.finalize();
        assert_eq!(digest.to_hex(), "8d1724bdb7c95026269c36827c31b89f5d63713c14d5474a78fefd7782b28c5c")
    }

    #[test]
    fn chunk_len() {
        let mut hasher = super::Sha256::new();
        hasher.update(b"b".repeat(CHUNK_LEN).as_slice());
        let digest = hasher.finalize();
        assert_eq!(digest.to_hex(), "a0fab1377f49a759b57f63318262ebe89fabfc990e8e93ceac2984561482b9d4")
    }

    #[test]
    fn chunk_len_plus_one() {
        let mut hasher = super::Sha256::new();
        hasher.update(b"b".repeat(CHUNK_LEN + 1).as_slice());
        let digest = hasher.finalize();
        assert_eq!(digest.to_hex(), "74b128f30cf83de43ddf4aafc40c7b50a7443d3c73a89a7cfca17e15e43d51ab")
    }

    #[test]
    fn chunk_len_minus_one() {
        let mut hasher = super::Sha256::new();
        hasher.update(b"b".repeat(CHUNK_LEN - 1).as_slice());
        let digest = hasher.finalize();
        assert_eq!(digest.to_hex(), "94e419fabac7f930810f9636354042f8c1426d2f834d4ab65c93dc1e69326b13")
    }
}
