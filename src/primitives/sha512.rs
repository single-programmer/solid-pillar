//! SHA-512 hashing implementation.
//!
//! # Example
//! ```rust
//! use solid_pillar::primitives::sha512::Sha512;
//!
//! let mut hasher = Sha512::new();
//! hasher.update(b"Hello, ");
//! hasher.update(b"world!");
//! let result = hasher.finalize();
//! assert_eq!(result.to_hex(), "c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421");
//! ```

use std::mem::swap;

const H0: u64 = 0x6a09e667f3bcc908;
const H1: u64 = 0xbb67ae8584caa73b;
const H2: u64 = 0x3c6ef372fe94f82b;
const H3: u64 = 0xa54ff53a5f1d36f1;
const H4: u64 = 0x510e527fade682d1;
const H5: u64 = 0x9b05688c2b3e6c1f;
const H6: u64 = 0x1f83d9abfb41bd6b;
const H7: u64 = 0x5be0cd19137e2179;

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

pub struct Sha512 {
    h0: u64,
    h1: u64,
    h2: u64,
    h3: u64,
    h4: u64,
    h5: u64,
    h6: u64,
    h7: u64,
    msgbytelen: usize,
    rest: [u8; CHUNK_LEN],
    restlen: usize,
}

const CHUNK_LEN_BITS: usize = 1024;
const CHUNK_LEN: usize = CHUNK_LEN_BITS / 8;
const DIGEST_LEN: usize = 512 / 8;

impl Sha512 {
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
        digest[0..8].copy_from_slice(&self.h0.to_be_bytes());
        digest[8..16].copy_from_slice(&self.h1.to_be_bytes());
        digest[16..24].copy_from_slice(&self.h2.to_be_bytes());
        digest[24..32].copy_from_slice(&self.h3.to_be_bytes());
        digest[32..40].copy_from_slice(&self.h4.to_be_bytes());
        digest[40..48].copy_from_slice(&self.h5.to_be_bytes());
        digest[48..56].copy_from_slice(&self.h6.to_be_bytes());
        digest[56..64].copy_from_slice(&self.h7.to_be_bytes());
        Digest { digest }
    }

    fn chunk_rest(&mut self) {
        let mut rest = [0; CHUNK_LEN];
        swap(&mut self.rest, &mut rest);
        self.chunk_round(&rest);
        swap(&mut self.rest, &mut rest);
    }

    fn chunk_round(&mut self, chunk: &[u8]) {
        let mut w = [0u64; 80];
        for (i, w) in &mut w[0..16].iter_mut().enumerate() {
            let i = i * 8;
            *w = u64::from_be_bytes([
                chunk[i],
                chunk[i + 1],
                chunk[i + 2],
                chunk[i + 3],
                chunk[i + 4],
                chunk[i + 5],
                chunk[i + 6],
                chunk[i + 7],
            ]);
        }
        for i in 16..80 {
            let s0 = (w[i - 15].rotate_right(1)) ^ (w[i - 15].rotate_right(8)) ^ (w[i - 15] >> 7);
            let s1 = (w[i - 2].rotate_right(19)) ^ (w[i - 2].rotate_right(61)) ^ (w[i - 2] >> 6);
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

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
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

impl Default for Sha512 {
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
    use super::*;

    #[test]
    fn empty() {
        let sha512 = super::Sha512::new();
        let digest = sha512.finalize();
        assert_eq!(digest.to_hex(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }

    #[test]
    fn boef() {
        let mut sha512 = super::Sha512::new();
        sha512.update(b"boef");
        let digest = sha512.finalize();
        assert_eq!(digest.to_hex(), "08f2741801e0f0556f77391be5518f88ca6996777e726ecb0ffdf26feea7666971f053da5408a832fa980cd3a069c54738f1ce0a756d3d3e12431c77965904c9");
    }

    #[test]
    fn multiple_updates() {
        let mut sha512 = super::Sha512::new();
        sha512.update(b"b");
        sha512.update(b"o");
        sha512.update(b"e");
        sha512.update(b"f");
        let digest = sha512.finalize();
        assert_eq!(digest.to_hex(), "08f2741801e0f0556f77391be5518f88ca6996777e726ecb0ffdf26feea7666971f053da5408a832fa980cd3a069c54738f1ce0a756d3d3e12431c77965904c9");
    }

    #[test]
    fn large_string() {
        let mut sha512 = super::Sha512::new();
        sha512.update(b"b".repeat(40000).as_slice());
        let digest = sha512.finalize();
        assert_eq!(digest.to_hex(), "ef40906c6f313fd7dc5dee8cf248e476409ffc3c2a339134e2948cd75cc851645252e623cd0c7b6fa49129410c6110c8062ee3705a333b9a1dfa24b31e4be55d");
    }

    #[test]
    fn chunk_len() {
        let mut sha512 = super::Sha512::new();
        sha512.update(b"b".repeat(CHUNK_LEN).as_slice());
        let digest = sha512.finalize();
        assert_eq!(digest.to_hex(), "fef679bea370b59c774dc497fa4435b9bd0e1d7f54dc24b4d0a55c16190d6e17da48c744ce7475b13565f533aab813430258db6734fb6acabc8549f9c35a7d1a");
    }

    #[test]
    fn chunk_len_minus_one() {
        let mut sha512 = super::Sha512::new();
        sha512.update(b"b".repeat(CHUNK_LEN - 1).as_slice());
        let digest = sha512.finalize();
        assert_eq!(digest.to_hex(), "1fb5054735807a95088312066bdd2acec2eb8f65454bf77873cdf93998f79c75fc0f229ab4a8ffe0bfd5310a3357272adcecb378d1f310ee43ed4a0634c6e5b8");
    }

    #[test]
    fn chunk_len_plus_one() {
        let mut sha512 = super::Sha512::new();
        sha512.update(b"b".repeat(CHUNK_LEN + 1).as_slice());
        let digest = sha512.finalize();
        assert_eq!(digest.to_hex(), "f2614faf8a38a9f4a8724556fb3757459e1e8a4780edb8cd071b5c57177019225fb06a530b88d0ab3639a62bf9b8e80bbe127cb23ce7e836c10cf8dbada192d5");
    }
}
