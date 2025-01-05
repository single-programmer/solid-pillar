//! SHA-256 hashing implementation.
//!
//! # Example
//! ```rust
//! use solid_pillar::primitives::sha256::Sha256;
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
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(msg: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    hasher.finalize()
}

pub struct Sha256 {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    h5: u32,
    h6: u32,
    h7: u32,
    w: [u32; 64],
    msgbytelen: usize,
    rest: [u8; CHUNK_LEN],
    restlen: usize,
}

const CHUNK_LEN_BITS: usize = 512;
const CHUNK_LEN: usize = CHUNK_LEN_BITS / 8;
pub(crate) const DIGEST_LEN: usize = 256 / 8;

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
            w: [0; 64],
            msgbytelen: 0,
            rest: [0; CHUNK_LEN],
            restlen: 0,
        }
    }

    pub fn update(&mut self, msg: &[u8]) {
        self.msgbytelen += msg.len();

        // If we can't fill a chunk yet, just store and return
        if self.restlen + msg.len() < CHUNK_LEN {
            self.rest[self.restlen..(self.restlen + msg.len())].copy_from_slice(msg);
            self.restlen += msg.len();
            return;
        }

        // Process any remaining data from previous update with new data
        let mut bytes = msg;
        if self.restlen > 0 {
            let needed = CHUNK_LEN - self.restlen;
            self.rest[self.restlen..].copy_from_slice(&bytes[..needed]);
            let rest_copy = self.rest;
            self.chunk_round(&rest_copy);
            bytes = &bytes[needed..];
            self.restlen = 0;
        }

        // Process full chunks
        while bytes.len() >= CHUNK_LEN {
            self.chunk_round(&bytes[..CHUNK_LEN]);
            bytes = &bytes[CHUNK_LEN..];
        }

        // Store any remaining bytes
        if !bytes.is_empty() {
            self.rest[..bytes.len()].copy_from_slice(bytes);
            self.restlen = bytes.len();
        }
    }

    pub fn finalize(mut self) -> Digest {
        // Add padding byte
        if self.restlen == CHUNK_LEN {
            self.chunk_rest();
            self.restlen = 0;
        }
        self.rest[self.restlen] = 0x80;
        self.restlen += 1;

        // Zero out the rest of the chunk
        for byte in &mut self.rest[self.restlen..CHUNK_LEN] {
            *byte = 0;
        }

        // Convert message length to bits and prepare for appending
        let length_bits = (self.msgbytelen as u64) * 8;
        let length_bytes = length_bits.to_be_bytes();

        // Check if we need an additional chunk for the length
        if self.restlen + 8 >= CHUNK_LEN {
            // Process current chunk
            self.chunk_rest();

            // Prepare final chunk with length
            let mut final_chunk = [0; CHUNK_LEN];
            final_chunk[CHUNK_LEN - 8..].copy_from_slice(&length_bytes);
            self.chunk_round(&final_chunk);
        } else {
            // We can fit length in current chunk
            self.rest[CHUNK_LEN - 8..].copy_from_slice(&length_bytes);
            self.chunk_rest();
        }

        // Prepare final digest
        let mut digest = [0; DIGEST_LEN];
        let state = [
            self.h0, self.h1, self.h2, self.h3, self.h4, self.h5, self.h6, self.h7,
        ];

        for (i, &value) in state.iter().enumerate() {
            let start = i * 4;
            digest[start..start + 4].copy_from_slice(&value.to_be_bytes());
        }

        Digest(digest)
    }

    fn chunk_rest(&mut self) {
        let mut rest = [0; CHUNK_LEN];
        swap(&mut self.rest, &mut rest);
        self.chunk_round(&rest);
        swap(&mut self.rest, &mut rest);
    }

    fn chunk_round(&mut self, chunk: &[u8]) {
        for (i, w) in &mut self.w[0..16].iter_mut().enumerate() {
            let i = i * 4;
            *w = u32::from_be_bytes([chunk[i], chunk[i + 1], chunk[i + 2], chunk[i + 3]]);
        }
        for i in 16..64 {
            let s0 = (self.w[i - 15].rotate_right(7))
                ^ (self.w[i - 15].rotate_right(18))
                ^ (self.w[i - 15] >> 3);
            let s1 = (self.w[i - 2].rotate_right(17))
                ^ (self.w[i - 2].rotate_right(19))
                ^ (self.w[i - 2] >> 10);
            self.w[i] = self.w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(self.w[i - 7])
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

        for (i, &k) in K.iter().enumerate() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k)
                .wrapping_add(self.w[i]);
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

pub struct Digest([u8; DIGEST_LEN]);

impl Digest {
    pub fn to_hex(&self) -> String {
        let mut hex = String::with_capacity(DIGEST_LEN * 2);
        for byte in &self.0 {
            hex.push_str(&format!("{:02x}", byte));
        }
        hex
    }
    pub fn to_bytes(&self) -> [u8; DIGEST_LEN] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_world() {
        let mut hasher = Sha256::new();
        hasher.update(b"hello world");
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

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
        assert_eq!(
            digest.to_hex(),
            "f7c43761f480a2f143927021124dab8809af52f7cf5aafee97c44b320411f763"
        )
    }

    #[test]
    fn multiple_updates() {
        let mut hasher = super::Sha256::new();
        hasher.update(b"b");
        hasher.update(b"o");
        hasher.update(b"e");
        hasher.update(b"f");
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "f7c43761f480a2f143927021124dab8809af52f7cf5aafee97c44b320411f763"
        )
    }

    #[test]
    fn large_string() {
        let mut hasher = super::Sha256::new();
        hasher.update(b"b".repeat(40000).as_slice());
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "8d1724bdb7c95026269c36827c31b89f5d63713c14d5474a78fefd7782b28c5c"
        )
    }

    #[test]
    fn chunk_len() {
        let mut hasher = super::Sha256::new();
        hasher.update(b"b".repeat(CHUNK_LEN).as_slice());
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "a0fab1377f49a759b57f63318262ebe89fabfc990e8e93ceac2984561482b9d4"
        )
    }

    #[test]
    fn chunk_len_plus_one() {
        let mut hasher = super::Sha256::new();
        hasher.update(b"b".repeat(CHUNK_LEN + 1).as_slice());
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "74b128f30cf83de43ddf4aafc40c7b50a7443d3c73a89a7cfca17e15e43d51ab"
        )
    }

    #[test]
    fn chunk_len_minus_one() {
        let mut hasher = super::Sha256::new();
        hasher.update(b"b".repeat(CHUNK_LEN - 1).as_slice());
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "94e419fabac7f930810f9636354042f8c1426d2f834d4ab65c93dc1e69326b13"
        )
    }

    #[test]
    fn test_lorem_ipsum() {
        let mut hasher = super::Sha256::new();
        hasher.update(b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur venenatis eget ligula nec ultricies. Vivamus ut mi maximus, gravida massa sed, congue justo. ");
        hasher.update(b"Maecenas interdum ligula id turpis dignissim, a elementum ex elementum. Donec congue vulputate commodo. Nullam faucibus eu nisl et porta. Fusce in fringilla lectus. Duis suscipit egestas justo, eget hendrerit tellus. Sed placerat ultrices tempus. Praesent lacus nibh, vestibulum et rutrum sit amet, vulputate non elit. Fusce suscipit enim enim, nec lacinia turpis tempor sed. Etiam pellentesque risus sit amet rutrum rutrum. Duis tempor aliquet justo, non ultricies diam maximus sed. Suspendisse potenti. Donec eu fermentum mauris, eu pretium elit. Nullam pharetra consectetur elit vitae finibus. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos.");
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "4b8ab73e9d4ef437a25024f8acfbed29c3cce8366ee5547cd66896b6570abb4c"
        );
    }

    #[test]
    fn test_hmac_data() {
        let mut hasher = super::Sha256::new();
        hasher.update(hex::decode("9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c3636363636363636363636363636363636363636363636363636363636363636363636363636363636363636").unwrap().as_slice());
        hasher.update(hex::decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap().as_slice());
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "8c430307395d8d846341209aa04fbe8633583c93bafecb668142713ab797525c"
        );
    }

    #[test]
    fn test_hmac_data2() {
        let mut hasher = super::Sha256::new();
        hasher.update(hex::decode("9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c3636363636363636363636363636363636363636363636363636363636363636363636363636363636363636dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap().as_slice());
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "8c430307395d8d846341209aa04fbe8633583c93bafecb668142713ab797525c"
        );
    }

    #[test]
    fn one_null_byte() {
        let mut hasher = super::Sha256::new();
        hasher.update(&[0]);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
    }

    #[test]
    fn two_null_bytes() {
        let mut hasher = super::Sha256::new();
        hasher.update(&[0, 0]);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"
        );
    }

    #[test]
    fn sixtythree_null_bytes() {
        let mut hasher = super::Sha256::new();
        hasher.update(&[0; 63]);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "c7723fa1e0127975e49e62e753db53924c1bd84b8ac1ac08df78d09270f3d971"
        );
    }

    #[test]
    fn sixtyfour_null_bytes() {
        let mut hasher = super::Sha256::new();
        hasher.update(&[0; 64]);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
        );
    }

    #[test]
    fn sixtyfive_null_bytes() {
        let mut hasher = super::Sha256::new();
        hasher.update(&[0; 65]);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "98ce42deef51d40269d542f5314bef2c7468d401ad5d85168bfab4c0108f75f7"
        );
    }

    #[test]
    fn one_dd_byte() {
        let mut hasher = super::Sha256::new();
        hasher.update(&[0xdd]);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "2795044ce0f83f718bc79c5f2add1e52521978df91ce9b7f82c9097191d33602"
        );
    }

    #[test]
    fn two_dd_bytes() {
        let mut hasher = super::Sha256::new();
        hasher.update(&[0xdd, 0xdd]);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "985930b3c0d5b34d8f750c8b879cde6480224c5d39f093d66489e4d98ceb4a42"
        );
    }

    #[test]
    fn sixtythree_dd_bytes() {
        let mut hasher = super::Sha256::new();
        hasher.update(&[0xdd; 63]);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "818364af20f99a458e17ca920ce4cac2d48ecce8725caff51e9507592b69d962"
        );
    }

    #[test]
    fn sixtyfour_dd_bytes() {
        let mut hasher = super::Sha256::new();
        hasher.update(&[0xdd; 64]);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "699549ecab4a117a50112d4885a80c2b190dd08a9409b6fe5a170a47d55c84de"
        );
    }

    #[test]
    fn sixtyfive_dd_bytes() {
        let mut hasher = super::Sha256::new();
        hasher.update(&[0xdd; 65]);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "3724aefaa1134f7d310b97385c01a32e1a6db7df3bff31167bb12891bb9e54cf"
        );
    }

    #[test]
    fn one_36_byte() {
        let mut hasher = super::Sha256::new();
        hasher.update(&[0x36]);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683"
        );
    }

    #[test]
    fn two_36_bytes() {
        let mut hasher = super::Sha256::new();
        hasher.update(&[0x36, 0x36]);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "3ada92f28b4ceda38562ebf047c6ff05400d4c572352a1142eedfef67d21e662"
        );
    }

    #[test]
    fn sixtythree_36_bytes() {
        let mut hasher = super::Sha256::new();
        hasher.update(&[0x36; 63]);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "bed73e8a8b67d9048f0a0c99e92e2d1b267808eaa2751df15ca6bc94d28db995"
        );
    }

    #[test]
    fn sixtyfour_36_bytes() {
        let mut hasher = super::Sha256::new();
        hasher.update(&[0x36; 64]);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "e72bbd4d429ac914a8a6c5bd49632ff6b00d4fef42afb443f0b8047df06c85d2"
        );
    }

    #[test]
    fn sixtyfive_36_bytes() {
        let mut hasher = super::Sha256::new();
        hasher.update(&[0x36; 65]);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "8e204235ffe8838f2f8c169ba7105b3b8c34b9c586511c0e19308e0f963e6d18"
        );
    }

    #[test]
    fn one_9c_byte() {
        let mut hasher = super::Sha256::new();
        hasher.update(&[0x9c]);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "6e3faf1e27d45fca70234ae8f6f0a734622cff8a6ea824b7f60d3ffafa2a4654"
        );
    }

    #[test]
    fn test_hmac_pattern_shorter() {
        let mut hasher = super::Sha256::new();
        // Half the length of each section compared to failing test
        hasher.update(
            hex::decode("9c9c9c9c9c9c9c9c9c9c363636363636363636363636dddddddddddddddddddddd")
                .unwrap()
                .as_slice(),
        );
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "17a5efa258129b5bb575cacce18056d2030a977de26207e43a67a963de68015a"
        );
    }

    #[test]
    fn test_hmac_pattern_longer() {
        let mut hasher = super::Sha256::new();
        // Double the length of each section
        hasher.update(hex::decode("9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c363636363636363636363636363636363636363636363636363636363636363636363636dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap().as_slice());
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "39689a1037c316778ce02cef07095d9ea91fcce80c239c2aa16638698f82e2fc"
        );
    }

    #[test]
    fn test_hmac_pattern_offset() {
        let mut hasher = super::Sha256::new();
        // Original pattern shifted by one byte
        hasher.update(&[0x00]); // Add one byte prefix
        hasher.update(hex::decode("9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c3636363636363636363636363636363636363636363636363636363636363636363636363636363636363636dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap().as_slice());
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "8b1c898f5c4ee8bc70ee0f2720efc2acbd036b0ea378df6581515e1bdc22c91f"
        );
    }

    #[test]
    fn test_hmac_different_patterns() {
        let mut hasher = super::Sha256::new();
        // Same lengths but different bytes
        hasher.update(
            hex::decode(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccc",
            )
            .unwrap()
            .as_slice(),
        ); // 0xcc instead of 0xdd
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "dc034d6e26d710a0b2cf6c5d51529b0cde58dc278b224ead750b80be81359c0d"
        );
    }

    #[test]
    fn test_hmac_split_at_different_points() {
        let mut hasher = super::Sha256::new();
        // Split the updates at different positions
        let data = hex::decode("9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c3636363636363636363636363636363636363636363636363636363636363636363636363636363636363636dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap();
        let split_point = 45; // Choose a different split point than the original test
        let (part1, part2) = data.split_at(split_point);
        hasher.update(part1);
        hasher.update(part2);
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "8c430307395d8d846341209aa04fbe8633583c93bafecb668142713ab797525c"
        );
    }

    #[test]
    fn test_hmac_chunk_boundary() {
        let mut hasher = super::Sha256::new();
        // Create input that ends exactly at chunk boundary
        let chunk_size = 64; // SHA-256 chunk size
        let pattern = hex::decode("9c36dd").unwrap();
        let repeats = chunk_size / pattern.len();
        for _ in 0..repeats {
            hasher.update(&pattern);
        }
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "33897e1d1c822dd2c7b34df77e00ca44096c34809b24dc317dbfb3fee43d6699"
        );
    }

    #[test]
    fn test_hmac_near_chunk_boundary() {
        let mut hasher = super::Sha256::new();
        // Create input that ends near chunk boundary
        let chunk_size = 64; // SHA-256 chunk size
        let pattern = hex::decode("9c36dd").unwrap();
        let repeats = chunk_size / pattern.len();
        for _ in 0..repeats {
            hasher.update(&pattern);
        }
        hasher.update(&[0x9c]); // Add one more byte to cross boundary
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "2fa3b267d4d181b0a19e30d71a004b1216b609fbec608d2e1721aca17154b2c9"
        );
    }

    #[test]
    fn test_hmac_single_byte_updates() {
        let mut hasher = super::Sha256::new();
        // Same pattern but update one byte at a time
        let data = hex::decode("9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c3636363636363636363636363636363636363636363636363636363636363636363636363636363636363636dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap();
        for byte in data {
            hasher.update(&[byte]);
        }
        let digest = hasher.finalize();
        assert_eq!(
            digest.to_hex(),
            "c39bdff39c9e01d05aab1c7a77b3646c07e572b4bd5895b09eebfb9d231b52cb"
        );
    }
}
