//! Implementation of the ChaCha20 stream cipher
//!
//! # Examples
//! ```rust
//! use solid_pillar::chacha20::ChaCha20KeyStream;
//!
//! let key = [
//!   0x00, 0x01, 0x02, 0x03,
//!   0x04, 0x05, 0x06, 0x07,
//!   0x08, 0x09, 0x0a, 0x0b,
//!   0x0c, 0x0d, 0x0e, 0x0f,
//!   0x10, 0x11, 0x12, 0x13,
//!   0x14, 0x15, 0x16, 0x17,
//!   0x18, 0x19, 0x1a, 0x1b,
//!   0x1c, 0x1d, 0x1e, 0x1f,
//! ];
//!
//! let nonce = [
//!   0x00, 0x00, 0x00, 0x00,
//!   0x00, 0x00, 0x00, 0x4a,
//!   0x00, 0x00, 0x00, 0x00,
//! ];
//!
//! let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
//!
//! let mut key_stream = ChaCha20KeyStream::new(key, 1, nonce);
//! let mut ciphertext = Vec::new();
//! for byte in plaintext {
//!  ciphertext.push(byte ^ key_stream.next().unwrap());
//! }
//! assert_eq!(ciphertext, [
//!   0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
//!   0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
//!   0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
//!   0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
//!   0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
//!   0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
//!   0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
//!   0x87, 0x4d,
//! ]);
//! ```

const C1: u32 = 0x61707865;
const C2: u32 = 0x3320646e;
const C3: u32 = 0x79622d32;
const C4: u32 = 0x6b206574;

const BLOCK_SIZE: usize = 64;

pub struct ChaCha20KeyStream {
    key: [u32; 8],
    blockcount: Option<u32>,
    nonce: [u32; 3],
    key_block: Option<BlockIterator>,
}

impl ChaCha20KeyStream {
    pub fn new(key: [u8; 32], initial_counter: u32, nonce: [u8; 12]) -> Self {
        ChaCha20KeyStream {
            key: [
                u32::from_le_bytes(key[0..4].try_into().unwrap()),
                u32::from_le_bytes(key[4..8].try_into().unwrap()),
                u32::from_le_bytes(key[8..12].try_into().unwrap()),
                u32::from_le_bytes(key[12..16].try_into().unwrap()),
                u32::from_le_bytes(key[16..20].try_into().unwrap()),
                u32::from_le_bytes(key[20..24].try_into().unwrap()),
                u32::from_le_bytes(key[24..28].try_into().unwrap()),
                u32::from_le_bytes(key[28..32].try_into().unwrap()),
            ],
            blockcount: Some(initial_counter),
            nonce: [
                u32::from_le_bytes(nonce[0..4].try_into().unwrap()),
                u32::from_le_bytes(nonce[4..8].try_into().unwrap()),
                u32::from_le_bytes(nonce[8..12].try_into().unwrap()),
            ],
            key_block: None,
        }
    }
}

impl Iterator for ChaCha20KeyStream {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        match (self.key_block.take(), self.blockcount) {
            (Some(mut key_block), _) => {
                if let Some(byte) = key_block.next() {
                    self.key_block = Some(key_block);
                    Some(byte)
                } else {
                    self.key_block = None; // Should already be the case, because of the take()
                    self.next()
                }
            }
            (None, Some(blockcount)) => {
                let block = chacha20_block(self.key, blockcount, self.nonce);
                self.blockcount = blockcount.checked_add(1);
                self.key_block = Some(BlockIterator::new(block));
                self.next()
            }
            (None, None) => {
                // The chunk_count overflowed, no more blocks can be generated
                None
            }
        }
    }
}

#[cfg(test)]
mod test_chacha_iterator {
    use super::*;

    #[test]
    fn test_rfc_vector() {
        let key = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f";
        let key: Vec<u8> = key
            .split(':')
            .map(|x| u8::from_str_radix(x, 16).unwrap())
            .collect();
        let nonce = "00:00:00:00:00:00:00:4a:00:00:00:00";
        let nonce: Vec<u8> = nonce
            .split(':')
            .map(|x| u8::from_str_radix(x, 16).unwrap())
            .collect();
        let key_stream =
            ChaCha20KeyStream::new(key.try_into().unwrap(), 1, nonce.try_into().unwrap());

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut ciphertext = Vec::new();
        for (pt_byte, key_byte) in plaintext.iter().zip(key_stream) {
            ciphertext.push(pt_byte ^ key_byte);
        }
        let expected = "6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81 e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57 16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8 07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e 52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36 5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42 87 4d";
        let expected: Vec<u8> = expected
            .split(' ')
            .map(|x| u8::from_str_radix(x, 16).unwrap())
            .collect();
        assert_eq!(ciphertext, expected);
    }
}

struct BlockIterator {
    buffer: [u8; BLOCK_SIZE],
    buffer_pos: usize,
}

impl BlockIterator {
    fn new(block: [u32; 16]) -> BlockIterator {
        let mut buffer = [0u8; BLOCK_SIZE];
        for (i, byte) in block.iter().flat_map(|word| word.to_le_bytes()).enumerate() {
            buffer[i] = byte;
        }

        BlockIterator {
            buffer,
            buffer_pos: 0,
        }
    }
}

impl Iterator for BlockIterator {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer_pos < BLOCK_SIZE {
            let byte = self.buffer[self.buffer_pos];
            self.buffer_pos += 1;
            Some(byte)
        } else {
            None
        }
    }
}

fn quarter_round_impl(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(16);
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(12);
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(8);
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(7);
    (a, b, c, d)
}

fn quarter_round(state: &mut [u32; 16], ai: usize, bi: usize, ci: usize, di: usize) {
    let (a, b, c, d) = quarter_round_impl(state[ai], state[bi], state[ci], state[di]);
    state[ai] = a;
    state[bi] = b;
    state[ci] = c;
    state[di] = d;
}

#[cfg(test)]
mod quarter_round_test {
    use super::quarter_round_impl;

    #[test]
    fn rfc_vector() {
        let a = 0x11111111;
        let b = 0x01020304;
        let c = 0x9b8d6f43;
        let d = 0x01234567;
        let (a, b, c, d) = quarter_round_impl(a, b, c, d);
        assert_eq!(a, 0xea2a92f4);
        assert_eq!(b, 0xcb1cf8ce);
        assert_eq!(c, 0x4581472e);
        assert_eq!(d, 0x5881c4bb);
    }
}

fn inner_block(state: &mut [u32; 16]) {
    quarter_round(state, 0, 4, 8, 12);
    quarter_round(state, 1, 5, 9, 13);
    quarter_round(state, 2, 6, 10, 14);
    quarter_round(state, 3, 7, 11, 15);
    quarter_round(state, 0, 5, 10, 15);
    quarter_round(state, 1, 6, 11, 12);
    quarter_round(state, 2, 7, 8, 13);
    quarter_round(state, 3, 4, 9, 14);
}

fn chacha20_block(key: [u32; 8], blockcount: u32, nonce: [u32; 3]) -> [u32; 16] {
    let mut state = [
        C1, C2, C3, C4, key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], blockcount,
        nonce[0], nonce[1], nonce[2],
    ];
    if blockcount == 2 {
        assert_eq!(
            state,
            [
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
                0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000002, 0x00000000,
                0x4a000000, 0x00000000
            ]
        )
    }
    let initial_state = state;
    for _ in 0..10 {
        inner_block(&mut state);
    }
    for (state_word, orig_word) in state.iter_mut().zip(initial_state) {
        *state_word = state_word.wrapping_add(orig_word);
    }
    if blockcount == 2 {
        assert_eq!(
            state,
            [
                0x9f74a669, 0x410f633f, 0x28feca22, 0x7ec44dec, 0x6d34d426, 0x738cb970, 0x3ac5e9f3,
                0x45590cc4, 0xda6e8b39, 0x892c831a, 0xcdea67c1, 0x2b7e1d90, 0x037463f3, 0xa11a2073,
                0xe8bcfb88, 0xedc49139
            ]
        )
    }
    state
}

#[cfg(test)]
mod chacha20_block_test {
    use super::*;

    #[test]
    fn rfc_vector() {
        let key = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f";
        let key: Vec<u8> = key
            .split(':')
            .map(|x| u8::from_str_radix(x, 16).unwrap())
            .collect();
        let key: Vec<u32> = key
            .chunks_exact(4)
            .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
            .collect();

        let nonce = "00:00:00:09:00:00:00:4a:00:00:00:00";
        let nonce: Vec<u8> = nonce
            .split(':')
            .map(|x| u8::from_str_radix(x, 16).unwrap())
            .collect();
        let nonce: Vec<u32> = nonce
            .chunks_exact(4)
            .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
            .collect();

        let blockcount = 1u32;
        let block = chacha20_block(
            [
                key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
            ],
            blockcount,
            [nonce[0], nonce[1], nonce[2]],
        );
        let block: Vec<u8> = block
            .iter()
            .flat_map(|x| x.to_le_bytes().to_vec())
            .collect();
        let block: Vec<String> = block.iter().map(|x| format!("{:02x}", x)).collect();
        let block = block.join(":");
        assert_eq!(block, "10:f1:e7:e4:d1:3b:59:15:50:0f:dd:1f:a3:20:71:c4:c7:d1:f4:c7:33:c0:68:03:04:22:aa:9a:c3:d4:6c:4e:d2:82:64:46:07:9f:aa:09:14:c2:d7:05:d9:8b:02:a2:b5:12:9c:d1:de:16:4e:b9:cb:d0:83:e8:a2:50:3c:4e");
    }
}
