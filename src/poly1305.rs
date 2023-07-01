//! Poly1305 MAC

const CHUNK_LEN: usize = 16;
const DIGEST_LEN: usize = 16;

pub fn poly1305_mac(msg: &[u8], key: [u8; 32]) -> [u8; 16] {
    todo!()
}

pub struct Poly1305 {
    r: [u32; 4],
    s: [u32; 4],
    h: [u32; 5],
    rest: [u8; 16],
    restlen: usize,
}

impl Poly1305 {
    pub fn new(key: [u8; 32]) -> Self {
        let mut r = [0; 4];
        r.copy_from_slice(&[
            u32::from_le_bytes(key[0..4].try_into().unwrap()),
            u32::from_le_bytes(key[4..8].try_into().unwrap()),
            u32::from_le_bytes(key[8..12].try_into().unwrap()),
            u32::from_le_bytes(key[12..16].try_into().unwrap()),
        ]);
        r[0] &= 0x0fffffff;
        r[1] &= 0x0ffffffc;
        r[2] &= 0x0ffffffc;
        r[3] &= 0x0ffffffc;
        let mut s: [u32; 4] = [0; 4];
        s.copy_from_slice(&[
            u32::from_le_bytes(key[16..20].try_into().unwrap()),
            u32::from_le_bytes(key[20..24].try_into().unwrap()),
            u32::from_le_bytes(key[24..28].try_into().unwrap()),
            u32::from_le_bytes(key[28..32].try_into().unwrap()),
        ]);
        dbg!(r);
        dbg!(s);
        Self {
            r,
            s,
            h: [0; 5],
            rest: [0; 16],
            restlen: 0,
        }
    }

    pub fn update(&mut self, msg: &[u8]) {
        let (left, right) = msg.split_at(CHUNK_LEN - self.restlen);
        self.rest[self.restlen..(self.restlen + left.len())].copy_from_slice(left);
        self.restlen += left.len();

        if self.restlen == CHUNK_LEN {
            mul_add(&mut self.h, self.r, self.rest, 1);
            self.restlen = 0;
        }

        let mut chunks = right.chunks_exact(CHUNK_LEN);
        for chunk in chunks.by_ref() {
            mul_add(&mut self.h, self.r, chunk.try_into().unwrap(), 1);
        }

        let rem = chunks.remainder();
        self.rest[..rem.len()].copy_from_slice(rem);
        self.restlen = rem.len();
    }

    pub fn finalize(mut self) -> Digest {
        // Process the last block (if any)
        // We move the final 1 according to remaining input length
        // (this will add less than 2^130 to the last input block)
        if self.restlen != 0 {
            // fill the rest of the buffer with zeros
            for i in self.restlen..CHUNK_LEN {
                self.rest[i] = 0;
            }
            // add the final 1
            self.rest[self.restlen] = 1;
            mul_add(&mut self.h, self.r, self.rest, 0);
        }

        let mut carry = 5u64;
        for i in 0..4 {
            carry += self.h[i] as u64;
            carry >>= 32;
        }
        println!("carry: {}", carry);
        carry += self.h[4] as u64;
        carry = (carry >> 2) * 5;
        let mut mac = [0; 16];
        for i in 0..4 {
            carry += (self.h[i] as u64).wrapping_add(self.s[i] as u64);
            mac[i*4..(i+1)*4].copy_from_slice(&(carry as u32).to_le_bytes());
            carry >>= 32;
        }
        Digest(mac)
    }
}

#[cfg(test)]
mod test_poly1305 {
    use super::*;

    #[test]
    fn test_rfc_vector() {
        let key = [0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x6, 0xa8, 0x1, 0x3, 0x80, 0x8a, 0xfb, 0xd, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b];
        let message = b"Cryptographic Forum Research Group";
        let mut poly = Poly1305::new(key);
        poly.update(message);
        let mac = poly.finalize();
        assert_eq!(mac.to_hex(), "a8061dc1305136c6c22b8baf0c0127a9");
    }
}

pub struct Digest([u8; 16]);

impl Digest {
    pub fn to_hex(&self) -> String {
        let mut hex = String::with_capacity(DIGEST_LEN * 2);
        for byte in &self.0 {
            hex.push_str(&format!("{:02x}", byte));
        }
        hex
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn mul_add(h: &mut [u32; 5], r: [u32; 4], inp: [u8; 16], end: u32) {
    let mut s = [0; 4];
    s[0] = u32::from_le_bytes(inp[0..4].try_into().unwrap());
    s[1] = u32::from_le_bytes(inp[4..8].try_into().unwrap());
    s[2] = u32::from_le_bytes(inp[8..12].try_into().unwrap());
    s[3] = u32::from_le_bytes(inp[12..16].try_into().unwrap());

    let s0: u64 = h[0] as u64 + (s[0] as u64); // s0 <= 1_fffffffe
    let s1: u64 = h[1] as u64 + (s[1] as u64); // s1 <= 1_fffffffe
    let s2: u64 = h[2] as u64 + (s[2] as u64); // s2 <= 1_fffffffe
    let s3: u64 = h[3] as u64 + (s[3] as u64); // s3 <= 1_fffffffe
    let s4: u32 = h[4] + end; // s4 <=          5

    // These would fit in 32 bits, but we need 64 bit multiplications
    let r0: u64 = r[0] as u64;
    let r1: u64 = r[1] as u64;
    let r2: u64 = r[2] as u64;
    let r3: u64 = r[3] as u64;
    let rr0: u64 = (r[0] as u64 >> 2) * 5; // lose 2 bottom bits...
    let rr1: u64 = (r[1] as u64 >> 2) * 5; // 2 bottom bits already cleared
    let rr2: u64 = (r[2] as u64 >> 2) * 5; // 2 bottom bits already cleared
    let rr3: u64 = (r[3] as u64 >> 2) * 5; // 2 bottom bits already cleared

    // school book modular multiplication (without carry propagation)
    let x0: u64 = s0 * r0 + s1 * rr3 + s2 * rr2 + s3 * rr1 + (s4 as u64) * rr0;
    let x1: u64 = s0 * r1 + s1 * r0 + s2 * rr3 + s3 * rr2 + (s4 as u64) * rr1;
    let x2: u64 = s0 * r2 + s1 * r1 + s2 * r0 + s3 * rr3 + (s4 as u64) * rr2;
    let x3: u64 = s0 * r3 + s1 * r2 + s2 * r1 + s3 * r0 + (s4 as u64) * rr3;
    let x4: u64 = (s4 as u64) * (r0 & 3); // ...recover those 2 bits

    // carry propagation (put the result back in h)
    let msb: u64 = x4 + (x3 >> 32);
    let mut u: u64 = (msb >> 2) * 5; // lose 2 bottom bits...
    u += x0 & 0xffffffff;
    h[0] = (u & 0xffffffff) as u32;
    u >>= 32;
    u += (x1 & 0xffffffff) + (x0 >> 32);
    h[1] = (u & 0xffffffff) as u32;
    u >>= 32;
    u += (x2 & 0xffffffff) + (x1 >> 32);
    h[2] = (u & 0xffffffff) as u32;
    u >>= 32;
    u += (x3 & 0xffffffff) + (x2 >> 32);
    h[3] = (u & 0xffffffff) as u32;
    u >>= 32;
    u += msb & 3 /* ...recover them */ ;
    h[4] = u as u32;
}
