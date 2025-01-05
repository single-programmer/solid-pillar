//! A pure Rust implementation of the X25519 ECDH key exchange algorithm.
//!
//! # Examples
//! ```rust
//! use solid_pillar::primitives::x25519::{new_keypair, PublicKey, SecretKey, KeyData};
//!
//! let (alice_sk, alice_pk) = new_keypair();
//! let (bob_sk, bob_pk) = new_keypair();
//!
//! // Bob generates his shared key the public key Alice sent him
//! let bob_shared = alice_pk.x25519(bob_sk);
//! // Alice generates her shared key the public key Bob sent her
//! let alice_shared = bob_pk.x25519(alice_sk);
//!
//! // They both share the same secret, even though only public information was exchanged
//! assert_eq!(alice_shared.to_bytes(), bob_shared.to_bytes());
//! ```
//!

#[cfg(test)]
use std::fmt::{self, Write};
use std::ops::{Add, Mul, Sub};

/// Generates a pair of secret and public key
///
/// This uses the `getrandom` crate for the random bytes.
///
/// See the [`SecretKey`] and [`PublicKey`] structs for more information about
/// how to use the output of this function.
pub fn new_keypair() -> (SecretKey, PublicKey) {
    let mut sk_bytes: [u8; 32] = [0; 32];
    getrandom::getrandom(&mut sk_bytes).expect("getting random bytes");
    let sk = Scalar::from_bytes(sk_bytes);
    let pk = &BASE * &sk;
    (SecretKey { s: sk }, PublicKey { p: pk })
}

pub struct SecretKey {
    s: Scalar,
}

#[cfg(test)]
impl SecretKey {
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            s: Scalar::from_bytes(bytes),
        }
    }
}

pub struct PublicKey {
    p: Point,
}

impl PublicKey {
    /// Get a public key from a byte array
    ///
    /// Use this when you receive a public key from the other party
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { p: Point { bytes } }
    }

    /// Convert the public key to bytes
    ///
    /// This is useful for sending the public key over the network
    pub fn to_bytes(self) -> [u8; 32] {
        self.p.bytes
    }

    /// Combine the public key of the other party with your own secret key to get the
    /// shared secret key
    #[must_use]
    pub fn x25519(self, sk: SecretKey) -> KeyData {
        KeyData { p: &self.p * &sk.s }
    }
}

pub struct KeyData {
    p: Point,
}

impl KeyData {
    pub fn to_bytes(self) -> [u8; 32] {
        self.p.bytes
    }
}

const BASE: Point = Point {
    bytes: [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
};
const _121665: Scalar = Scalar {
    limbs: [0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
};

struct Point {
    bytes: [u8; 32],
}

impl<'a, 'b> Mul<&'a Scalar> for &'b Point {
    type Output = Point;

    fn mul(self, rhs: &'a Scalar) -> Self::Output {
        let mut clamped = rhs.clone().into_bytes();
        clamped[0] &= 0xf8;
        clamped[31] = (clamped[31] & 0x7f) | 0x40;
        let x = Scalar::from_bytes(self.bytes);
        let mut b = Scalar::from_bytes(self.bytes);
        let mut c = Scalar::zero();
        let mut a = Scalar::one();
        let mut d = Scalar::one();
        for i in (0..=254).rev() {
            let bit = ((clamped[i >> 3] >> (i & 7)) & 1) == 1;
            swap25519(&mut a.limbs, &mut b.limbs, bit);
            swap25519(&mut c.limbs, &mut d.limbs, bit);
            let mut e = &a + &c;
            a = &a - &c;
            c = &b + &d;
            b = &b - &d;
            d = &e * &e;
            let f = &a * &a;
            a = &c * &a;
            c = &b * &e;
            e = &a + &c;
            a = &a - &c;
            b = &a * &a;
            c = &d - &f;
            a = &c * &_121665;
            a = &a + &d;
            c = &c * &a;
            a = &d * &f;
            d = &b * &x;
            b = &e * &e;
            swap25519(&mut a.limbs, &mut b.limbs, bit);
            swap25519(&mut c.limbs, &mut d.limbs, bit);
        }
        c = c.recip();
        a = &a * &c;
        Point {
            bytes: a.into_bytes(),
        }
    }
}

/// Test vectors from NaCl
#[cfg(test)]
mod test_scalar_mult {
    use super::*;

    #[test]
    fn scalarmult() {
        let alicesk = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let expected = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        let sk = Scalar::from_bytes(alicesk);
        println!("{}", sk.write_polynomial().unwrap());
        let pubkey = &BASE * &sk;
        assert_eq!(pubkey.bytes, expected);
    }

    #[test]
    fn scalarmult2() {
        let bobsk = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];
        let expected = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];
        let sk = Scalar::from_bytes(bobsk);
        println!("{}", sk.write_polynomial().unwrap());
        let pubkey = &BASE * &sk;
        assert_eq!(pubkey.bytes, expected);
    }

    #[test]
    fn scalarmult5() {
        let alicesk = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bobpk = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];
        let expected = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];
        let sk = SecretKey::from_bytes(alicesk);
        let pk = PublicKey::from_bytes(bobpk);
        let keydata = pk.x25519(sk);
        assert_eq!(keydata.to_bytes(), expected);
    }

    #[test]
    fn scalarmult6() {
        let bobsk = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];
        let alicepk = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        let expected = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];
        let sk = SecretKey::from_bytes(bobsk);
        let pk = PublicKey::from_bytes(alicepk);
        let keydata = pk.x25519(sk);
        assert_eq!(keydata.to_bytes(), expected);
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Scalar {
    limbs: [i64; 16],
}

/// Scalars in the GF(2**255 - 19) field
impl Scalar {
    fn zero() -> Self {
        Self { limbs: [0; 16] }
    }
    fn one() -> Self {
        let mut limbs = [0; 16];
        limbs[0] = 1;
        Self { limbs }
    }
    fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0; 16];
        for (i, chunk) in bytes.chunks_exact(2).enumerate() {
            let [b1, b2] = chunk else {
                unreachable!()
            };
            limbs[i] = (*b1 as i64) + ((*b2 as i64) << 8);
        }
        limbs[15] &= 0x7fff;
        Self { limbs }
    }

    fn into_bytes(self) -> [u8; 32] {
        let mut t = self.limbs;
        let mut m: [i64; 16] = [0; 16];
        carry25519(&mut t);
        carry25519(&mut t);
        carry25519(&mut t);
        for _ in 0..2 {
            m[0] = t[0] - 0xffed;
            for i in 1..15 {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            let carry = (m[15] >> 16) & 1;
            m[14] &= 0xffff;
            swap25519(&mut t, &mut m, (1 - carry) != 0);
        }
        let mut bytes: [u8; 32] = [0; 32];
        for i in 0..16 {
            bytes[2 * i] = (t[i] & 0xff) as u8;
            bytes[2 * i + 1] = (t[i] >> 8) as u8;
        }
        bytes
    }

    fn recip(&self) -> Self {
        let mut c = self.clone();
        for i in (0..=253).rev() {
            c = &c * &c;
            if i != 2 && i != 4 {
                c = &c * self;
            }
        }
        c
    }

    /// Print out the contents of the limbs in polynomial form (Python syntax)
    #[cfg(test)]
    fn write_polynomial(&self) -> Result<String, fmt::Error> {
        let mut o = String::new();
        for (i, limb) in self.limbs.iter().enumerate() {
            let p = i * 16;
            if i > 0 {
                write!(&mut o, " + ")?;
            }
            write!(&mut o, "{} * 2**{}", limb, p)?;
        }
        Ok(o)
    }
}

#[cfg(test)]
mod test_bignum {
    use std::process::Command;

    use super::*;

    fn run_python<S>(code: S) -> String
    where
        S: AsRef<str>,
    {
        let code = code.as_ref();
        let code = format!("print(({code}) % (2**255 - 19))");
        println!("{code}");
        String::from_utf8(
            Command::new("python3")
                .args(["-c", &code])
                .output()
                .expect("cannot run python")
                .stdout,
        )
        .expect("output must be utf-8")
    }

    #[test]
    fn test_recip() {
        let s = Scalar::from_bytes([
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);
        assert_eq!(
            run_python(s.recip().write_polynomial().unwrap()),
            run_python(format!(
                "pow({}, -1, 2**255 - 19)",
                s.write_polynomial().unwrap()
            ))
        )
    }

    #[test]
    fn test_recip2() {
        let s = Scalar::from_bytes([
            117, 14, 242, 210, 45, 213, 171, 8, 67, 98, 45, 27, 152, 117, 254, 77, 251, 200, 181,
            52, 207, 53, 204, 48, 226, 245, 20, 240, 15, 58, 209, 79,
        ]);
        assert_eq!(
            run_python(s.recip().write_polynomial().unwrap()),
            run_python(format!(
                "pow({}, -1, 2**255 - 19)",
                s.write_polynomial().unwrap()
            ))
        )
    }

    #[test]
    fn test_recip3() {
        let s = Scalar::from_bytes([
            170, 58, 143, 154, 242, 81, 210, 13, 54, 38, 8, 197, 77, 27, 91, 79, 225, 189, 237,
            230, 252, 19, 149, 25, 3, 77, 173, 126, 81, 102, 9, 134,
        ]);
        assert_eq!(
            run_python(s.recip().write_polynomial().unwrap()),
            run_python(format!(
                "pow({}, -1, 2**255 - 19)",
                s.write_polynomial().unwrap()
            ))
        )
    }

    #[test]
    fn test_trivial_add() {
        let lhs = Scalar::from_bytes([0; 32]);
        let rhs = Scalar::from_bytes([0; 32]);
        assert_eq!(&lhs + &rhs, lhs);
    }

    #[test]
    fn test_simple_add() {
        let scalar = Scalar::from_bytes([1; 32]);
        let scalar2 = Scalar::from_bytes([
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);
        let st = (&scalar + &scalar2).write_polynomial().unwrap();
        println!("{st}");
        assert_eq!(
            run_python(st),
            run_python(format!(
                "({}) + ({})",
                scalar.write_polynomial().unwrap(),
                scalar2.write_polynomial().unwrap()
            ))
        )
    }

    #[test]
    fn test_random_add_2141() {
        let lhs = Scalar::from_bytes([
            117, 14, 242, 210, 45, 213, 171, 8, 67, 98, 45, 27, 152, 117, 254, 77, 251, 200, 181,
            52, 207, 53, 204, 48, 226, 245, 20, 240, 15, 58, 209, 79,
        ]);
        let rhs = Scalar::from_bytes([
            243, 46, 194, 185, 26, 237, 79, 215, 153, 179, 102, 230, 14, 213, 39, 167, 83, 39, 110,
            111, 221, 47, 82, 24, 162, 119, 47, 46, 191, 207, 184, 199,
        ]);
        let rust_result = (&lhs + &rhs).write_polynomial().unwrap();
        assert_eq!(
            run_python(rust_result),
            run_python(format!(
                "({}) + ({})",
                lhs.write_polynomial().unwrap(),
                rhs.write_polynomial().unwrap()
            ))
        );
    }
    #[test]
    fn test_random_add_6121() {
        let lhs = Scalar::from_bytes([
            159, 205, 33, 253, 115, 134, 47, 152, 195, 129, 56, 21, 30, 126, 242, 74, 136, 101,
            241, 172, 68, 122, 137, 191, 40, 187, 72, 167, 136, 111, 87, 66,
        ]);
        let rhs = Scalar::from_bytes([
            170, 58, 143, 154, 242, 81, 210, 13, 54, 38, 8, 197, 77, 27, 91, 79, 225, 189, 237,
            230, 252, 19, 149, 25, 3, 77, 173, 126, 81, 102, 9, 134,
        ]);
        let rust_result = (&lhs + &rhs).write_polynomial().unwrap();
        assert_eq!(
            run_python(rust_result),
            run_python(format!(
                "({}) + ({})",
                lhs.write_polynomial().unwrap(),
                rhs.write_polynomial().unwrap()
            ))
        );
    }
    #[test]
    fn test_random_add_8494() {
        let lhs = Scalar::from_bytes([
            175, 45, 135, 21, 191, 45, 136, 89, 34, 202, 43, 23, 24, 34, 28, 179, 48, 197, 241,
            215, 164, 0, 254, 14, 107, 181, 218, 123, 213, 174, 56, 8,
        ]);
        let rhs = Scalar::from_bytes([
            64, 38, 115, 165, 63, 147, 143, 214, 142, 31, 106, 107, 132, 203, 115, 78, 90, 103, 28,
            6, 204, 8, 153, 215, 41, 2, 17, 155, 12, 187, 245, 239,
        ]);
        let rust_result = (&lhs + &rhs).write_polynomial().unwrap();
        assert_eq!(
            run_python(rust_result),
            run_python(format!(
                "({}) + ({})",
                lhs.write_polynomial().unwrap(),
                rhs.write_polynomial().unwrap()
            ))
        );
    }
    #[test]
    fn test_random_add_1760() {
        let lhs = Scalar::from_bytes([
            163, 162, 38, 39, 170, 92, 28, 208, 37, 3, 137, 239, 141, 22, 109, 71, 69, 193, 75,
            152, 204, 6, 139, 158, 134, 196, 172, 68, 17, 5, 184, 195,
        ]);
        let rhs = Scalar::from_bytes([
            98, 195, 72, 177, 141, 7, 142, 32, 1, 188, 170, 27, 217, 231, 246, 28, 87, 87, 38, 152,
            48, 109, 80, 115, 217, 204, 110, 195, 16, 231, 62, 227,
        ]);
        let rust_result = (&lhs + &rhs).write_polynomial().unwrap();
        assert_eq!(
            run_python(rust_result),
            run_python(format!(
                "({}) + ({})",
                lhs.write_polynomial().unwrap(),
                rhs.write_polynomial().unwrap()
            ))
        );
    }

    #[test]
    fn test_random_sub_8029() {
        let lhs = Scalar::from_bytes([
            151, 226, 224, 99, 50, 101, 117, 78, 60, 23, 66, 24, 128, 146, 238, 82, 94, 233, 238,
            176, 132, 82, 164, 238, 238, 58, 20, 192, 0, 254, 192, 152,
        ]);
        let rhs = Scalar::from_bytes([
            175, 223, 208, 151, 101, 202, 195, 131, 120, 182, 173, 117, 1, 136, 11, 173, 235, 42,
            95, 65, 159, 170, 24, 4, 242, 249, 199, 203, 61, 215, 159, 75,
        ]);
        let rust_result = (&lhs - &rhs).write_polynomial().unwrap();
        assert_eq!(
            run_python(rust_result),
            run_python(format!(
                "({}) - ({})",
                lhs.write_polynomial().unwrap(),
                rhs.write_polynomial().unwrap()
            ))
        );
    }

    #[test]
    fn test_random_sub_9177() {
        let lhs = Scalar::from_bytes([
            59, 57, 188, 202, 125, 71, 93, 168, 253, 88, 193, 117, 162, 223, 69, 127, 0, 232, 209,
            180, 242, 1, 62, 222, 207, 85, 194, 189, 210, 136, 68, 84,
        ]);
        let rhs = Scalar::from_bytes([
            85, 93, 21, 206, 205, 226, 127, 198, 139, 249, 255, 19, 22, 162, 84, 22, 182, 194, 84,
            227, 241, 187, 86, 215, 53, 47, 220, 233, 114, 43, 7, 79,
        ]);
        let rust_result = (&lhs - &rhs).write_polynomial().unwrap();
        assert_eq!(
            run_python(rust_result),
            run_python(format!(
                "({}) - ({})",
                lhs.write_polynomial().unwrap(),
                rhs.write_polynomial().unwrap()
            ))
        );
    }
    #[test]
    fn test_random_sub_2083() {
        let lhs = Scalar::from_bytes([
            144, 98, 27, 67, 141, 216, 121, 184, 163, 21, 80, 212, 127, 82, 52, 160, 169, 26, 158,
            98, 68, 125, 107, 138, 235, 3, 222, 212, 0, 184, 241, 202,
        ]);
        let rhs = Scalar::from_bytes([
            224, 107, 89, 224, 85, 243, 232, 190, 71, 228, 9, 191, 122, 54, 117, 26, 145, 249, 1,
            253, 61, 64, 83, 201, 32, 232, 152, 152, 196, 52, 219, 173,
        ]);
        let rust_result = (&lhs - &rhs).write_polynomial().unwrap();
        assert_eq!(
            run_python(rust_result),
            run_python(format!(
                "({}) - ({})",
                lhs.write_polynomial().unwrap(),
                rhs.write_polynomial().unwrap()
            ))
        );
    }
    #[test]
    fn test_random_sub_6832() {
        let lhs = Scalar::from_bytes([
            101, 189, 188, 221, 50, 198, 70, 0, 136, 173, 185, 86, 58, 188, 245, 44, 56, 52, 122,
            16, 3, 42, 227, 244, 146, 13, 151, 181, 4, 144, 76, 194,
        ]);
        let rhs = Scalar::from_bytes([
            28, 22, 64, 0, 248, 5, 75, 173, 132, 178, 194, 72, 162, 178, 202, 102, 200, 210, 241,
            79, 250, 108, 36, 22, 165, 252, 228, 254, 21, 56, 111, 214,
        ]);
        let rust_result = (&lhs - &rhs).write_polynomial().unwrap();
        assert_eq!(
            run_python(rust_result),
            run_python(format!(
                "({}) - ({})",
                lhs.write_polynomial().unwrap(),
                rhs.write_polynomial().unwrap()
            ))
        );
    }

    #[test]
    fn test_random_mul_5748() {
        let lhs = Scalar::from_bytes([
            118, 30, 97, 221, 149, 186, 156, 238, 53, 67, 69, 27, 127, 11, 237, 2, 109, 138, 212,
            46, 27, 11, 250, 167, 187, 53, 115, 43, 130, 142, 42, 225,
        ]);
        let rhs = Scalar::from_bytes([
            93, 121, 34, 3, 14, 250, 234, 52, 206, 122, 16, 113, 129, 52, 45, 142, 122, 14, 80,
            176, 130, 202, 118, 49, 100, 174, 203, 55, 216, 9, 36, 145,
        ]);
        let rust_result = (&lhs * &rhs).write_polynomial().unwrap();
        assert_eq!(
            run_python(rust_result),
            run_python(format!(
                "({}) * ({})",
                lhs.write_polynomial().unwrap(),
                rhs.write_polynomial().unwrap()
            ))
        );
    }

    #[test]
    fn test_random_mul_3560() {
        let lhs = Scalar::from_bytes([
            20, 62, 136, 118, 108, 95, 51, 121, 247, 103, 153, 5, 4, 97, 156, 113, 59, 236, 196,
            159, 219, 24, 105, 250, 249, 139, 33, 42, 28, 200, 192, 238,
        ]);
        let rhs = Scalar::from_bytes([
            26, 187, 233, 79, 170, 73, 195, 56, 0, 188, 16, 169, 33, 42, 74, 216, 31, 78, 132, 255,
            59, 97, 132, 13, 106, 237, 74, 190, 140, 173, 188, 197,
        ]);
        let rust_result = (&lhs * &rhs).write_polynomial().unwrap();
        assert_eq!(
            run_python(rust_result),
            run_python(format!(
                "({}) * ({})",
                lhs.write_polynomial().unwrap(),
                rhs.write_polynomial().unwrap()
            ))
        );
    }
    #[test]
    fn test_random_mul_9124() {
        let lhs = Scalar::from_bytes([
            34, 169, 2, 34, 18, 140, 58, 206, 13, 148, 222, 7, 140, 145, 151, 193, 247, 7, 66, 101,
            89, 113, 163, 14, 172, 17, 102, 147, 185, 13, 103, 70,
        ]);
        let rhs = Scalar::from_bytes([
            103, 82, 36, 116, 75, 188, 173, 235, 239, 233, 188, 100, 3, 23, 188, 146, 35, 201, 214,
            210, 47, 245, 234, 79, 6, 246, 35, 81, 47, 55, 18, 239,
        ]);
        let rust_result = (&lhs * &rhs).write_polynomial().unwrap();
        assert_eq!(
            run_python(rust_result),
            run_python(format!(
                "({}) * ({})",
                lhs.write_polynomial().unwrap(),
                rhs.write_polynomial().unwrap()
            ))
        );
    }
    #[test]
    fn test_random_mul_4135() {
        let lhs = Scalar::from_bytes([
            211, 225, 41, 28, 16, 73, 159, 71, 91, 157, 156, 171, 181, 73, 71, 215, 249, 20, 82,
            202, 78, 60, 10, 82, 22, 199, 80, 52, 114, 230, 159, 165,
        ]);
        let rhs = Scalar::from_bytes([
            181, 21, 251, 60, 62, 121, 181, 130, 4, 2, 230, 186, 143, 178, 6, 113, 194, 73, 149,
            104, 55, 138, 172, 208, 77, 231, 164, 174, 109, 183, 243, 25,
        ]);
        let rust_result = (&lhs * &rhs).write_polynomial().unwrap();
        assert_eq!(
            run_python(rust_result),
            run_python(format!(
                "({}) * ({})",
                lhs.write_polynomial().unwrap(),
                rhs.write_polynomial().unwrap()
            ))
        );
    }
}

impl<'a, 'b> Add<&'a Scalar> for &'b Scalar {
    type Output = Scalar;

    fn add(self, rhs: &'a Scalar) -> Self::Output {
        let mut limbs = [0; 16];
        for (i, (l, r)) in self.limbs.iter().zip(rhs.limbs).enumerate() {
            limbs[i] = l + r;
        }
        Scalar { limbs }
    }
}

impl<'a, 'b> Sub<&'a Scalar> for &'b Scalar {
    type Output = Scalar;

    fn sub(self, rhs: &'a Scalar) -> Self::Output {
        let mut limbs = [0; 16];
        for (i, (l, r)) in self.limbs.iter().zip(rhs.limbs).enumerate() {
            limbs[i] = l - r;
        }
        Scalar { limbs }
    }
}

impl<'a, 'b> Mul<&'a Scalar> for &'b Scalar {
    type Output = Scalar;

    fn mul(self, rhs: &'a Scalar) -> Self::Output {
        let mut product = [0; 31];
        for (i, limb_l) in self.limbs.iter().enumerate() {
            for (j, limb_r) in rhs.limbs.iter().enumerate() {
                product[i + j] += limb_l * limb_r;
            }
        }
        for i in 0..15 {
            product[i] += 38 * product[i + 16];
        }
        let mut limbs = [0; 16];
        limbs.copy_from_slice(&product[0..16]);
        carry25519(&mut limbs);
        carry25519(&mut limbs);
        Scalar { limbs }
    }
}

fn carry25519(limbs: &mut [i64; 16]) {
    for i in 0..limbs.len() {
        let carry = limbs[i] >> 16;
        limbs[i] -= carry << 16;
        if i < 15 {
            limbs[i + 1] += carry;
        } else {
            limbs[0] += 38 * carry;
        }
    }
}

fn swap25519(p: &mut [i64; 16], q: &mut [i64; 16], swap: bool) {
    let c: u64 = !(swap as u64).wrapping_sub(1);
    let c = i64::from_ne_bytes(c.to_ne_bytes());
    for i in 0..p.len() {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}
