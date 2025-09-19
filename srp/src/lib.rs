#![no_std]

use argon2::{Argon2, Block, Params};
use crypto_bigint::U512;
pub use crypto_bigint::{Encoding, U256, U4096, Uint};
use digest::{
    consts::{U32, U64},
    generic_array::GenericArray,
};

pub mod client;
pub mod groups;
pub mod server;
mod utils;

/// SRP authentication error.
pub enum SrpAuthError {
    IllegalParameter,
    BadRecordMac,
}

pub trait DigestNum {
    type Num;
    fn to_num(self) -> Self::Num;
}

impl DigestNum for GenericArray<u8, U32> {
    type Num = U256;
    fn to_num(self) -> Self::Num {
        U256::from_be_bytes(self.into())
    }
}
impl DigestNum for GenericArray<u8, U64> {
    type Num = U512;
    fn to_num(self) -> Self::Num {
        U512::from_be_bytes(self.into())
    }
}

pub struct A2;
impl client::UserPasswordHasher for A2 {
    type Out = [u8; 32];
    fn hash_user_password(username: &[u8], password: &[u8], salt: &[u8]) -> Self::Out {
        const P: Params = match Params::new(4096, 1, 1, Some(32)) {
            Ok(p) => p,
            _ => panic!(),
        };

        let mut out = [0; 32];
        Argon2::new_with_secret(
            username,
            argon2::Algorithm::Argon2d,
            argon2::Version::V0x13,
            P,
        )
        .unwrap()
        .hash_password_into(password, salt, &mut out)
        .unwrap();
        out
    }
}
