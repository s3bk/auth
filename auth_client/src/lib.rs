#![no_std]

extern crate wee_alloc;

// Use `wee_alloc` as the global allocator.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use core::{any::type_name, mem::MaybeUninit};

use argon2::{Argon2, Block, Params, ParamsBuilder};
use auth_common::{AuthReq, Data, PreAuthReq, PreAuthResp, RegisterReq};
use blake2::Blake2b512;
use js_sys::{ArrayBuffer, Promise, Uint8Array};
use srp::{
    A2, DigestNum, Encoding, U4096, Uint,
    client::{SrpClient4096, SrpClientVerifier4096},
};
use wasm_bindgen::prelude::*;

type Digest = Blake2b512;

#[wasm_bindgen]
unsafe extern "C" {
    type Crypto;
    #[wasm_bindgen(method)]
    fn getRandomValues(this: &Crypto, buffer: Uint8Array) -> ArrayBuffer;
}

fn rand_buf<const N: usize>(crypto: &Crypto) -> Result<[u8; N], JsValue> {
    let bytes = unsafe {
        let mut buf = MaybeUninit::<[u8; N]>::uninit();
        let filled = crypto.getRandomValues(Uint8Array::view_mut_raw(buf.as_mut_ptr().cast(), N));
        let len = filled.byte_length();
        if len as usize != N {
            return Err(JsValue::from_str("not enough data"));
        }
        buf.assume_init()
    };
    Ok(bytes)
}

#[wasm_bindgen]
pub struct Step1 {
    client: SrpClient4096<A2, Digest>,
}

#[wasm_bindgen]
impl Step1 {
    #[wasm_bindgen(constructor)]
    pub fn new(crypto: &Crypto) -> Result<Step1, JsValue> {
        let a = U4096::from_le_bytes(rand_buf(crypto)?);
        let client = SrpClient4096::new(a);

        Ok(Step1 { client })
    }
    pub fn req(&self, username: &str) -> Result<Uint8Array, JsValue> {
        let a_pub = self.client.compute_a_pub();
        encode(
            &mut [0; 1024],
            &PreAuthReq {
                a_pub: a_pub.to_le_bytes().into(),
                username,
            },
        )
    }
    pub fn auth(
        &self,
        username: &str,
        password: &str,
        resp: &Uint8Array,
    ) -> Result<Step2, JsValue> {
        let mut buf = [0; 1024];
        let resp: PreAuthResp = decode(&mut buf, resp).ok_or(JsValue::from_str("invalid data"))?;
        let verifier = self
            .client
            .process_reply(
                username.as_bytes(),
                password.as_bytes(),
                &resp.salt,
                &U4096::from_le_bytes(resp.b_pub.into()),
            )
            .map_err(|_| JsValue::from_str("authentication failed"))?;

        Ok(Step2 {
            verifier,
            key: resp.key,
        })
    }
}

#[wasm_bindgen]
pub fn register(crypto: &Crypto, username: &str, password: &str) -> Result<Uint8Array, JsValue> {
    let salt = rand_buf::<32>(crypto)?;
    let verifier = SrpClient4096::<A2, Digest>::compute_verifier(
        username.as_bytes(),
        &password.as_bytes(),
        &salt,
    );

    Ok(encode(
        &mut [0; 1024],
        &RegisterReq {
            username,
            salt: salt.into(),
            verifier: verifier.to_le_bytes().into(),
        },
    )?)
}

fn encode<'a, D: Data<'a>>(buf: &'a mut [u8], value: &'a D) -> Result<Uint8Array, JsValue> {
    let data = value
        .encode(buf)
        .ok_or(JsValue::from_str(type_name::<D>()))?;
    Ok(Uint8Array::from(data))
}

fn decode<'a, D: Data<'a>>(buf: &'a mut [u8], data: &Uint8Array) -> Option<D> {
    let len = data.length() as usize;
    let (dst, _) = buf.split_at_mut_checked(len)?;
    data.copy_to(dst);

    let (val, _) = D::decode(dst)?;
    Some(val)
}

#[wasm_bindgen]
pub struct Step2 {
    verifier: SrpClientVerifier4096<Digest>,
    key: [u8; 8],
}

#[wasm_bindgen]
impl Step2 {
    pub fn req(&self) -> Result<Uint8Array, JsValue> {
        encode(
            &mut [0; AuthReq::SIZE],
            &AuthReq {
                proof: (*self.verifier.proof()).into(),
                key: self.key,
            },
        )
    }
    pub fn get_key(&self) -> Uint8Array {
        let key_bytes = self.verifier.key().to_le_bytes();
        let out = Uint8Array::new_with_length(key_bytes.len() as u32);
        out.copy_from(&key_bytes);
        out
    }
}
