use core::marker::PhantomData;

use crypto_bigint::modular::{ConstMontyForm, ConstMontyParams};
use crypto_bigint::{
    ConcatMixed, Encoding, U256, U512, U4096, Uint, WideningMul, Zero, const_monty_form,
};
use digest::{Digest, Output, OutputSizeUser};
use subtle::ConstantTimeEq;

use crate::DigestNum;
use crate::groups::g_4096::{G_MOD_N, ModN, N, mod_n};
use crate::SrpAuthError;
use crate::utils::{compute_m1, compute_m2, mod4096};

pub trait UserPasswordHasher {
    type Out: AsRef<[u8]>;
    fn hash_user_password(username: &[u8], password: &[u8], salt: &[u8]) -> Self::Out;
}
impl<D: Digest + OutputSizeUser> UserPasswordHasher for D {
    type Out = Output<Self>;
    fn hash_user_password(username: &[u8], password: &[u8], salt: &[u8]) -> Output<Self> {
        //  H(<username> | ":" | <raw password>)
        let mut d = D::new();
        d.update(username);
        d.update(b":");
        d.update(password);
        let identity_hash = d.finalize();

        // x = H(<salt> | H(<username> | ":" | <raw password>))
        let mut x = D::new();
        x.update(salt);
        x.update(identity_hash);
        x.finalize()
    }
}

pub struct SrpClient4096<P, D: Digest> {
    a: U4096,
    _p: PhantomData<P>,
    _d: PhantomData<D>,
}
pub struct SrpClientVerifier4096<D: Digest> {
    m1: Output<D>,
    m2: Output<D>,
    key: U4096,
}

const L: usize = U4096::LIMBS;
impl<const D_N: usize, P: UserPasswordHasher<Out = [u8; 32]>, D: Digest> SrpClient4096<P, D>
where
    Output<D>: DigestNum<Num = Uint<D_N>>,
{
    pub fn new(a: U4096) -> Self {
        SrpClient4096 {
            a,
            _p: PhantomData,
            _d: PhantomData,
        }
    }
    pub fn compute_a_pub(&self) -> U4096 {
        G_MOD_N.pow(&self.a).retrieve()
    }
    /// Get password verifier (v in RFC5054) for user registration on the server.
    pub fn compute_verifier(username: &[u8], password: &[u8], salt: &[u8]) -> U4096 {
        let x = U256::from_be_bytes(P::hash_user_password(username, password, salt));
        Self::compute_v(&x)
    }
    // v = g^x % N
    fn compute_v(x: &U256) -> U4096 {
        G_MOD_N.pow(x).retrieve()
    }

    /// Process server reply to the handshake.
    /// a is a random value,
    /// username, password is supplied by the user
    /// salt and b_pub come from the server
    pub fn process_reply(
        &self,
        username: &[u8],
        password: &[u8],
        salt: &[u8],
        b_pub: &U4096,
    ) -> Result<SrpClientVerifier4096<D>, SrpAuthError> {
        let a_pub = self.compute_a_pub();

        // Safeguard against malicious B
        if mod_n(b_pub).is_zero().into() {
            return Err(SrpAuthError::IllegalParameter);
        }

        let u = mod4096::compute_u::<D>(&a_pub, &b_pub).to_num();
        let k = mod4096::compute_k::<D>().to_num();
        let x = U256::from_be_bytes(P::hash_user_password(username, password, salt));

        let key = self.compute_premaster_secret(&b_pub, &k, &x, &u);

        let m1 = compute_m1::<D>(
            &a_pub.to_be_bytes(),
            &b_pub.to_be_bytes(),
            &key.to_be_bytes(),
        );

        let m2 = compute_m2::<D>(&a_pub.to_be_bytes(), &m1, &key.to_be_bytes());

        Ok(SrpClientVerifier4096 { m1, m2, key })
    }

    // (B - (k * g^x)) ^ (a + (u * x)) % N
    pub fn compute_premaster_secret(
        &self,
        b_pub: &U4096,
        k: &Uint<D_N>,
        x: &U256,
        u: &Uint<D_N>,
    ) -> U4096 {
        // Because we do operation in modulo N we can get: b_pub > base. That's not good. So we add N to b_pub to make sure.
        // B - k (g^x)
        let base = mod_n(b_pub) - G_MOD_N.pow(x).mul(&mod_n(&k.resize()));
        let exp = u.resize::<L>() * x.resize::<L>() + self.a;
        // S = (B - kg^x) ^ (a + ux)
        // or
        // S = base ^ exp
        base.pow(&exp).retrieve()
    }
}

impl<D: Digest> SrpClientVerifier4096<D> {
    /// Get shared secret key without authenticating server, e.g. for using with
    /// authenticated encryption modes. DO NOT USE this method without
    /// some kind of secure authentication
    pub fn key(&self) -> &U4096 {
        &self.key
    }

    /// Verification data for sending to the server.
    pub fn proof(&self) -> &Output<D> {
        &self.m1
    }

    /// Verify server reply to verification data.
    pub fn verify_server(&self, reply: &[u8]) -> Result<(), SrpAuthError> {
        if self.m2.ct_eq(reply).unwrap_u8() != 1 {
            // aka == 0
            Err(SrpAuthError::BadRecordMac)
        } else {
            Ok(())
        }
    }
}
