use core::marker::PhantomData;

use crypto_bigint::{Uint, Zero, U256, U4096};
use digest::{Digest, Output};
use subtle::ConstantTimeEq;

use crate::groups::g_4096::{mod_n, ConstMontyModN, G_MOD_N};
use crate::{SrpAuthError, DigestNum};
use crate::utils::{compute_m1, compute_m2, mod4096};



pub struct SrpServer4096<D: Digest> {
    _d: PhantomData<D>,
    b: U4096
}

/// SRP server state after handshake with the client.
pub struct SrpServerVerifier4096<D: Digest> {
    m1: Output<D>,
    m2: Output<D>,
    key: U4096,
}

impl<const D_N: usize, D: Digest> SrpServer4096<D> where
    Output<D>: DigestNum<Num = Uint<D_N>>
{
    pub fn new(b: U4096) -> Self {
        SrpServer4096 { _d: PhantomData, b }
    }

    //  k*v + g^b % N
    pub fn compute_b_pub(&self, k: &Uint<D_N>, v: &U4096) -> U4096 {
        ((mod_n(&k.resize()) * mod_n(v)) + G_MOD_N.pow(&self.b)).retrieve()
    }

    /// Get public ephemeral value for sending to the client.
    pub fn compute_public_ephemeral(&self, v: &U4096) -> U4096 {
        let k = mod4096::compute_k::<D>().to_num();
        self.compute_b_pub(&k, v)
    }

    // <premaster secret> = (A * v^u) ^ b % N
    pub fn compute_premaster_secret(&self, a_pub: &U4096, v: &U4096, u: &Uint<D_N>) -> U4096 {
        // (A * v^u)^b
        (mod_n(a_pub) * mod_n(v).pow(u)).pow(&self.b).retrieve()
    }

    /// Process client reply to the handshake.
    /// b is a random value,
    /// v is the provided during initial user registration
    pub fn process_reply(
        &self,
        v: &U4096,
        a_pub: &U4096,
    ) -> Result<SrpServerVerifier4096<D>, SrpAuthError> {
        let k = mod4096::compute_k::<D>().to_num();
        let b_pub = self.compute_b_pub(&k, v);

        // Safeguard against malicious A
        if mod_n(a_pub).is_zero().into() {
            return Err(SrpAuthError::IllegalParameter);
        }

        let u = mod4096::compute_u::<D>(a_pub, &b_pub).to_num();

        let key = self.compute_premaster_secret(&a_pub, &v, &u);

        let m1 = compute_m1::<D>(
            &a_pub.to_be_bytes(),
            &b_pub.to_be_bytes(),
            &key.to_be_bytes(),
        );

        let m2 = compute_m2::<D>(&a_pub.to_be_bytes(), &m1, &key.to_be_bytes());

        Ok(SrpServerVerifier4096 {
            m1,
            m2,
            key,
        })
    }
}
impl<D: Digest> SrpServerVerifier4096<D> {
    /// Process user proof of having the same shared secret.
    pub fn verify_client(&self, reply: &[u8]) -> Result<(), SrpAuthError> {
        if self.m1.ct_eq(reply).unwrap_u8() != 1 {
            // aka == 0
            Err(SrpAuthError::BadRecordMac)
        } else {
            Ok(())
        }
    }

    /// Get shared secret between user and the server. (do not forget to verify
    /// that keys are the same!)
    pub fn key(&self) -> &U4096 {
        &self.key
    }

    /// Verification data for sending to the client.
    pub fn proof(&self) -> &[u8] {
        // TODO not Output
        self.m2.as_slice()
    }

}
