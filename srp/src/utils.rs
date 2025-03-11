use digest::{Digest, Output};

pub mod mod4096 {
    use crypto_bigint::{Encoding, U256, U4096};
    use digest::{Digest, Output};

    use crate::{groups::g_4096::*, DigestNum};

    // u = H(PAD(A) | PAD(B))
    pub fn compute_u<D: Digest>(a_pub: &U4096, b_pub: &U4096) -> Output<D> {
        let mut u = D::new();
        u.update(a_pub.to_be_bytes());
        u.update(b_pub.to_be_bytes());
        u.finalize()
    }

    // k = H(N | PAD(g))
    pub fn compute_k<D: Digest>() -> Output<D> {
        let mut d = D::new();
        d.update(N.to_be_bytes());
        d.update(G.to_be_bytes());
        d.finalize()
    }
}


// M1 = H(A, B, K) this doesn't follow the spec but apparently no one does for M1
// M1 should equal =  H(H(N) XOR H(g) | H(U) | s | A | B | K) according to the spec
pub fn compute_m1<D: Digest>(a_pub: &[u8], b_pub: &[u8], key: &[u8]) -> Output<D> {
    let mut d = D::new();
    d.update(a_pub);
    d.update(b_pub);
    d.update(key);
    d.finalize()
}

// M2 = H(A, M1, K)
pub fn compute_m2<D: Digest>(a_pub: &[u8], m1: &[u8], key: &[u8]) -> Output<D> {
    let mut d = D::new();
    d.update(&a_pub);
    d.update(&m1);
    d.update(&key);
    d.finalize()
}
