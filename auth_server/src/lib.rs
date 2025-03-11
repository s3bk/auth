use auth_common::AuthResponse;
pub use auth_common::{AuthReq, Data, PreAuthReq, PreAuthResp, RegisterReq};
use blake2::Blake2b512;
use gxhash::{GxBuildHasher, GxHasher, HashMap};
use rand::{random, Rng, RngCore};
use serde::{Deserialize, Serialize};
use srp::{server::SrpServer4096, Encoding, Uint, U4096, SrpAuthError};
use std::{hash::Hash, time::Instant};

#[derive(Serialize, Deserialize)]
pub struct UserData {
    #[serde(with = "serdapt_base64::StdBase64Array")]
    salt: [u8; 32],
    #[serde(with = "serdapt_base64::StdBase64Array")]
    v: [u8; 512],
}

type Digest = Blake2b512;

pub trait CredHasher {
    fn get_user_data(&self, username: &str) -> impl Future<Output=Option<UserData>>;
}

fn rand_num<const N: usize>() -> Uint<N> {
    let mut buf = [0; N];
    rand::thread_rng().fill(buf.as_mut_slice());
    Uint::from_words(buf)
}


pub struct SrpAuth<K: Eq + Hash + Clone, D> {
    logins: HashMap<(K, u64), Step1<D>>
}

pub struct Authenticated<D> {
    shared_key: U4096,
    pub data: D
}
impl<D> Authenticated<D> {
    pub fn get_key(&self) -> [u8; 512] {
        self.shared_key.to_le_bytes()
    }
}

impl<K: Hash + Eq + Clone + Unpin, D: Unpin> SrpAuth<K, D> {
    pub fn new() -> Self {
        SrpAuth { logins: HashMap::with_hasher(GxBuildHasher::default()) }
    }
    pub fn pre_auth(&mut self, req: PreAuthReq<'_>, user_data: &UserData, key1: K, data: D, expires: Instant) -> Result<PreAuthResp, ()> {
        let b = rand_num();
        let server = SrpServer4096::<Digest>::new(b);

        let salt = user_data.salt;
        let v = U4096::from_le_bytes(user_data.v);
        let a_pub = U4096::from_le_bytes(req.a_pub.into());
        let b_pub = server.compute_public_ephemeral(&v).to_le_bytes().into();

        let key2 = random();

        self.logins.insert((key1, key2), Step1 { server, v, a_pub, data, expires });
        
        Ok(PreAuthResp { salt, b_pub, key: key2.to_le_bytes() })
    }
    pub fn auth(&mut self, req: AuthReq, key1: K, now: Instant) -> Result<Authenticated<D>, AuthError> {
        let key2 = u64::from_le_bytes(req.key);
        let step1 = self.logins.remove(&(key1, key2)).ok_or(AuthError::KeyNotFound)?;
        if step1.expires < now {
            return Err(AuthError::Expired);
        }
        let auth = step1.step2(req).map_err(AuthError::Srp)?;
        Ok(auth)
    }
    pub fn clean(&mut self, now: Instant) {
        self.logins.retain(|_, s| s.expires >= now);
    }
}
pub enum AuthError {
    Srp(SrpAuthError),
    KeyNotFound,
    Expired
}
impl AuthError {
    pub fn message(&self) -> &'static str {
        match *self {
            AuthError::Srp(SrpAuthError::BadRecordMac) => "bad record mac",
            AuthError::Srp(SrpAuthError::IllegalParameter) => "illegal parameter",
            AuthError::Expired => "expired",
            AuthError::KeyNotFound => "key not found"
        }
    }
}
impl std::fmt::Debug for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}


pub struct Step1<D> {
    server: SrpServer4096::<Blake2b512>,
    v: U4096,
    a_pub: U4096,
    data: D,
    expires: Instant,
}
impl<D> Step1<D> {
    pub fn step2(self, req: AuthReq) -> Result<Authenticated<D>, SrpAuthError> {
        let verifier = self.server.process_reply(&self.v, &self.a_pub)?;
        verifier.verify_client(&req.proof)?;
        Ok(Authenticated { shared_key: *verifier.key(), data: self.data })
    }
}

pub fn decode_register_req<'a>(req: &'a [u8]) -> Option<(&'a str, UserData)> {
    use auth_common::Data;

    let (req, _) = RegisterReq::decode(req)?;
    Some((req.username, UserData { salt: req.salt, v: req.verifier }))
}

pub fn encode<D: for <'a> Data<'a>>(val: &D) -> Option<Vec<u8>> {
    let mut buf = vec![0; D::SIZE];
    let encoded = val.encode(&mut buf)?;
    let len = encoded.len();
    buf.truncate(len);
    Some(buf)
}

#[test]
fn test_encode() {
    let buf = encode(&PreAuthResp {
        b_pub: random(),
        key: random(),
        salt: random()
    }).unwrap();
    assert_eq!(buf.len(), 512 + 8 + 32);
}
