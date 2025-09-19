use auth_common::{Data, RegisterReq};
use base64::{Engine, prelude::BASE64_STANDARD};
use blake2::Blake2b512;
use clap::Parser;
use rand::Rng;
use srp::{A2, U4096, Uint, client::SrpClient4096};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    user: String,

    /// Number of times to greet
    #[arg(short, long)]
    pass: Option<String>,
}

type Digest = Blake2b512;


fn register_with_username(username: &str, password: &str) {
    let salt: [u8; 32] = rand::random();
    let verifier = SrpClient4096::<A2, Digest>::compute_verifier(
        username.as_bytes(),
        &password.as_bytes(),
        &salt,
    );

    let mut buf = [0; 1024];

    let encoded = RegisterReq {
        username,
        salt: salt.into(),
        verifier: verifier.to_le_bytes().into(),
    }
    .encode(&mut buf)
    .unwrap();

    println!("{}", BASE64_STANDARD.encode(&encoded));
}

fn main() {
    let args = Args::parse();
    let pass = match args.pass {
        Some(pw) => pw,
        None => rpassword::prompt_password("Password: ").unwrap(),
    };
    register_with_username(&args.user, &pass);
}
