use auth_common::{Data, RegisterReq};
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

fn rand_num<const N: usize>() -> Uint<N> {
    let mut buf = [0; N];
    rand::thread_rng().fill(buf.as_mut_slice());
    Uint::from_words(buf)
}

fn register(username: &str, password: &str) {
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

    println!("{}", base64::encode(&encoded));
}

fn main() {
    let args = Args::parse();
    let pass = match args.pass {
        Some(pw) => pw,
        None => rpassword::prompt_password("Password: ").unwrap(),
    };
    register(&args.user, &pass);
}
