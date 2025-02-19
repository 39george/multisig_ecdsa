use rand::Rng;
use secp256k1::ecdsa;
use secp256k1::hashes::Hash;
use secp256k1::Keypair;
use secp256k1::Message;
use secp256k1::PublicKey;
use secp256k1::Secp256k1;
use secp256k1::SecretKey;
use secp256k1::Signing;
use secp256k1::VerifyOnly;

use secrecy::ExposeSecret;

pub fn sign<C: Signing>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    seckey: &SecretKey,
) -> Result<ecdsa::Signature, secp256k1::Error> {
    let msg = secp256k1::hashes::sha256::Hash::hash(msg);
    let msg = Message::from_digest_slice(msg.as_ref())?;
    Ok(secp.sign_ecdsa(&msg, seckey))
}

pub fn verify(
    secp: &Secp256k1<VerifyOnly>,
    msg: &[u8],
    signature: &ecdsa::Signature,
    pubkey: &PublicKey,
) -> Result<(), secp256k1::Error> {
    let msg = secp256k1::hashes::sha256::Hash::hash(msg);
    let msg = Message::from_digest_slice(msg.as_ref())?;
    secp.verify_ecdsa(&msg, signature, pubkey)
}

fn run() {
    let mut rng = rand::rng();
    let ctx = Secp256k1::new();
    let verify_ctx = Secp256k1::verification_only();

    let msg = b"Hello world!";

    let keypairs = std::iter::repeat_with(|| {
        let secret_key =
            secrecy::SecretBox::init_with(|| rng.random::<[u8; 32]>());
        Keypair::from_seckey_slice(&ctx, secret_key.expose_secret())
    })
    .take(3)
    .collect::<Result<Vec<_>, _>>()
    .expect("Failed");

    let pubkeys = keypairs.iter().map(|k| k.public_key()).collect::<Vec<_>>();
    let seckeys = keypairs.iter().map(|k| k.secret_key()).collect::<Vec<_>>();

    // Sign with each private key
    let signatures: Vec<ecdsa::Signature> = seckeys
        .iter()
        .map(|seckey| sign(&ctx, msg, seckey).expect("Failed to sign"))
        .collect();

    // Verify with each public key
    let verification_results: Vec<Result<(), secp256k1::Error>> = pubkeys
        .iter()
        .zip(signatures.iter())
        .map(|(pubkey, signature)| verify(&verify_ctx, msg, signature, pubkey))
        .collect();

    // Check if all signatures are valid
    if verification_results.iter().all(Result::is_ok) {
        println!("Multisig verification successful!");
    } else {
        println!("Multisig verification failed!");
    }
}
