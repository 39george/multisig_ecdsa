use base58::FromBase58;
use base58::ToBase58;
use rand::Rng;
use secp256k1::ecdsa;
use secp256k1::hashes::hash160;
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

pub fn bt_addr_from_pk(pubkey: &PublicKey) -> String {
    use secp256k1::hashes::sha256::Hash as Sha256;

    // Create PKH
    let pubkey_hash = hash160::Hash::hash(&pubkey.serialize());

    // Add `0` before bytes
    let mut with_version = vec![0x00];
    with_version.extend_from_slice(&pubkey_hash.to_byte_array());

    let hash = Sha256::hash(&with_version).hash_again();

    // Use first 4 bytes as checksum
    let checksum = &hash[..4];
    // And add to the end
    with_version.extend_from_slice(checksum);

    // Encode to base58
    with_version.to_base58()
}

pub fn pkh_from_bt_addr(address: &str) -> Result<hash160::Hash, &'static str> {
    use secp256k1::hashes::sha256::Hash as Sha256;

    // Base58 Decoding
    let decoded = address
        .from_base58()
        .map_err(|_| "Invalid base58 encoding")?;

    // Length Check
    if decoded.len() != 25 {
        return Err("Invalid address length");
    }

    // Version Byte Check
    let version = decoded[0];
    if version != 0x00 {
        // Check for P2PKH version
        return Err("Not a P2PKH address");
    }

    // Checksum Verification
    let checksum = &decoded[21..]; // Last 4 bytes
    let data_without_checksum = &decoded[..21];
    let expected_checksum =
        Sha256::hash(data_without_checksum).hash_again()[..4].to_vec();

    if checksum != expected_checksum {
        return Err("Invalid checksum");
    }

    // Extract Public Key Hash
    let pubkey_hash = hash160::Hash::from_byte_array(
        decoded[1..21]
            .try_into()
            .map_err(|_| "failed to build hash from bytes")?,
    );

    Ok(pubkey_hash)
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
