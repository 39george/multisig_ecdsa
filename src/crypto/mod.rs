use base58::FromBase58;
use base58::ToBase58;
use rand::Rng;
use secp256k1::ecdsa;
use secp256k1::hashes::hash160;
use secp256k1::hashes::Hash;
use secp256k1::All;
use secp256k1::Keypair;
use secp256k1::Message;
use secp256k1::PublicKey;
use secp256k1::Secp256k1;
use secp256k1::SecretKey;
use secp256k1::Signing;

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
    secp: &Secp256k1<All>,
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

pub fn new_keypair(
    secp: &Secp256k1<secp256k1::All>,
) -> Result<Keypair, secp256k1::Error> {
    let mut rng = rand::rng();
    let secret_key = secrecy::SecretBox::init_with(|| rng.random::<[u8; 32]>());
    Keypair::from_seckey_slice(secp, secret_key.expose_secret())
}
