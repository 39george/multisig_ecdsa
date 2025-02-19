use secp256k1::VerifyOnly;
use secp256k1::{ecdsa, Keypair, PublicKey, Secp256k1, Signing};

use crate::crypto;

#[derive(thiserror::Error)]
pub enum Error {
    #[error("No public key found")]
    PublicKeyNotFound,
    #[error(transparent)]
    Secp256k1(#[from] secp256k1::Error),
    #[error("Not enough signatures, provided: {0}, required: {1}")]
    NotEnoughSignatures(usize, usize),
}

crate::impl_debug!(Error);

pub struct Message {
    content: Vec<u8>,
    /// Signatures with public keys
    signatures: Vec<(PublicKey, Option<ecdsa::Signature>)>,
    /// Min required signatures count for approve message
    count_required: usize,
}

impl Message {
    pub fn new(
        content: &[u8],
        pubkeys: Vec<PublicKey>,
        required_signature_count: Option<usize>,
    ) -> Message {
        Message {
            content: content.to_vec(),
            signatures: Default::default(),
            count_required: required_signature_count
                .unwrap_or(pubkeys.len())
                .max(pubkeys.len()),
        }
    }
    pub fn sign_with<C: Signing>(
        &mut self,
        secp: &Secp256k1<C>,
        keypair: &Keypair,
    ) -> Result<(), Error> {
        let (_, signature) = self
            .signatures
            .iter_mut()
            .find(|(pk, _)| pk.eq_fast_unstable(&keypair.public_key()))
            .ok_or(Error::PublicKeyNotFound)?;
        match signature {
            Some(_) => {
                tracing::warn!("signature alreay exists, skip signing");
                return Ok(());
            }
            None => {
                *signature = Some(crypto::sign(
                    secp,
                    &self.content,
                    &keypair.secret_key(),
                )?)
            }
        }
        Ok(())
    }
    pub fn verify(&self, secp: &Secp256k1<VerifyOnly>) -> Result<(), Error> {
        let signatures = self
            .signatures
            .iter()
            .filter_map(|(pk, s)| s.as_ref().map(|s| (pk, s)))
            .collect::<Vec<_>>();
        let sig_count = signatures.len();
        if sig_count < self.count_required {
            return Err(Error::NotEnoughSignatures(
                sig_count,
                self.count_required,
            ));
        }
        for (pubkey, signature) in signatures {
            crypto::verify(secp, &self.content, signature, pubkey)?;
        }
        tracing::info!("verification successed");
        Ok(())
    }
}
