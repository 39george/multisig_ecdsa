use secp256k1::All;
use secp256k1::{ecdsa, Keypair, PublicKey, Secp256k1, Signing};

use crate::crypto;

#[derive(thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("No public key found")]
    PublicKeyNotFound,
    #[error(transparent)]
    Secp256k1(#[from] secp256k1::Error),
    #[error("Not enough signatures, provided: {0}, required: {1}")]
    NotEnoughSignatures(usize, usize),
}

crate::impl_debug!(Error);

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Multisig(Vec<(PublicKey, Option<ecdsa::Signature>)>);

impl Multisig {
    pub fn new(pubkeys: Vec<PublicKey>) -> Self {
        Multisig(pubkeys.into_iter().map(|pk| (pk, None)).collect())
    }
    pub fn sign<C: Signing>(
        &mut self,
        secp: &Secp256k1<C>,
        content: &[u8],
        keypair: &Keypair,
    ) -> Result<(), Error> {
        let (_, signature) = self
            .0
            .iter_mut()
            .find(|(pk, _)| pk.eq_fast_unstable(&keypair.public_key()))
            .ok_or(Error::PublicKeyNotFound)?;
        match signature {
            Some(_) => {
                tracing::warn!("signature alreay exists, skip signing");
                return Ok(());
            }
            None => {
                *signature =
                    Some(crypto::sign(secp, content, &keypair.secret_key())?)
            }
        }
        Ok(())
    }
    pub fn verify(
        &self,
        secp: &Secp256k1<All>,
        content: &[u8],
        count_required: usize,
    ) -> Result<(), Error> {
        let signatures = self
            .0
            .iter()
            .filter_map(|(pk, s)| s.as_ref().map(|s| (pk, s)))
            .collect::<Vec<_>>();
        let sig_count = signatures.len();
        if sig_count < count_required {
            return Err(Error::NotEnoughSignatures(sig_count, count_required));
        }
        for (pubkey, signature) in signatures {
            crypto::verify(secp, content, signature, pubkey)?;
        }
        tracing::info!("verification successed");
        Ok(())
    }
}
