use secp256k1::PublicKey;

use super::multisig::Multisig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: uuid::Uuid,
    pub content: Vec<u8>,
    /// Signatures with public keys
    pub signature: Multisig,
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
            count_required: required_signature_count
                .unwrap_or(pubkeys.len())
                .max(pubkeys.len()),
            signature: Multisig::new(pubkeys),
            id: uuid::Uuid::new_v4(),
        }
    }
}

#[cfg(test)]
mod tests {
    // TODO: implement me!
}
