use secp256k1::PublicKey;

use super::multisig::Multisig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: uuid::Uuid,
    pub content: Vec<u8>,
    /// Signatures with public keys
    pub signature: Multisig,
    /// Min required signatures count for approve message
    pub count_required: usize,
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
    use crate::{crypto, domain::multisig};

    use super::Message;

    #[test]
    fn signature_with_correct_keys_works(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let secp = secp256k1::Secp256k1::new();
        let keypairs = generate_keypairs(&secp, 3)?;
        let mut msg =
            Message::new(b"Hello world!", extract_pubkeys(&keypairs), None);
        for keypair in keypairs {
            assert!(msg.signature.sign(&secp, &msg.content, &keypair).is_ok());
        }
        assert!(msg
            .signature
            .verify(&secp, &msg.content, msg.count_required)
            .is_ok());
        Ok(())
    }

    #[test]
    fn signature_with_incorrect_key_fail(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let secp = secp256k1::Secp256k1::new();
        let keypairs = generate_keypairs(&secp, 3)?;
        let mut msg =
            Message::new(b"Hello world!", extract_pubkeys(&keypairs), None);
        for keypair in keypairs.iter().take(2) {
            assert!(msg.signature.sign(&secp, &msg.content, keypair).is_ok());
        }
        let wrong_keypair = crypto::new_keypair(&secp)?;
        assert_eq!(
            msg.signature.sign(&secp, &msg.content, &wrong_keypair),
            Err(multisig::Error::PublicKeyNotFound)
        );
        assert!(msg
            .signature
            .verify(&secp, &msg.content, msg.count_required)
            .is_err());
        Ok(())
    }

    #[test]
    fn signature_with_not_enough_keys_fail(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let secp = secp256k1::Secp256k1::new();
        let keypairs = generate_keypairs(&secp, 3)?;
        let mut msg =
            Message::new(b"Hello world!", extract_pubkeys(&keypairs), None);
        for keypair in keypairs.iter().take(2) {
            assert!(msg.signature.sign(&secp, &msg.content, keypair).is_ok());
        }
        assert_eq!(
            msg.signature
                .verify(&secp, &msg.content, msg.count_required),
            Err(multisig::Error::NotEnoughSignatures(2, 3)),
        );
        Ok(())
    }

    #[test]
    fn signature_with_incorrect_msg_fail(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let secp = secp256k1::Secp256k1::new();
        let keypairs = generate_keypairs(&secp, 3)?;
        let mut msg =
            Message::new(b"Hello world!", extract_pubkeys(&keypairs), None);
        for keypair in keypairs.iter().take(3) {
            assert!(msg.signature.sign(&secp, b"other msg", keypair).is_ok());
        }
        assert_eq!(
            msg.signature
                .verify(&secp, &msg.content, msg.count_required),
            Err(multisig::Error::Secp256k1(
                secp256k1::Error::IncorrectSignature
            )),
        );
        Ok(())
    }

    #[test]
    fn multisig_more_signatures_than_required_success(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let secp = secp256k1::Secp256k1::new();
        let keypairs = generate_keypairs(&secp, 3)?;
        let pubkeys = extract_pubkeys(&keypairs);
        let content = b"Hello world!";
        let required_count = 2;
        let mut msg = Message::new(content, pubkeys, Some(required_count));

        for keypair in &keypairs {
            msg.signature.sign(&secp, content, keypair)?;
        }

        assert!(msg.signature.verify(&secp, content, required_count).is_ok());

        Ok(())
    }

    #[test]
    fn multisig_empty_message() -> Result<(), Box<dyn std::error::Error>> {
        let secp = secp256k1::Secp256k1::new();
        let keypairs = generate_keypairs(&secp, 3)?;
        let pubkeys = extract_pubkeys(&keypairs);
        let content = b"";
        let mut msg = Message::new(content, pubkeys, None);

        for keypair in &keypairs {
            msg.signature.sign(&secp, content, keypair)?;
        }

        assert!(msg.signature.verify(&secp, content, 3).is_ok());

        Ok(())
    }

    // Helpers

    fn extract_pubkeys(
        keypairs: &[secp256k1::Keypair],
    ) -> Vec<secp256k1::PublicKey> {
        keypairs.iter().map(|k| k.public_key()).collect()
    }

    fn generate_keypairs(
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        count: usize,
    ) -> Result<Vec<secp256k1::Keypair>, secp256k1::Error> {
        std::iter::repeat_with(|| crypto::new_keypair(secp))
            .take(count)
            .collect::<Result<Vec<_>, _>>()
    }
}
