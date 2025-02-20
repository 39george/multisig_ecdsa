use std::collections::HashMap;

use fake::Fake;
use secp256k1::Keypair;

type KeyId = i32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: uuid::Uuid,
    pub name: String,
    pub keys: HashMap<KeyId, Keypair>,
}

impl Default for User {
    fn default() -> Self {
        User {
            name: fake::faker::internet::en::Username().fake(),
            keys: Default::default(),
            id: uuid::Uuid::new_v4(),
        }
    }
}
