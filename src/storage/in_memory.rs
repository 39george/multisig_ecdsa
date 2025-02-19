use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;

use secp256k1::hashes::Hash;

use crate::domain::{messages::Message, user::User};

use super::Error;

#[derive(Debug, Default)]
struct Inner {
    users: HashMap<uuid::Uuid, User>,
    msgs: Vec<Message>,
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryStorage {
    inner: Arc<Mutex<Inner>>,
}

impl InMemoryStorage {
    fn lock(&self) -> Result<MutexGuard<Inner>, Error> {
        Ok(self.inner.lock().map_err(|e| {
            anyhow::anyhow!("failed to acquire mutex lock: {e}")
        })?)
    }
}

#[async_trait::async_trait]
impl super::Storage for InMemoryStorage {
    async fn store_user(&self, user: User) -> Result<(), Error> {
        let mut lock = self.lock()?;
        if lock.users.contains_key(&user.id) {
            return Err(Error::UserExists);
        }
        lock.users.insert(user.id, user);
        Ok(())
    }

    async fn get_user(
        &self,
        user_id: &uuid::Uuid,
    ) -> Result<Option<User>, Error> {
        let lock = self.lock()?;
        Ok(lock.users.get(user_id).cloned())
    }

    async fn update_user(&self, user: User) -> Result<(), Error> {
        let mut lock = self.lock()?;
        if !lock.users.contains_key(&user.id) {
            return Err(Error::NoUser);
        }
        lock.users.entry(user.id).and_modify(|u| *u = user);
        Ok(())
    }

    async fn remove_user(&self, user_id: &uuid::Uuid) -> Result<(), Error> {
        let mut lock = self.lock()?;
        lock.users.remove(user_id);
        Ok(())
    }

    async fn all_users(&self) -> Result<Vec<User>, Error> {
        let lock = self.lock()?;
        Ok(lock.users.values().cloned().collect())
    }

    async fn store_msg(&self, msg: Message) -> Result<(), Error> {
        let mut lock = self.lock()?;
        if lock.msgs.iter().any(|m| m.eq(&msg)) {
            return Err(Error::MsgExists);
        }
        lock.msgs.push(msg);
        Ok(())
    }

    async fn get_msg(
        &self,
        msg_hash: &secp256k1::hashes::sha256::Hash,
    ) -> Result<Option<Message>, Error> {
        let lock = self.lock()?;
        let msg = lock.msgs.iter().find(|m| {
            let h = secp256k1::hashes::sha256::Hash::hash(&m.content);
            h.eq(msg_hash)
        });
        Ok(msg.cloned())
    }

    async fn update_msg(
        &self,
        msg: Message,
        with: super::MsgModifier,
    ) -> Result<(), Error> {
        let mut lock = self.lock()?;
        let msg = lock
            .msgs
            .iter_mut()
            .find(|m| msg.eq(m))
            .ok_or(Error::NoMsg)?;
        with(msg);
        Ok(())
    }

    async fn remove_msg(
        &self,
        msg_hash: &secp256k1::hashes::sha256::Hash,
    ) -> Result<(), Error> {
        let mut lock = self.lock()?;
        let (idx, _) = lock
            .msgs
            .iter()
            .enumerate()
            .find(|(_, m)| {
                let h = secp256k1::hashes::sha256::Hash::hash(&m.content);
                h.eq(msg_hash)
            })
            .ok_or(Error::NoMsg)?;
        lock.msgs.remove(idx);
        Ok(())
    }

    async fn all_messages(&self) -> Result<Vec<Message>, Error> {
        let lock = self.lock()?;
        Ok(lock.msgs.clone())
    }
}
