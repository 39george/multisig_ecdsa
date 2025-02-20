use crate::api::ErrorResponse;
use crate::domain::{messages::Message, user::User};

pub mod in_memory;

type MsgModifier = fn(&mut Message);

#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
    #[error("user exists already")]
    UserExists,
    #[error("no user found")]
    NoUser,
    #[error("message exists already")]
    MsgExists,
    #[error("no message found")]
    NoMsg,
}

crate::impl_debug!(Error);

impl From<Error> for ErrorResponse {
    fn from(value: Error) -> Self {
        match value {
            Error::Internal(e) => ErrorResponse::InternalError(e.into()),
            Error::UserExists | Error::MsgExists => {
                ErrorResponse::ConflictError(value.into())
            }
            Error::NoUser | Error::NoMsg => {
                ErrorResponse::NotFoundError(value.into())
            }
        }
    }
}

#[async_trait::async_trait]
pub trait Storage {
    // CRUD for user

    async fn store_user(&self, user: User) -> Result<(), Error>;
    async fn get_user(&self, username: &str) -> Result<Option<User>, Error>;
    async fn update_user(&self, user: User) -> Result<(), Error>;
    async fn remove_user(&self, user_id: &uuid::Uuid) -> Result<(), Error>;
    async fn all_users(&self) -> Result<Vec<User>, Error>;

    // CRUD for msgs

    async fn store_msg(&self, msg: Message) -> Result<(), Error>;
    async fn get_msg(
        &self,
        msg_hash: &secp256k1::hashes::sha256::Hash,
    ) -> Result<Option<Message>, Error>;
    /// Use that function to add signature
    async fn update_msg(
        &self,
        msg: Message,
        with: MsgModifier,
    ) -> Result<(), Error>;
    async fn remove_msg(
        &self,
        msg_hash: &secp256k1::hashes::sha256::Hash,
    ) -> Result<(), Error>;
    async fn all_messages(&self) -> Result<Vec<Message>, Error>;
}
