use crate::domain::user::User;

pub mod in_memory;

#[allow(async_fn_in_trait)]
pub trait Storage {
    type Err;
    type Msg;

    // CRUD for user

    async fn store_user(user: User) -> Result<(), Self::Err>;
    async fn update_user(user: User) -> Result<(), Self::Err>;
    async fn remove_user(user_id: uuid::Uuid) -> Result<(), Self::Err>;
    async fn all_users() -> Result<Vec<User>, Self::Err>;

    // CRUD for msgs

    async fn store_msg(msg: Self::Msg) -> Result<(), Self::Err>;
    /// Use that function to add signature
    async fn update_msg<F: Fn(&mut Self::Msg)>(
        msg: Self::Msg,
        with: F,
    ) -> Result<(), Self::Err>;
    async fn remove_msg(user_id: uuid::Uuid) -> Result<(), Self::Err>;
    async fn all_messages() -> Result<Vec<()>, Self::Err>;
}
