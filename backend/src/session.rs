#[derive(Clone, Debug)]
pub struct Session {
    pub username: String,
    /// Bearer JWT for the external service
    pub jwt: String,
}
