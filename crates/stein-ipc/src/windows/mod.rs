mod identity;
mod security;
mod transport;

pub use identity::{current_user_sid, default_pipe_name};
pub(crate) use identity::{ensure_pipe_client_is_current_user, ensure_pipe_server_is_current_user};
pub(crate) use security::PipeSecurity;
pub(crate) use transport::{connect_pipe, create_pipe_server, create_private_pipe_server};
