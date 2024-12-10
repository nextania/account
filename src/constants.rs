pub const SERVICE: &str = "account";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const SHORT_SESSION: u128 = 604800000; // 7 days
pub const LONG_SESSION: u128 = 2592000000; // 30 days
pub const ELEVATED_SESSION: u128 = 300000; // 5 minutes

pub const CONTINUE_TIMEOUT: u64 = 3600; // 1 hour
