use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    constants::CONTINUE_TIMEOUT,
    routes::{forgot, login, mfa, register},
};

pub fn run() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Unexpected error: failed to get system time")
        .as_secs();
    for pending in login::PENDING_LOGINS.iter() {
        if now - pending.value().time > CONTINUE_TIMEOUT {
            login::PENDING_LOGINS.remove(pending.key());
        }
    }
    for pending in login::PENDING_MFAS.iter() {
        if now - pending.value().time > CONTINUE_TIMEOUT {
            login::PENDING_MFAS.remove(pending.key());
        }
    }
    for pending in register::PENDING_REGISTERS1.iter() {
        if now - pending.value().time > CONTINUE_TIMEOUT {
            register::PENDING_REGISTERS1.remove(pending.key());
        }
    }
    for pending in register::PENDING_REGISTERS2.iter() {
        if now - pending.value().time > CONTINUE_TIMEOUT {
            register::PENDING_REGISTERS2.remove(pending.key());
        }
    }
    for pending in mfa::PENDING_MFA_SETUPS.iter() {
        if now - pending.value().time > CONTINUE_TIMEOUT {
            mfa::PENDING_MFA_SETUPS.remove(pending.key());
        }
    }
    for pending in forgot::PENDING_FORGOTS1.iter() {
        if now - pending.value().time > CONTINUE_TIMEOUT {
            forgot::PENDING_FORGOTS1.remove(pending.key());
        }
    }
    for pending in forgot::PENDING_FORGOTS2.iter() {
        if now - pending.value().time > CONTINUE_TIMEOUT {
            forgot::PENDING_FORGOTS2.remove(pending.key());
        }
    }
}
