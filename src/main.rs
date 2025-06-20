use std::process::ExitCode;

use std::io;

fn env_val_by_key(key: &'static str) -> Result<String, io::Error> {
    std::env::var(key)
        .map_err(|_| format!("no env var: {key}"))
        .map_err(io::Error::other)
}

fn env2mode() -> bool {
    env_val_by_key("ENV_SEAL")
        .ok()
        .and_then(|s| str::parse(s.as_str()).ok())
        .unwrap_or(false)
}

fn env2secret_key_filename() -> Result<String, io::Error> {
    env_val_by_key("ENV_SECRET_KEY_LOCATION")
}

fn env2msg_filename() -> Result<String, io::Error> {
    env_val_by_key("ENV_PLAIN_MSG_FILENAME")
}

fn env2sealed_filename() -> Result<String, io::Error> {
    env_val_by_key("ENV_SEALED_MSG_FILENAME")
}

fn env2msg_size_max() -> u64 {
    env_val_by_key("ENV_MSG_SIZE_MAX")
        .ok()
        .and_then(|s| str::parse(s.as_str()).ok())
        .unwrap_or(1048576)
}

fn env2sealed_msg_filesize() -> u64 {
    env_val_by_key("ENV_SEALED_MSG_SIZE_MAX")
        .ok()
        .and_then(|s| str::parse(s.as_str()).ok())
        .unwrap_or(1048576)
}

fn file2msg2sealed2stdout() -> Result<(), io::Error> {
    rs_seal_msg::file2msg2sealed2stdout(
        env2secret_key_filename()?,
        env2msg_filename()?,
        env2msg_size_max(),
    )
}

fn file2sealed2msg2stdout() -> Result<(), io::Error> {
    rs_seal_msg::file2sealed2msg2stdout(
        env2secret_key_filename()?,
        env2sealed_filename()?,
        env2sealed_msg_filesize(),
    )
}

fn sub() -> Result<(), io::Error> {
    let seal_mode: bool = env2mode();
    match seal_mode {
        true => file2msg2sealed2stdout(),
        false => file2sealed2msg2stdout(),
    }
}

fn main() -> ExitCode {
    sub().map(|_| ExitCode::SUCCESS).unwrap_or_else(|e| {
        eprintln!("some error happend: {e}");
        ExitCode::FAILURE
    })
}
