#![doc = include_str!("../README.md")]
use anyhow::*;
use clap::Parser;
use sodiumoxide::crypto::{pwhash, secretbox};
use std::{
    borrow::Cow,
    io::{Read, Write},
    path::{Path, PathBuf},
};

/// Perform an encrypted backup of BitWarden
#[derive(clap::Parser)]
struct Opt {
    /// File to save encrypted data to
    #[clap(long, global = true)]
    file: Option<PathBuf>,

    /// Verbose output?
    #[clap(long, short, global = true)]
    verbose: bool,

    #[clap(subcommand)]
    cmd: Command,
}

#[derive(clap::Parser)]
enum Command {
    /// Perform a backup for the given email address.
    ///
    /// Note that you will likely need to `bw login` first to provide MFA information.
    Backup {
        /// Email address for account to back up
        #[clap(long)]
        email: String,
    },
    /// Decrypt a previous captured backup file.
    Restore {},
}

const PASSWORDENV: &str = "BW_PASSWORD";
const SESSIONENV: &str = "BW_SESSION";

impl Opt {
    fn get_file(&self) -> Result<Cow<Path>> {
        self.file.as_ref().map_or_else(
            || {
                let mut path =
                    directories_next::ProjectDirs::from("com", "Snoyman", "BitWarden Backup")
                        .context("Unable to get project directories")
                        .map(|pd| pd.config_dir().to_owned())?;
                std::fs::create_dir_all(&path)
                    .with_context(|| format!("Could not create directory {}", path.display()))?;
                path.push("backup.json.enc");
                Ok(path.into())
            },
            |path| Ok(path.as_path().into()),
        )
    }
}

fn main() -> Result<()> {
    let opt = Opt::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if opt.verbose { "debug" } else { "info" }),
    )
    .init();
    let filepath = opt.get_file()?;

    log::debug!("File path is {}", filepath.display());

    let password = rpassword::prompt_password("Master password: ")
        .context("Could not read master password")?;

    match &opt.cmd {
        Command::Backup { email } => backup(&filepath, email, &password),
        Command::Restore {} => restore(&filepath, &password),
    }
}

fn backup(filepath: &Path, email: &str, password: &str) -> Result<()> {
    let login_exit_status = std::process::Command::new("bw")
        .arg("--raw")
        .arg("--nointeraction")
        .arg("login")
        .arg("--passwordenv")
        .arg(PASSWORDENV)
        .env(PASSWORDENV, &password)
        .env_remove(SESSIONENV)
        .arg(&email)
        .stdin(std::process::Stdio::null())
        .status()
        .context("bw login command failed")?;

    log::debug!("Login exit status: {:?}", login_exit_status);

    let output = std::process::Command::new("bw")
        .arg("--raw")
        .arg("--nointeraction")
        .arg("unlock")
        .arg(&password)
        .env_remove(SESSIONENV)
        .output()
        .context("Error running 'bw unlock'")?;
    log::debug!("Unlock output: {:?}", output);
    ensure!(output.status.success(), "bw unlock exited unsuccessfully");
    let session = String::from_utf8(output.stdout).context("Invalid UTF8 encoding in stdout")?;

    let output = std::process::Command::new("bw")
        .arg("--raw")
        .arg("--nointeraction")
        .arg("export")
        .arg(password)
        .arg("--format")
        .arg("json")
        .env(SESSIONENV, session)
        .output()
        .context("Error running 'bw unlock'")?;
    log::debug!("bw export output: {:?}", output);
    ensure!(output.status.success(), "bw export exited unsuccessfully");

    let sealed = seal(password, &output.stdout)?;

    let mut file = std::fs::File::create(&filepath).context("Could not open save file")?;
    file.write_all(&sealed)
        .context("Could not write output to file")?;
    file.flush().context("Could not flush file")?;
    println!("Saved to {}", filepath.display());

    Ok(())
}

fn seal(password: &str, data: &[u8]) -> Result<Vec<u8>> {
    let mut kb = [0; secretbox::KEYBYTES];
    let salt = pwhash::gen_salt();
    let nonce = secretbox::gen_nonce();
    pwhash::derive_key_interactive(&mut kb, password.as_bytes(), &salt)
        .ok()
        .context("Could not derive key")?;
    let key = secretbox::Key(kb);
    let encrypted = secretbox::seal(data, &nonce, &key);

    let mut result = Vec::new();
    result.extend_from_slice(&salt.0);
    result.extend_from_slice(&nonce.0);
    result.extend_from_slice(&encrypted);
    Ok(result)
}

fn restore(filepath: &Path, password: &str) -> Result<()> {
    let mut file = std::fs::File::open(filepath)
        .with_context(|| format!("Could not open for reading: {}", filepath.display()))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).context("Could not read file")?;

    ensure!(buf.len() > 56, "Insufficient bytes in file");
    let salt = pwhash::Salt::from_slice(&buf[0..32]).expect("Invalid salt size");
    let nonce = secretbox::Nonce::from_slice(&buf[32..56]).expect("Invalid nonce size");
    let mut kb = [0; secretbox::KEYBYTES];
    pwhash::derive_key_interactive(&mut kb, password.as_bytes(), &salt)
        .ok()
        .context("Could not derive key")?;
    let key = secretbox::Key(kb);
    let decrypted = secretbox::open(&buf[56..], &nonce, &key)
        .ok()
        .context("Unable to decrypt")?;

    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    stdout
        .write_all(&decrypted)
        .context("Unable to write to stdout")
}
