//! vmguard — CTAP2/CTAPHID management tool for the
//! Kensington VeriMark Guard 2.1 (USB 047d:813f).
//!
//! The device is a FIDO2 security key with *match-on-chip* biometrics:
//! fingerprints are enrolled and matched inside the key and never reach the
//! host. This tool drives the `authenticatorBioEnrollment` and clientPIN
//! CTAP2 commands so you can set a PIN and enroll/list/delete fingerprints.
//! Actual login integration is handled separately by pam-u2f.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use ctap_hid_fido2::fidokey::get_info::InfoOption;
use ctap_hid_fido2::{Cfg, FidoKeyHid, FidoKeyHidFactory};
use std::io::{self, Write};

mod reset;

const VID: u16 = 0x047d;
const PID: u16 = 0x813f;
/// Per-capture timeout the key waits for a finger touch.
const CAPTURE_TIMEOUT_MS: u16 = 10_000;

#[derive(Parser)]
#[command(
    name = "vmguard",
    about = "Manage the Kensington VeriMark Guard 2.1 FIDO2 fingerprint key"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show device capabilities and current PIN/bio state.
    Info,
    /// Show fingerprint-sensor characteristics (touch/swipe, samples needed).
    BioInfo,
    /// Set the device PIN (required before any bio enrollment).
    SetPin,
    /// List fingerprints currently enrolled on the key.
    BioList {
        /// Device PIN (omit to be prompted securely).
        #[arg(long)]
        pin: Option<String>,
    },
    /// Enroll a new fingerprint (touch the sensor repeatedly when prompted).
    BioEnroll {
        /// Device PIN (omit to be prompted securely).
        #[arg(long)]
        pin: Option<String>,
        /// Friendly name for the new fingerprint (e.g. "right-index").
        #[arg(long, default_value = "finger")]
        name: String,
    },
    /// Delete an enrolled fingerprint by its template id (hex, from bio-list).
    BioDelete {
        /// Device PIN (omit to be prompted securely).
        #[arg(long)]
        pin: Option<String>,
        /// Template id in hex (no spaces), as shown by `bio-list`.
        #[arg(long)]
        id: String,
    },
    /// Make the key's LED blink, to confirm you're talking to the right device.
    Wink,
    /// Factory-reset the key: ERASES the PIN, all credentials, and all fingerprints.
    Reset {
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Info => info(),
        Cmd::BioInfo => bio_info(),
        Cmd::SetPin => set_pin(),
        Cmd::BioList { pin } => bio_list(&pin_or_prompt(pin, "Device PIN: ")?),
        Cmd::BioEnroll { pin, name } => {
            bio_enroll(&pin_or_prompt(pin, "Device PIN: ")?, &name)
        }
        Cmd::BioDelete { pin, id } => {
            bio_delete(&pin_or_prompt(pin, "Device PIN: ")?, &id)
        }
        Cmd::Wink => device()?.wink().map_err(|e| anyhow!(e)),
        Cmd::Reset { yes } => reset_cmd(yes),
    }
}

/// Confirm (unless `--yes`) and then factory-reset the key.
fn reset_cmd(yes: bool) -> Result<()> {
    if !yes {
        println!(
            "This will ERASE the device PIN, all credentials, and all enrolled\n\
             fingerprints on the VeriMark Guard. This cannot be undone."
        );
        print!("Type 'RESET' to confirm: ");
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        if line.trim() != "RESET" {
            return Err(anyhow!("aborted (you did not type RESET)"));
        }
    }
    reset::reset(VID, PID)
}

/// Open the VeriMark Guard specifically (ignores any other FIDO keys).
fn device() -> Result<FidoKeyHid> {
    let cfg = Cfg::init();
    let target = ctap_hid_fido2::get_fidokey_devices()
        .into_iter()
        .find(|d| d.vid == VID && d.pid == PID)
        .ok_or_else(|| {
            anyhow!("VeriMark Guard ({VID:04x}:{PID:04x}) not found — is it plugged in?")
        })?;
    FidoKeyHidFactory::create_by_params(&[target.param], &cfg).map_err(|e| anyhow!(e))
}

fn opt(dev: &FidoKeyHid, o: InfoOption) -> String {
    match dev.enable_info_option(&o) {
        Ok(Some(true)) => "yes".into(),
        Ok(Some(false)) => "supported, not configured".into(),
        Ok(None) => "unsupported".into(),
        Err(e) => format!("error: {e}"),
    }
}

fn info() -> Result<()> {
    let dev = device()?;
    let info = dev.get_info().map_err(|e| anyhow!(e))?;
    println!("VeriMark Guard 2.1  ({VID:04x}:{PID:04x})");
    println!("  CTAP versions : {}", info.versions.join(", "));
    let algs: Vec<&str> = info.algorithms.iter().map(|(a, _)| a.as_str()).collect();
    let algs = if algs.is_empty() {
        "(not reported)".to_string()
    } else {
        algs.join(", ")
    };
    println!("  algorithms    : {algs}");
    println!("  PIN protocols : {:?}", info.pin_uv_auth_protocols);
    println!("  clientPin     : {}", opt(&dev, InfoOption::ClientPin));
    println!("  bioEnroll     : {}", opt(&dev, InfoOption::BioEnroll));
    println!("  uv (built-in) : {}", opt(&dev, InfoOption::Uv));
    println!("  pinUvAuthToken: {}", opt(&dev, InfoOption::PinUvAuthToken));
    println!("  alwaysUv      : {}", opt(&dev, InfoOption::AlwaysUv));
    match dev.get_pin_retries() {
        Ok(n) => println!("  PIN retries   : {n}"),
        Err(e) => println!("  PIN retries   : error: {e}"),
    }
    if let Ok(n) = dev.get_uv_retries() {
        println!("  UV retries    : {n}");
    }
    Ok(())
}

fn bio_info() -> Result<()> {
    let dev = device()?;
    let si = dev
        .bio_enrollment_get_fingerprint_sensor_info()
        .map_err(|e| anyhow!(e))?;
    println!("{si}");
    Ok(())
}

fn set_pin() -> Result<()> {
    let dev = device()?;
    let pin = rpassword::prompt_password("New PIN (4-63 chars): ")?;
    let confirm = rpassword::prompt_password("Confirm PIN: ")?;
    if pin != confirm {
        return Err(anyhow!("PINs do not match"));
    }
    if pin.chars().count() < 4 {
        return Err(anyhow!("PIN must be at least 4 characters"));
    }
    dev.set_new_pin(&pin).map_err(|e| anyhow!(e))?;
    println!("PIN set. Keep it safe — too many wrong tries locks the key.");
    Ok(())
}

/// Use the supplied PIN, or prompt for it without echoing to the terminal.
fn pin_or_prompt(pin: Option<String>, prompt: &str) -> Result<String> {
    match pin {
        Some(p) => Ok(p),
        None => Ok(rpassword::prompt_password(prompt)?),
    }
}

fn bio_list(pin: &str) -> Result<()> {
    let dev = device()?;
    let templates = dev
        .bio_enrollment_enumerate_enrollments(pin)
        .map_err(|e| anyhow!(e))?;
    if templates.is_empty() {
        println!("No fingerprints enrolled.");
        return Ok(());
    }
    println!("Enrolled fingerprints:");
    for t in templates {
        let name = t.template_friendly_name.unwrap_or_default();
        println!("  {}  {}", hex(&t.template_id), name);
    }
    Ok(())
}

fn bio_enroll(pin: &str, name: &str) -> Result<()> {
    let dev = device()?;
    println!("Starting enrollment. Touch the sensor when prompted.");
    let (enroll, mut status) = dev
        .bio_enrollment_begin(pin, Some(CAPTURE_TIMEOUT_MS))
        .map_err(|e| anyhow!(e))?;
    println!(
        "  capture: {} (remaining: {})",
        status.message, status.remaining_samples
    );
    while !status.is_finish {
        status = dev
            .bio_enrollment_next(&enroll, Some(CAPTURE_TIMEOUT_MS))
            .map_err(|e| anyhow!(e))?;
        println!(
            "  capture: {} (remaining: {})",
            status.message, status.remaining_samples
        );
    }
    dev.bio_enrollment_set_friendly_name(pin, &enroll.template_id, name)
        .map_err(|e| anyhow!(e))?;
    println!("Enrolled '{}' (id {}).", name, hex(&enroll.template_id));
    Ok(())
}

fn bio_delete(pin: &str, id_hex: &str) -> Result<()> {
    let dev = device()?;
    let id = unhex(id_hex)?;
    dev.bio_enrollment_remove(pin, &id).map_err(|e| anyhow!(e))?;
    println!("Deleted fingerprint {id_hex}.");
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(anyhow!("hex id must have an even number of digits"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!(e)))
        .collect()
}
