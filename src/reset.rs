//! Factory reset for the VeriMark Guard via CTAP2 `authenticatorReset` (0x07).
//!
//! The `ctap-hid-fido2` crate (3.5.x) does not expose a reset, so we speak the
//! CTAPHID transport ourselves over `hidapi`: open the FIDO HID interface, do a
//! CTAPHID_INIT handshake to obtain a channel id, then send the one-byte CBOR
//! command `0x07`. A reset wipes the PIN, every credential, and every enrolled
//! fingerprint, restoring the key to factory state.
//!
//! Authenticators only allow a reset shortly after power-up (typically within
//! ~10s of being plugged in) and require a physical touch to confirm.

use anyhow::{anyhow, bail, Result};
use hidapi::{DeviceInfo, HidApi, HidDevice};
use std::time::{Duration, Instant};

const FIDO_USAGE_PAGE: u16 = 0xF1D0;
const HID_RPT_SIZE: usize = 64;

// CTAPHID command bytes (high bit set marks an initialization packet).
const CMD_INIT: u8 = 0x06 | 0x80; // 0x86
const CMD_CBOR: u8 = 0x10 | 0x80; // 0x90
const CMD_KEEPALIVE: u8 = 0x3B | 0x80; // 0xBB
const CMD_ERROR: u8 = 0x3F | 0x80; // 0xBF

const BROADCAST_CID: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

// CTAPHID_KEEPALIVE status bytes.
const KEEPALIVE_UP_NEEDED: u8 = 0x02; // waiting for the user to touch the key.

// How long to wait overall for the user to touch (and the key to answer).
const RESET_DEADLINE: Duration = Duration::from_secs(30);

/// Perform a full factory reset of the key identified by `vid:pid`.
pub fn reset(vid: u16, pid: u16) -> Result<()> {
    let dev = open_fido(vid, pid)?;

    // 1. CTAPHID_INIT — negotiate a channel id with an 8-byte nonce we echo-check.
    let nonce = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64)
        .to_le_bytes();
    let cid = ctaphid_init(&dev, &nonce)?;

    // 2. authenticatorReset is CBOR command 0x07 with no parameters.
    send_init_packet(&dev, cid, CMD_CBOR, &[0x07])?;

    println!("Touch the key now to confirm the reset...");

    // 3. Read keepalives until the final CBOR response (or an error/timeout).
    let start = Instant::now();
    let mut prompted = false;
    loop {
        if start.elapsed() > RESET_DEADLINE {
            bail!("timed out waiting for the reset to complete (no touch?)");
        }
        let mut buf = [0u8; HID_RPT_SIZE];
        let n = dev.read_timeout(&mut buf, 500)?;
        if n == 0 {
            continue; // read timeout; keep waiting until the deadline.
        }
        if buf[0..4] != cid {
            continue; // a frame for some other channel.
        }
        match buf[4] {
            CMD_KEEPALIVE => {
                if buf[7] == KEEPALIVE_UP_NEEDED && !prompted {
                    println!("  waiting for your touch...");
                    prompted = true;
                }
            }
            CMD_CBOR => {
                // First payload byte is the CTAP status code.
                let status = buf[7];
                if status == 0x00 {
                    println!("Key reset to factory state.");
                    println!("PIN, all credentials, and all fingerprints have been erased.");
                    return Ok(());
                }
                bail!("reset rejected: {}", ctap_status_message(status));
            }
            CMD_ERROR => bail!("CTAPHID error 0x{:02x} during reset", buf[7]),
            _ => continue,
        }
    }
}

/// Open the FIDO HID interface of the target device (prefers usage page 0xF1D0).
fn open_fido(vid: u16, pid: u16) -> Result<HidDevice> {
    let api = HidApi::new()?;
    let mut chosen: Option<&DeviceInfo> = None;
    for d in api.device_list() {
        if d.vendor_id() == vid && d.product_id() == pid {
            if d.usage_page() == FIDO_USAGE_PAGE {
                chosen = Some(d);
                break;
            }
            chosen.get_or_insert(d);
        }
    }
    let info = chosen
        .ok_or_else(|| anyhow!("VeriMark Guard ({vid:04x}:{pid:04x}) not found — is it plugged in?"))?;
    api.open_path(info.path())
        .map_err(|e| anyhow!("cannot open the key: {e}"))
}

/// CTAPHID_INIT handshake; returns the negotiated 4-byte channel id.
fn ctaphid_init(dev: &HidDevice, nonce: &[u8; 8]) -> Result<[u8; 4]> {
    send_init_packet(dev, BROADCAST_CID, CMD_INIT, nonce)?;
    let start = Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(2) {
            bail!("no response to CTAPHID_INIT");
        }
        let mut buf = [0u8; HID_RPT_SIZE];
        let n = dev.read_timeout(&mut buf, 500)?;
        if n == 0 {
            continue;
        }
        // INIT reply echoes the nonce in data bytes 0..8, then the new cid in 8..12.
        if buf[4] == CMD_INIT && &buf[7..15] == nonce {
            return Ok([buf[15], buf[16], buf[17], buf[18]]);
        }
    }
}

/// Write a single CTAPHID initialization packet (payloads here fit in one frame).
fn send_init_packet(dev: &HidDevice, cid: [u8; 4], cmd: u8, data: &[u8]) -> Result<()> {
    // Linux hidraw expects a leading report-id byte (0 for FIDO's unnumbered report).
    let mut buf = [0u8; 1 + HID_RPT_SIZE];
    buf[1..5].copy_from_slice(&cid);
    buf[5] = cmd;
    buf[6] = (data.len() >> 8) as u8;
    buf[7] = (data.len() & 0xff) as u8;
    let n = data.len().min(HID_RPT_SIZE - 7);
    buf[8..8 + n].copy_from_slice(&data[..n]);
    dev.write(&buf)?;
    Ok(())
}

/// Human-readable message for the CTAP status codes a reset can return.
fn ctap_status_message(status: u8) -> String {
    match status {
        0x27 => "operation denied — reset is only allowed shortly after power-up. \
                 Unplug the key, plug it back in, and run 'vmguard reset' within ~10 seconds."
            .to_string(),
        0x2f => "timed out waiting for your touch (CTAP2_ERR_USER_ACTION_TIMEOUT).".to_string(),
        0x30 => "not allowed (CTAP2_ERR_NOT_ALLOWED).".to_string(),
        0x3a => "operation timed out (CTAP2_ERR_ACTION_TIMEOUT).".to_string(),
        0x3b => "user presence required — touch the key (CTAP2_ERR_UP_REQUIRED).".to_string(),
        other => format!("CTAP error 0x{other:02x}"),
    }
}
