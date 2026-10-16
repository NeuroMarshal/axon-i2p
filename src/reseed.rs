//! Bootstrapping from a reseed server: an su3 file, signed by the server's
//! operator, holding a zip archive of router infos.

use std::time::Duration;

use axon_addons::{der, rsa::PublicKey};
use sha2::{Digest, Sha512};

use crate::router_info::RouterInfo;

/// Reseed servers of the I2P network.
pub const RESEED_URLS: &[&str] = &[
    "https://reseed2.i2p.net/",
    "https://reseed.diva.exchange/",
    "https://reseed-fr.i2pd.xyz/",
    "https://reseed.onion.im/",
    "https://i2pseed.creativecowpat.net:8443/",
    "https://reseed-pl.i2pd.xyz/",
    "https://www2.mk16.de/",
    "https://i2p.novg.net/",
    "https://reseed.stormycloud.org/",
    "https://reseed.sahil.world/",
    "https://i2p.diyarciftci.xyz/",
    "https://spiral.likogan.dev/",
    "https://reseed2.i2pgit.org/",
    "https://reseed.kiota.ch/",
    "https://sto01.i2p-reseed.hosted-by.skhron.eu/",
    "https://waw01.i2p-reseed.hosted-by.skhron.eu/",
];

macro_rules! include_cert {
    ($name:literal) => {
        include_str!(concat!("../reseed-certificates/", $name))
    };
}

/// Certificates of the reseed operators, as the I2P project distributes them.
const CERTIFICATES: &[&str] = &[
    include_cert!("acetone_at_mail.i2p.crt"),
    include_cert!("admin_at_likogan.dev.crt"),
    include_cert!("admin_at_stormycloud.org.crt"),
    include_cert!("creativecowpat_at_mail.i2p.crt"),
    include_cert!("damian.buho_at_proton.me.crt"),
    include_cert!("diyarciftci_at_protonmail.com.crt"),
    include_cert!("echelon3_at_mail.i2p.crt"),
    include_cert!("freedompeer_at_skhron.eu.crt"),
    include_cert!("i2p-reseed_at_mk16.de.crt"),
    include_cert!("idk_at_stormycloud.org.crt"),
    include_cert!("igor_at_novg.net.crt"),
    include_cert!("lazygravy_at_mail.i2p.crt"),
    include_cert!("orignal_at_mail.i2p.crt"),
    include_cert!("r4sas-reseed_at_mail.i2p.crt"),
    include_cert!("rambler_at_mail.i2p.crt"),
    include_cert!("reseed_at_diva.exchange.crt"),
    include_cert!("reseedserver_at_mail.i2p.crt"),
    include_cert!("sahil_at_mail.i2p.crt"),
    include_cert!("vserod1488_at_proton.me.crt"),
];

#[derive(Debug)]
pub enum ReseedError {
    Format(&'static str),
    UnknownSigner(String),
    BadSignature,
    Download(String),
}

impl std::fmt::Display for ReseedError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Format(what) => write!(formatter, "reseed file: {what}"),
            Self::UnknownSigner(signer) => write!(formatter, "reseed signer {signer} is unknown"),
            Self::BadSignature => formatter.write_str("reseed signature does not verify"),
            Self::Download(error) => write!(formatter, "reseed download: {error}"),
        }
    }
}

impl std::error::Error for ReseedError {}

/// The issuer's common name and the RSA key of a PEM certificate.
fn certificate_key(pem: &str) -> Option<(String, PublicKey)> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let bytes = data_encoding::BASE64.decode(body.trim().as_bytes()).ok()?;
    let name = String::from_utf8_lossy(der::certificate_issuer_name(&bytes)?).into_owned();
    Some((name, PublicKey::from_certificate(&bytes)?))
}

/// The contents of an su3 reseed file, after checking its signature.
pub fn su3_contents(file: &[u8]) -> Result<&[u8], ReseedError> {
    if file.len() < 40 || &file[..6] != b"I2Psu3" {
        return Err(ReseedError::Format("not an su3 file"));
    }
    let signature_type = u16::from_be_bytes([file[8], file[9]]);
    let signature_len = usize::from(u16::from_be_bytes([file[10], file[11]]));
    let version_len = usize::from(file[13]);
    let signer_len = usize::from(file[15]);
    let content_len = u64::from_be_bytes(file[16..24].try_into().expect("fixed slice")) as usize;
    if file[25] != 0 || file[27] != 3 {
        return Err(ReseedError::Format("not a zip of reseed data"));
    }
    let header_len = 40 + version_len;
    let signer = file
        .get(header_len..header_len + signer_len)
        .ok_or(ReseedError::Format("truncated header"))?;
    let signer = String::from_utf8_lossy(signer).into_owned();
    let content_start = header_len + signer_len;
    let signed_len = content_start + content_len;
    let signature = file
        .get(signed_len..signed_len + signature_len)
        .ok_or(ReseedError::Format("truncated content or signature"))?;
    if signature_type != 6 || signature_len != 512 {
        return Err(ReseedError::Format("unsupported signature type"));
    }
    let key = CERTIFICATES
        .iter()
        .filter_map(|pem| certificate_key(pem))
        .find(|(name, _)| *name == signer)
        .map(|(_, key)| key)
        .ok_or_else(|| ReseedError::UnknownSigner(signer.clone()))?;
    // su3 files sign the bare SHA-512 digest, without a DigestInfo.
    let digest = Sha512::digest(&file[..signed_len]);
    if !key.verify_pkcs1(&digest, signature) {
        return Err(ReseedError::BadSignature);
    }
    Ok(&file[content_start..signed_len])
}

/// The files of a zip archive.
pub fn zip_entries(archive: &[u8]) -> Result<Vec<(String, Vec<u8>)>, ReseedError> {
    let u16_at = |at: usize| -> Result<usize, ReseedError> {
        archive
            .get(at..at + 2)
            .map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])))
            .ok_or(ReseedError::Format("truncated zip"))
    };
    let u32_at = |at: usize| -> Result<usize, ReseedError> {
        archive
            .get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
            .ok_or(ReseedError::Format("truncated zip"))
    };
    let end = (0..archive.len().saturating_sub(21))
        .rev()
        .find(|&at| archive[at..at + 4] == [0x50, 0x4b, 0x05, 0x06])
        .ok_or(ReseedError::Format("no end of central directory"))?;
    let count = u16_at(end + 10)?;
    let mut at = u32_at(end + 16)?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if archive.get(at..at + 4) != Some(&[0x50, 0x4b, 0x01, 0x02][..]) {
            return Err(ReseedError::Format("bad central directory entry"));
        }
        let method = u16_at(at + 10)?;
        let compressed = u32_at(at + 20)?;
        let name_len = u16_at(at + 28)?;
        let extra_len = u16_at(at + 30)?;
        let comment_len = u16_at(at + 32)?;
        let local = u32_at(at + 42)?;
        let name = archive
            .get(at + 46..at + 46 + name_len)
            .map(|name| String::from_utf8_lossy(name).into_owned())
            .ok_or(ReseedError::Format("truncated zip"))?;
        at += 46 + name_len + extra_len + comment_len;
        let data_start = local + 30 + u16_at(local + 26)? + u16_at(local + 28)?;
        let data = archive
            .get(data_start..data_start + compressed)
            .ok_or(ReseedError::Format("truncated zip entry"))?;
        let contents = match method {
            0 => data.to_vec(),
            8 => miniz_oxide::inflate::decompress_to_vec_with_limit(data, 64 * 1024)
                .map_err(|_| ReseedError::Format("bad deflate data"))?,
            _ => return Err(ReseedError::Format("unsupported zip compression")),
        };
        entries.push((name, contents));
    }
    Ok(entries)
}

/// The valid router infos in an su3 reseed file.
pub fn router_infos(file: &[u8]) -> Result<Vec<RouterInfo>, ReseedError> {
    let entries = zip_entries(su3_contents(file)?)?;
    Ok(entries
        .into_iter()
        .filter(|(name, _)| name.starts_with("routerInfo-") && name.ends_with(".dat"))
        .filter_map(|(_, bytes)| RouterInfo::parse(&bytes))
        .collect())
}

/// Downloads router infos from the reseed servers, trying them in random
/// order until one answers with a valid file.
pub async fn fetch(urls: &[&str]) -> Result<Vec<RouterInfo>, ReseedError> {
    let mut order = urls.to_vec();
    for i in (1..order.len()).rev() {
        let mut byte = [0u8; 8];
        let _ = getrandom::getrandom(&mut byte);
        order.swap(i, (u64::from_le_bytes(byte) % (i as u64 + 1)) as usize);
    }
    let mut failures = Vec::new();
    for url in order {
        // Reseed servers answer this agent only.
        let result = axon_runtime::https::get(
            &format!("{url}i2pseeds.su3"),
            &[("User-Agent", "Wget/1.11.4")],
            Duration::from_secs(30),
        )
        .await;
        match result.map_err(|error| ReseedError::Download(error.to_string())) {
            Ok(file) => match router_infos(&file) {
                Ok(infos) if !infos.is_empty() => return Ok(infos),
                Ok(_) => failures.push(format!("{url}: no router infos")),
                Err(error) => failures.push(format!("{url}: {error}")),
            },
            Err(error) => failures.push(format!("{url}: {error}")),
        }
    }
    Err(ReseedError::Download(failures.join("; ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_certificate_yields_a_signer_and_a_4096_bit_key() {
        for pem in CERTIFICATES {
            let (name, key) = certificate_key(pem).expect("parsable certificate");
            assert!(name.contains('@'), "{name}");
            assert_eq!(key.bits(), 4096, "{name}");
        }
    }
}
