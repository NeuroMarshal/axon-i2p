//! I2P's common structures: strings, mappings, the I2P base64 alphabet and
//! b32 names.

use std::sync::OnceLock;

use data_encoding::{BASE32_NOPAD, Encoding, Specification};

/// Base64 with `-` and `~` in place of `+` and `/`, as I2P writes keys and
/// destinations.
pub fn base64() -> &'static Encoding {
    static ENCODING: OnceLock<Encoding> = OnceLock::new();
    ENCODING.get_or_init(|| {
        let mut spec = Specification::new();
        spec.symbols
            .push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~");
        spec.padding = Some('=');
        spec.encoding().expect("a valid base64 alphabet")
    })
}

/// The `<base32>.b32.i2p` name of a destination hash.
pub fn b32_name(hash: &[u8; 32]) -> String {
    let mut name = BASE32_NOPAD.encode(hash).to_ascii_lowercase();
    name.push_str(".b32.i2p");
    name
}

/// The hash a `<base32>.b32.i2p` name stands for. Longer names of blinded
/// (encrypted) lease sets are not supported.
pub fn parse_b32_name(name: &str) -> Option<[u8; 32]> {
    let encoded = name.strip_suffix(".b32.i2p")?;
    if encoded.len() != 52 {
        return None;
    }
    BASE32_NOPAD
        .decode(encoded.to_ascii_uppercase().as_bytes())
        .ok()?
        .try_into()
        .ok()
}

/// Reads I2P structures from a byte slice.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub const fn position(&self) -> usize {
        self.position
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }

    pub fn is_empty(&self) -> bool {
        self.position >= self.bytes.len()
    }

    pub fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(length)?;
        let slice = self.bytes.get(self.position..end)?;
        self.position = end;
        Some(slice)
    }

    pub fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    pub fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.array()?))
    }

    /// A string: one length byte and up to 255 bytes.
    pub fn string(&mut self) -> Option<String> {
        let length = usize::from(self.u8()?);
        Some(String::from_utf8_lossy(self.take(length)?).into_owned())
    }

    /// A mapping: a two-byte size, then `key=value;` pairs of strings.
    pub fn mapping(&mut self) -> Option<Vec<(String, String)>> {
        let size = usize::from(self.u16()?);
        let mut inner = Reader::new(self.take(size)?);
        let mut pairs = Vec::new();
        while !inner.is_empty() {
            let key = inner.string()?;
            if inner.u8()? != b'=' {
                return None;
            }
            let value = inner.string()?;
            if inner.u8()? != b';' {
                return None;
            }
            pairs.push((key, value));
        }
        Some(pairs)
    }
}

pub fn write_string(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let length = bytes.len().min(255);
    out.push(length as u8);
    out.extend_from_slice(&bytes[..length]);
}

/// Writes a mapping with its keys sorted, as signed structures require.
pub fn write_mapping(out: &mut Vec<u8>, pairs: &[(String, String)]) {
    let mut sorted = pairs.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut body = Vec::new();
    for (key, value) in &sorted {
        write_string(&mut body, key);
        body.push(b'=');
        write_string(&mut body, value);
        body.push(b';');
    }
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
}

/// Looks up a key in a mapping.
pub fn get<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, value)| value.as_str())
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mappings_round_trip_sorted() {
        let mut out = Vec::new();
        write_mapping(
            &mut out,
            &[("netId".into(), "2".into()), ("caps".into(), "LU".into())],
        );
        let pairs = Reader::new(&out).mapping().unwrap();
        assert_eq!(
            pairs,
            vec![("caps".into(), "LU".into()), ("netId".into(), "2".into())]
        );
    }

    #[test]
    fn base64_uses_the_i2p_alphabet() {
        assert_eq!(base64().encode(&[0xfb, 0xff]), "-~8=");
        assert_eq!(base64().decode(b"-~8=").unwrap(), vec![0xfb, 0xff]);
    }

    #[test]
    fn b32_names_round_trip() {
        let hash = [7u8; 32];
        let name = b32_name(&hash);
        assert_eq!(name.len(), 52 + ".b32.i2p".len());
        assert_eq!(parse_b32_name(&name), Some(hash));
    }
}
