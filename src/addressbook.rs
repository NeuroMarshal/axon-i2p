//! Names of I2P sites. An address book maps `name.i2p` to a destination
//! hash and fills from hosts.txt files that registry sites publish.
//! `<base32>.b32.i2p` names carry the hash and need no address book.

use std::{collections::BTreeMap, fs, io, path::Path};

use crate::{
    data::{b32_name, base64, parse_b32_name},
    identity::Identity,
};

/// Project sites known from the start, so that their hosts.txt files can
/// fill an empty address book.
pub const BOOTSTRAP: [(&str, &str); 3] = [
    (
        "i2p-projekt.i2p",
        "udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p",
    ),
    (
        "stats.i2p",
        "7tbay5p4kzeekxvyvbf6v7eauazemsnnl2aoyqhg5jzpr5eke7tq.b32.i2p",
    ),
    (
        "zzz.i2p",
        "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p",
    ),
];

#[derive(Debug, Clone, Default)]
pub struct AddressBook {
    names: BTreeMap<String, [u8; 32]>,
}

fn valid_name(name: &str) -> bool {
    name.len() <= 67
        && name.ends_with(".i2p")
        && !name.ends_with(".b32.i2p")
        && !name.starts_with(['.', '-'])
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte))
}

/// The hash a hosts.txt value stands for: a destination in I2P base64, or
/// a b32 name in our own saved files.
fn hash_of(value: &str) -> Option<[u8; 32]> {
    if let Some(hash) = parse_b32_name(value) {
        return Some(hash);
    }
    let bytes = base64().decode(value.as_bytes()).ok()?;
    let (identity, length) = Identity::parse(&bytes)?;
    (length == bytes.len()).then(|| *identity.hash())
}

impl AddressBook {
    /// Adds the [`BOOTSTRAP`] names the book does not have.
    pub fn add_bootstrap(&mut self) {
        for (name, b32) in BOOTSTRAP {
            self.names
                .entry(name.to_owned())
                .or_insert_with(|| parse_b32_name(b32).expect("valid b32 name"));
        }
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Adds the `name=destination` lines of a hosts.txt file. Names already
    /// known keep their destination, as I2P address books do. Returns how
    /// many names were new.
    pub fn add_hosts(&mut self, text: &str) -> usize {
        let mut added = 0;
        for line in text.lines() {
            // Properties after "#!" and comments after "#" are not needed.
            let line = line.split('#').next().unwrap_or_default().trim();
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            let name = name.trim().to_ascii_lowercase();
            if !valid_name(&name) || self.names.contains_key(&name) {
                continue;
            }
            if let Some(hash) = hash_of(value.trim()) {
                self.names.insert(name, hash);
                added += 1;
            }
        }
        added
    }

    /// The destination hash of a host name, if it is a b32 name or known.
    pub fn resolve(&self, host: &str) -> Option<[u8; 32]> {
        let host = host.to_ascii_lowercase();
        parse_b32_name(&host).or_else(|| self.names.get(&host).copied())
    }

    /// Reads a book saved by [`AddressBook::save`]; a missing file is an
    /// empty book.
    pub fn load(path: &Path) -> io::Result<Self> {
        let mut book = Self::default();
        match fs::read_to_string(path) {
            Ok(text) => {
                book.add_hosts(&text);
                Ok(book)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(book),
            Err(error) => Err(error),
        }
    }

    /// Writes the book as `name=<base32>.b32.i2p` lines.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let mut text = String::new();
        for (name, hash) in &self.names {
            text.push_str(name);
            text.push('=');
            text.push_str(&b32_name(hash));
            text.push('\n');
        }
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, text)?;
        fs::rename(temporary, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PrivateIdentity;

    #[test]
    fn hosts_files_fill_the_book() {
        let keys = PrivateIdentity::generate_destination();
        let destination = base64().encode(keys.identity.bytes());
        let text = format!(
            "# a comment\nsite.i2p={destination}#!sig=xyz\nBAD NAME=abc\n\
             other.i2p=notbase64\nsite.i2p={destination}\n"
        );
        let mut book = AddressBook::default();
        assert_eq!(book.add_hosts(&text), 1);
        assert_eq!(book.resolve("SITE.i2p"), Some(*keys.identity.hash()));
        assert_eq!(book.resolve("other.i2p"), None);
        let b32 = b32_name(keys.identity.hash());
        assert_eq!(book.resolve(&b32), Some(*keys.identity.hash()));
    }

    #[test]
    fn a_saved_book_loads_back() {
        let directory = std::env::temp_dir().join(format!("axon-i2p-book-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("names.txt");
        let mut book = AddressBook::default();
        book.add_bootstrap();
        book.save(&path).unwrap();
        let loaded = AddressBook::load(&path).unwrap();
        assert_eq!(loaded.len(), BOOTSTRAP.len());
        assert_eq!(loaded.resolve("zzz.i2p"), book.resolve("zzz.i2p"));
        fs::remove_dir_all(directory).unwrap();
    }
}
