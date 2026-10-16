//! What this router knows about the network: router infos and lease sets,
//! and which floodfills are responsible for a key today.

use std::collections::HashMap;

use axon_addons::netdb::closest;

use crate::{data::now_ms, identity::sha256, lease_set::LeaseSet, router_info::RouterInfo};

/// The UTC date of `ms` as `yyyyMMdd`.
pub fn utc_date(ms: u64) -> String {
    // Civil date from days since the epoch (Howard Hinnant's algorithm).
    let days = (ms / 86_400_000) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}{month:02}{day:02}")
}

/// Where a key lives in the network database on the day of `ms`: the
/// floodfills closest to this hash hold it.
pub fn routing_key(key: &[u8; 32], ms: u64) -> [u8; 32] {
    let mut input = key.to_vec();
    input.extend_from_slice(utc_date(ms).as_bytes());
    sha256(&input)
}

#[derive(Default)]
pub struct NetDb {
    routers: HashMap<[u8; 32], RouterInfo>,
    lease_sets: HashMap<[u8; 32], LeaseSet>,
}

impl NetDb {
    /// Keeps a router info unless a newer one of the same router is known.
    pub fn add_router(&mut self, info: RouterInfo) {
        let newer = self
            .routers
            .get(info.hash())
            .is_none_or(|known| info.published > known.published);
        if newer {
            self.routers.insert(*info.hash(), info);
        }
    }

    pub fn add_lease_set(&mut self, set: LeaseSet) {
        let newer = self
            .lease_sets
            .get(set.hash())
            .is_none_or(|known| set.published >= known.published);
        if newer {
            self.lease_sets.insert(*set.hash(), set);
        }
    }

    pub fn router(&self, hash: &[u8; 32]) -> Option<&RouterInfo> {
        self.routers.get(hash)
    }

    /// The lease set of a destination, while it has not expired.
    pub fn lease_set(&self, hash: &[u8; 32]) -> Option<&LeaseSet> {
        let now = (now_ms() / 1000) as u32;
        self.lease_sets.get(hash).filter(|set| set.expires > now)
    }

    pub fn routers(&self) -> impl Iterator<Item = &RouterInfo> {
        self.routers.values()
    }

    pub fn len(&self) -> usize {
        self.routers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routers.is_empty()
    }

    /// The reachable floodfills closest to `key` today, closest first.
    pub fn closest_floodfills(
        &self,
        key: &[u8; 32],
        now_ms: u64,
        count: usize,
        exclude: &[[u8; 32]],
    ) -> Vec<[u8; 32]> {
        let target = routing_key(key, now_ms);
        closest(
            &target,
            self.routers
                .values()
                .filter(|info| info.is_floodfill() && info.ntcp2().is_some())
                .map(|info| *info.hash())
                .filter(|hash| !exclude.contains(hash)),
            count,
        )
    }

    /// Routers fit to be tunnel hops: reachable over NTCP2 on IPv4, not
    /// hidden, on the main network, with an X25519 key.
    pub fn tunnel_candidates(&self) -> Vec<&RouterInfo> {
        self.routers
            .values()
            .filter(|info| {
                info.is_usable() && info.ntcp2().is_some() && info.encryption_key().is_some()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_utc_calendar_days() {
        assert_eq!(utc_date(0), "19700101");
        assert_eq!(utc_date(951_782_400_000), "20000229");
        assert_eq!(utc_date(1_790_812_799_000), "20260930");
        assert_eq!(utc_date(1_790_812_800_000), "20261001");
    }
}
