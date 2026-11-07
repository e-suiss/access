//! The MMDB file adapter of the `GeoResolver` (OP-151 m.1 (b)): any `MaxMind` DB producer
//! (`GeoLite2` Country, City or ASN, `IPinfo` country/ASN files) at the path the operator configures.
//! No data is embedded and none is distributed. The file is read whole into memory and read
//! again when its size or modification time changes, so an operator replaces it in place. A
//! missing or unreadable file makes every answer unavailable (MD-8).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use maxminddb::Reader;
use serde::Deserialize;

use crate::domain::geo::{GeoAnswer, Place, Point, country};
use crate::ports::{GeoResolver, GeoStatus};

/// Largest file read (PD): City databases are well under this.
pub const MAX_FILE_BYTES: u64 = 512 << 20;

/// How often [`MmdbGeo::watch`] looks at the file (PD).
pub const WATCH_EVERY: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
}

enum Loaded {
    Missing,
    Unreadable(Stamp),
    Ready(Arc<Reader<Vec<u8>>>, Stamp),
}

/// A GeoIP/ASN source in one MMDB file.
pub struct MmdbGeo {
    path: PathBuf,
    loaded: RwLock<Loaded>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CountryField {
    Code(String),
    Record {
        #[serde(default)]
        iso_code: Option<String>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AsnField {
    Number(u32),
    Text(String),
}

#[derive(Deserialize)]
struct Location {
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
}

#[derive(Deserialize)]
struct Record {
    #[serde(default)]
    country: Option<CountryField>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    location: Option<Location>,
    #[serde(default)]
    autonomous_system_number: Option<u32>,
    #[serde(default)]
    asn: Option<AsnField>,
}

impl Record {
    fn place(&self) -> Place {
        let code = match &self.country {
            Some(CountryField::Code(c)) => Some(c.as_str()),
            Some(CountryField::Record { iso_code }) => iso_code.as_deref(),
            None => None,
        }
        .or(self.country_code.as_deref());
        let asn = self.autonomous_system_number.or(match &self.asn {
            Some(AsnField::Number(n)) => Some(*n),
            Some(AsnField::Text(t)) => t
                .strip_prefix("AS")
                .or(Some(t.as_str()))
                .and_then(|n| n.parse().ok()),
            None => None,
        });
        let point = self
            .location
            .as_ref()
            .and_then(|l| Point::from_degrees(l.latitude?, l.longitude?));
        Place {
            country: code.and_then(country),
            asn: asn.filter(|a| *a != 0),
            point,
        }
    }
}

fn stamp(path: &Path) -> Option<Stamp> {
    let meta = std::fs::metadata(path).ok()?;
    meta.is_file().then(|| Stamp {
        len: meta.len(),
        modified: meta.modified().ok(),
    })
}

fn load(path: &Path, s: Stamp) -> Loaded {
    if s.len > MAX_FILE_BYTES {
        return Loaded::Unreadable(s);
    }
    match std::fs::read(path).map(Reader::from_source) {
        Ok(Ok(r)) => Loaded::Ready(Arc::new(r), s),
        _ => Loaded::Unreadable(s),
    }
}

impl MmdbGeo {
    /// The source at `path`, read now.
    #[must_use]
    pub fn open(path: PathBuf) -> Self {
        let g = Self {
            path,
            loaded: RwLock::new(Loaded::Missing),
        };
        g.refresh();
        g
    }

    /// Reads the file again when it changed; returns whether it did.
    pub fn refresh(&self) -> bool {
        let now = stamp(&self.path);
        let current = match self.loaded.read() {
            Ok(l) => match &*l {
                Loaded::Missing => None,
                Loaded::Unreadable(s) | Loaded::Ready(_, s) => Some(*s),
            },
            Err(_) => return false,
        };
        if now == current {
            return false;
        }
        let next = now.map_or(Loaded::Missing, |s| load(&self.path, s));
        match &next {
            Loaded::Ready(r, _) => tracing::info!(
                event = "geo.source.loaded",
                database_type = %r.metadata().database_type,
                build_epoch = r.metadata().build_epoch,
                "GeoIP source loaded"
            ),
            Loaded::Missing | Loaded::Unreadable(_) => tracing::warn!(
                event = "geo.source.unavailable",
                "GeoIP source cannot be read; geographic signals are unavailable"
            ),
        }
        if let Ok(mut l) = self.loaded.write() {
            *l = next;
            return true;
        }
        false
    }

    /// Looks at the file every `every` until the task is aborted.
    pub async fn watch(self: Arc<Self>, every: Duration) {
        let mut tick = tokio::time::interval(every);
        loop {
            tick.tick().await;
            self.refresh();
        }
    }

    fn reader(&self) -> Option<Arc<Reader<Vec<u8>>>> {
        match &*self.loaded.read().ok()? {
            Loaded::Ready(r, _) => Some(Arc::clone(r)),
            Loaded::Missing | Loaded::Unreadable(_) => None,
        }
    }
}

impl GeoResolver for MmdbGeo {
    fn locate(&self, ip: IpAddr) -> GeoAnswer {
        let Some(reader) = self.reader() else {
            return GeoAnswer::Unavailable;
        };
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 @ IpAddr::V4(_) => v4,
        };
        match reader.lookup(ip).and_then(|r| r.decode::<Record>()) {
            Ok(Some(r)) => GeoAnswer::Found(r.place()),
            Ok(None) | Err(_) => GeoAnswer::Unavailable,
        }
    }

    fn status(&self) -> GeoStatus {
        match self.loaded.read().as_deref() {
            Ok(Loaded::Ready(r, _)) => GeoStatus::Ready {
                database_type: r.metadata().database_type.clone(),
                build_epoch: r.metadata().build_epoch,
            },
            Ok(Loaded::Missing | Loaded::Unreadable(_)) | Err(_) => GeoStatus::Unreadable,
        }
    }
}
