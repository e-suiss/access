//! What a GeoIP/ASN source says about an address (OP-151 m.1 (b)): country, ASN and a coarse
//! position, and the impossible-travel rule over two of them. Positions are kept to a hundredth
//! of a degree (about a kilometre); an address itself is never stored, only its keyed pseudonym
//! and its network prefix.

/// A coarse position in hundredths of a degree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    /// Latitude, -9000..=9000.
    pub lat_cdeg: i32,
    /// Longitude, -18000..=18000.
    pub lon_cdeg: i32,
}

impl Point {
    /// A point in range.
    #[must_use]
    pub const fn new(lat_cdeg: i32, lon_cdeg: i32) -> Option<Self> {
        if lat_cdeg < -9000 || lat_cdeg > 9000 || lon_cdeg < -18000 || lon_cdeg > 18000 {
            return None;
        }
        Some(Self { lat_cdeg, lon_cdeg })
    }

    /// The point of a position in degrees, rounded to a hundredth.
    #[must_use]
    pub fn from_degrees(lat: f64, lon: f64) -> Option<Self> {
        if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
            return None;
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "range checked above: |value| <= 18000"
        )]
        let c = |v: f64| (v * 100.0).round() as i32;
        Self::new(c(lat), c(lon))
    }

    /// Great-circle distance in kilometres (haversine, mean Earth radius).
    #[must_use]
    pub fn distance_km(self, other: Self) -> f64 {
        const RADIUS_KM: f64 = 6371.0;
        let rad = |c: i32| (f64::from(c) / 100.0).to_radians();
        let (la1, la2) = (rad(self.lat_cdeg), rad(other.lat_cdeg));
        let dla = la2 - la1;
        let dlo = rad(other.lon_cdeg) - rad(self.lon_cdeg);
        let h = (dla / 2.0).sin().powi(2) + la1.cos() * la2.cos() * (dlo / 2.0).sin().powi(2);
        2.0 * RADIUS_KM * h.sqrt().min(1.0).asin()
    }
}

/// What the source says about one address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Place {
    /// ISO 3166-1 alpha-2, upper case.
    pub country: Option<[u8; 2]>,
    /// Autonomous system number.
    pub asn: Option<u32>,
    /// Coarse position.
    pub point: Option<Point>,
}

impl Place {
    /// The country as text.
    #[must_use]
    pub fn country_code(&self) -> Option<String> {
        self.country
            .and_then(|c| core::str::from_utf8(&c).ok().map(str::to_owned))
    }
}

/// A country code from text: two ASCII letters, upper-cased.
#[must_use]
pub fn country(code: &str) -> Option<[u8; 2]> {
    let b = code.as_bytes();
    match b {
        [x, y] if x.is_ascii_alphabetic() && y.is_ascii_alphabetic() => {
            Some([x.to_ascii_uppercase(), y.to_ascii_uppercase()])
        }
        _ => None,
    }
}

/// The answer of a `GeoResolver`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeoAnswer {
    /// The source knows the address (some fields may still be missing).
    Found(Place),
    /// No source, the source failed or it does not know the address: geographic signals are
    /// unavailable, never "fine" (MD-8).
    Unavailable,
}

/// Faster than this between two sign-ins is impossible travel (PD): an airliner's cruise
/// speed with margin.
pub const MAX_SPEED_KMH: u32 = 1000;

/// Shorter than this is never impossible travel (PD): `GeoIP` positions are city-level at best
/// and mobile networks move addresses across a country.
pub const MIN_DISTANCE_KM: u32 = 500;

/// Whether going from `from` at `from_ms` to `to` at `to_ms` is impossible travel.
#[must_use]
pub fn impossible_travel(from: Point, from_ms: u64, to: Point, to_ms: u64) -> bool {
    let km = from.distance_km(to);
    if km < f64::from(MIN_DISTANCE_KM) {
        return false;
    }
    let seconds = u32::try_from(to_ms.saturating_sub(from_ms) / 1000).unwrap_or(u32::MAX);
    km * 3600.0 > f64::from(MAX_SPEED_KMH) * f64::from(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-151 m.1 (b), IDP-39
    #[test]
    fn impossible_travel_by_distance_and_time() {
        let ist = Point::from_degrees(41.01, 28.98).unwrap();
        let nyc = Point::from_degrees(40.71, -74.01).unwrap();
        let ank = Point::from_degrees(39.93, 32.86).unwrap();
        let km = ist.distance_km(nyc);
        assert!((8000.0..8100.0).contains(&km), "{km}");
        let hour = 3_600_000;
        assert!(impossible_travel(ist, 0, nyc, hour));
        assert!(!impossible_travel(ist, 0, nyc, 24 * hour));
        assert!(!impossible_travel(ist, 0, ank, 1000));
        assert!(impossible_travel(ist, hour, nyc, 0));
        assert!(Point::from_degrees(91.0, 0.0).is_none());
        assert!(Point::from_degrees(f64::NAN, 0.0).is_none());
    }

    #[test]
    fn country_codes() {
        assert_eq!(country("tr"), Some(*b"TR"));
        assert_eq!(country("TUR"), None);
    }
}
