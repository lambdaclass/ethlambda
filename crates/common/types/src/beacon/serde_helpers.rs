//! The serde adapters the beacon types need, in both directions.
//!
//! Reading covers the two scalar shapes an eth2 `config.yaml` uses; writing
//! covers the Beacon API's JSON encoding. The two are not symmetric, and the
//! asymmetries are documented on each adapter: reading an integer accepts a
//! quoted or bare scalar, writing one always quotes.

use serde::{Deserialize as _, Deserializer};

/// An integer written either quoted or bare.
///
/// The specification's own configuration files quote large integers so that a
/// JavaScript client does not lose precision reading them, but the convention
/// is not universal and a generator may emit either. Accepting only one form
/// silently leaves the field at its default, which is the failure mode this
/// avoids.
///
/// Every scalar is taken as a string and parsed, rather than matched against
/// an untagged enum of "string or integer". YAML resolves a bare `0x...` to an
/// integer, and an untagged enum makes serde buffer the value first, which
/// fails outright on `DEPOSIT_CONTRACT_ADDRESS`: twenty bytes of hex overflow
/// `u128` and the buffered value cannot even be constructed. Asking for a
/// string hands us the scalar's own text whether or not it was quoted, which
/// is the same coercion Teku applies and the reason Teku has none of the
/// quoting bugs Prysm worked around.
pub mod quoted_or_bare {
    use super::*;

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        let text = String::deserialize(deserializer)?;
        text.trim().parse().map_err(serde::de::Error::custom)
    }

    /// Always written quoted, whatever form it was read in.
    ///
    /// The asymmetry with [`deserialize`] is deliberate: a `config.yaml` may
    /// quote an integer or not, and both must parse, but every integer in a
    /// Beacon API response is a quoted string. Reading is permissive, writing
    /// is not.
    ///
    /// Intended for the unsigned integer aliases (`Slot`, `Epoch`, `Gwei`,
    /// `ValidatorIndex`, ...), whose `Display` output already is their wire
    /// form. A `Display` type whose text is not its wire form, such as a
    /// `bool` or a signed integer, would silently misencode through here.
    ///
    /// Goes through `collect_str` rather than `serialize_str(&value.to_string())`:
    /// `to_string()` always allocates a `String`, but serde_json overrides
    /// `collect_str` to format straight into its output buffer, so on that
    /// (our) backend this allocates nothing. A field of this type appears
    /// once per validator in a `BeaconState`, so the difference is millions
    /// of allocations on a mainnet-sized response.
    pub fn serialize<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: std::fmt::Display,
    {
        serializer.collect_str(value)
    }
}

/// A fixed-width byte array written as hex, with or without a `0x` prefix.
///
/// Used for fork versions and the snappy message domains, which are four
/// bytes, and for the deposit contract address, which is twenty.
pub mod hex_array {
    use super::*;

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        let digits = text.trim();
        let digits = digits.strip_prefix("0x").unwrap_or(digits);

        if digits.len() != N * 2 {
            return Err(serde::de::Error::custom(format!(
                "expected {N} bytes of hex, got {} characters",
                digits.len()
            )));
        }

        let mut out = [0u8; N];
        hex::decode_to_slice(digits, &mut out).map_err(serde::de::Error::custom)?;
        Ok(out)
    }

    /// Always written with the `0x` prefix, though [`deserialize`] accepts it
    /// either way.
    ///
    /// Formats through the [`HexPrefixed`] `Display` adapter and
    /// `collect_str` rather than `serialize_str(&format!("0x{}", hex::encode(value)))`:
    /// the latter allocates twice (once in `hex::encode`, once in `format!`)
    /// per call, but serde_json overrides `collect_str` to write straight
    /// into its output buffer with no intermediate `String`, so on that (our)
    /// backend the adapter allocates nothing. The saving here is small in
    /// absolute terms, since the fixed-width byte types this serves
    /// (`Version`, `DomainType`, `ForkDigest`, `Domain`) appear a handful of
    /// times per state rather than per validator: it is written this way to
    /// match its sibling above, so that neither adapter is the one that
    /// allocates.
    pub fn serialize<S, const N: usize>(value: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&HexPrefixed(value.as_slice()))
    }
}

/// A zero-allocation `Display` adapter writing `0x`-prefixed lowercase hex.
///
/// Module-scoped rather than private to [`hex_array`] so [`ssz_hex`] can
/// format its owned SSZ encoding through the same path without a second
/// allocation. Public so everything else that writes Beacon API hex reuses it
/// too rather than repeating `format!("0x{}", hex::encode(..))`:
/// `beacon::primitives`'s hand-written `Serialize` impls for the fixed-width
/// byte newtypes, the RPC crate's hand-built JSON, and the validator client's
/// request bodies. Call `.to_string()` on it where a `String` is needed.
pub struct HexPrefixed<'a>(pub &'a [u8]);

impl std::fmt::Display for HexPrefixed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x")?;
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// A sequence of integers, each written quoted.
///
/// Takes any `IntoIterator` of `Display` by reference so it serves a
/// `Vec<u64>` and an `SszList<u64, N>` alike, which is what the containers
/// need: `libssz-types` has no serde support and is a foreign crate, so its
/// collections cannot carry an impl of their own.
///
/// Carries the same caveat as [`quoted_or_bare::serialize`]: it is intended
/// for sequences of the unsigned integer aliases (`Slot`, `Epoch`, `Gwei`,
/// `ValidatorIndex`, ...), whose `Display` output already is their wire form.
/// A sequence of some other `Display` type whose text is not its wire form,
/// such as `bool` or a signed integer, would silently misencode through
/// here, element by element.
pub mod quoted_u64_seq {
    /// Wraps one `Display` element so [`serde::ser::SerializeSeq::serialize_element`]
    /// routes it through `collect_str` instead of `serialize_str(&value.to_string())`:
    /// the latter always allocates a `String` per element, but serde_json
    /// overrides `collect_str` to format straight into its output buffer, so
    /// on that (our) backend this allocates nothing. This runs once per
    /// element of fields like `Attestation.attesting_indices`, which reach
    /// into the millions across a mainnet `BeaconState`.
    struct Quoted<T>(T);

    impl<T: std::fmt::Display> serde::Serialize for Quoted<T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.collect_str(&self.0)
        }
    }

    pub fn serialize<S, C, T>(values: C, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        C: IntoIterator<Item = T>,
        C::IntoIter: ExactSizeIterator,
        T: std::fmt::Display,
    {
        use serde::ser::SerializeSeq as _;

        let iter = values.into_iter();
        let mut seq = serializer.serialize_seq(Some(iter.len()))?;
        for item in iter {
            seq.serialize_element(&Quoted(item))?;
        }
        seq.end()
    }

    /// The inverse, into an `SszList<u64, N>`: each element is read quoted or
    /// bare, and a sequence past the list's bound fails as soon as the extra
    /// element arrives rather than after buffering all of it.
    pub fn deserialize<'de, D, const N: usize>(
        deserializer: D,
    ) -> Result<libssz_types::SszList<u64, N>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// One element, accepted as a bare integer or a decimal string.
        struct Element(u64);

        impl<'de> serde::Deserialize<'de> for Element {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct ElementVisitor;

                impl serde::de::Visitor<'_> for ElementVisitor {
                    type Value = Element;

                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        f.write_str("an unsigned integer, bare or quoted")
                    }

                    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Element, E> {
                        Ok(Element(value))
                    }

                    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Element, E> {
                        value.trim().parse().map(Element).map_err(E::custom)
                    }
                }

                deserializer.deserialize_any(ElementVisitor)
            }
        }

        struct ListVisitor<const N: usize>;

        impl<'de, const N: usize> serde::de::Visitor<'de> for ListVisitor<N> {
            type Value = libssz_types::SszList<u64, N>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a sequence of at most {N} unsigned integers")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut list = libssz_types::SszList::new();
                while let Some(Element(value)) = seq.next_element()? {
                    list.push(value).map_err(|err| {
                        serde::de::Error::custom(format!("sequence exceeds its bound: {err:?}"))
                    })?;
                }
                Ok(list)
            }
        }

        deserializer.deserialize_seq(ListVisitor::<N>)
    }
}

/// A sequence of sequences of integers, each innermost value written quoted.
///
/// [`quoted_u64_seq`] drives one flat sequence of `Display` scalars; this
/// drives it once per outer element, for a field like
/// `gloas::BeaconState.ptc_window`
/// (`SszVector<SszVector<ValidatorIndex, PTC_SIZE>, PTC_WINDOW_LENGTH>`)
/// whose elements are themselves a foreign `SszVector` with no `Serialize`
/// of their own. Neither [`seq`] (which needs the element itself to already
/// implement `Serialize`) nor [`quoted_u64_seq`] alone (which needs the
/// element to already be the scalar) applies to a field shaped like this.
pub mod nested_quoted_u64_seq {
    use serde::ser::SerializeSeq as _;

    /// Wraps one inner sequence so [`serde::ser::SerializeSeq::serialize_element`]
    /// drives it through [`super::quoted_u64_seq::serialize`] instead of
    /// requiring the inner sequence itself to implement `Serialize`.
    struct Inner<C>(C);

    impl<C, T> serde::Serialize for Inner<C>
    where
        C: IntoIterator<Item = T> + Copy,
        C::IntoIter: ExactSizeIterator,
        T: std::fmt::Display,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            super::quoted_u64_seq::serialize(self.0, serializer)
        }
    }

    pub fn serialize<S, C, D, T>(values: C, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        C: IntoIterator<Item = D>,
        C::IntoIter: ExactSizeIterator,
        // `D` is the outer iterator's item, an inner sequence reached by
        // reference (e.g. `&SszVector<u64, N>`), so it is `Copy` the same
        // way any shared reference is.
        D: IntoIterator<Item = T> + Copy,
        D::IntoIter: ExactSizeIterator,
        T: std::fmt::Display,
    {
        let iter = values.into_iter();
        let mut seq = serializer.serialize_seq(Some(iter.len()))?;
        for item in iter {
            seq.serialize_element(&Inner(item))?;
        }
        seq.end()
    }
}

/// Anything SSZ-encodable, written as `0x`-prefixed hex of that encoding.
///
/// This is how the Beacon API carries bitfields: `SszBitlist` and
/// `SszBitvector` have no JSON form of their own, and their SSZ encoding —
/// which already carries the length-delimiting bit for a bitlist — is exactly
/// what the specification's hex string holds.
pub mod ssz_hex {
    use super::HexPrefixed;

    /// `to_ssz()` allocates the `Vec<u8>` holding the encoding; that
    /// allocation is genuinely unavoidable for `SszBitlist`, which must set
    /// a delimiter bit no existing buffer holds. It is not strictly needed
    /// for `SszBitvector` (`as_bytes()` already is the encoding) or a byte
    /// list (`SszList<u8, N>` derefs to `[u8]`, which already is the
    /// encoding too) — but one shared `SszEncode`/`to_ssz()` path across all
    /// three is preferred over hand-picking a zero-allocation route per
    /// type, for one allocation that is a handful of bytes, not a
    /// per-validator or per-element cost. What this function still avoids is
    /// a *second* allocation on top of `to_ssz()`'s: formatting through
    /// [`HexPrefixed`] and `collect_str` (serde_json writes straight into
    /// its output buffer for that call) means the hex text itself is never
    /// materialized as its own `String`.
    pub fn serialize<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: libssz::SszEncode,
    {
        serializer.collect_str(&HexPrefixed(&value.to_ssz()))
    }

    /// The inverse: hex (with or without `0x`) of the value's SSZ encoding,
    /// decoded through `SszDecode`, so a bitlist's delimiter bit and a
    /// bitvector's width are checked by the same code that checks them on the
    /// wire.
    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: libssz::SszDecode,
    {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        let digits = text.trim();
        let bytes = hex::decode(digits.strip_prefix("0x").unwrap_or(digits))
            .map_err(serde::de::Error::custom)?;
        T::from_ssz_bytes(&bytes)
            .map_err(|err| serde::de::Error::custom(format!("invalid SSZ encoding: {err:?}")))
    }
}

/// A sequence of SSZ-encodable byte strings, each written as its own
/// `0x`-prefixed hex, from a foreign collection.
///
/// Neither [`seq`] nor [`ssz_hex`] alone produces this shape. [`seq::serialize`]
/// needs each element to already implement `Serialize`, but an element here is
/// itself a foreign `SszList<u8, N>` (from `libssz-types`), which the orphan
/// rule rules out an impl for, the same constraint [`seq`]'s own doc comment
/// describes. [`ssz_hex::serialize`] over the whole field would go the other
/// way: it would hex-encode the *entire list's* SSZ encoding as one string,
/// rather than emitting one hex string per element. This module composes the
/// two: an internal per-element wrapper gives each element `Serialize` by
/// deferring to the same [`HexPrefixed`] formatting [`ssz_hex`] uses, and
/// [`serialize`](self::serialize) drives the sequence the way
/// [`quoted_u64_seq`] drives its own per-element wrapper.
///
/// `ExecutionPayload.transactions` is the motivating field: a
/// `SszList<Transaction, N>` where `Transaction` is itself a
/// `SszList<u8, M>`, so the Beacon API's JSON array of `0x`-prefixed
/// transaction hex strings needs exactly this shape.
pub mod ssz_hex_seq {
    use libssz::SszEncode as _;

    use super::HexPrefixed;

    /// Wraps one element so [`serde::ser::SerializeSeq::serialize_element`]
    /// routes it through `collect_str` instead of allocating a `String` per
    /// element the way `serialize_str(&format!("0x{}", hex::encode(...)))`
    /// would: serde_json overrides `collect_str` to format straight into its
    /// output buffer, so on that (our) backend only `to_ssz()`'s own
    /// allocation remains — the same one [`ssz_hex::serialize`] cannot avoid
    /// either.
    ///
    /// Generic over `T: Deref<Target: SszEncode>` rather than `T: SszEncode`
    /// directly: sequence iteration (below) hands over `&Element`, not
    /// `Element`, and `SszEncode` (unlike `serde::Serialize` or `Display`)
    /// carries no blanket impl for references, so the bound has to look
    /// through the reference instead of requiring one on it.
    struct Hex<T>(T);

    impl<T> serde::Serialize for Hex<T>
    where
        T: std::ops::Deref,
        T::Target: libssz::SszEncode,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.collect_str(&HexPrefixed(&self.0.to_ssz()))
        }
    }

    pub fn serialize<S, C, T>(values: C, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        C: IntoIterator<Item = T>,
        C::IntoIter: ExactSizeIterator,
        T: std::ops::Deref,
        T::Target: libssz::SszEncode,
    {
        use serde::ser::SerializeSeq as _;

        let iter = values.into_iter();
        let mut seq = serializer.serialize_seq(Some(iter.len()))?;
        for item in iter {
            seq.serialize_element(&Hex(item))?;
        }
        seq.end()
    }
}

/// A sequence of values that serialize themselves, from a foreign collection.
///
/// `SszList` and `SszVector` come from `libssz-types`, which has no serde
/// support, so the orphan rule rules out an impl on them and every field of one
/// routes through here instead.
pub mod seq {
    use serde::ser::SerializeSeq as _;

    pub fn serialize<S, C, T>(values: C, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        C: IntoIterator<Item = T>,
        C::IntoIter: ExactSizeIterator,
        T: serde::Serialize,
    {
        let iter = values.into_iter();
        let mut seq = serializer.serialize_seq(Some(iter.len()))?;
        for item in iter {
            seq.serialize_element(&item)?;
        }
        seq.end()
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Sample {
        #[serde(deserialize_with = "super::quoted_or_bare::deserialize")]
        count: u64,
        #[serde(deserialize_with = "super::hex_array::deserialize")]
        version: [u8; 4],
    }

    #[test]
    fn quoted_and_bare_integers_parse_identically() {
        let quoted: Sample = serde_yaml_ng::from_str("count: '64'\nversion: '0x01000000'").unwrap();
        let bare: Sample = serde_yaml_ng::from_str("count: 64\nversion: 0x01000000").unwrap();
        assert_eq!(quoted.count, 64);
        assert_eq!(bare.count, 64);
        assert_eq!(quoted.version, [0x01, 0x00, 0x00, 0x00]);
        assert_eq!(bare.version, [0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn hex_without_prefix_parses() {
        let sample: Sample = serde_yaml_ng::from_str("count: 1\nversion: '01000000'").unwrap();
        assert_eq!(sample.version, [0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn a_hex_value_of_the_wrong_length_is_an_error() {
        let err = serde_yaml_ng::from_str::<Sample>("count: 1\nversion: '0x0100'")
            .unwrap_err()
            .to_string();
        assert!(err.contains("expected 4 bytes"), "got {err}");
    }

    /// Twenty bytes of unquoted hex, exactly as `eth-clients/mainnet` writes
    /// `DEPOSIT_CONTRACT_ADDRESS`. This is the case that rules out reading a
    /// scalar through an untagged "string or integer" enum: the value exceeds
    /// `u128`, so serde cannot buffer it and the parse fails before any of our
    /// code runs. Asking for a `String` sees the scalar's own text instead.
    #[test]
    fn a_twenty_byte_unquoted_address_parses() {
        #[derive(Debug, serde::Deserialize)]
        struct Address {
            #[serde(deserialize_with = "super::hex_array::deserialize")]
            deposit_contract_address: [u8; 20],
        }

        let parsed: Address = serde_yaml_ng::from_str(
            "deposit_contract_address: 0x00000000219ab540356cBB839Cbe05303d7705Fa",
        )
        .expect("an unquoted twenty-byte address parses");
        assert_eq!(
            parsed.deposit_contract_address[0..4],
            [0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(parsed.deposit_contract_address[19], 0xfa);
    }

    #[derive(Debug, serde::Serialize)]
    struct Out {
        #[serde(with = "super::quoted_or_bare")]
        count: u64,
        #[serde(with = "super::hex_array")]
        version: [u8; 4],
    }

    #[test]
    fn integers_are_written_quoted() {
        let json = serde_json::to_string(&Out {
            count: 64,
            version: [0x01, 0x00, 0x00, 0x00],
        })
        .unwrap();
        assert_eq!(json, r#"{"count":"64","version":"0x01000000"}"#);
    }

    #[test]
    fn a_written_hex_array_always_carries_the_prefix() {
        let json = serde_json::to_string(&Out {
            count: 0,
            version: [0xde, 0xad, 0xbe, 0xef],
        })
        .unwrap();
        assert!(json.contains(r#""0xdeadbeef""#), "got {json}");
    }

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct RoundTrip {
        #[serde(with = "super::quoted_or_bare")]
        count: u64,
    }

    /// The module doc's whole reason for quoting is protecting large
    /// integers from JavaScript's float precision loss, so the round trip
    /// must hold exactly at `u64::MAX`, not just for small values.
    #[test]
    fn a_quoted_integer_survives_a_round_trip_at_u64_max() {
        let original = RoundTrip { count: u64::MAX };
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, r#"{"count":"18446744073709551615"}"#);
        let parsed: RoundTrip = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }

    #[derive(Debug, serde::Serialize)]
    struct Coll {
        #[serde(serialize_with = "super::quoted_u64_seq::serialize")]
        indices: Vec<u64>,
        #[serde(serialize_with = "super::quoted_u64_seq::serialize")]
        list: libssz_types::SszList<u64, 8>,
        #[serde(serialize_with = "super::ssz_hex::serialize")]
        bits: libssz_types::SszBitlist<64>,
    }

    #[test]
    fn a_list_of_integers_quotes_every_element() {
        let value = Coll {
            indices: vec![1, 2, 300],
            list: libssz_types::SszList::try_from(vec![4, 5, 600]).unwrap(),
            bits: libssz_types::SszBitlist::new(),
        };
        let json = serde_json::to_value(&value).unwrap();
        assert_eq!(json["indices"], serde_json::json!(["1", "2", "300"]));
        // Same adapter, driven through an `SszList<u64, N>` rather than a
        // `Vec<u64>` — the whole reason `quoted_u64_seq` is generic over
        // `IntoIterator` instead of hard-coded to `Vec`.
        assert_eq!(json["list"], serde_json::json!(["4", "5", "600"]));
    }

    #[test]
    fn a_bitfield_is_written_as_hex_of_its_ssz_encoding() {
        let mut bits = libssz_types::SszBitlist::<64>::with_length(8).unwrap();
        bits.set(0, true).unwrap();
        let value = Coll {
            indices: vec![],
            list: libssz_types::SszList::new(),
            bits,
        };
        let json = serde_json::to_value(&value).unwrap();
        // Data byte 0x01 (bit 0 set) followed by the length-delimiter byte
        // 0x01 (the delimiter bit lands at bit index 8, i.e. bit 0 of the
        // second byte, since the bitlist encoding is `ceil((len + 1) / 8)`
        // bytes wide).
        assert_eq!(json["bits"], serde_json::json!("0x0101"));
    }

    #[test]
    fn an_empty_bitfield_is_just_the_delimiter_byte() {
        let value = Coll {
            indices: vec![],
            list: libssz_types::SszList::new(),
            bits: libssz_types::SszBitlist::new(),
        };
        let json = serde_json::to_value(&value).unwrap();
        // No data bits at all: the encoding is the lone delimiter bit set in
        // an otherwise-empty byte, not an empty string and not an all-zero
        // byte.
        assert_eq!(json["bits"], serde_json::json!("0x01"));
    }

    #[test]
    fn a_list_of_integers_reads_quoted_or_bare_and_stops_at_its_bound() {
        #[derive(Debug, serde::Deserialize)]
        struct Holder {
            #[serde(deserialize_with = "super::quoted_u64_seq::deserialize")]
            values: libssz_types::SszList<u64, 2>,
        }

        let ok: Holder = serde_json::from_str(r#"{"values": ["1", 2]}"#).unwrap();
        assert_eq!(ok.values.iter().copied().collect::<Vec<_>>(), vec![1, 2]);
        let err = serde_json::from_str::<Holder>(r#"{"values": [1, 2, 3]}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("exceeds its bound"), "got {err}");
    }
}
