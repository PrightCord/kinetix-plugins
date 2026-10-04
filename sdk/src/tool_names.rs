use std::collections::BTreeMap;
use std::fmt;

const RESERVED_PREFIX: &str = "_ktx_";
const MAX_WIRE_NAME_BYTES: usize = 64;

/// A reversible mapping between canonical tool names and provider-safe names.
///
/// Names already accepted by Gemini pass through unchanged. Other names use a
/// reserved, hex-encoded form so the response parser can restore the original
/// name without request-local state. Names that cannot fit are rejected rather
/// than truncated or aliased.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ToolNameMap {
    client_to_wire: BTreeMap<String, String>,
    wire_to_client: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolNameError(String);

impl fmt::Display for ToolNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ToolNameError {}

impl ToolNameMap {
    /// Create a deterministic mapping for the supplied client names.
    pub fn new<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<Self, ToolNameError> {
        let mut mapping = Self::default();
        let mut names: Vec<&str> = names.into_iter().collect();
        names.sort_unstable();
        names.dedup();

        for name in names {
            if name.is_empty() {
                return Err(ToolNameError("tool name must not be empty".into()));
            }
            let wire = if is_wire_safe(name) && !name.starts_with(RESERVED_PREFIX) {
                name.to_owned()
            } else {
                encode_name(name)?
            };
            if let Some(previous) = mapping.wire_to_client.get(&wire) {
                if previous != name {
                    return Err(ToolNameError(format!(
                        "tool names '{previous}' and '{name}' map to the same provider name"
                    )));
                }
            }
            mapping.client_to_wire.insert(name.to_owned(), wire.clone());
            mapping.wire_to_client.insert(wire, name.to_owned());
        }
        Ok(mapping)
    }

    /// Return a provider-safe name. Names must be included when creating the map.
    pub fn to_wire(&self, client_name: &str) -> Result<&str, ToolNameError> {
        self.client_to_wire
            .get(client_name)
            .map(String::as_str)
            .ok_or_else(|| {
                ToolNameError(format!("tool name '{client_name}' is not in the mapping"))
            })
    }

    /// Restore a client name from a provider-returned name.
    ///
    /// Unknown provider-safe names pass through so providers may return known
    /// extension tools. Malformed uses of the reserved encoding are rejected.
    pub fn from_wire(wire_name: &str) -> Result<String, ToolNameError> {
        if let Some(encoded) = wire_name.strip_prefix(RESERVED_PREFIX) {
            return decode_name(encoded);
        }
        if is_wire_safe(wire_name) {
            Ok(wire_name.to_owned())
        } else {
            Err(ToolNameError(format!(
                "provider returned invalid tool name '{wire_name}'"
            )))
        }
    }
}

fn is_wire_safe(name: &str) -> bool {
    if name.len() > MAX_WIRE_NAME_BYTES {
        return false;
    }
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}

fn encode_name(name: &str) -> Result<String, ToolNameError> {
    let mut wire = String::with_capacity(RESERVED_PREFIX.len() + name.len() * 2);
    wire.push_str(RESERVED_PREFIX);
    for byte in name.as_bytes() {
        use fmt::Write;
        write!(&mut wire, "{byte:02x}").expect("writing to String cannot fail");
    }
    if wire.len() > MAX_WIRE_NAME_BYTES {
        return Err(ToolNameError(format!(
            "tool name is not representable within the provider's {MAX_WIRE_NAME_BYTES}-byte limit"
        )));
    }
    Ok(wire)
}

fn decode_name(encoded: &str) -> Result<String, ToolNameError> {
    if !encoded.len().is_multiple_of(2) || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ToolNameError(
            "provider returned malformed encoded tool name".into(),
        ));
    }
    let bytes = encoded
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("hex source is ASCII");
            u8::from_str_radix(pair, 16).expect("validated hex pair")
        })
        .collect::<Vec<_>>();
    let name = String::from_utf8(bytes)
        .map_err(|_| ToolNameError("provider returned non-UTF-8 encoded tool name".into()))?;
    if name.is_empty() {
        return Err(ToolNameError(
            "provider returned an empty encoded tool name".into(),
        ));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names_pass_through_and_invalid_names_round_trip() {
        let names = ["read_file", "read file", "δοκιμή", "_ktx_reserved"];
        let mapping = ToolNameMap::new(names).unwrap();
        assert_eq!(mapping.to_wire("read_file").unwrap(), "read_file");
        for name in ["read file", "δοκιμή", "_ktx_reserved"] {
            let wire = mapping.to_wire(name).unwrap();
            assert!(wire.starts_with(RESERVED_PREFIX));
            assert_eq!(ToolNameMap::from_wire(wire).unwrap(), name);
        }
    }

    #[test]
    fn names_never_collide_with_encoded_forms() {
        let names = ["foo!", "_ktx_666f6f21", "foo?"];
        let mapping = ToolNameMap::new(names).unwrap();
        let wires = names
            .iter()
            .map(|name| mapping.to_wire(name).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            wires
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
        for name in names {
            assert_eq!(
                ToolNameMap::from_wire(mapping.to_wire(name).unwrap()).unwrap(),
                name
            );
        }
    }

    #[test]
    fn overlong_unrepresentable_names_fail_instead_of_truncating() {
        let name = format!("{}!", "a".repeat(31));
        let error = ToolNameMap::new([name.as_str()]).unwrap_err();
        assert!(error.to_string().contains("not representable"));
    }

    #[test]
    fn malformed_reserved_wire_names_are_rejected() {
        assert!(ToolNameMap::from_wire("_ktx_0").is_err());
        assert!(ToolNameMap::from_wire("_ktx_gg").is_err());
    }
}
