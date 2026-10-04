use super::{
    error, normalize,
    profiles::{feature, IntersectionPolicy, TuplePolicy, UnionPolicy},
    validate, walk, SchemaError, SchemaMode, SchemaProfile,
};
use serde_json::{json, Map, Value};

pub(super) fn translate(
    schema: &mut Value,
    profile: SchemaProfile,
    mode: SchemaMode,
) -> Result<(), SchemaError> {
    let policy = *profile.policy();
    walk::postorder(schema, "$", 0, &mut 0, &mut |node, path| {
        let Some(map) = node.as_object_mut() else {
            return Ok(());
        };
        // Validate before stripping: malformed constraints and unknown keywords
        // remain errors, even inside a constraint that will be discarded.
        validate::node(map, path, false)?;
        if policy.intersection == IntersectionPolicy::MergeSafely {
            if let Some(branches) = map.remove("allOf") {
                let mut merged = Map::new();
                for branch in branches.as_array().unwrap() {
                    let branch = branch.as_object().ok_or_else(|| {
                        error(path, "boolean allOf branch cannot be merged safely")
                    })?;
                    normalize::merge(&mut merged, branch.clone(), path)?;
                }
                normalize::merge(map, merged, path)?;
            }
        }
        if policy.union == UnionPolicy::WidenToAnyOf {
            if let Some(branches) = map.remove("oneOf") {
                if map.contains_key("anyOf") {
                    return Err(error(
                        &format!("{path}.oneOf"),
                        "cannot combine oneOf and anyOf safely",
                    ));
                }
                if mode == SchemaMode::Strict && !disjoint(branches.as_array().unwrap()) {
                    return Err(error(
                        &format!("{path}.oneOf"),
                        "overlapping oneOf cannot be translated losslessly",
                    ));
                }
                map.insert("anyOf".into(), branches);
            }
        }
        if policy.tuple == TuplePolicy::NormalizeToHomogeneousItems {
            tuple(map, path, mode)?;
        }
        let keys: Vec<_> = map.keys().cloned().collect();
        for key in keys {
            if let Some(feature) = feature(&key) {
                if !policy.supports(feature) {
                    if mode == SchemaMode::Strict || !policy.may_drop(feature) {
                        return Err(error(
                            &format!("{path}.{key}"),
                            format!("unsupported JSON Schema keyword '{key}'"),
                        ));
                    }
                    if key == "patternProperties"
                        && map
                            .get(&key)
                            .and_then(Value::as_object)
                            .is_some_and(|p| !p.is_empty())
                    {
                        // Matching dynamic keys were exempt from additionalProperties.
                        // Dropping only the patterns would newly forbid/constrain those
                        // keys. Widen the fallback as part of this lossy translation.
                        map.remove("additionalProperties");
                    }
                    map.remove(&key);
                }
            }
            if policy.dropped_annotations.contains(&key.as_str()) {
                map.remove(&key);
            }
        }
        Ok(())
    })
}

fn tuple(map: &mut Map<String, Value>, path: &str, mode: SchemaMode) -> Result<(), SchemaError> {
    let legacy = map.get("items").is_some_and(Value::is_array);
    if !legacy && !map.contains_key("prefixItems") && !map.contains_key("additionalItems") {
        return Ok(());
    }
    let keyword = if legacy {
        "items"
    } else if map.contains_key("prefixItems") {
        "prefixItems"
    } else {
        "additionalItems"
    };
    if mode == SchemaMode::Strict {
        return Err(error(
            &format!("{path}.{keyword}"),
            "tuple keywords require lossy normalization",
        ));
    }
    if legacy && map.contains_key("prefixItems") {
        return Err(error(
            path,
            "cannot combine legacy items tuple and prefixItems",
        ));
    }
    let variants = if legacy {
        map.remove("items")
    } else {
        map.remove("prefixItems")
    };
    let tail = if legacy {
        map.remove("additionalItems")
    } else {
        map.remove("items")
    };
    if !legacy && map.remove("additionalItems").is_some() {
        return Err(error(path, "additionalItems requires legacy tuple items"));
    }
    let mut variants = variants
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    match tail {
        None | Some(Value::Bool(true)) => {
            map.insert("items".into(), json!({}));
        }
        Some(Value::Bool(false)) => {
            if variants.is_empty() {
                map.insert("items".into(), json!({}));
            } else {
                map.insert("items".into(), union(variants));
            }
        }
        Some(tail) => {
            variants.push(tail);
            map.insert("items".into(), union(variants));
        }
    }
    Ok(())
}

fn union(mut variants: Vec<Value>) -> Value {
    if variants.len() == 1 {
        variants.remove(0)
    } else {
        json!({"anyOf": variants})
    }
}

fn disjoint(branches: &[Value]) -> bool {
    for (i, left) in branches.iter().enumerate() {
        for right in &branches[i + 1..] {
            if let (Some(l), Some(r)) = (
                left.get("enum").and_then(Value::as_array),
                right.get("enum").and_then(Value::as_array),
            ) {
                if !l
                    .iter()
                    .any(|value| r.iter().any(|other| equivalent(value, other)))
                {
                    continue;
                }
            }
            if let (Some(l), Some(r)) = (
                left.get("type").and_then(Value::as_str),
                right.get("type").and_then(Value::as_str),
            ) {
                if l != r && !matches!((l, r), ("integer", "number") | ("number", "integer")) {
                    continue;
                }
            }
            return false;
        }
    }
    true
}

// JSON Schema treats numeric 1 and 1.0 as equal, unlike serde_json::Value.
// Float conversion may conservatively equate distinct large integers. That
// only rejects a proof of disjointness, never permits a lossy strict lowering.
fn equivalent(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(l), Value::Number(r)) => l.as_f64() == r.as_f64(),
        (Value::Array(l), Value::Array(r)) => {
            l.len() == r.len() && l.iter().zip(r).all(|(l, r)| equivalent(l, r))
        }
        (Value::Object(l), Value::Object(r)) => {
            l.len() == r.len()
                && l.iter()
                    .all(|(key, l)| r.get(key).is_some_and(|r| equivalent(l, r)))
        }
        _ => left == right,
    }
}
