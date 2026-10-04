use super::{error, walk, SchemaError, SchemaMode, SchemaProfile};
use serde_json::{json, Map, Value};

pub(super) fn normalize(
    schema: &Value,
    profile: SchemaProfile,
    mode: SchemaMode,
) -> Result<Value, SchemaError> {
    let policy = *profile.policy();
    // Inline only for a surface that cannot carry refs. Other JSON profiles retain
    // refs/defs, including recursive schemas, rather than degrade them.
    let mut out = if profile.inlines_local_refs() {
        inline(schema, schema, mode, "$", 0, &mut 0, &mut Vec::new())?
    } else {
        schema.clone()
    };
    walk::postorder(&mut out, "$", 0, &mut 0, &mut |node, path| {
        let Some(map) = node.as_object_mut() else {
            return if node.is_boolean() {
                Ok(())
            } else {
                Err(error(path, "schema nodes must be JSON objects or booleans"))
            };
        };
        if policy.coerce_numeric_strings {
            for key in [
                "minimum",
                "maximum",
                "exclusiveMinimum",
                "exclusiveMaximum",
                "multipleOf",
                "minLength",
                "maxLength",
                "minItems",
                "maxItems",
                "minProperties",
                "maxProperties",
                "minContains",
                "maxContains",
            ] {
                if let Some(Value::String(value)) = map.get(key) {
                    let number: Value = serde_json::from_str(value)
                        .map_err(|_| error(&format!("{path}.{key}"), "invalid numeric string"))?;
                    if !number.is_number() {
                        return Err(error(&format!("{path}.{key}"), "invalid numeric string"));
                    }
                    map.insert(key.into(), number);
                }
            }
        }
        for (exclusive, bound) in [
            ("exclusiveMinimum", "minimum"),
            ("exclusiveMaximum", "maximum"),
        ] {
            if let Some(Value::Bool(enabled)) = map.get(exclusive) {
                if *enabled {
                    if let Some(bound) = map.remove(bound) {
                        map.insert(exclusive.into(), bound);
                    } else {
                        map.remove(exclusive);
                    }
                } else {
                    map.remove(exclusive);
                }
            }
        }
        if policy.normalize_type_aliases {
            if let Some(kind) = map.get_mut("type") {
                match kind {
                    Value::String(kind) => normalize_type(kind),
                    Value::Array(types) => {
                        for value in types.iter_mut() {
                            if let Some(kind) = value.as_str() {
                                let mut kind = kind.to_string();
                                normalize_type(&mut kind);
                                *value = json!(kind);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if profile.needs_structure()
            && !map.contains_key("type")
            && (map.contains_key("properties") || map.contains_key("patternProperties"))
        {
            map.insert("type".into(), json!("object"));
        }
        if let Some(value) = map.remove("const") {
            if let Some(existing) = map.get("enum") {
                let existing = existing
                    .as_array()
                    .ok_or_else(|| error(&format!("{path}.enum"), "must be an array"))?;
                if !existing.contains(&value) {
                    return Err(error(&format!("{path}.const"), "const conflicts with enum"));
                }
            }
            map.insert("enum".into(), json!([value]));
        }
        if let Some(nullable) = map.remove("nullable") {
            let nullable = nullable
                .as_bool()
                .ok_or_else(|| error(&format!("{path}.nullable"), "must be a boolean"))?;
            if nullable {
                let branch = Value::Object(std::mem::take(map));
                // Union the entire schema, including enum and other constraints.
                // Adding null to type alone would not make enum schemas nullable.
                map.insert("anyOf".into(), json!([branch, {"type": "null"}]));
            }
        }
        if mode == SchemaMode::Compatible {
            // Common malformed per-property boolean required convention.
            let mut promoted = Vec::new();
            if let Some(properties) = map.get_mut("properties").and_then(Value::as_object_mut) {
                for (name, child) in properties {
                    if let Some(child) = child.as_object_mut() {
                        if child.get("required").is_some_and(Value::is_boolean)
                            && child.remove("required") == Some(json!(true))
                        {
                            promoted.push(json!(name));
                        }
                    }
                }
            }
            if !promoted.is_empty() {
                let required = map.entry("required").or_insert_with(|| json!([]));
                if let Some(required) = required.as_array_mut() {
                    required.extend(promoted);
                }
            }
        }
        Ok(())
    })?;
    Ok(out)
}

fn normalize_type(kind: &mut String) {
    let normalized = match kind.to_ascii_lowercase().as_str() {
        "int" | "int32" | "int64" | "uint32" | "uint64" | "sint32" | "sint64" | "fixed32"
        | "fixed64" => "integer",
        "float" | "double" => "number",
        "bool" => "boolean",
        "str" => "string",
        "object" => "object",
        "array" => "array",
        "string" => "string",
        "number" => "number",
        "integer" => "integer",
        "boolean" => "boolean",
        "null" => "null",
        _ => return,
    };
    *kind = normalized.into();
}

fn inline(
    node: &Value,
    root: &Value,
    mode: SchemaMode,
    path: &str,
    depth: usize,
    nodes: &mut usize,
    active: &mut Vec<String>,
) -> Result<Value, SchemaError> {
    walk::limit(path, depth, nodes)?;
    let mut out = node.clone();
    if let Some(map) = out.as_object_mut() {
        if depth > 0 && map.contains_key("$id") {
            return Err(error(path, "nested $id scope cannot be inlined safely"));
        }
        map.remove("$defs");
        map.remove("definitions");
        if let Some(reference) = map.remove("$ref") {
            let reference = reference
                .as_str()
                .ok_or_else(|| error(&format!("{path}.$ref"), "must be a string"))?;
            if !reference.starts_with("#/") && reference != "#" {
                return Err(error(
                    path,
                    "only root-local JSON pointer references can be inlined",
                ));
            }
            if active.iter().any(|r| r == reference) {
                return match mode {
                    SchemaMode::Strict => {
                        Err(error(path, "recursive $ref cannot be inlined losslessly"))
                    }
                    SchemaMode::Compatible => Ok(json!({})),
                };
            }
            let target = root
                .pointer(&reference[1..])
                .ok_or_else(|| error(path, format!("unresolved $ref '{reference}'")))?;
            active.push(reference.into());
            let target = inline(target, root, mode, path, depth + 1, nodes, active)?;
            active.pop();
            let siblings = Value::Object(std::mem::take(map));
            out = if siblings.as_object().unwrap().is_empty() {
                target
            } else {
                json!({"allOf": [target, siblings]})
            };
        }
    }
    walk::children(&mut out, path, |child, path| {
        *child = inline(child, root, mode, path, depth + 1, nodes, active)?;
        Ok(())
    })?;
    Ok(out)
}

/// Conservative conjunctive merge. Never overwrite contradictory validation.
pub(super) fn merge(
    target: &mut Map<String, Value>,
    incoming: Map<String, Value>,
    path: &str,
) -> Result<(), SchemaError> {
    // A closed object's properties are scoped to that branch, not the union of
    // allOf property maps. Merging them would silently permit forbidden fields.
    for (closed, other) in [(&*target, &incoming), (&incoming, &*target)] {
        if closed
            .get("additionalProperties")
            .is_some_and(|v| v != &json!(true))
            && other.get("properties").is_some()
            && closed.get("properties") != other.get("properties")
        {
            return Err(error(
                path,
                "conflicting allOf closed-object constraints cannot be represented safely",
            ));
        }
    }
    for (key, value) in incoming {
        match (key.as_str(), target.get_mut(&key)) {
            ("properties", Some(Value::Object(destination))) => {
                let source = value
                    .as_object()
                    .ok_or_else(|| error(path, "properties must be an object"))?;
                for (name, schema) in source {
                    if destination
                        .get(name)
                        .is_some_and(|previous| previous != schema)
                    {
                        return Err(error(
                            &format!("{path}.properties.{name}"),
                            "conflicting allOf schemas cannot be represented safely",
                        ));
                    }
                    destination.insert(name.clone(), schema.clone());
                }
            }
            ("required", Some(Value::Array(destination))) => {
                let source = value
                    .as_array()
                    .ok_or_else(|| error(path, "required must be an array"))?;
                for item in source {
                    if !destination.contains(item) {
                        destination.push(item.clone());
                    }
                }
            }
            ("title" | "description", Some(_)) => {}
            (_, Some(previous)) if previous != &value => {
                return Err(error(
                    &format!("{path}.{key}"),
                    "conflicting allOf constraints cannot be represented safely",
                ))
            }
            (_, Some(_)) => {}
            _ => {
                target.insert(key, value);
            }
        }
    }
    Ok(())
}
