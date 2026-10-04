use super::{error, profiles::feature, walk, SchemaError, SchemaProfile};
use serde_json::{Map, Value};

pub(super) fn node(
    map: &Map<String, Value>,
    path: &str,
    repaired: bool,
) -> Result<(), SchemaError> {
    for (key, value) in map {
        let path = format!("{path}.{key}");
        let valid = match key.as_str() {
            "type" => match value {
                Value::String(kind) => valid_type(kind),
                Value::Array(types) => {
                    !types.is_empty() && types.iter().all(|v| v.as_str().is_some_and(valid_type))
                }
                _ => false,
            },
            "title" | "description" | "pattern" | "format" | "$schema" | "$id" | "$anchor"
            | "$comment" | "$ref" | "contentMediaType" | "contentEncoding" => value.is_string(),
            "minimum" | "maximum" => number_or_numeric_string(value),
            "exclusiveMinimum" | "exclusiveMaximum" => {
                number_or_numeric_string(value) || value.is_boolean()
            }
            "multipleOf" => numeric_value(value).is_some_and(|v| v > 0.0),
            "minLength" | "maxLength" | "minItems" | "maxItems" | "minProperties"
            | "maxProperties" | "minContains" | "maxContains" => unsigned_integer(value),
            "enum" => value.as_array().is_some_and(|v| !v.is_empty()),
            "const" => true,
            "nullable" => value.is_boolean(),
            "allOf" | "anyOf" | "oneOf" => value.as_array().is_some_and(|v| !v.is_empty()),
            "prefixItems" => value.is_array(),
            "properties" | "patternProperties" | "$defs" | "definitions" | "dependentSchemas"
            | "dependencies" | "dependentRequired" => value.is_object(),
            "required" if !repaired => true, // repaired according to policy later
            "required" | "propertyOrdering" => strings(value),
            "items" => value.is_object() || value.is_boolean() || value.is_array(),
            "additionalProperties"
            | "additionalItems"
            | "not"
            | "if"
            | "then"
            | "else"
            | "propertyNames"
            | "contains"
            | "unevaluatedProperties"
            | "unevaluatedItems"
            | "contentSchema" => value.is_object() || value.is_boolean(),
            "uniqueItems" | "deprecated" | "readOnly" | "writeOnly" | "strict" | "encrypted" => {
                value.is_boolean()
            }
            "default" | "example" => true,
            "examples" => value.is_array(),
            other => {
                return Err(error(
                    &path,
                    format!("unknown JSON Schema keyword '{other}'"),
                ))
            }
        };
        if !valid {
            let message = if matches!(key.as_str(), "pattern" | "title" | "description" | "$ref") {
                "must be a string"
            } else {
                "invalid keyword value"
            };
            return Err(error(&path, message));
        }
        if key == "dependentRequired" || key == "dependencies" {
            for (name, dependency) in value.as_object().unwrap() {
                if (key == "dependentRequired" || dependency.is_array()) && !strings(dependency) {
                    return Err(error(
                        &format!("{path}.{name}"),
                        "must be an array of strings",
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn validate_source(schema: &Value) -> Result<(), SchemaError> {
    let mut checked = schema.clone();
    walk::postorder(&mut checked, "$", 0, &mut 0, &mut |schema_node, path| {
        if let Some(map) = schema_node.as_object() {
            node(map, path, false)
        } else if schema_node.is_boolean() {
            Ok(())
        } else {
            Err(error(path, "schema nodes must be JSON objects or booleans"))
        }
    })
}

pub(super) fn validate(schema: &Value, profile: SchemaProfile) -> Result<(), SchemaError> {
    let mut checked = schema.clone();
    walk::postorder(&mut checked, "$", 0, &mut 0, &mut |node_value, path| {
        let Some(map) = node_value.as_object() else {
            if node_value.is_boolean() && !profile.needs_structure() {
                return Ok(());
            }
            return Err(error(path, "schema nodes must be JSON objects"));
        };
        node(map, path, true)?;
        for key in map.keys() {
            if feature(key).is_some_and(|feature| !profile.policy().supports(feature)) {
                return Err(error(
                    &format!("{path}.{key}"),
                    "unsupported keyword survived translation",
                ));
            }
        }
        if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
            if (!reference.starts_with("#/") && reference != "#")
                || schema.pointer(&reference[1..]).is_none()
            {
                return Err(error(
                    &format!("{path}.$ref"),
                    "unresolved or non-local reference",
                ));
            }
            if !schema
                .pointer(&reference[1..])
                .is_some_and(|v| v.is_object() || v.is_boolean())
            {
                return Err(error(
                    &format!("{path}.$ref"),
                    "reference target must be a schema",
                ));
            }
        }
        if profile.needs_structure() {
            if map.get("type") == Some(&Value::String("array".into())) && !map.contains_key("items")
            {
                return Err(error(path, "array must have items"));
            }
            if map.get("type") == Some(&Value::String("object".into()))
                && !map
                    .get("properties")
                    .and_then(Value::as_object)
                    .is_some_and(|p| !p.is_empty())
            {
                return Err(error(path, "object must have nonempty properties"));
            }
        }
        Ok(())
    })
}

fn number_or_numeric_string(value: &Value) -> bool {
    value.is_number()
        || value.as_str().is_some_and(|value| {
            serde_json::from_str::<Value>(value)
                .ok()
                .is_some_and(|value| value.is_number())
        })
}

fn unsigned_integer(value: &Value) -> bool {
    value.as_u64().is_some()
        || value
            .as_str()
            .and_then(|value| serde_json::from_str::<Value>(value).ok())
            .is_some_and(|value| value.as_u64().is_some())
}

fn numeric_value(value: &Value) -> Option<f64> {
    value.as_f64().or_else(|| {
        value
            .as_str()
            .and_then(|value| serde_json::from_str::<Value>(value).ok())
            .and_then(|value| value.as_f64())
    })
}

fn valid_type(kind: &str) -> bool {
    matches!(
        kind.to_ascii_lowercase().as_str(),
        "object"
            | "array"
            | "string"
            | "str"
            | "number"
            | "float"
            | "double"
            | "integer"
            | "int"
            | "int32"
            | "int64"
            | "uint32"
            | "uint64"
            | "sint32"
            | "sint64"
            | "fixed32"
            | "fixed64"
            | "boolean"
            | "bool"
            | "null"
    )
}
fn strings(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|values| values.iter().all(Value::is_string))
}
