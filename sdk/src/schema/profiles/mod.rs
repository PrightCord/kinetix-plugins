use super::SchemaProfile;

/// Features are grouped by semantics rather than a plugin-local keyword denylist.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Feature {
    StringBounds,
    ObjectBounds,
    ArrayBounds,
    ExclusiveBounds,
    MultipleOf,
    Format,
    PatternProperties,
    Tuple,
    Intersection,
    ExclusiveUnion,
    Reference,
    JsonApplicator,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum IntersectionPolicy {
    Preserve,
    MergeSafely,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum UnionPolicy {
    PreserveExclusive,
    WidenToAnyOf,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TuplePolicy {
    Preserve,
    NormalizeToHomogeneousItems,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ReferencePolicy {
    PreserveLocal,
    InlineRootLocal,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ObjectPolicy {
    JsonSchema,
    RequireDeclaredProperties,
}

#[derive(Clone, Copy)]
pub(super) struct ProfilePolicy {
    pub supported_features: &'static [Feature],
    pub compatible_drops: &'static [Feature],
    pub intersection: IntersectionPolicy,
    pub union: UnionPolicy,
    pub tuple: TuplePolicy,
    pub references: ReferencePolicy,
    pub objects: ObjectPolicy,
    pub coerce_numeric_strings: bool,
    pub normalize_type_aliases: bool,
    pub dropped_annotations: &'static [&'static str],
}

impl ProfilePolicy {
    pub(super) fn supports(self, feature: Feature) -> bool {
        self.supported_features.contains(&feature)
    }

    pub(super) fn may_drop(self, feature: Feature) -> bool {
        self.compatible_drops.contains(&feature)
    }
}

const STANDARD_FEATURES: &[Feature] = &[
    Feature::StringBounds,
    Feature::ObjectBounds,
    Feature::ArrayBounds,
    Feature::ExclusiveBounds,
    Feature::MultipleOf,
    Feature::Format,
    Feature::PatternProperties,
    Feature::Tuple,
    Feature::Intersection,
    Feature::ExclusiveUnion,
    Feature::Reference,
    Feature::JsonApplicator,
];

const ANTIGRAVITY_COMPATIBLE_DROPS: &[Feature] = &[
    Feature::StringBounds,
    Feature::ObjectBounds,
    Feature::ArrayBounds,
    Feature::ExclusiveBounds,
    Feature::MultipleOf,
    Feature::Format,
    Feature::PatternProperties,
    Feature::Tuple,
    Feature::Intersection,
    Feature::ExclusiveUnion,
    Feature::Reference,
    Feature::JsonApplicator,
];

const ANTIGRAVITY_DROPPED_ANNOTATIONS: &[&str] = &[
    "$schema",
    "$comment",
    "$id",
    "$anchor",
    "strict",
    "encrypted",
    "default",
    "examples",
    "example",
    "deprecated",
    "readOnly",
    "writeOnly",
];

const fn standard_policy() -> ProfilePolicy {
    ProfilePolicy {
        supported_features: STANDARD_FEATURES,
        compatible_drops: &[],
        intersection: IntersectionPolicy::Preserve,
        union: UnionPolicy::PreserveExclusive,
        tuple: TuplePolicy::Preserve,
        references: ReferencePolicy::PreserveLocal,
        objects: ObjectPolicy::JsonSchema,
        coerce_numeric_strings: true,
        normalize_type_aliases: true,
        dropped_annotations: &[],
    }
}

const ANTIGRAVITY: ProfilePolicy = ProfilePolicy {
    supported_features: &[],
    compatible_drops: ANTIGRAVITY_COMPATIBLE_DROPS,
    intersection: IntersectionPolicy::MergeSafely,
    union: UnionPolicy::WidenToAnyOf,
    tuple: TuplePolicy::NormalizeToHomogeneousItems,
    references: ReferencePolicy::InlineRootLocal,
    objects: ObjectPolicy::RequireDeclaredProperties,
    coerce_numeric_strings: true,
    normalize_type_aliases: true,
    dropped_annotations: ANTIGRAVITY_DROPPED_ANNOTATIONS,
};

const GEMINI: ProfilePolicy = standard_policy();
const OPENAI: ProfilePolicy = standard_policy();
const OPENAI_RESPONSES: ProfilePolicy = standard_policy();
const ANTHROPIC: ProfilePolicy = standard_policy();
const OPENAI_COMPATIBLE: ProfilePolicy = standard_policy();

impl SchemaProfile {
    pub(super) fn policy(self) -> &'static ProfilePolicy {
        match self {
            Self::Antigravity => &ANTIGRAVITY,
            Self::Gemini => &GEMINI,
            Self::OpenAI => &OPENAI,
            Self::OpenAIResponses => &OPENAI_RESPONSES,
            Self::Anthropic => &ANTHROPIC,
            Self::OpenAICompatible => &OPENAI_COMPATIBLE,
        }
    }

    pub(super) fn needs_structure(self) -> bool {
        self.policy().objects == ObjectPolicy::RequireDeclaredProperties
    }

    pub(super) fn inlines_local_refs(self) -> bool {
        self.policy().references == ReferencePolicy::InlineRootLocal
    }
}

pub(super) fn feature(keyword: &str) -> Option<Feature> {
    Some(match keyword {
        "minLength" | "maxLength" => Feature::StringBounds,
        "minProperties" | "maxProperties" => Feature::ObjectBounds,
        "minItems" | "maxItems" | "uniqueItems" => Feature::ArrayBounds,
        "exclusiveMinimum" | "exclusiveMaximum" => Feature::ExclusiveBounds,
        "multipleOf" => Feature::MultipleOf,
        "format" => Feature::Format,
        "patternProperties" => Feature::PatternProperties,
        "prefixItems" | "additionalItems" => Feature::Tuple,
        "allOf" => Feature::Intersection,
        "oneOf" => Feature::ExclusiveUnion,
        "$ref" | "$defs" | "definitions" => Feature::Reference,
        "not"
        | "if"
        | "then"
        | "else"
        | "propertyNames"
        | "contains"
        | "minContains"
        | "maxContains"
        | "unevaluatedItems"
        | "unevaluatedProperties"
        | "dependentSchemas"
        | "dependentRequired"
        | "dependencies" => Feature::JsonApplicator,
        _ => return None,
    })
}
