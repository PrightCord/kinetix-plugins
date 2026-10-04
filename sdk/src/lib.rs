//! Kinetix plugin SDK.
//!
//! This crate is the author-facing side of the plugin ABI documented in
//! `docs/KINETIX-PLUGIN-ARCHITECTURE.md`. It generates the WIT bindings for the
//! `plugin` world, re-exports them, and provides small helpers for the parts of
//! a plugin that are boilerplate (reading host KV, publishing cached facts,
//! constructing `PluginError`s).
//!
//! A plugin crate depends on this SDK, implements the `Guest` traits for the
//! capabilities it declares, and calls [`export!`]:
//!
//! ```ignore
//! use kinetix_plugin_sdk::{exports, kinetix, export};
//! use kinetix::plugin::types::*;
//!
//! struct Component;
//! impl exports::credential_strategy::Guest for Component { /* ... */ }
//! export!(Component with_types_in kinetix_plugin_sdk);
//! ```
//!
//! The ABI is the WIT interface, not this crate: the SDK only removes
//! boilerplate and never changes what the host enforces.

pub mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "plugin",
        pub_export_macro: true,
    });
}

/// Bindings for the optional browser/account authorization world.
pub mod auth {
    wit_bindgen::generate!({
        path: "wit",
        world: "plugin-auth",
        pub_export_macro: true,
    });
}

/// Bindings for the optional account-aware model discovery world.
pub mod model_source {
    wit_bindgen::generate!({
        path: "wit",
        world: "plugin-model-source",
        pub_export_macro: true,
    });
}

/// Bindings for structured quota observations. This opt-in v2 world leaves the
/// legacy health probe in `plugin` unchanged for existing components.
pub mod health {
    wit_bindgen::generate!({
        path: "wit",
        world: "plugin-health-v2",
        pub_export_macro: true,
    });
}

/// Bindings for the `plugin-adapter` world (§6.3). A component that provides a
/// `provider-adapter` capability implements `adapter::exports::provider_adapter::Guest`
/// and invokes `adapter::export!(Component with_types_in kinetix_plugin_sdk::adapter)`.
pub mod adapter {
    wit_bindgen::generate!({
        path: "wit",
        world: "plugin-adapter",
        pub_export_macro: true,
    });
}

/// Bindings for the legacy session-aware API v2 adapter world, which retains
/// its API v1 host imports for compatibility.
pub mod adapter_v2 {
    wit_bindgen::generate!({
        path: "wit-v2",
        world: "plugin-adapter-v2",
        pub_export_macro: true,
        generate_all,
    });
}

/// Bindings for the import-free, session-aware API v3 adapter world.
pub mod adapter_v3 {
    wit_bindgen::generate!({
        path: "wit-v3",
        world: "plugin-adapter-v3",
        pub_export_macro: true,
        generate_all,
    });
}

pub use bindings::export;
pub use bindings::{exports, kinetix};

pub mod prelude {
    pub use crate::bindings::{exports, kinetix};
    pub use crate::export;
    pub use crate::helpers::*;
    pub use crate::integration_capabilities::*;
    pub use crate::model_capabilities::*;
}

pub mod helpers;
pub mod integration_capabilities;
pub mod model_capabilities;
pub mod oauth;
pub mod schema;
pub mod tool_names;
