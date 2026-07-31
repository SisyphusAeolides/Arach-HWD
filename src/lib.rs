//! Signed hardware resolution and provisioning plans for Arach OS.

pub mod catalog;
pub mod facts;
pub mod health;
pub mod plan;
pub mod preflight;
pub mod profile;
pub mod scan;
pub mod signature;

pub use facts::{
    Bus, CapabilityRequirement, HardwareCapability, HardwareDevice, Inventory, SystemFacts,
};
pub use health::{HealthEvidence, RecoveryDisposition, assess_recovery};
pub use plan::{ProvisionPlan, build_plan};
pub use preflight::{PREFLIGHT_SCHEMA, PreflightReport, UnresolvedDevice, preflight_inventory};
pub use profile::{HardwareProfile, ResolveError, VerifiedProfile, resolve};
pub use scan::{
    default_modules_alias, default_modules_firmware, scan_inventory,
    scan_inventory_with_modules_alias, scan_inventory_with_modules_metadata,
};
