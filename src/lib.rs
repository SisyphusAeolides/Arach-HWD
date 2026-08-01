//! Signed hardware resolution and provisioning plans for Arach OS.

pub mod catalog;
pub mod facts;
pub mod health;
pub mod plan;
pub mod preflight;
pub mod profile;
pub mod repository;
pub mod scan;
pub mod signature;
pub mod sources;

pub use facts::{
    Bus, CapabilityRequirement, CpuArchitecture, CpuFacts, CpuFeature, HardwareCapability,
    HardwareDevice, Inventory, SystemFacts,
};
pub use health::{HealthEvidence, RecoveryDisposition, assess_recovery};
pub use plan::{CompilerTarget, ProvisionPlan, build_plan};
pub use preflight::{PREFLIGHT_SCHEMA, PreflightReport, UnresolvedDevice, preflight_inventory};
pub use profile::{HardwareProfile, ResolveError, VerifiedProfile, resolve};
pub use repository::{
    REPOSITORY_FORMAT, RepositoryError, RepositoryManifest, RepositoryObject, sync_catalog,
    sync_catalog_with_fetcher,
};
pub use scan::{
    default_firmware_roots, default_modules_alias, default_modules_aliases,
    default_modules_builtin_files, default_modules_dep_files, default_modules_firmware,
    default_modules_firmware_files, scan_inventory, scan_inventory_with_driver_metadata,
    scan_inventory_with_driver_sources, scan_inventory_with_modules_alias,
    scan_inventory_with_modules_metadata,
};
pub use sources::{
    DRIVER_SOURCE_SCHEMA, DriverAuthority, DriverSourceEvidence, DriverSourceKind,
    DriverSourceManifest,
};
