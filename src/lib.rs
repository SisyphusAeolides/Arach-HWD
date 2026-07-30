//! Signed hardware resolution and provisioning plans for Arach OS.

pub mod facts;
pub mod health;
pub mod plan;
pub mod profile;
pub mod scan;
pub mod signature;

pub use facts::{Bus, HardwareDevice, Inventory, SystemFacts};
pub use health::{HealthEvidence, RecoveryDisposition, assess_recovery};
pub use plan::{ProvisionPlan, build_plan};
pub use profile::{HardwareProfile, ResolveError, VerifiedProfile, resolve};
pub use scan::scan_inventory;
