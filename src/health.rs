use crate::profile::RecoveryPolicy;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthEvidence {
    pub driver_bound: bool,
    pub event_nodes_present: bool,
    pub kernel_recoveries: u32,
    pub guardian_recoveries: u32,
    pub window_age_seconds: u64,
    pub last_recovery_succeeded: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryDisposition {
    Healthy,
    Recovered,
    Degraded,
    Quarantine,
}

pub fn assess_recovery(policy: RecoveryPolicy, evidence: HealthEvidence) -> RecoveryDisposition {
    let recoveries = if evidence.window_age_seconds <= policy.window_seconds {
        evidence
            .kernel_recoveries
            .saturating_add(evidence.guardian_recoveries)
    } else {
        0
    };
    if !evidence.driver_bound || !evidence.event_nodes_present || !evidence.last_recovery_succeeded
    {
        return if recoveries >= policy.max_recoveries {
            RecoveryDisposition::Quarantine
        } else {
            RecoveryDisposition::Degraded
        };
    }
    if recoveries == 0 {
        RecoveryDisposition::Healthy
    } else if recoveries < policy.max_recoveries {
        RecoveryDisposition::Recovered
    } else if recoveries < policy.max_recoveries.saturating_mul(2) {
        RecoveryDisposition::Degraded
    } else {
        RecoveryDisposition::Quarantine
    }
}

pub fn parse_elan_runtime_watchdog(value: &str) -> Option<u32> {
    value
        .split_ascii_whitespace()
        .find_map(|field| field.strip_prefix("recoveries="))?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RecoveryPolicy {
        RecoveryPolicy {
            max_recoveries: 3,
            window_seconds: 300,
            cooldown_seconds: 5,
            quarantine_seconds: 900,
        }
    }

    #[test]
    fn successful_guardian_recovery_keeps_device_available() {
        assert_eq!(
            assess_recovery(
                policy(),
                HealthEvidence {
                    driver_bound: true,
                    event_nodes_present: true,
                    kernel_recoveries: 1,
                    guardian_recoveries: 0,
                    window_age_seconds: 10,
                    last_recovery_succeeded: true,
                }
            ),
            RecoveryDisposition::Recovered
        );
    }

    #[test]
    fn repeated_recovery_does_not_loop_forever() {
        assert_eq!(
            assess_recovery(
                policy(),
                HealthEvidence {
                    driver_bound: true,
                    event_nodes_present: true,
                    kernel_recoveries: 3,
                    guardian_recoveries: 3,
                    window_age_seconds: 30,
                    last_recovery_succeeded: true,
                }
            ),
            RecoveryDisposition::Quarantine
        );
    }

    #[test]
    fn parses_kernel_watchdog_generation() {
        assert_eq!(
            parse_elan_runtime_watchdog("enabled=1 recoveries=4"),
            Some(4)
        );
    }
}
