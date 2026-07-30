# Recovery health and ELAN guardian

Recovery is a bounded health transition, not an endless reset loop.

elan-guardian remains responsible for evidence-driven, controller-specific
in-place recovery and rebind operations. Arach HWD passively observes its
kernel recovery generation, whether the driver is bound, and whether event
nodes returned. It does not read ELAN attributes that issue live SMBus
transactions.

Within the signed profile window:

- zero recoveries with a bound driver and event nodes is healthy;
- a successful recovery below the threshold is recovered;
- reaching the threshold is degraded and requires operator-visible telemetry;
- twice the threshold, a failed recovery, or a missing driver/event node at
  the threshold quarantines the profile for its declared interval.

Quarantine prevents a failing controller from cycling package activation or
resetting indefinitely. A later signed policy may request a different driver
or firmware transaction, but statistical ranking cannot override quarantine.
