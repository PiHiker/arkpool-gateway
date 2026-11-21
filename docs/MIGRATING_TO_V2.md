# Migrating an existing gateway to Stratum V2

Use this checklist with the exact build and instructions for your platform:
[Docker native V2](NATIVE_V2.md), [V1 translation](V1_TO_V2.md),
[StartOS](https://gitlab.com/arkpool/arkpool-gateway-startos), or
[Umbrel](https://gitlab.com/arkpool/arkpool-gateway-umbrel).
A source commit, published image and installed package are separate states.
Check the package qualification record before treating a candidate as released.

1. **Record and back up the working setup.** Save exact image revisions, miner
   settings, payout identities, client access policy, credentials, certificates
   and Tor state privately. Check free disk space and verify the backup before
   changing services. Preserve intentional solo-mining assignments.
2. **Choose the miner connection.** A native V2 miner uses the package's native
   V2 listener and requires the independently verified pool Noise authority key.
   A V1 miner can keep its firmware but requires a translator-enabled gateway
   build and the exact owner Ark identity. The base image alone lacks the
   translator binary. Do not confuse the miner listener port with the pool port.
3. **Prepare the gateway separately.** Configure the verified V2 receiver and
   authority key, preserve exact payout identities and private client policy,
   and retain both Tor state volumes. Confirm authentication, readiness, LAN
   reachability and dashboard access before moving a miner. Do not use the
   legacy V1 Umbrel generators to recreate a V2 installation.
4. **Move one approved miner.** Preserve tuning and recovery settings. Follow
   its firmware's documented pool-selection and restart procedure; do not hot
   edit an active pool when the firmware cannot safely reload it. Keep other
   miners on their working paths until this one is verified.
5. **Verify both hops and real work.** The dashboard should distinguish
   miner-to-gateway V1 or V2 from gateway-to-ArkPool V2. Confirm fresh jobs,
   hashrate and a new pool-accepted share. Native encrypted traffic requires
   miner or receiver evidence; a relay connection alone proves neither shares
   nor authentication. Accepted shares do not prove payment.
6. **Check recovery and persist the configuration.** Reconnects must retain
   the verified authority and V2-only gateway upstream. Do not silently restore
   V1 upstream on failure. A miner's separately chosen solo/DATUM backup is an
   independent policy; preserve it unless its owner requests a change. Document
   outstanding reconnect, backup/restore and platform qualification checks.

On failure, stop the affected migration and diagnose from bounded logs. Keep
unaffected mining running. A code rollback does not authorize a protocol
downgrade, replacement payout identity, cleared Tor state or deleted wallet.
