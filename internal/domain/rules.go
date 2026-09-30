package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"time"
)

func ActivatePlan(plan *RolloutPlan, now time.Time) error {
	if plan.State != PlanDraft {
		return InvalidState("plan can be activated only from draft", map[string]any{
			"plan_id": plan.ID,
			"state":   plan.State,
		})
	}
	if plan.LatestRevisionID == "" {
		return InvalidState("plan needs a zone revision before activation", map[string]any{
			"plan_id": plan.ID,
		})
	}
	plan.State = PlanActive
	plan.ActivatedAt = timePointer(now.UTC())
	plan.Version++
	return nil
}

func CompletePlan(plan *RolloutPlan, now time.Time) error {
	if plan.State != PlanActive {
		return InvalidState("plan can be completed only from active", map[string]any{
			"plan_id": plan.ID,
			"state":   plan.State,
		})
	}
	plan.State = PlanCompleted
	plan.CompletedAt = timePointer(now.UTC())
	plan.Version++
	return nil
}

func LeaseFingerprint(planID string, input LeaseInput) string {
	payload := fmt.Sprintf(
		"%s|%s|%s|%d|%d",
		planID,
		input.RequestKey,
		input.Region,
		input.LeaseSeconds,
		input.MaxNodes,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func ProbeFingerprint(leaseID string, input ProbeInput) string {
	payload := fmt.Sprintf(
		"%s|%s|%t|%d|%d|%s",
		leaseID,
		input.RequestKey,
		input.Success,
		input.ObservedSerial,
		input.LatencyMS,
		input.ObservedAt.UTC().Format(time.RFC3339Nano),
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// ProbeRequestLedgerKey returns the idempotency ledger key for a probe
// request. The key is scoped to the lease so that a request key only denotes
// a retry within the same lease: different leases keep independent ledger
// entries even when they reuse the same request key.
func ProbeRequestLedgerKey(leaseID string, input ProbeInput) string {
	return leaseID + "\x00" + input.RequestKey
}

func ProbeContentFingerprint(input ProbeInput) string {
	return probeContentFingerprint(
		input.Success,
		input.ObservedSerial,
		input.LatencyMS,
		input.ObservedAt,
	)
}

func ProbeContentFingerprintForProbe(probe Probe) string {
	return probeContentFingerprint(
		probe.Success,
		probe.ObservedSerial,
		probe.LatencyMS,
		probe.ObservedAt,
	)
}

func probeContentFingerprint(
	success bool,
	observedSerial uint32,
	latencyMS int,
	observedAt time.Time,
) string {
	payload := fmt.Sprintf(
		"%t|%d|%d|%s",
		success,
		observedSerial,
		latencyMS,
		observedAt.UTC().Format(time.RFC3339Nano),
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// EnsureProbeRequestLedger rebuilds the probe request ledger from the probe
// and lease facts. It is idempotent and runs on every state load so that
// snapshots written by older builds are repaired:
//
//   - shadow probes that were accepted against a lease but only persisted as
//     ledger claims are promoted to first-class probes;
//   - reported leases bound to another lease's probe are repointed to the
//     probe that actually belongs to them;
//   - the ledger is re-scoped by lease and request key so every observation
//     has exactly one authoritative entry.
func EnsureProbeRequestLedger(state *State) {
	if state == nil {
		return
	}
	if state.ProbeRequestLedger == nil {
		state.ProbeRequestLedger = make(map[string]ProbeRequestEntry)
	}

	// Promote shadow probes: older builds appended a full probe to a ledger
	// claim when a second lease reused a request key, but never stored it in
	// the probe set. The lease was reported and the node released, so the
	// observation is an accepted fact and must live with the other probes.
	for _, entry := range state.ProbeRequestLedger {
		for _, claim := range entry.Claims {
			probe := claim.Probe
			if probe.ID == "" {
				continue
			}
			if _, exists := state.Probes[probe.ID]; exists {
				continue
			}
			if lease, ok := state.Leases[probe.LeaseID]; ok {
				if probe.PlanID == "" {
					probe.PlanID = lease.PlanID
				}
				if probe.NodeID == "" {
					probe.NodeID = lease.NodeID
				}
			}
			if probe.RequestKey == "" {
				probe.RequestKey = entry.RequestKey
			}
			state.Probes[probe.ID] = probe
		}
	}

	// Repair lease bindings: a reported lease must reference a probe that
	// belongs to that lease. Repoint dangling or cross-lease bindings to the
	// earliest probe stored for the lease, and clear bindings that cannot be
	// resolved so a lease never points at another lease's result.
	probesByLease := make(map[string][]Probe)
	for _, probe := range state.Probes {
		probesByLease[probe.LeaseID] = append(probesByLease[probe.LeaseID], probe)
	}
	for leaseID, lease := range state.Leases {
		if lease.State != LeaseReported {
			continue
		}
		own := probesByLease[leaseID]
		sort.Slice(own, func(i, j int) bool {
			if !own[i].StoredAt.Equal(own[j].StoredAt) {
				return own[i].StoredAt.Before(own[j].StoredAt)
			}
			return own[i].ID < own[j].ID
		})
		if lease.ProbeID != "" {
			probe, ok := state.Probes[lease.ProbeID]
			if ok && probe.LeaseID == leaseID {
				continue
			}
		}
		if len(own) > 0 {
			lease.ProbeID = own[0].ID
		} else {
			lease.ProbeID = ""
		}
		state.Leases[leaseID] = lease
	}

	// Rebuild the ledger from the sorted probe facts. Sorting by stored time
	// then id makes the earliest probe for each (lease, request key) the
	// primary, matching the replay semantics for new submissions.
	probes := make([]Probe, 0, len(state.Probes))
	for _, probe := range state.Probes {
		probes = append(probes, probe)
	}
	sort.Slice(probes, func(i, j int) bool {
		if !probes[i].StoredAt.Equal(probes[j].StoredAt) {
			return probes[i].StoredAt.Before(probes[j].StoredAt)
		}
		return probes[i].ID < probes[j].ID
	})

	ledger := make(map[string]ProbeRequestEntry)
	for _, probe := range probes {
		if probe.RequestKey == "" {
			continue
		}
		key := ProbeRequestLedgerKey(probe.LeaseID, ProbeInput{RequestKey: probe.RequestKey})
		entry := ledger[key]
		entry.RequestKey = probe.RequestKey
		if entry.PrimaryProbeID == "" {
			entry.PrimaryProbeID = probe.ID
			entry.ContentFingerprint = ProbeContentFingerprintForProbe(probe)
		}
		entry.Claims = append(entry.Claims, ProbeRequestClaim{
			LeaseID: probe.LeaseID,
			PlanID:  probe.PlanID,
			NodeID:  probe.NodeID,
			Probe:   probe,
		})
		ledger[key] = entry
	}
	state.ProbeRequestLedger = ledger
}

func BuildAssessment(
	id string,
	plan RolloutPlan,
	revision ZoneRevision,
	probes []Probe,
	now time.Time,
) RolloutAssessment {
	reasons := make(map[string]struct{})
	if len(probes) == 0 {
		reasons["no_probes"] = struct{}{}
	}
	probeCount := len(probes)
	successCount := 0
	maximumLatency := 0
	nodes := make(map[string]struct{})
	for _, probe := range probes {
		nodes[probe.NodeID] = struct{}{}
		if probe.LatencyMS > maximumLatency {
			maximumLatency = probe.LatencyMS
		}
		if probe.Success {
			successCount++
			if probe.ObservedSerial != revision.Serial {
				reasons["serial_mismatch"] = struct{}{}
			}
		}
	}
	if len(nodes) < plan.ExpectedNodes {
		reasons["node_not_observed"] = struct{}{}
	}
	successRatio := 0.0
	if probeCount > 0 {
		successRatio = round(float64(successCount)/float64(probeCount), 6)
	}
	if successRatio < plan.MinimumSuccessRatio {
		reasons["success_ratio_below_minimum"] = struct{}{}
	}
	if maximumLatency > plan.MaximumLatencyMS {
		reasons["latency_limit_exceeded"] = struct{}{}
	}
	reasonList := make([]string, 0, len(reasons))
	for reason := range reasons {
		reasonList = append(reasonList, reason)
	}
	sort.Strings(reasonList)
	verdict := VerdictConsistent
	if len(reasonList) > 0 {
		verdict = VerdictReviewRequired
	}
	return RolloutAssessment{
		ID:               id,
		PlanID:           plan.ID,
		RevisionID:       revision.ID,
		Verdict:          verdict,
		Reasons:          reasonList,
		ProbeCount:       probeCount,
		SuccessCount:     successCount,
		SuccessRatio:     successRatio,
		MaximumLatencyMS: maximumLatency,
		CreatedAt:        now.UTC(),
	}
}

func round(value float64, places int) float64 {
	scale := math.Pow10(places)
	return math.Round(value*scale) / scale
}

func timePointer(value time.Time) *time.Time {
	return &value
}
