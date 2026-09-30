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

// ProbeRequestLedgerKey scopes a submitted request key to the lease it is
// being submitted to. The same request key on a different lease produces a
// distinct idempotency bucket.
func ProbeRequestLedgerKey(leaseID string, input ProbeInput) string {
	return ProbeLedgerKey(leaseID, input.RequestKey)
}

// ProbeLedgerKey identifies the idempotency bucket for a single lease.
func ProbeLedgerKey(leaseID string, requestKey string) string {
	return leaseID + "\x00" + requestKey
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

// EnsureProbeRequestLedger recovers probe-to-lease bindings from facts after
// an upgrade or restart.
//
// Historically the probe retry ledger was keyed only by request key. Two
// leases reusing the same key could end up sharing an entry: the later lease
// was marked reported with ProbeID pointing at the first lease's probe while
// its own observation was parked as a ledger claim and absent from Probes.
//
// Reconciliation makes the stored facts authoritative:
//
//  1. Every shadow probe parked in legacy ledger claims is promoted into
//     State.Probes (filling in missing lease/plan/node identity first).
//  2. Each reported lease is rebound to a probe that actually belongs to it;
//     a lease whose probe belongs to another lease loses the foreign binding.
//  3. The ledger is rebuilt as strictly per-(lease, request key) entries from
//     the probes themselves, so a retry key can only ever denote a retry
//     inside its own lease.
//
// The function is idempotent and deterministic.
func EnsureProbeRequestLedger(state *State) {
	if state == nil {
		return
	}
	if state.ProbeRequestLedger == nil {
		state.ProbeRequestLedger = make(map[string]ProbeRequestEntry)
	}
	if state.Probes == nil {
		state.Probes = make(map[string]Probe)
	}

	promoteLegacyClaimProbes(state)
	repairLeaseProbeBindings(state)
	rebuildProbeLedger(state)
}

// promoteLegacyClaimProbes moves probes that were stored only inside global
// ledger claims into State.Probes so no real observation is hidden from lease
// state or from consistency assessment.
func promoteLegacyClaimProbes(state *State) {
	for _, entry := range state.ProbeRequestLedger {
		for _, claim := range entry.Claims {
			probe := claim.Probe
			if probe.ID == "" {
				continue
			}
			if probe.LeaseID == "" {
				probe.LeaseID = claim.LeaseID
			}
			if probe.PlanID == "" {
				probe.PlanID = claim.PlanID
				if lease, ok := state.Leases[probe.LeaseID]; ok {
					probe.PlanID = lease.PlanID
				}
			}
			if probe.NodeID == "" {
				probe.NodeID = claim.NodeID
				if lease, ok := state.Leases[probe.LeaseID]; ok {
					probe.NodeID = lease.NodeID
				}
			}
			if probe.RequestKey == "" {
				probe.RequestKey = entry.RequestKey
			}
			existing, exists := state.Probes[probe.ID]
			if !exists {
				state.Probes[probe.ID] = probe
				continue
			}
			if existing.LeaseID == "" && probe.LeaseID != "" {
				existing.LeaseID = probe.LeaseID
			}
			if existing.PlanID == "" && probe.PlanID != "" {
				existing.PlanID = probe.PlanID
			}
			if existing.NodeID == "" && probe.NodeID != "" {
				existing.NodeID = probe.NodeID
			}
			if existing.RequestKey == "" && probe.RequestKey != "" {
				existing.RequestKey = probe.RequestKey
			}
			state.Probes[probe.ID] = existing
		}
	}
}

// repairLeaseProbeBindings ensures every lease points at a probe that
// genuinely belongs to it. Leases that were bound to another lease's probe
// are rebound to their own promoted probe; leases with no surviving
// observation fall back to claimed and their node is marked leased again.
func repairLeaseProbeBindings(state *State) {
	probesByLease := make(map[string][]Probe)
	for _, probe := range state.Probes {
		probesByLease[probe.LeaseID] = append(probesByLease[probe.LeaseID], probe)
	}
	for leaseID := range probesByLease {
		sort.Slice(probesByLease[leaseID], func(i, j int) bool {
			left, right := probesByLease[leaseID][i], probesByLease[leaseID][j]
			if !left.StoredAt.Equal(right.StoredAt) {
				return left.StoredAt.Before(right.StoredAt)
			}
			return left.ID < right.ID
		})
	}

	for leaseID, lease := range state.Leases {
		if own := probesByLease[leaseID]; len(own) > 0 {
			ownProbe := own[0]
			if lease.ProbeID != ownProbe.ID || lease.State != LeaseReported {
				lease.ProbeID = ownProbe.ID
				lease.State = LeaseReported
				finishedAt := ownProbe.StoredAt.UTC()
				lease.FinishedAt = &finishedAt
				state.Leases[leaseID] = lease
			}
			continue
		}

		// No probe belongs to this lease. A ProbeID pointing at a probe owned
		// by another lease is the legacy misbinding: clear it and reopen the
		// lease so its node can be observed for real.
		if lease.ProbeID != "" {
			if primary, ok := state.Probes[lease.ProbeID]; !ok || primary.LeaseID != leaseID {
				lease.ProbeID = ""
				lease.FinishedAt = nil
				lease.State = LeaseClaimed
				state.Leases[leaseID] = lease
				reopenNodeForLease(state, lease)
			}
		}
	}
}

// reopenNodeForLease marks the node backing a reopened lease as leased again
// unless the node already has another active (claimed) lease, in which case it
// must stay tied to that lease.
func reopenNodeForLease(state *State, lease NodeLease) {
	node, ok := state.Nodes[lease.NodeID]
	if !ok {
		return
	}
	for otherID, other := range state.Leases {
		if otherID == lease.ID || other.NodeID != lease.NodeID {
			continue
		}
		if other.State == LeaseClaimed {
			return
		}
	}
	if node.State == NodeReady {
		node.State = NodeLeased
		node.Version++
		node.UpdatedAt = lease.ClaimedAt.UTC()
		state.Nodes[node.ID] = node
	}
}

// rebuildProbeLedger derives the per-(lease, request key) ledger solely from
// the probes, dropping any global legacy interpretation.
func rebuildProbeLedger(state *State) {
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
		key := ProbeLedgerKey(probe.LeaseID, probe.RequestKey)
		if _, exists := ledger[key]; exists {
			continue
		}
		ledger[key] = ProbeRequestEntry{
			RequestKey:         probe.RequestKey,
			ContentFingerprint: ProbeContentFingerprintForProbe(probe),
			PrimaryProbeID:     probe.ID,
		}
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
