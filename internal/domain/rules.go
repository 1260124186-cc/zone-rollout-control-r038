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

func ProbeRequestLedgerKey(input ProbeInput) string {
	return input.RequestKey
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

func EnsureProbeRequestLedger(state *State) {
	if state == nil {
		return
	}
	if state.ProbeRequestLedger == nil {
		state.ProbeRequestLedger = make(map[string]ProbeRequestEntry)
	}

	claims := make(map[string]struct{})
	for requestKey, entry := range state.ProbeRequestLedger {
		entry.RequestKey = requestKey
		for index := range entry.Claims {
			claim := entry.Claims[index]
			if claim.LeaseID == "" {
				claim.LeaseID = claim.Probe.LeaseID
			}
			if claim.PlanID == "" {
				claim.PlanID = claim.Probe.PlanID
			}
			if claim.NodeID == "" {
				claim.NodeID = claim.Probe.NodeID
			}
			if claim.Probe.RequestKey == "" {
				claim.Probe.RequestKey = requestKey
			}
			entry.Claims[index] = claim
			claims[probeClaimKey(claim.LeaseID, claim.Probe.ID)] = struct{}{}
		}
		if entry.PrimaryProbeID != "" {
			primary, ok := state.Probes[entry.PrimaryProbeID]
			if ok {
				claimKey := probeClaimKey(primary.LeaseID, primary.ID)
				if _, exists := claims[claimKey]; !exists {
					entry.Claims = append(entry.Claims, ProbeRequestClaim{
						LeaseID: primary.LeaseID,
						PlanID:  primary.PlanID,
						NodeID:  primary.NodeID,
						Probe:   primary,
					})
					claims[claimKey] = struct{}{}
				}
				if entry.ContentFingerprint == "" {
					entry.ContentFingerprint = ProbeContentFingerprintForProbe(primary)
				}
			}
		}
		state.ProbeRequestLedger[requestKey] = entry
	}

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
	for _, probe := range probes {
		requestKey := probe.RequestKey
		if requestKey == "" {
			continue
		}
		entry := state.ProbeRequestLedger[requestKey]
		entry.RequestKey = requestKey
		if entry.PrimaryProbeID == "" {
			entry.PrimaryProbeID = probe.ID
		}
		if entry.ContentFingerprint == "" {
			entry.ContentFingerprint = ProbeContentFingerprintForProbe(probe)
		}
		claimKey := probeClaimKey(probe.LeaseID, probe.ID)
		if _, exists := claims[claimKey]; !exists {
			entry.Claims = append(entry.Claims, ProbeRequestClaim{
				LeaseID: probe.LeaseID,
				PlanID:  probe.PlanID,
				NodeID:  probe.NodeID,
				Probe:   probe,
			})
			claims[claimKey] = struct{}{}
		}
		state.ProbeRequestLedger[requestKey] = entry
	}
}

func probeClaimKey(leaseID string, probeID string) string {
	return leaseID + "\x00" + probeID
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
