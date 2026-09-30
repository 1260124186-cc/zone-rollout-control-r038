package workflowprobe

import (
	"fmt"
	"net/http"
	"time"

	"solo-0014-zone-rollout-control/internal/domain"
)

func runProbeIngestion() error {
	harness, err := newHarness()
	if err != nil {
		return err
	}
	defer harness.close()

	if _, err := enrollNode(harness, "resolver-probe-01", "central"); err != nil {
		return err
	}
	plan, revision, err := createActivePlan(harness, "probe.example", 2049, 1, 1, 50)
	if err != nil {
		return err
	}
	group, err := allocate(harness, plan.ID, "probe-lease-0001", "central", 1)
	if err != nil {
		return err
	}
	leaseID := group.LeaseIDs[0]
	first, err := submitProbe(harness, leaseID, "probe-request-0001", true, revision.Serial, 12)
	if err != nil {
		return err
	}
	if !first.Success || first.ObservedSerial != revision.Serial {
		return ensure(false, "probe values were not preserved")
	}
	replay, err := submitProbe(harness, leaseID, "probe-request-0001", true, revision.Serial, 12)
	if err != nil {
		return err
	}
	if replay.ID != first.ID {
		return ensure(false, "probe replay returned a different item")
	}
	_, err = submitProbe(harness, leaseID, "probe-request-0001", true, revision.Serial, 25)
	if err := expectFailure(err, http.StatusConflict, string(domain.CodeIdempotencyConflict)); err != nil {
		return err
	}
	err = harness.call(http.MethodPatch, "/v1/leases/"+leaseID+"/release", nil, nil)
	if err := expectFailure(err, http.StatusConflict, string(domain.CodeInvalidState)); err != nil {
		return err
	}

	if err := verifyCrossLeaseIsolation(); err != nil {
		return err
	}
	return verifyLegacyBindingRecovery()
}

// verifyCrossLeaseIsolation proves a retry key only denotes a retry within the
// same lease: two leases sharing the identical request key and payload each
// store and bind their own probe, survive a restart, and both feed the
// assessment.
func verifyCrossLeaseIsolation() error {
	harness, err := newHarness()
	if err != nil {
		return err
	}
	defer harness.close()

	if _, err := enrollNode(harness, "resolver-key-01", "central"); err != nil {
		return err
	}
	if _, err := enrollNode(harness, "resolver-key-02", "central"); err != nil {
		return err
	}
	plan, revision, err := createActivePlan(harness, "keys.example", 2101, 2, 1, 50)
	if err != nil {
		return err
	}
	group, err := allocate(harness, plan.ID, "key-lease-group-0001", "central", 2)
	if err != nil {
		return err
	}
	leaseA, leaseB := group.LeaseIDs[0], group.LeaseIDs[1]

	// Identical request key and identical payload on both leases.
	probeA, err := submitProbe(harness, leaseA, "shared-request-key", true, revision.Serial, 10)
	if err != nil {
		return err
	}
	probeB, err := submitProbe(harness, leaseB, "shared-request-key", true, revision.Serial, 10)
	if err != nil {
		return err
	}
	if probeA.ID == probeB.ID {
		return ensure(false, "second lease reused the first lease's probe")
	}
	if probeB.LeaseID != leaseB || probeB.NodeID == probeA.NodeID {
		return ensure(false, "second probe was not bound to its own lease and node")
	}

	// Replay on each lease still returns that lease's first probe.
	replayA, err := submitProbe(harness, leaseA, "shared-request-key", true, revision.Serial, 10)
	if err != nil {
		return err
	}
	replayB, err := submitProbe(harness, leaseB, "shared-request-key", true, revision.Serial, 10)
	if err != nil {
		return err
	}
	if replayA.ID != probeA.ID || replayB.ID != probeB.ID {
		return ensure(false, "replay did not resolve within the originating lease")
	}

	// Same key, different content is still a conflict within one lease.
	if _, err := submitProbe(harness, leaseA, "shared-request-key", true, revision.Serial, 40); err == nil {
		return ensure(false, "same key with different content on a lease was accepted")
	}

	// Both observations must survive a real restart.
	if err := harness.restart(); err != nil {
		return err
	}
	replayA, err = submitProbe(harness, leaseA, "shared-request-key", true, revision.Serial, 10)
	if err != nil {
		return err
	}
	replayB, err = submitProbe(harness, leaseB, "shared-request-key", true, revision.Serial, 10)
	if err != nil {
		return err
	}
	if replayA.ID != probeA.ID || replayB.ID != probeB.ID {
		return ensure(false, "per-lease retry bindings did not survive restart")
	}

	var assessment domain.RolloutAssessment
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "key-assessment-0001",
	}, &assessment); err != nil {
		return err
	}
	if assessment.Verdict != domain.VerdictConsistent || assessment.ProbeCount != 2 {
		return ensure(false, fmt.Sprintf("assessment missed the second lease observation: %+v", assessment))
	}
	return nil
}

// verifyLegacyBindingRecovery boots a snapshot written by the old global-key
// implementation and proves the misbinding is healed from probe and lease
// facts: shadow claims are promoted, foreign lease bindings are rebound, the
// lease with no observation reopens, and the recovered observations drive the
// assessment consistently.
func verifyLegacyBindingRecovery() error {
	now := time.Date(2026, time.September, 25, 12, 0, 0, 0, time.UTC)
	observed := now.Add(-1 * time.Minute)

	node1 := domain.ResolverNode{ID: "ndr-legacy-01", NodeName: "resolver-legacy-01", Region: "central", State: domain.NodeReady, Version: 2, CreatedAt: now, UpdatedAt: now}
	node2 := domain.ResolverNode{ID: "ndr-legacy-02", NodeName: "resolver-legacy-02", Region: "central", State: domain.NodeReady, Version: 2, CreatedAt: now, UpdatedAt: now}
	node3 := domain.ResolverNode{ID: "ndr-legacy-03", NodeName: "resolver-legacy-03", Region: "central", State: domain.NodeReady, Version: 1, CreatedAt: now, UpdatedAt: now}

	plan := domain.RolloutPlan{
		ID: "pln-legacy-01", Zone: "legacy.example", State: domain.PlanActive,
		MinimumSuccessRatio: 1, MaximumLatencyMS: 50, ExpectedNodes: 3,
		Version: 2, LatestRevisionID: "rev-legacy-01", CreatedAt: now, ActivatedAt: &now,
	}
	revision := domain.ZoneRevision{
		ID: "rev-legacy-01", PlanID: plan.ID, Serial: 3101, Authority: "ns1.legacy.example",
		Entries: []domain.ZoneEntry{
			{Owner: "legacy.example", Type: domain.EntryA, Value: "192.0.2.31"},
		},
		EntryCount: 1, CreatedAt: now,
	}

	lease1 := domain.NodeLease{ID: "lse-legacy-01", PlanID: plan.ID, NodeID: node1.ID, AllocationID: "grp-legacy-01", State: domain.LeaseReported, ClaimedAt: now, ExpiresAt: now.Add(time.Hour), FinishedAt: &now, ProbeID: "prb-legacy-01"}
	// Legacy bug: lease 2 is "reported" but points at lease 1's probe; its own
	// observation is parked only inside the global ledger claim.
	lease2 := domain.NodeLease{ID: "lse-legacy-02", PlanID: plan.ID, NodeID: node2.ID, AllocationID: "grp-legacy-01", State: domain.LeaseReported, ClaimedAt: now, ExpiresAt: now.Add(time.Hour), FinishedAt: &now, ProbeID: "prb-legacy-01"}
	// Legacy bug: lease 3 reports the same key yet has no observation at all.
	lease3 := domain.NodeLease{ID: "lse-legacy-03", PlanID: plan.ID, NodeID: node3.ID, AllocationID: "grp-legacy-01", State: domain.LeaseReported, ClaimedAt: now, ExpiresAt: now.Add(time.Hour), FinishedAt: &now, ProbeID: "prb-legacy-01"}

	probe1 := domain.Probe{ID: "prb-legacy-01", LeaseID: lease1.ID, PlanID: plan.ID, NodeID: node1.ID, RequestKey: "shared-legacy-key", Success: true, ObservedSerial: revision.Serial, LatencyMS: 10, ObservedAt: observed, StoredAt: now, PayloadFingerprint: "legacy-fp-01"}
	shadow2 := domain.Probe{ID: "prb-legacy-02", LeaseID: lease2.ID, PlanID: plan.ID, NodeID: node2.ID, RequestKey: "shared-legacy-key", Success: true, ObservedSerial: revision.Serial, LatencyMS: 12, ObservedAt: observed, StoredAt: now.Add(time.Second), PayloadFingerprint: "legacy-fp-02"}

	legacy := domain.State{
		SchemaVersion: 1,
		Revision:      5,
		Plans:         map[string]domain.RolloutPlan{plan.ID: plan},
		Revisions:     map[string]domain.ZoneRevision{revision.ID: revision},
		Nodes:         map[string]domain.ResolverNode{node1.ID: node1, node2.ID: node2, node3.ID: node3},
		Leases:        map[string]domain.NodeLease{lease1.ID: lease1, lease2.ID: lease2, lease3.ID: lease3},
		LeaseGroups:   map[string]domain.LeaseGroup{},
		Probes:        map[string]domain.Probe{probe1.ID: probe1},
		ProbeRequestLedger: map[string]domain.ProbeRequestEntry{
			// Old global key: bare request key shared by three different leases.
			"shared-legacy-key": {
				RequestKey:         "shared-legacy-key",
				ContentFingerprint: domain.ProbeContentFingerprintForProbe(probe1),
				PrimaryProbeID:     probe1.ID,
				Claims: []domain.ProbeRequestClaim{
					{LeaseID: lease1.ID, PlanID: plan.ID, NodeID: node1.ID, Probe: probe1},
					{LeaseID: lease2.ID, PlanID: plan.ID, NodeID: node2.ID, Probe: shadow2},
				},
			},
		},
		Assessments:           map[string]domain.RolloutAssessment{},
		LeaseRequestKeys:      map[string]string{},
		AssessmentRequestKeys: map[string]string{},
		AuditEvents:           []domain.AuditEvent{},
	}

	harness, err := newHarnessFromSnapshot(legacy)
	if err != nil {
		return err
	}
	defer harness.close()

	// Lease 2's replayed request must resolve to its own recovered probe.
	replay2, err := submitProbeRaw(harness, lease2.ID, domain.ProbeInput{
		RequestKey: "shared-legacy-key", Success: true, ObservedSerial: revision.Serial,
		LatencyMS: 12, ObservedAt: observed,
	})
	if err != nil {
		return err
	}
	if replay2.ID != shadow2.ID || replay2.LeaseID != lease2.ID || replay2.NodeID != node2.ID {
		return ensure(false, "legacy claim probe was not recovered and rebound to lease 2")
	}

	// Lease 3 had no observation: it reopens and node 3 is leased again.
	if _, err := submitProbe(harness, lease3.ID, "shared-legacy-key", true, revision.Serial, 14); err != nil {
		return fmt.Errorf("submit probe to recovered lease 3: %w", err)
	}

	// Persist recovery and reload from disk as a fresh process.
	if err := harness.restart(); err != nil {
		return err
	}

	var assessment domain.RolloutAssessment
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "legacy-assessment-0001",
	}, &assessment); err != nil {
		return err
	}
	if assessment.Verdict != domain.VerdictConsistent || assessment.ProbeCount != 3 ||
		assessment.SuccessCount != 3 || assessment.MaximumLatencyMS != 14 {
		return ensure(false, fmt.Sprintf("recovered assessment did not see all real observations: %+v", assessment))
	}

	// A further restart keeps the single interpretation.
	if err := harness.restart(); err != nil {
		return err
	}
	var latest domain.RolloutAssessment
	if err := harness.call(http.MethodGet, "/v1/plans/"+plan.ID+"/assessments/latest", nil, &latest); err != nil {
		return err
	}
	if latest.ID != assessment.ID || latest.ProbeCount != 3 {
		return ensure(false, "recovery diverged on the second restart")
	}
	return nil
}

// submitProbeRaw submits a probe with full control over every input field.
func submitProbeRaw(harness *harness, leaseID string, input domain.ProbeInput) (domain.Probe, error) {
	var result domain.Probe
	err := harness.call(http.MethodPatch, "/v1/leases/"+leaseID+"/probes", input, &result)
	return result, err
}
