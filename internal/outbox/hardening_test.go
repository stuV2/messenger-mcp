package outbox

import (
	"context"
	"strings"
	"sync"
	"testing"
)

func TestLostAtomicClaimNeverDispatches(t *testing.T) {
	q, f, _, _ := setup(t)
	v := enqueueText(t, q, "synthetic", "claim")
	// A BEFORE trigger deterministically commits cancellation between Step's
	// SELECT and UPDATE, then suppresses the claim UPDATE. The real SQLite
	// RowsAffected is zero, exactly the original lost-claim failure mode.
	_, err := q.db.Exec(`CREATE TRIGGER cancel_before_claim BEFORE UPDATE OF status ON outbox
 WHEN OLD.status='queued' AND NEW.status='sending'
 BEGIN UPDATE outbox SET status='cancelled' WHERE job_id=OLD.job_id; SELECT RAISE(IGNORE); END;`)
	if err != nil {
		t.Fatal(err)
	}
	did, err := q.Step(context.Background())
	if err != nil || did || len(f.calls) != 0 {
		t.Fatalf("lost claim dispatched: did=%v calls=%d err=%v", did, len(f.calls), err)
	}
	got, err := q.Get(context.Background(), v.JobID)
	if err != nil || got.Status != StatusCancelled || got.Attempts != 0 {
		t.Fatalf("cancel result %+v %v", got, err)
	}
}

func TestConcurrentCancelSuccessImpliesNoTransmission(t *testing.T) {
	for i := 0; i < 20; i++ {
		q, f, _, _ := setup(t)
		v := enqueueText(t, q, "synthetic", "")
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var cancelErr, stepErr error
		go func() { defer wg.Done(); <-start; _, cancelErr = q.Cancel(context.Background(), v.JobID) }()
		go func() { defer wg.Done(); <-start; _, stepErr = q.Step(context.Background()) }()
		close(start)
		wg.Wait()
		if stepErr != nil {
			t.Fatal(stepErr)
		}
		if cancelErr == nil && len(f.calls) != 0 {
			t.Fatalf("successful cancellation transmitted %d messages", len(f.calls))
		}
	}
}

func TestReadOnlyQueueDoesNotReplayOrMutateOldJobs(t *testing.T) {
	q, f, _, _ := setup(t)
	v := enqueueText(t, q, "old synthetic queued text", "")
	ro, err := New(q.l, f, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ro.Enqueue(context.Background(), Job{ChatID: v.ChatID, Kind: KindText, Text: "new"}); err == nil {
		t.Fatal("readonly enqueue accepted")
	}
	if _, err := ro.Cancel(context.Background(), v.JobID); err == nil {
		t.Fatal("readonly cancel accepted")
	}
	if did, err := ro.Step(context.Background()); err != nil || did {
		t.Fatalf("readonly Step %v %v", did, err)
	}
	ro.Run(context.Background()) // must return immediately, no ticker/replay
	got, err := ro.Get(context.Background(), v.JobID)
	if err != nil || got.Status != StatusQueued || got.Attempts != 0 || len(f.calls) != 0 {
		t.Fatalf("old work changed %+v %v", got, err)
	}
}

func TestFileSendingMechanicallyRefusedIncludingLegacyQueue(t *testing.T) {
	q, f, _, _ := setup(t)
	if _, err := q.Enqueue(context.Background(), Job{ChatID: "245962885415945", Kind: KindFile, FilePath: "/never-open", Text: "caption"}); err == nil {
		t.Fatal("file enqueue accepted")
	}
	_, err := q.db.Exec(`INSERT INTO outbox(job_id,idempotency_key,chat_id,kind,file_path,status,created_at,updated_at) VALUES('old-file','old-file','245962885415945','file','/never-open','queued',1,1)`)
	if err != nil {
		t.Fatal(err)
	}
	if did, err := q.Step(context.Background()); err != nil || did || len(f.calls) != 0 {
		t.Fatalf("old mutable pathname sent: did=%v err=%v", did, err)
	}
	v, err := q.Get(context.Background(), "old-file")
	if err != nil || v.Status != StatusFailed || !strings.Contains(v.Error, "disabled") {
		t.Fatalf("legacy file %+v %v", v, err)
	}
}

func TestTextAndPendingQueueBudgetsPreserveIdempotency(t *testing.T) {
	q, _, _, _ := setup(t)
	ctx := context.Background()
	if _, err := q.Enqueue(ctx, Job{ChatID: "245962885415945", Kind: KindText, Text: strings.Repeat("x", (16<<10)+1)}); err == nil {
		t.Fatal("oversize text accepted")
	}
	for i := 0; i < 100; i++ {
		enqueueText(t, q, "x", "")
	}
	if _, err := q.Enqueue(ctx, Job{ChatID: "245962885415945", Kind: KindText, Text: "overflow"}); err == nil {
		t.Fatal("pending row cap bypassed")
	}
	q2, _, _, _ := setup(t)
	first := enqueueText(t, q2, strings.Repeat("x", 16<<10), "repeat")
	for i := 1; i < 64; i++ {
		enqueueText(t, q2, strings.Repeat("x", 16<<10), "")
	}
	if _, err := q2.Enqueue(ctx, Job{ChatID: "245962885415945", Kind: KindText, Text: "overflow"}); err == nil {
		t.Fatal("pending byte cap bypassed")
	}
	repeat, err := q2.Enqueue(ctx, Job{ChatID: "245962885415945", Kind: KindText, Text: strings.Repeat("x", 16<<10), IdempotencyKey: "repeat"})
	if err != nil || repeat.JobID != first.JobID {
		t.Fatalf("idempotency at cap broken %+v %v", repeat, err)
	}
}
