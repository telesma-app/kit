package logging

import (
	"testing"

	"github.com/telesma-app/kit/model"
)

func TestJournalReadsFromCursor(t *testing.T) {
	journal := NewJournal(3, 1<<20)
	journal.Append(model.LogEntry{Command: "first"})
	cursor := journal.Cursor()
	journal.Append(model.LogEntry{Command: "second"})

	batch := journal.Read(cursor)
	assertJournalBatch(t, batch, 2, false, "second")
}

func TestJournalReportsRetentionGap(t *testing.T) {
	journal := NewJournal(2, 1<<20)
	journal.Append(model.LogEntry{Command: "first"})
	journal.Append(model.LogEntry{Command: "second"})
	journal.Append(model.LogEntry{Command: "third"})

	batch := journal.Read(0)
	assertJournalBatch(t, batch, 3, true, "second", "third")

	if batch.Entries[0].Sequence != 2 {
		t.Fatalf("first retained sequence = %d, want 2", batch.Entries[0].Sequence)
	}
}

func TestJournalClearPreservesCursorWithoutRetentionGap(t *testing.T) {
	journal := NewJournal(3, 1<<20)
	journal.Append(model.LogEntry{Command: "before"})
	cursor := journal.Clear()
	journal.Append(model.LogEntry{Command: "after"})

	for _, after := range []uint64{0, cursor} {
		batch := journal.Read(after)
		assertJournalBatch(t, batch, 2, false, "after")
	}
}

func TestJournalCoalescesChangeNotifications(t *testing.T) {
	journal := NewJournal(3, 1<<20)
	journal.Append(model.LogEntry{Command: "first"})
	journal.Append(model.LogEntry{Command: "second"})

	select {
	case <-journal.Changes():
	default:
		t.Fatal("change notification is missing")
	}

	select {
	case <-journal.Changes():
		t.Fatal("change notifications were not coalesced")
	default:
	}
}

func assertJournalBatch(
	t *testing.T,
	batch model.LogJournalBatch,
	cursor uint64,
	truncated bool,
	commands ...string,
) {
	t.Helper()

	if batch.Cursor != cursor {
		t.Fatalf("cursor = %d, want %d", batch.Cursor, cursor)
	}

	if batch.Truncated != truncated {
		t.Fatalf("truncated = %t, want %t", batch.Truncated, truncated)
	}

	if len(batch.Entries) != len(commands) {
		t.Fatalf("entry count = %d, want %d: %#v", len(batch.Entries), len(commands), batch)
	}

	for i, command := range commands {
		if batch.Entries[i].Entry.Command != command {
			t.Fatalf("entry %d command = %q, want %q", i, batch.Entries[i].Entry.Command, command)
		}
	}
}
