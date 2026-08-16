package logging

import (
	"encoding/json"
	"slices"
	"sync"

	"github.com/telesma-app/kit/model"
)

type journalRecord struct {
	record model.LogJournalRecord
	bytes  int
}

type Journal struct {
	mu sync.RWMutex

	records        []journalRecord
	head           int
	storedBytes    int
	sequence       uint64
	evictedThrough uint64
	entryLimit     int
	byteLimit      int
	changed        chan struct{}
}

func NewJournal(entryLimit, byteLimit int) *Journal {
	return &Journal{
		entryLimit: entryLimit,
		byteLimit:  byteLimit,
		changed:    make(chan struct{}, 1),
	}
}

func (j *Journal) Append(entry model.LogEntry) {
	size := entrySize(entry)
	j.mu.Lock()
	j.sequence++
	j.records = append(j.records, journalRecord{
		record: model.LogJournalRecord{Sequence: j.sequence, Entry: entry},
		bytes:  size,
	})
	j.storedBytes += size
	j.trimLocked()
	j.mu.Unlock()

	select {
	case j.changed <- struct{}{}:
	default:
	}
}

func (j *Journal) Read(after uint64) model.LogJournalBatch {
	j.mu.RLock()
	defer j.mu.RUnlock()

	batch := model.LogJournalBatch{
		Entries:   make([]model.LogJournalRecord, 0, len(j.records)-j.head),
		Cursor:    j.sequence,
		Truncated: after < j.evictedThrough,
	}

	for _, stored := range j.records[j.head:] {
		if stored.record.Sequence > after {
			batch.Entries = append(batch.Entries, stored.record)
		}
	}

	return batch
}

func (j *Journal) Clear() uint64 {
	j.mu.Lock()
	clear(j.records)
	j.records = nil
	j.head = 0
	j.storedBytes = 0
	j.evictedThrough = 0
	cursor := j.sequence
	j.mu.Unlock()

	return cursor
}

func (j *Journal) Cursor() uint64 {
	j.mu.RLock()
	defer j.mu.RUnlock()

	return j.sequence
}

func (j *Journal) Changes() <-chan struct{} {
	return j.changed
}

func (j *Journal) trimLocked() {
	for j.head < len(j.records) &&
		(len(j.records)-j.head > j.entryLimit || j.storedBytes > j.byteLimit) {
		j.storedBytes -= j.records[j.head].bytes
		j.evictedThrough = j.records[j.head].record.Sequence
		j.records[j.head] = journalRecord{}
		j.head++
	}

	if j.head == len(j.records) {
		j.records = nil
		j.head = 0
	} else if j.head > len(j.records)/2 {
		j.records = slices.Clone(j.records[j.head:])
		j.head = 0
	}
}

func entrySize(entry model.LogEntry) int {
	encoded, err := json.Marshal(entry)
	if err != nil {
		panic(err)
	}

	return len(encoded)
}
