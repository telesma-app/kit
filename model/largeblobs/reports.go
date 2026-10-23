package largeblobs

import (
	"github.com/telesma-app/kit/model/report"
)

type ReadReport struct {
	Device       report.EndpointReport `json:"device"`
	Target       BlobTarget            `json:"target"`
	State        ReadState             `json:"state"`
	RawHex       string                `json:"rawHex,omitempty"`
	RawByteCount int                   `json:"rawByteCount"`
	RawBytes     []byte                `json:"-"`
}

type ListReport struct {
	Device  report.EndpointReport `json:"device"`
	Support SupportReport         `json:"support"`
	Array   ListArraySummary      `json:"array"`
	Entries []ArrayEntry          `json:"entries,omitempty"`
}

type ListArraySummary struct {
	Read                   bool `json:"read"`
	BlobCount              int  `json:"blobCount"`
	MatchedBlobCount       int  `json:"matchedBlobCount"`
	OrphanedBlobCount      int  `json:"orphanedBlobCount"`
	NonconformingBlobCount int  `json:"nonconformingBlobCount"`
	CorruptBlobCount       int  `json:"corruptBlobCount"`
}

type ArrayEntry struct {
	Index                    int         `json:"index"`
	State                    EntryState  `json:"state"`
	Target                   *BlobTarget `json:"target,omitempty"`
	CiphertextByteCount      int         `json:"ciphertextByteCount"`
	DeclaredPayloadByteCount uint        `json:"declaredPayloadByteCount"`
	PayloadByteCount         int         `json:"payloadByteCount,omitempty"`
}
