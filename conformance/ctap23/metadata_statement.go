package ctap23

import (
	"fmt"

	mdsmodel "github.com/telesma-app/mds/model"
)

type metadataStatement struct {
	fields mdsmodel.MetadataStatementDocument
}

func parseMetadataStatement(input string) (metadataStatement, error) {
	if input == "" {
		return metadataStatement{}, fmt.Errorf("ctap23: metadata statement is required")
	}

	fields, err := mdsmodel.ParseMetadataStatementDocument([]byte(input))
	if err != nil {
		return metadataStatement{}, fmt.Errorf("ctap23: decode metadata statement: %w", err)
	}

	return metadataStatement{fields: fields}, nil
}

func (s metadataStatement) field(name string, target any) (bool, error) {
	present, err := s.fields.DecodeField(name, target)
	if err != nil {
		return present, fmt.Errorf("ctap23: metadata field %s: %w", name, err)
	}

	return present, nil
}

func (s metadataStatement) has(name string) bool {
	_, present := s.fields[name]

	return present
}

func (s metadataStatement) fieldNames() []string {
	names := make([]string, 0, len(s.fields))
	for name := range s.fields {
		names = append(names, name)
	}

	return names
}
