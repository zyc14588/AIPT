package orchestrator

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"unicode/utf8"

	"github.com/zyc14588/AIPT/internal/protocol"
)

var (
	identityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@+/\-]{0,127}$`)
	sha256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func validIdentity(field, value string) error {
	if !utf8.ValidString(value) || !identityPattern.MatchString(value) {
		return fmt.Errorf("%s is not a bounded identity", field)
	}
	return nil
}

func validSHA256(field, value string) error {
	if !sha256Pattern.MatchString(value) {
		return fmt.Errorf("%s is not lowercase SHA-256", field)
	}
	return nil
}

func canonicalValue(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	canonical, err := protocol.CanonicalJSON(raw)
	if err != nil {
		return nil, err
	}
	return []byte(canonical), nil
}

func canonicalRaw(value json.RawMessage) ([]byte, error) {
	if len(value) == 0 {
		return nil, errors.New("missing JSON value")
	}
	canonical, err := protocol.CanonicalJSON(value)
	if err != nil {
		return nil, err
	}
	return []byte(canonical), nil
}

func sha256Bytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func sha256String(value string) string { return sha256Bytes([]byte(value)) }

func cloneRaw(value json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), value...)
}

func cloneSeatIDs(values []SeatID) []SeatID { return append([]SeatID{}, values...) }

func validSeatList(values []SeatID) bool {
	seen := make(map[SeatID]struct{}, len(values))
	for _, value := range values {
		if !containsSeat(baselineSeatIDs(), value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validScopedSeatList(scope VisibilityScope, values []SeatID) bool {
	if !validSeatList(values) {
		return false
	}
	if scope == ScopeSeatPrivate {
		return len(values) > 0
	}
	return len(values) == 0
}

func validRoleList(values []Role) bool {
	seen := make(map[Role]struct{}, len(values))
	for _, value := range values {
		if value != RoleGM && value != RolePlayer {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func sortSeatIDs(values []SeatID, order []SeatID) []SeatID {
	rank := make(map[SeatID]int, len(order))
	for index, seatID := range order {
		rank[seatID] = index
	}
	copy := cloneSeatIDs(values)
	sort.Slice(copy, func(left, right int) bool {
		leftRank, leftOK := rank[copy[left]]
		rightRank, rightOK := rank[copy[right]]
		if leftOK && rightOK && leftRank != rightRank {
			return leftRank < rightRank
		}
		if leftOK != rightOK {
			return leftOK
		}
		return bytes.Compare([]byte(copy[left]), []byte(copy[right])) < 0
	})
	return copy
}

func containsSeat(values []SeatID, seatID SeatID) bool {
	for _, value := range values {
		if value == seatID {
			return true
		}
	}
	return false
}

func validClassification(classification DataClassification) bool {
	switch classification {
	case ClassPublic, ClassUnreleasedRemoteAllowed, ClassTableHiddenRemoteAllowed,
		ClassLocalOnlySecret, ClassHumanPrivateData, ClassCredentialSecret, ClassSystemInternal:
		return true
	default:
		return false
	}
}

func validScope(scope VisibilityScope) bool {
	switch scope {
	case ScopePublic, ScopeGMOnly, ScopeSeatPrivate, ScopeSystemInternal:
		return true
	default:
		return false
	}
}
