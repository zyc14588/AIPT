package runcore

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

// CryptoSeedSource is the production default. Tests inject a fixed source.
type CryptoSeedSource struct{}

func (CryptoSeedSource) RootSeed(ctx context.Context, _ RunBinding) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return seed, nil
}

func seedCommitment(binding RunBinding, seed []byte) (string, error) {
	if err := validSeed(seed); err != nil {
		return "", err
	}
	bindingBytes, err := canonicalValue(binding)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	writeCommitmentField(h, []byte(SeedCommitmentV1))
	writeCommitmentField(h, bindingBytes)
	writeCommitmentField(h, seed)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeCommitmentField(h interface{ Write([]byte) (int, error) }, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(value)
}

func validSeed(seed []byte) error {
	if len(seed) < 32 || len(seed) > 128 {
		return errors.New("root seed must contain 32..128 bytes")
	}
	return nil
}

// VerifySeedCommitment is the evidence-authorized verification primitive.
// It accepts seed material explicitly and never returns or stores that seed.
func VerifySeedCommitment(binding RunBinding, seed []byte, commitment string) bool {
	expected, err := seedCommitment(binding, seed)
	if err != nil {
		return false
	}
	left, err := hex.DecodeString(expected)
	if err != nil {
		return false
	}
	right, err := hex.DecodeString(commitment)
	return err == nil && hmac.Equal(left, right)
}

func deterministicDraw(seed []byte, runID, streamID string, drawIndex int64) (string, error) {
	if err := validSeed(seed); err != nil {
		return "", err
	}
	if err := validIdentity("stream_id", streamID); err != nil || drawIndex < 1 || drawIndex > maxSafeJSONInteger {
		return "", errors.New("invalid deterministic draw coordinates")
	}
	h := hmac.New(sha256.New, seed)
	writeCommitmentField(h, []byte(RNGVersionV1))
	writeCommitmentField(h, []byte(runID))
	writeCommitmentField(h, []byte(streamID))
	var index [8]byte
	binary.BigEndian.PutUint64(index[:], uint64(drawIndex))
	writeCommitmentField(h, index[:])
	return hex.EncodeToString(h.Sum(nil)[:8]), nil
}
