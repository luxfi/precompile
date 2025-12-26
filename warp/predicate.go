// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"errors"
	"fmt"

	"github.com/luxfi/geth/common"
)

var (
	ErrInvalidAllZeroBytes  = errors.New("predicate specified invalid all zero bytes")
	ErrInvalidPadding       = errors.New("predicate specified invalid padding")
	ErrInvalidEndDelimiter  = errors.New("predicate invalid end delimiter byte")
)

const (
	// EndByte is the delimiter byte used to signal the end of the predicate
	EndByte = byte(0xff)
)

// UnpackPredicate unpacks a predicate by stripping right-padded zeros and the end delimiter
func UnpackPredicate(paddedPredicate []byte) ([]byte, error) {
	trimmedPredicateBytes := common.TrimRightZeroes(paddedPredicate)
	if len(trimmedPredicateBytes) == 0 {
		return nil, fmt.Errorf("%w: 0x%x", ErrInvalidAllZeroBytes, paddedPredicate)
	}

	if expectedPaddedLength := (len(trimmedPredicateBytes) + 31) / 32 * 32; expectedPaddedLength != len(paddedPredicate) {
		return nil, fmt.Errorf("%w: got length (%d), expected length (%d)", ErrInvalidPadding, len(paddedPredicate), expectedPaddedLength)
	}

	if trimmedPredicateBytes[len(trimmedPredicateBytes)-1] != EndByte {
		return nil, ErrInvalidEndDelimiter
	}

	return trimmedPredicateBytes[:len(trimmedPredicateBytes)-1], nil
}

// PackPredicate packs a predicate by appending the end delimiter and padding to 32-byte boundary
func PackPredicate(predicateBytes []byte) []byte {
	predicateBytesWithDelimiter := append(predicateBytes, EndByte)
	paddedLength := (len(predicateBytesWithDelimiter) + 31) / 32 * 32
	paddedBytes := make([]byte, paddedLength)
	copy(paddedBytes, predicateBytesWithDelimiter)
	return paddedBytes
}
