package adb

import (
	"context"
	"errors"
	"time"
)

// PairAndConnectCode is the convenience path for the six-digit Android pairing UI.
func PairAndConnectCode(ctx context.Context, serviceName, code string, key *Key) (*Client, *PairResult, error) {
	result, err := PairCode(ctx, serviceName, code, key)
	if err != nil {
		return nil, nil, err
	}
	address := result.ConnectAddress
	if address == "" {
		discoverCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		ep, derr := WaitConnectEndpoint(discoverCtx, result.GUID)
		if derr != nil {
			return nil, result, errors.Join(ErrConnectNotFound, derr)
		}
		address = ep.Address()
		result.ConnectAddress = address
	}
	client, err := Connect(ctx, address, key)
	return client, result, err
}

// PairAndConnectQR waits for a phone to scan q.Payload, pairs it, and connects.
func PairAndConnectQR(ctx context.Context, q *QRSession, key *Key) (*Client, *PairResult, error) {
	result, err := q.Pair(ctx, key)
	if err != nil {
		return nil, nil, err
	}
	address := result.ConnectAddress
	if address == "" {
		discoverCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		ep, derr := WaitConnectEndpoint(discoverCtx, result.GUID)
		if derr != nil {
			return nil, result, errors.Join(ErrConnectNotFound, derr)
		}
		address = ep.Address()
		result.ConnectAddress = address
	}
	client, err := Connect(ctx, address, key)
	return client, result, err
}
