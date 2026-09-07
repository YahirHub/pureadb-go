package adb

import (
	"context"
	"time"
)

// PairCode discovers a visible Android "Pair device with pairing code" service
// and pairs using the six-digit code shown by Android. If serviceName is empty,
// the first pairing service found on the LAN is used.
func PairCode(ctx context.Context, serviceName, code string, key *Key) (*PairResult, error) {
	ctx, cancel := withDefaultTimeout(ctx, 2*time.Minute)
	defer cancel()
	ep, err := WaitPairingEndpoint(ctx, serviceName)
	if err != nil {
		return nil, err
	}
	result, err := Pair(ctx, ep.Address(), code, key)
	if err != nil {
		return nil, err
	}

	connectCtx, connectCancel := context.WithTimeout(ctx, 15*time.Second)
	defer connectCancel()
	if cep, err := WaitConnectEndpoint(connectCtx, result.GUID); err == nil {
		result.ConnectAddress = cep.Address()
	}
	return result, nil
}
