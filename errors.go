package adb

import "errors"

var (
	ErrClosed          = errors.New("adb: connection closed")
	ErrUnauthorized    = errors.New("adb: device did not authorize this key")
	ErrPairingFailed   = errors.New("adb: pairing failed")
	ErrProtocol        = errors.New("adb: protocol error")
	ErrServiceClosed   = errors.New("adb: service closed")
	ErrInstallFailed   = errors.New("adb: package installation failed")
	ErrPairingNotFound = errors.New("adb: pairing service not found")
	ErrConnectNotFound = errors.New("adb: secure connect service not found")
)
