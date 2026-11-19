module github.com/mahmoudahmed3132/Doppel/sensors/remote-access-decoy

go 1.27.0

toolchain go1.27.3

require (
	github.com/mahmoudahmed3132/Doppel/sdk/go v0.0.0
	golang.org/x/crypto v0.58.0
)

require golang.org/x/sys v0.49.0 // indirect

replace github.com/mahmoudahmed3132/Doppel/sdk/go => ../../sdk/go
