package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	adb "github.com/example/pureadb"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	key, err := adb.GenerateKey("my-tool@go")
	if err != nil {
		log.Fatal(err)
	}
	// Persist this in a real application. Reusing the key is what makes future
	// secure Wi-Fi connections remain trusted.
	_ = os.WriteFile("adbkey.pem", key.MarshalPrivateKeyPEM(), 0600)

	if len(os.Args) < 2 {
		log.Fatal("usage: wifi <6-digit-pairing-code>")
	}
	client, pair, err := adb.PairAndConnectCode(ctx, "", os.Args[1], key)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	fmt.Println("paired GUID:", pair.GUID)
	fmt.Println("connected:", pair.ConnectAddress)
	out, err := client.Shell(ctx, "getprop ro.product.model")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("model:", out)
}
