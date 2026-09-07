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
	key, err := adb.LoadOrCreateKey("adbkey.pem", "my-tool@go")
	if err != nil {
		log.Fatal(err)
	}
	q, err := adb.NewQRSession()
	if err != nil {
		log.Fatal(err)
	}
	pngData, err := q.PNG(512)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("pair.png", pngData, 0644); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Show pair.png and scan it from Android > Wireless debugging > Pair device with QR code")
	fmt.Println("Payload:", q.Payload)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	client, result, err := adb.PairAndConnectQR(ctx, q, key)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	fmt.Println("paired:", result.GUID, result.ConnectAddress)
}
