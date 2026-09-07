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
	if len(os.Args) != 2 {
		log.Fatal("usage: direct 192.168.1.50:37123")
	}
	key, err := adb.LoadOrCreateKey("adbkey.pem", "my-tool@go")
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := adb.Connect(ctx, os.Args[1], key)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	out, err := client.Shell(ctx, "getprop ro.build.version.release")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(out)
}
