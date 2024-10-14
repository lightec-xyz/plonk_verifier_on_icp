package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net/url"
	"time"

	agent "github.com/aviate-labs/agent-go"
	"github.com/aviate-labs/agent-go/principal"
)

func main() {
	network := flag.String("network", "", "ic or local")
	canister := flag.String("canister", "", "Specify the canister ID")
	// 解析命令行参数
	flag.Parse()

	// 打印输入的参数
	fmt.Printf("Network: %s\n", *network)
	fmt.Printf("Canister: %s\n", *canister)

	host, _ := url.Parse("http://localhost:4943")
	if *network == "ic" {
		host, _ = url.Parse("https://icp0.io/")
	}

	cfg := agent.Config{
		ClientConfig:                   &agent.ClientConfig{Host: host},
		FetchRootKey:                   false,
		PollTimeout:                    30 * time.Second,
		DisableSignedQueryVerification: true,
	}

	a, err := agent.New(cfg)
	if err != nil {
		panic(err)
	}

	principal := principal.MustDecode(*canister)

	vkBytes, proofBytes, witBytes := buildProof("hasher", false)
	var result bool
	err = a.Query(principal, "verify_bytes", []any{vkBytes, proofBytes, witBytes, true}, []any{&result})
	if err != nil {
		panic(err)
	}

	if !result {
		panic("verification failed")
	}

	fmt.Printf("vk: %v\n", hex.EncodeToString(vkBytes))
	fmt.Printf("proof: %v\n", hex.EncodeToString(proofBytes))
	fmt.Printf("wit: %v\n", hex.EncodeToString(witBytes))
	fmt.Println("verification success")
}
