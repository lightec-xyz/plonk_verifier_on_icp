package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadFiles(t *testing.T) {
	vk_bytes, err := os.ReadFile("./test_data/cubic.vk")
	assert.NoError(t, err)
	fmt.Printf("vk: %v\n", hex.EncodeToString(vk_bytes))




}