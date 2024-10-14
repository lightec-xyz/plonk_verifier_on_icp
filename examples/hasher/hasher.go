package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test/unsafekzg"
)

var dataDir = "./test_data"

type Circuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	Input  []uints.U8
	OutPut []uints.U8 `gnark:",public"`
}

// Define declares the circuit's constraints
func (c *Circuit) Define(api frontend.API) error {
	// hash function
	h, err := sha2.New(api)
	if err != nil {
		return err
	}

	h.Write(c.Input)
	output := h.Sum()
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(output[i].Val, c.OutPut[i].Val)
	}
	return nil
}

func buildProof(name string, saveFiles bool) ([]byte, []byte, []byte) {
	field := ecc.BN254.ScalarField()
	input := []byte("plonk verifer on icp")

	output := sha256.Sum256(input)
	fmt.Printf("output: %v\n", output)

	circuit := Circuit{
		Input:  make([]uints.U8, len(input)),
		OutPut: make([]uints.U8, len(output)),
	}

	assignment := &Circuit{
		Input:  uints.NewU8Array(input),
		OutPut: uints.NewU8Array(output[:]),
	}

	ccs, err := frontend.Compile(field, scs.NewBuilder, &circuit)
	fmt.Printf("nbConstraints: %v\n", ccs.GetNbConstraints())
	if err != nil {
		panic(err)
	}
	// NB! UNSAFE! Use MPC.
	srs, lsrs, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		panic(err)
	}

	pk, vk, err := native_plonk.Setup(ccs, srs, lsrs)
	if err != nil {
		panic(err)
	}

	wit, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	proof, err := native_plonk.Prove(ccs, pk, wit)
	if err != nil {
		panic(err)
	}
	pubWit, err := wit.Public()
	if err != nil {
		panic(err)
	}
	err = native_plonk.Verify(proof, vk, pubWit)
	if err != nil {
		panic(err)
	}

	var vkBuffer bytes.Buffer
	_, err = vk.WriteTo(&vkBuffer)
	if err != nil {
		panic(err)
	}

	var proofBuffer bytes.Buffer
	_, err = proof.WriteTo(&proofBuffer)
	if err != nil {
		panic(err)
	}

	var pubWitBuffer bytes.Buffer
	_, err = pubWit.WriteTo(&pubWitBuffer)
	if err != nil {
		panic(err)
	}

	//empty the lines
	// vk.(*plonk_bn254.VerifyingKey).Kzg.Lines = [2][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{}
	if saveFiles {
		fvk, err := os.Create(filepath.Join(dataDir, fmt.Sprintf("%s.vk", name)))
		if err != nil {
			panic(err)
		}

		defer fvk.Close()
		vk.WriteTo(fvk)
		//compressed proof
		fproof, err := os.Create(filepath.Join(dataDir, fmt.Sprintf("%s_compressed.proof", name)))
		if err != nil {
			panic(err)
		}
		defer fproof.Close()
		proof.WriteTo(fproof)

		fwit, err := os.Create(filepath.Join(dataDir, fmt.Sprintf("%s.wtns", name)))
		if err != nil {
			panic(err)
		}
		defer fwit.Close()
		pubWit.WriteTo(fwit)

		//uncompresssed_proof is the product of MarshalSolidity()
		bn254proof := proof.(*plonk_bn254.Proof)
		unCompressedProofBytes := bn254proof.MarshalSolidity()

		funCompressedProof, err := os.Create(filepath.Join(dataDir, fmt.Sprintf("%s_uncompressed.proof", name)))
		if err != nil {
			panic(err)
		}
		defer funCompressedProof.Close()
		funCompressedProof.Write(unCompressedProofBytes)
	}

	return vkBuffer.Bytes(), proofBuffer.Bytes(), pubWitBuffer.Bytes()
}
