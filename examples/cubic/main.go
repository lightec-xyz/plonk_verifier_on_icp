package main

import (
	"fmt"
	"path/filepath"

	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

var (
	dataDir = "./test_data"
)

// Circuit defines a simple circuit
// x**3 + x + 5 == y
type Circuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *Circuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

func main() {
	field := ecc.BN254.ScalarField()
	var circuit Circuit
	assignment := &Circuit{
		X: 3,
		Y: 35,
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

	//empty the lines
	// vk.(*plonk_bn254.VerifyingKey).Kzg.Lines = [2][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{}
	fvk, err := os.Create(filepath.Join(dataDir, "cubic.vk"))
	if err != nil {
		panic(err)
	}

	defer fvk.Close()
	vk.WriteTo(fvk)
	//compressed proof 
	fproof, err := os.Create(filepath.Join(dataDir, "cubic.proof"))
	if err != nil {
		panic(err)
	}
	defer fproof.Close()
	proof.WriteTo(fproof)

	fwit, err := os.Create(filepath.Join(dataDir, "cubic.wtns"))
	if err != nil {
		panic(err)
	}
	defer fwit.Close()
	pubWit.WriteTo(fwit)

	//uncompresssed_proof is the product of MarshalSolidity()
	bn254proof := proof.(*plonk_bn254.Proof)
	unCompressedProofBytes := bn254proof.MarshalSolidity()

	funCompressedProof, err := os.Create(filepath.Join(dataDir,"cubic_uncompressed.proof"))
	if err != nil {
		panic(err)
	}
	defer funCompressedProof.Close()
	funCompressedProof.Write(unCompressedProofBytes)
}
