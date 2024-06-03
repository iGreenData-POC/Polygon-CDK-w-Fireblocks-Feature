package types

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/0xPolygon/cdk-data-availability/log"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	solsha3 "github.com/miguelmota/go-solidity-sha3"
	"google.golang.org/api/idtoken"
)

const (
	signatureLen = 65
)

// Sequence represents the data that the sequencer will send to L1
// and other metadata needed to build the accumulated input hash aka accInputHash
type Sequence []ArgBytes

type MessagePayload struct {
	Data string `json:"data"`
}

type FireblocksAdaptorResponse struct {
	Status string `json:"status"`
	Data   struct {
		FinalSignature string `json:"finalSignature"`
	} `json:"data"`
	Error struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
}

// HashToSign returns the accumulated input hash of the sequence.
// Note that this is equivalent to what happens on the smart contract
func (s *Sequence) HashToSign() []byte {
	currentHash := common.Hash{}.Bytes()
	for _, batchData := range ([]ArgBytes)(*s) {
		types := []string{
			"bytes32",
			"bytes32",
		}
		values := []interface{}{
			currentHash,
			crypto.Keccak256(batchData),
		}
		currentHash = solsha3.SoliditySHA3(types, values)
	}
	return currentHash
}

func constructBearerToken(ctx context.Context, url string) (string, error) {
	// Replace with your Cloud Run service URL
	cloudRunURL := url

	// Create a token source using the Cloud Run URL
	tokenSource, err := idtoken.NewTokenSource(context.Background(), cloudRunURL)
	if err != nil {
		log.Errorf("failed to create token source: %v", err)
	}

	// Obtain an identity token
	token, err := tokenSource.Token()
	if err != nil {
		log.Errorf("failed to obtain token: %v", err)
	}
	return token.AccessToken, nil
}

func sendRequestsToAdaptor(ctx context.Context, url string, payload MessagePayload) (string, error) {
	client := &http.Client{
		Timeout: time.Second * 60, // Set a timeout for the request
	}

	// Marshal the payload into JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Errorf("Failed to marshal payload: %v", err)
		return "", err
	}

	// Create the POST request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Errorf("Failed to create request: %v", err)
		return "", err
	}
	token, err := constructBearerToken(ctx, url)
	log.Infof("=========================The constructed token is:==================", token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("Request failed: %v", err)
		return "", err
	}
	defer resp.Body.Close()

	// Read the response body
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Failed to read response body: %v", err)
		return "", err
	}

	// Unmarshal the response into a struct
	var fireblocksAdaptorResponse FireblocksAdaptorResponse
	if err := json.Unmarshal(responseBody, &fireblocksAdaptorResponse); err != nil {
		log.Errorf("Failed to unmarshal response: %v", err)
		return "", err
	}

	// Check the response status and extract finalSignature if successful
	if fireblocksAdaptorResponse.Status == "SUCCESS" {
		finalSignature := fireblocksAdaptorResponse.Data.FinalSignature
		log.Infof("Received finalSignature: %s", finalSignature)
		return finalSignature, nil
	}

	// Handle error response
	err = errors.New(fireblocksAdaptorResponse.Error.Message + " : " + fireblocksAdaptorResponse.Error.Code)
	log.Errorf("Adaptor error: %v", err)
	return "", err
}

// Sign returns a signed sequence by the private key.
// Note that what's being signed is the accumulated input hash
func (s *Sequence) Sign(privateKey *ecdsa.PrivateKey, fireblocksFeatureEnabled bool, rawSigningAdaptorUrl string) (*SignedSequence, error) {
	log.Infof("Inside sequence.go Sign function!")
	hashToSign := s.HashToSign()

	var signature []byte
	var err error

	if fireblocksFeatureEnabled {
		signature, err = signWithAdaptor(hashToSign, rawSigningAdaptorUrl)
		if err != nil {
			log.Infof("Failed to send message request to adaptor: %v", err)
			return nil, err
		}
	} else {
		signature, err = signWithPrivateKey(hashToSign, privateKey)
		if err != nil {
			return nil, err
		}
	}

	finalSignature, err := processSignature(signature, fireblocksFeatureEnabled)
	if err != nil {
		log.Infof("Failed to process signature: %v", err)
		return nil, err
	}

	return &SignedSequence{
		Sequence:  *s,
		Signature: finalSignature,
	}, nil
}

func signWithAdaptor(hashToSign []byte, rawSigningAdaptorUrl string) ([]byte, error) {
	payload := MessagePayload{
		Data: hex.EncodeToString(hashToSign),
	}
	signature, err := sendRequestsToAdaptor(context.Background(), rawSigningAdaptorUrl, payload)
	if err != nil {
		return nil, err
	}

	trimmedSignature := signature[2:]
	sig, err := hex.DecodeString(trimmedSignature)
	if err != nil {
		return nil, err
	}

	log.Infof("Trimmed and decoded signature from adaptor: %x", sig)
	return sig, nil
}

func signWithPrivateKey(hashToSign []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	sig, err := crypto.Sign(hashToSign, privateKey)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func processSignature(sig []byte, fireblocksFeatureEnabled bool) ([]byte, error) {
	rBytes := sig[:32]
	sBytes := sig[32:64]
	vByte := sig[64]

	if strings.ToUpper(common.Bytes2Hex(sBytes)) > "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0" {
		magicNumber := common.Hex2Bytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
		sBig := big.NewInt(0).SetBytes(sBytes)
		magicBig := big.NewInt(0).SetBytes(magicNumber)
		s1 := magicBig.Sub(magicBig, sBig)
		sBytes = s1.Bytes()
		if vByte == 0 {
			vByte = 1
		} else {
			vByte = 0
		}
	}

	if !fireblocksFeatureEnabled {
		vByte += 27
	}

	actualSignature := []byte{}
	actualSignature = append(actualSignature, rBytes...)
	actualSignature = append(actualSignature, sBytes...)
	actualSignature = append(actualSignature, vByte)

	log.Infof("Processed signature: %x", actualSignature)
	return actualSignature, nil
}

// OffChainData returns the data that needs to be stored off chain from a given sequence
func (s *Sequence) OffChainData() []OffChainData {
	od := []OffChainData{}
	for _, batchData := range ([]ArgBytes)(*s) {
		od = append(od, OffChainData{
			Key:   crypto.Keccak256Hash(batchData),
			Value: batchData,
		})
	}
	return od
}

// SignedSequence is a sequence but signed
type SignedSequence struct {
	Sequence  Sequence `json:"sequence"`
	Signature ArgBytes `json:"signature"`
}

// Signer returns the address of the signer
func (s *SignedSequence) Signer(fireblocksFeatureEnabled bool) (common.Address, error) {
	if len(s.Signature) != signatureLen {
		return common.Address{}, errors.New("invalid signature")
	}

	sig := make([]byte, 65)
	copy(sig, s.Signature)
	sig[64] -= 27

	
	pubKey, err := crypto.SigToPub(s.Sequence.HashToSign(), sig)
	if err != nil {
			return common.Address{}, err
		}
		
		return crypto.PubkeyToAddress(*pubKey), nil
	
}
