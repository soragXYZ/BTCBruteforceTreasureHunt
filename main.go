package main

import (
	"bufio"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
)

const (
	englishWordsFile = "wordlist-en.txt"
	frenchWordsFile  = "wordlist-fr.txt"
	winAdress        = "bc1q8zfy6wvvtskzkg4s343x42pyf363nmejspgc02"
)

var treasureHuntVerifierWords = []string{
	"alien",
	"detect",
	"flip",
	"gas",
	"organ",
	"pleasant",
	"staff",
	"trigger",
}

// Images
var W1 = []string{"échelle"}
var W2 = []string{"libre"}
var W3 = []string{"fossile"}
var W4 = []string{"travail", "physique", "manuel"}
var W5 = []string{"manuel", "bilan", "physique"}
var W6 = []string{"bilan", "indice"}
var W7 = []string{"indice", "baguette"}
var W8 = []string{"baguette", "acheter"}
var W9 = []string{"pluie", "acheter"}
var W10 = []string{"soleil", "pluie"}
var W11 = []string{"joindre", "soleil"}
var W12 = []string{"métier", "joindre"}

// Cover
var W13 = []string{"énergie"}
var W14 = []string{"monnaie"}

// Olympics
var W15 = []string{"canal"}
var W16 = []string{"orange"}

// Author
var W17 = []string{"pierre"}

// Summary
var W18 = []string{"progrès", "bonheur"}
var W19 = []string{"amour", "science"}

// Main chapter
var W20 = []string{"physique", "relatif"}
var W21 = []string{"émotion", "sortir"}

// Samsung feat Txt
var W22 = []string{"open"}   // ENGLISH
var W23 = []string{"always"} // ENGLISH
var W24 = []string{"win"}

var WAll = [][]string{W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15, W16, W17, W18, W19, W20, W21, W22, W23}

var enMap, enKeyMap, _ = fromFileToHash(englishWordsFile)
var frMap, _, frWords = fromFileToHash(frenchWordsFile)

// Load the 2048 words and return them as map
func fromFileToHash(filename string) (map[string]uint, map[uint]string, []string) {

	wordMap := make(map[string]uint) // key: word && value: bin value
	keyMap := make(map[uint]string)  // key: bin value && value: word
	words := []string{}

	// Open file
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("failed to open file: %s", err)
	}
	defer file.Close()

	// Create a new scanner to read the file line by line
	scanner := bufio.NewScanner(file)

	wordIndex := uint(0)

	// Loop through the file and read each line
	for scanner.Scan() {
		word := scanner.Text() // Get the line as a string
		wordMap[word] = wordIndex
		keyMap[wordIndex] = word
		words = append(words, word)
		wordIndex++
	}

	// Check for errors during the scan
	if err := scanner.Err(); err != nil {
		log.Fatalf("error reading file: %s", err)
	}

	return wordMap, keyMap, words
}

// For a given mnemonic of 24 words, return the number (bigInt) associated to it
// which represents entropy + checksum
func getEntropyAndChecksum(wordList map[string]uint, list []string) *big.Int {

	number := big.NewInt(0)

	for index, word := range list {

		// Loop through each word and shift bits accordingly ->
		// For example with 24 words:
		// word pos 24 harbor (in binary: 01101001000): add value 01101001000
		// word pos 23 excuse (in binary: 01001111000): add value 10011110000 00000000000
		// word pos 22 harbor (in binary: 01101001000): add value 01101001000 00000000000 00000000000 etc...

		// We are bigEndian -> most significant units are put first, so first word weights more than the 24th

		number.Add(number, big.NewInt(0).Lsh(big.NewInt(int64(wordList[word])), uint(len(list)-1-index)*11))

	}

	// fmt.Printf("Entropy and checksum number is: %x\n", number)

	return number
}

// Calculate if for a given entropy + checksum, the checksum is equal to the one included in the word
func isSeedValid(entropyAndChecksum *big.Int, wordToVerify uint) bool {

	// For 24 words, we have 256 % 32 = 8 bits of checksum
	// So we shift by 8 bits to keep the entropy only and remove the checksum
	// Then we calculate the sha256 of this entropy
	hash := sha256.Sum256(entropyAndChecksum.Rsh(entropyAndChecksum, 8).Bytes())

	// fmt.Printf("Calculated hash: %x\n", hash)
	// fmt.Printf("Calculated checksum:        %011b\n", hash[0])
	// fmt.Printf("Word to verify:             %011b\n", wordToVerify)
	// fmt.Printf("checksum in word to verify: %011b\n", wordToVerify&255)

	// Then we compare the checksum we calculated which is the first 8 bits of the hash (hash[0] here)
	// with the checksum included in the last word
	// We only keep the last 8 bit of the last word (2^8 = 255), corresponding to the checksum
	return uint(hash[0]) == wordToVerify&255

}

// Verify if the mnemonic is correct with the 8 words given
func are8ChecksumWordsCorrect(preSeed, verifierWords []string) bool {

	// We know that every mnemonic made from the first 23 words and a verifier word are valid
	// If every verifier word is valid, return true. Otherwise, return false
	for _, word := range verifierWords {

		mnemonic := append(preSeed, word)

		// fmt.Println("Trying mnemonic:", mnemonic)

		entropyAndChecksum := getEntropyAndChecksum(enMap, mnemonic)

		if !isSeedValid(entropyAndChecksum, enMap[word]) {
			return false
		}

		// fmt.Println("Mnemonic is valid:", mnemonic)

	}

	fmt.Println("Mnemonic is valid with 8 verifier words:", preSeed)
	return true
}

// GenerateBIP84Address derives a native SegWit (P2WPKH, Bech32) address using BIP84
func GenerateBIP84Address(mnemonic string) (string, error) {

	// 0. Generate the seed with hmac sha512
	seed, err := pbkdf2.Key(sha512.New, mnemonic, []byte("mnemonic"), 2048, 64)
	if err != nil {
		return "", err
	}

	// 1. Master key
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", err
	}

	// 2. Derive BIP84 path: m/84'/0'/0'/0/0
	purpose, err := masterKey.Child(hdkeychain.HardenedKeyStart + 84)
	if err != nil {
		return "", err
	}

	coinType, err := purpose.Child(hdkeychain.HardenedKeyStart + 0) // 0 = Bitcoin mainnet
	if err != nil {
		return "", err
	}

	account, err := coinType.Child(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", err
	}

	change, err := account.Child(0) // external chain
	if err != nil {
		return "", err
	}

	childKey, err := change.Child(0) // first address
	if err != nil {
		return "", err
	}

	// 3. Get the associated public key
	pubKey, err := childKey.ECPubKey()
	if err != nil {
		return "", err
	}

	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())

	// 4. Generate P2WPKH address (Bech32 native SegWit)
	address, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return "", err
	}

	return address.EncodeAddress(), nil
}

func main() {

	start := time.Now()
	nbMnemonicTested := 0.0

	// Get the speed of the bruteforce every 10s
	go func() {
		for {
			time.Sleep(time.Second * 10)
			fmt.Printf("mnemonic/s: %.f\n", nbMnemonicTested/float64(time.Since(start).Seconds()))
		}
	}()

	for i := range len(WAll) {
		for j := i + 1; j < len(WAll); j++ {

			// We try the bruteforce for every combination for 2 words (so we can have max 2 errors in our words)
			// So we replace the list of guesses for this position with the list of 2048 words

			// Ex: If we try to bruteforce 2 words with 4 placement possibilies,
			//  with X=2048 words and _ = known words (for example ["physique", "relatif"]) we will try:
			// X X _ _
			// X _ X _
			// X _ _ X
			//
			// _ X X _
			// _ X _ X
			//
			// _ _ X X
			//
			// This way we are sure to test every possibility

			tempMnemonicPossibilities := make([][]string, len(WAll))
			copy(tempMnemonicPossibilities, WAll) // Deep copy

			// Replace the list of guesses for position i and j with the list of 2048 words
			tempMnemonicPossibilities[i] = frWords
			tempMnemonicPossibilities[j] = frWords

			for _, w1 := range tempMnemonicPossibilities[0] {
				for _, w2 := range tempMnemonicPossibilities[1] {
					for _, w3 := range tempMnemonicPossibilities[2] {
						for _, w4 := range tempMnemonicPossibilities[3] {
							for _, w5 := range tempMnemonicPossibilities[4] {
								for _, w6 := range tempMnemonicPossibilities[5] {
									for _, w7 := range tempMnemonicPossibilities[6] {
										for _, w8 := range tempMnemonicPossibilities[7] {
											for _, w9 := range tempMnemonicPossibilities[8] {
												for _, w10 := range tempMnemonicPossibilities[9] {
													for _, w11 := range tempMnemonicPossibilities[10] {
														for _, w12 := range tempMnemonicPossibilities[11] {
															for _, w13 := range tempMnemonicPossibilities[12] {
																for _, w14 := range tempMnemonicPossibilities[13] {
																	for _, w15 := range tempMnemonicPossibilities[14] {
																		for _, w16 := range tempMnemonicPossibilities[15] {
																			for _, w17 := range tempMnemonicPossibilities[16] {
																				for _, w18 := range tempMnemonicPossibilities[17] {
																					for _, w19 := range tempMnemonicPossibilities[18] {
																						for _, w20 := range tempMnemonicPossibilities[19] {
																							for _, w21 := range tempMnemonicPossibilities[20] {
																								for _, w22 := range tempMnemonicPossibilities[21] {
																									for _, w23 := range tempMnemonicPossibilities[22] {

																										preSeed := []string{
																											enKeyMap[frMap[w1]],
																											enKeyMap[frMap[w2]],
																											enKeyMap[frMap[w3]],
																											enKeyMap[frMap[w4]],
																											enKeyMap[frMap[w5]],
																											enKeyMap[frMap[w6]],
																											enKeyMap[frMap[w7]],
																											enKeyMap[frMap[w8]],
																											enKeyMap[frMap[w9]],
																											enKeyMap[frMap[w10]],
																											enKeyMap[frMap[w11]],
																											enKeyMap[frMap[w12]],
																											enKeyMap[frMap[w13]],
																											enKeyMap[frMap[w14]],
																											enKeyMap[frMap[w15]],
																											enKeyMap[frMap[w16]],
																											enKeyMap[frMap[w17]],
																											enKeyMap[frMap[w18]],
																											enKeyMap[frMap[w19]],
																											enKeyMap[frMap[w20]],
																											enKeyMap[frMap[w21]],
																											w22,
																											w23,
																										}

																										nbMnemonicTested++

																										// if the 8 checksum words are valid, calculate the adress (which is computationally intensive)
																										if are8ChecksumWordsCorrect(preSeed, treasureHuntVerifierWords) {

																											// Create a single string (mnemonic) with the words
																											stringMnemonic := ""
																											for index, word := range preSeed {
																												if index == 0 {
																													stringMnemonic += word
																												} else {
																													stringMnemonic += " " + word
																												}
																											}
																											// add the last word
																											stringMnemonic += W24[0]

																											fmt.Println("Mnemonic try exact adress:", stringMnemonic)

																											address, err := GenerateBIP84Address(stringMnemonic)
																											if err != nil {
																												log.Fatal(err)
																											}

																											// fmt.Printf("BIP84 Bitcoin Address: %s\n", address)

																											if address == winAdress {
																												fmt.Println("Found the exact mnemonic!", stringMnemonic)
																												return
																											}
																										}
																									}
																								}
																							}
																						}
																					}
																				}
																			}
																		}
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}

		}
	}

	fmt.Println("Total mnemonic tested:", nbMnemonicTested)

}
