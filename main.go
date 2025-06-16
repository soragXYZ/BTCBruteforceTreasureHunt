package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"os"
)

const (
	englishWordsFile = "wordlist-en.txt"
	frenchWordsFile  = "wordlist-fr.txt"
)

// Load the 2048 words into memory, return them as a map
func fromFileToHash(filename string) map[string]uint {

	wordMap := make(map[string]uint)

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
		wordIndex++
	}

	// Check for errors during the scan
	if err := scanner.Err(); err != nil {
		log.Fatalf("error reading file: %s", err)
	}

	return wordMap
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

func main() {

	enMap := fromFileToHash(englishWordsFile)
	// frMap := fromFileToHash(frenchWordsFile)

	verifierWords := []string{
		"alien",
		"detect",
		"flip",
		"gas",
		"organ",
		"pleasant",
		"staff",
		"trigger",
		"stumble", // for test, correct
		"stumble", // for test, correct
	}

	preSeed := []string{"spawn", "mass", "begin", "twist", "sausage", "other", "race", "amateur", "nasty", "follow", "rookie", "leader", "kiwi", "normal", "rifle", "square", "soap", "fault", "pet", "involve", "evolve", "call", "canyon"}

	// We know that every mnemonic made from the first 23 words and a verifier word are valid
	// So we loop until we found 23 words which are compatible with the given verifier word list

	for _, word := range verifierWords {

		mnemonic := append(preSeed, word)

		// fmt.Println("Trying mnemonic: ", mnemonic)

		entropyAndChecksum := getEntropyAndChecksum(enMap, mnemonic)

		if isSeedValid(entropyAndChecksum, enMap[word]) {
			fmt.Println("Mnemonic found ! ", mnemonic)
			return

		} else {
			// 1 verifier word invalid means that one of the 23 words used is invalid
			// Process to the next iteration
			continue
		}

	}

}
