package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
)

const (
	englishWordsFile = "wordlist-en.txt"
	frenchWordsFile  = "wordlist-fr.txt"
)

// Return the words as a map
func fromFileToHash(filename string) map[string]int {

	wordMap := make(map[string]int)

	// Open file
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("failed to open file: %s", err)
	}
	defer file.Close()

	// Create a new scanner to read the file line by line
	scanner := bufio.NewScanner(file)

	wordIndex := 1

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
func main() {

	enMap := fromFileToHash(englishWordsFile)
	frMap := fromFileToHash(frenchWordsFile)

	fmt.Println(enMap)
	fmt.Println(frMap)

	// fmt.Printf("Left shift by 2 bits: %08b (%d)\n", 1<<3, 1<<3)
}
