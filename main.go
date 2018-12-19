package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	// Download/upload files via wetransfer.com
	programName := os.Args[0]
	messageFlag := flag.String("m", "", "Message description for the transfer.")
	fromFlag := flag.String("f", "", "Sender email.")
	toFlag := flag.String("t", "", "Recipient emails. Separate with comma(,)")
	printFlag := flag.Bool("p", false, "Only print the direct link (without downloading it)")
	limitParallelFlag := flag.Int("l", runtime.NumCPU(), "Parallel limit for uploading/downloading files")

	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Printf("Usage: %s [file] ... [url] ...\n", programName)
		flag.PrintDefaults()
		return
	}

	filePaths, fileNames, rawURLs := getResources(flag.Args())

	if len(filePaths) == 0 && len(rawURLs) == 0 {
		fmt.Printf("%s: %s\n", programName, "There are no file(s)/url(s) to upload/download")
	}

	// Files to download
	for _, rawURL := range rawURLs {
		var (
			err  error
			link string
		)

		if *printFlag {
			link, err = GetDirectLink(rawURL)
		} else {
			err = DownloadFile(rawURL)
		}
		if err != nil {
			fmt.Printf("%s: %v\n", programName, err)
		} else if *printFlag && link != "" {
			fmt.Println(link)
		}
	}

	// Files to upload
	if len(filePaths) > 0 {
		result, err := UploadFile(filePaths, fileNames, *messageFlag, *fromFlag, strings.Split(*toFlag, ","), *limitParallelFlag)
		if err != nil {
			fmt.Printf("%s: %v\n", programName, err)
			return
		}

		// TODO [Copied to clipboard]
		// https://github.com/atotto/clipboard ?
		fmt.Printf("\n%s: %v\n", programName, result.ShortenedURL)
	}
}

func getResources(URIs []string) (filePaths []string, fileNames []string, rawURLs []string) {
	for _, uri := range URIs {
		if IsValidURL(uri) {
			found := false
			for _, f := range rawURLs {
				if f == uri {
					found = true
					break
				}
			}
			if !found {
				rawURLs = append(rawURLs, uri)
			}
		} else {
			// Check that all files exists
			if stat, err := os.Stat(uri); os.IsNotExist(err) {
				fmt.Printf("%s doesn't exist, ignoring...\n", uri)
			} else if stat.Size() == 0 {
				fmt.Printf("%s is empty, ignoring...\n", uri)
			} else {
				fileName := filepath.Base(uri)
				// Check that there are no duplicates filenames,
				// despite possible different dirname
				found := false
				for _, f := range fileNames {
					if f == fileName {
						found = true
						break
					}
				}

				if !found {
					fileNames = append(fileNames, fileName)
					filePaths = append(filePaths, uri)
				}
			}
		}
	}
	return
}
