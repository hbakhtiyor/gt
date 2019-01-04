package cli

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/hbakhtiyor/grab"
	"github.com/hbakhtiyor/gt/gt/utils"
	"github.com/hbakhtiyor/gt/gt/wt"
)

var (
	inProgress = 0
	failed     = 0
	succeeded  = 0
)

func Run() {
	// Download/upload files via wetransfer.com, send.firefox.com
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
	if len(rawURLs) > 0 {
		if *printFlag {
			fmt.Println(getDownloadLinks(rawURLs))
		} else {
			err := downloadFiles(rawURLs, *limitParallelFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", programName, err)
				os.Exit(1)
			}
		}
	}

	// Files to upload
	if len(filePaths) > 0 {
		result, err := wt.UploadFile(filePaths, fileNames, *messageFlag, *fromFlag, strings.Split(*toFlag, ","), *limitParallelFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", programName, err)
			os.Exit(1)
		}

		// TODO [Copied to clipboard]
		// https://github.com/atotto/clipboard ?
		fmt.Printf("\n%s: %v\n", programName, result.ShortenedURL)
	}
}

func getResources(URIs []string) (filePaths []string, fileNames []string, rawURLs []string) {
	for _, uri := range URIs {
		if utils.IsValidURL(uri) {
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

// DownloadFiles download files from the given a `we.tl/', `wetransfer.com/downloads/', or any URLs.
//
// First a direct link is retrieved (via GetDirectLink()), the filename will
// be extracted to it and it will be fetched and stored on the current
// working directory.
func downloadFiles(rawURLs []string, workers int) error {
	directLinks := getDownloadLinks(rawURLs)

	if len(directLinks) == 0 {
		return fmt.Errorf("There are no url(s) to download\n")
	}

	fmt.Printf("Downloading %d files...\n", len(directLinks))
	respch, err := grab.GetBatch(workers, ".", directLinks...)
	if err != nil {
		return err
	}

	// monitor downloads
	responses := make([]*grab.Response, 0, len(directLinks))
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case resp := <-respch:
			if resp != nil {
				// a new response has been received and has started downloading
				responses = append(responses, resp)
			} else {
				// channel is closed - all downloads are complete
				updateUI(responses)
				fmt.Printf(
					"Finished %d successful, %d failed, %d incomplete.\n",
					succeeded,
					failed,
					inProgress)

				return nil
			}

		case <-t.C:
			// update UI every 200ms
			updateUI(responses)
		}
	}
}

func getDownloadLinks(rawURLs []string) []string {
	directLinks := []string{}
	for _, rawURL := range rawURLs {
		directLink := rawURL
		URL, err := url.Parse(rawURL)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "Error downloading %s: %v\n", rawURL, err)
			continue
		}

		hostName := URL.Hostname()
		if hostName == "we.tl" || hostName == "wetransfer.com" {
			// TODO make it run in concurrency
			directLink, err = wt.GetDirectLink(rawURL)
			if err != nil {
				failed++
				fmt.Fprintf(os.Stderr, "Error downloading %s: %v\n", rawURL, err)
				continue
			}
		}
		directLinks = append(directLinks, directLink)
	}
	return directLinks
}

// updateUI prints the progress of all downloads to the terminal
func updateUI(responses []*grab.Response) {
	// clear lines for incomplete downloads
	if inProgress > 0 {
		fmt.Printf("\033[%dA\033[K", inProgress)
	}

	// print newly completed downloads
	for i, resp := range responses {
		if resp != nil && resp.IsComplete() {
			if resp.Err() != nil {
				failed++
				fmt.Fprintf(os.Stderr, "Error downloading %s: %v\n",
					resp.Request.URL(),
					resp.Err())
			} else {
				succeeded++
				fmt.Printf("Finished %s %d / %d bytes (%d%%)\n",
					resp.Filename,
					resp.BytesComplete(),
					resp.Size,
					int(100*resp.Progress()))
			}
			responses[i] = nil
		}
	}

	// print progress for incomplete downloads
	inProgress = 0
	for _, resp := range responses {
		if resp != nil {
			fmt.Printf("Downloading %s %d / %d bytes (%d%%) - %.02fKBp/s ETA: %ds \033[K\n",
				resp.Filename,
				resp.BytesComplete(),
				resp.Size,
				int(100*resp.Progress()),
				resp.BytesPerSecond()/1024,
				int64(resp.ETA().Sub(time.Now()).Seconds()))
			inProgress++
		}
	}
}
