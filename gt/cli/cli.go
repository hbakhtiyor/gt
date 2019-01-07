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
	"io"

	"github.com/hbakhtiyor/grab"
	"github.com/hbakhtiyor/gt/gt/fsend"
	"github.com/hbakhtiyor/gt/gt/utils"
	"github.com/hbakhtiyor/gt/gt/wt"
	"golang.org/x/crypto/ssh/terminal"
	aesgcm "github.com/hbakhtiyor/openssl_gcm"
)

var (
	inProgress = 0
	failed     = 0
	succeeded  = 0
)

var programName string

func Run() {
	// Download/upload files via wetransfer.com, send.firefox.com
	programName = os.Args[0]
	fsCommand := flag.NewFlagSet("fs", flag.ExitOnError)
	wtCommand := flag.NewFlagSet("wt", flag.ExitOnError)

	messageFlag := wtCommand.String("m", "", "Message description for the transfer.")
	fromFlag := wtCommand.String("f", "", "Sender email.")
	toFlag := wtCommand.String("t", "", "Recipient emails. Separate with comma(,)")
	printFlag := wtCommand.Bool("p", false, "Only print the direct link (without downloading it)")
	limitParallelFlag := flag.Int("l", runtime.NumCPU(), "Parallel limit for uploading/downloading files")

	passwordFlag := flag.Bool("pwd", false, "Prompt to set a password to the file.")
	downloadLimitFlag := fsCommand.Int("dl", 0, "Set download limit of the file.")
	// TODO show some flags in some subcommands
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Printf("Usage: %s [command] [file] ... [url] ...\n", programName)
		fmt.Printf("The most commonly used %s commands are:\n", programName)
		fmt.Println(" fs  Upload files via Firefox Send")
		fmt.Println(" wt  Upload files via WeTransfer")
		flag.PrintDefaults()
		return
	}

	args := flag.Args()

	switch os.Args[1] {
	case "wt":
		wtCommand.Parse(os.Args[2:])
		if wtCommand.NArg() < 1 {
			fmt.Printf("Usage: %s wt [file] ... [url] ...\n", programName)
			wtCommand.PrintDefaults()
			return
		}
		args = wtCommand.Args()
	case "fs":
		fsCommand.Parse(os.Args[2:])
		if fsCommand.NArg() < 1 {
			fmt.Printf("Usage: %s fs [file] ... [url] ...\n", programName)
			fsCommand.PrintDefaults()
			return
		}
		args = fsCommand.Args()
	// default:
	// 	// TODO for filename need
	// 	fmt.Printf("%q is not valid command.\n", os.Args[1])
	// 	os.Exit(2)
	}

	filePaths, fileNames, rawURLs := getResources(args)

	if len(filePaths) == 0 && len(rawURLs) == 0 {
		fmt.Printf("%s: %s\n", programName, "There are no file(s)/url(s) to upload/download")
	}

	// Files to download
	if len(rawURLs) > 0 {
		if wtCommand.Parsed() && *printFlag {
			// TODO Print only wt direct download links
			return
		}

		password := checkPasswordPrompt(*passwordFlag)
		err := downloadFiles(rawURLs, *limitParallelFlag, password, false)
		checkError(err, true)
	}

	// Files to upload
	if len(filePaths) > 0 {
		if wtCommand.Parsed() {
			result, err := wt.UploadFiles(filePaths, fileNames, *messageFlag, *fromFlag, strings.Split(*toFlag, ","), *limitParallelFlag)
			checkError(err, true)

			// TODO [Copied to clipboard]
			// https://github.com/atotto/clipboard ?
			fmt.Printf("\n%s: %v\n", programName, result.ShortenedURL)
		} else if fsCommand.Parsed() {
			password := checkPasswordPrompt(*passwordFlag)
			for _, filePath := range filePaths {
				fileInfo := &fsend.FileInfo{Password: password, DownloadLimit: *downloadLimitFlag}
				result, err := fsend.UploadFile(filePath, fileInfo, false)
				checkError(err, false)
				if result != nil {
					fmt.Printf("%s\n", result.URL)
				}
			}
		}
	}
}

func checkError(err error, exit bool) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", programName, err)
		if exit {
			os.Exit(1)
		}
	}
}

func checkPasswordPrompt(flag bool) string {
	if flag {
		fmt.Print("Please enter password now: ")
		password, err := terminal.ReadPassword(0)
		checkError(err, true)
		fmt.Println()
		return string(password)
	}
	return ""
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

// DownloadFiles download files from the given a `we.tl/', `wetransfer.com/downloads/', `send.firefox.com` or any URLs.
//
// First a direct link is retrieved (via GetDirectLink() for wt), the filename will
// be extracted to it and it will be fetched and stored on the current
// working directory.
func downloadFiles(rawURLs []string, workers int, password string, ignoreVersion bool) error {
	requests := createGrabRequests(rawURLs)

	if len(requests) == 0 {
		return fmt.Errorf("there are no url(s) to download")
	}

	fmt.Printf("Downloading %d files...\n", len(requests))
	client := grab.NewClient()

	respch := client.DoBatch(workers, requests...)

	return monitorDownloads(respch, len(requests))
}


func monitorDownloads(respch <-chan *grab.Response, ln int) error {
	responses := make([]*grab.Response, 0, ln)
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


func createGrabRequests(rawURLs []string) []*grab.Request {
	reqs := []*grab.Request{}
	for _, rawURL := range rawURLs {
		var req *grab.Request
		var fi *fsend.FileInfo
		downloadLink, dst := rawURL, "."

		URL, err := url.Parse(rawURL)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "Error downloading %s: %v\n", rawURL, err)
			continue
		}

		switch URL.Hostname() {
		case "we.tl", "wetransfer.com":
			// TODO subdomains, e.g/ sub.wetransfer.com
			// TODO make it run in concurrency
			downloadLink, err = wt.GetDirectLink(rawURL)
			if err != nil {
				failed++
				fmt.Fprintf(os.Stderr, "Error downloading %s: %v\n", rawURL, err)
				continue
			}
		case "send.firefox.com":
			// TODO custom domain too
			fi, err = fsend.PrepareDownload(rawURL, "", false)
			if err != nil {
				failed++
				fmt.Fprintf(os.Stderr, "Error downloading %s: %v\n", rawURL, err)
				continue
			}

			downloadLink, dst = fmt.Sprintf(fi.BaseURL+"api/download/%s", fi.FileID), fi.Name
		}

		req, err = grab.NewRequest(dst, downloadLink)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "Error downloading %s: %v\n", rawURL, err)
			continue
		}

		if fi != nil {
			func(key, iv []byte, size int64) {
				req.GetReader = func(reader io.Reader) (io.Reader, error) {
					// https://www.w3.org/TR/WebCryptoAPI/#aes-gcm-operations
					r, err := aesgcm.NewGcmDecryptReader(reader, key, iv, nil, size)
					if err != nil {
						return nil, err
					}
					return r, nil
				}
			}(fi.Key.EncryptKey, fi.Key.EncryptIV, fi.Size)

			req.HTTPRequest.Header.Set("Authorization", fi.Key.AuthHeader())
			req.Size = fi.Size
			fi = nil
		}

		reqs = append(reqs, req)
	}

	return reqs
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
