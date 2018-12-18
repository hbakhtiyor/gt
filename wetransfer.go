// Download/upload files via wetransfer.com
//
// transfergo is a CLI to download/upload files via wetransfer.com.
//
// It exposes `download' and `upload' subcommands, respectively used to download
// files from a `we.tl' or `wetransfer.com/downloads' URLs and upload files that
// will be shared via emails or link.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	WeTransferAPIURL         = "https://wetransfer.com/api/v4/transfers"
	WeTransferDownloadURL    = WeTransferAPIURL + "/%s/download"
	WeTransferUploadEmailURL = WeTransferAPIURL + "/email"
	WeTransferUploadLinkURL  = WeTransferAPIURL + "/link"
	WeTransferFilesURL       = WeTransferAPIURL + "/%s/files"
	WeTransferPartPutURL     = WeTransferFilesURL + "/%s/part-put-url"
	WeTransferFinalizeMPPURL = WeTransferFilesURL + "/%s/finalize-mpp"
	WeTransferFinalizeURL    = WeTransferAPIURL + "/%s/finalize"

	WeTransferDefaultChunkSize = 5242880

	Debug = false
)

type WeRequest struct {
	SecurityHash string `json:"security_hash"`
	RecipientID  string `json:"recipient_id"`
}

type WeDirectLink struct {
	DirectLink string `json:"direct_link"`
}

type WeID struct {
	ID string `json:"id"`
}

type WeShortenedURL struct {
	ShortenedURL string `json:"shortened_url"`
}

type WeURL struct {
	RawURL string `json:"url"`
}

type WeUpload struct {
	FileNames  []string `json:"filenames"`
	From       string   `json:"from"`
	Message    string   `json:"message"`
	Recipients []string `json:"recipients"`
	UILanguage string   `json:"ui_language"`
}

type WeFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type WeChunk struct {
	ChunkCRC    uint32 `json:"chunk_crc"`
	ChunkNumber int    `json:"chunk_number"`
	ChunkSize   int    `json:"chunk_size"`
	Retries     int    `json:"retries"`
}

type WeChunkCount struct {
	ChunkCount int `json:"chunk_count"`
}

// DefaultClient is the default Client and is used by Put, and Options.
var DefaultClient = &http.Client{}

// GetDirectLink returns the download URL (AKA `direct_link') as a str.
//
// Given a wetransfer.com download URL download return the downloadable URL.
//
// The URL should be of the form `https://we.tl/' or
// `https://wetransfer.com/downloads/'. If it is a short URL (i.e. `we.tl')
// the redirect is followed in order to retrieve the corresponding
// `wetransfer.com/downloads/' URL.
//
// The following type of URLs are supported:
//  - `https://we.tl/<short_url_id>`:
// 	received via link upload, via email to the sender and printed by
// 	`upload` action
//  - `https://wetransfer.com/<transfer_id>/<security_hash>`:
// 	directly not shared in any ways but the short URLs actually redirect to
// 	them
//  - `https://wetransfer.com/<transfer_id>/<recipient_id>/<security_hash>`:
// 	received via email by recipients when the files are shared via email
// 	upload
func GetDirectLink(rawURL string) (string, error) {
	if strings.HasPrefix(rawURL, "https://we.tl/") {
		response, err := http.Head(rawURL)
		if err != nil {
			return "", err
		}
		if response.StatusCode != 200 {
			if Debug {
				log.Printf("GetDirectLink: Error occurs while processing HEAD request: %s %v\n", rawURL, response)
			}
			return "", errors.New(response.Status)
		}
		rawURL = response.Request.URL.String()
	}

	path := strings.Replace(rawURL, "https://wetransfer.com/downloads/", "", 1)
	params := strings.Split(path, "/")

	transferID, recipientID, securityHash := "", "", ""

	if len(params) == 2 {
		transferID, securityHash = params[0], params[1]
	} else if len(params) == 3 {
		transferID, recipientID, securityHash = params[0], params[1], params[2]
	}

	j := &WeRequest{securityHash, recipientID}
	b := bytes.NewBuffer(nil)
	if err := json.NewEncoder(b).Encode(j); err != nil {
		return "", err
	}

	response, err := http.Post(
		fmt.Sprintf(WeTransferDownloadURL, transferID),
		"application/json; charset=utf-8",
		b,
	)

	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		if Debug {
			bodyBytes, _ := ioutil.ReadAll(response.Body)
			log.Printf("GetDirectLink: Error occurs while processing POST request: %s %s %v\n", rawURL, bodyBytes, response)
		}
		return "", errors.New(response.Status)
	}

	if Debug {
		bodyBytes, _ := ioutil.ReadAll(response.Body)
		//reset the response body to the original unread state
		response.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
		log.Printf("GetDirectLink: Received body while processing POST request: %s %s %v\n", rawURL, bodyBytes, response)
	}

	result := &WeDirectLink{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.DirectLink, nil
}

// DownloadFile downloads a file from the given a `we.tl/' or `wetransfer.com/downloads/' URL.
//
// First a direct link is retrieved (via GetDirectLink()), the filename will
// be extracted to it and it will be fetched and stored on the current
// working directory.
func DownloadFile(rawURL string) error {
	directLink, err := GetDirectLink(rawURL)
	if err != nil {
		return err
	}
	URL, err := url.Parse(directLink)
	if err != nil {
		return err
	}
	paths := strings.Split(URL.Path, "/")
	fileName := paths[len(paths)-1]

	response, err := http.Get(directLink)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		if Debug {
			bodyBytes, _ := ioutil.ReadAll(response.Body)
			log.Printf("DownloadFile: Error occurs while processing GET request: %s %s %v\n", rawURL, bodyBytes, response)
		}
		return errors.New(response.Status)
	}

	reader := bufio.NewReader(response.Body)
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = io.Copy(file, reader); err != nil {
		return err
	}
	return nil
}

// PrepareEmailUpload returns the parsed JSON response.
//
// Given a list of filenames, message a sender and recipients prepare for
// the email upload.
func PrepareEmailUpload(fileNames []string, message string, sender string, recipients []string) (*WeID, error) {
	j := &WeUpload{fileNames, sender, message, recipients, "en"}
	b := bytes.NewBuffer(nil)
	if err := json.NewEncoder(b).Encode(j); err != nil {
		return nil, err
	}

	response, err := http.Post(
		WeTransferUploadEmailURL,
		"application/json; charset=utf-8",
		b,
	)

	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		if Debug {
			bodyBytes, _ := ioutil.ReadAll(response.Body)
			log.Printf("PrepareEmailUpload: Error occurs while processing POST request: %s %v\n", bodyBytes, response)
		}
		return nil, errors.New(response.Status)
	}
	if Debug {
		bodyBytes, _ := ioutil.ReadAll(response.Body)
		//reset the response body to the original unread state
		response.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
		log.Printf("PrepareEmailUpload: Received body while processing POST request: %s %v\n", bodyBytes, response)
	}
	result := &WeID{}

	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// PrepareLinkUpload returns the parsed JSON response.
//
// Given a list of filenames and a message prepare for the link upload.
func PrepareLinkUpload(fileNames []string, message string) (*WeID, error) {
	j := &WeUpload{
		FileNames:  fileNames,
		Message:    message,
		UILanguage: "en",
	}

	b := bytes.NewBuffer(nil)
	if err := json.NewEncoder(b).Encode(j); err != nil {
		return nil, err
	}

	response, err := http.Post(
		WeTransferUploadLinkURL,
		"application/json; charset=utf-8",
		b,
	)

	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		if Debug {
			bodyBytes, _ := ioutil.ReadAll(response.Body)
			log.Printf("PrepareLinkUpload: Error occurs while processing POST request: %s %v\n", bodyBytes, response)
		}
		return nil, errors.New(response.Status)
	}
	if Debug {
		bodyBytes, _ := ioutil.ReadAll(response.Body)
		//reset the response body to the original unread state
		response.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
		log.Printf("PrepareLinkUpload: Received body while processing POST request: %s %v\n", bodyBytes, response)
	}

	result := &WeID{}

	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// PrepareFileUpload returns the parsed JSON response.
//
// Given a transfer_id and file prepare it for the upload.
func PrepareFileUpload(transferID string, filePath string) (*WeID, error) {
	fileStat, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}

	j := &WeFile{filepath.Base(filePath), fileStat.Size()}

	b := bytes.NewBuffer(nil)
	if err := json.NewEncoder(b).Encode(j); err != nil {
		return nil, err
	}

	response, err := http.Post(
		fmt.Sprintf(WeTransferFilesURL, transferID),
		"application/json; charset=utf-8",
		b,
	)

	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		if Debug {
			bodyBytes, _ := ioutil.ReadAll(response.Body)
			log.Printf("PrepareFileUpload: Error occurs while processing POST request: %s %v\n", bodyBytes, response)
		}
		return nil, errors.New(response.Status)
	}
	if Debug {
		bodyBytes, _ := ioutil.ReadAll(response.Body)
		//reset the response body to the original unread state
		response.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
		log.Printf("PrepareFileUpload: Received body while processing POST request: %s %v\n", bodyBytes, response)
	}

	result := &WeID{}

	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// FinalizeUpload returns the parsed JSON response.
//
// Given a transfer_id finalize the upload.
func FinalizeUpload(transferID string) (*WeShortenedURL, error) {
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf(WeTransferFinalizeURL, transferID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	response, err := DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		if Debug {
			bodyBytes, _ := ioutil.ReadAll(response.Body)
			log.Printf("FinalizeUpload: Error occurs while processing PUT request: %s %v\n", bodyBytes, response)
		}
		return nil, errors.New(response.Status)
	}
	if Debug {
		bodyBytes, _ := ioutil.ReadAll(response.Body)
		//reset the response body to the original unread state
		response.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
		log.Printf("FinalizeUpload: Received body while processing PUT request: %s %v\n", bodyBytes, response)
	}

	result := &WeShortenedURL{}

	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// UploadChunks uploads file partially.
//
// Given a transfer_id, file_id and file upload it.
func UploadChunks(transferID string, fileID string, filePath string, defaultChunkSize int) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	fileStat, err := os.Stat(filePath)
	if err != nil {
		return err
	}
	fileSize := int(fileStat.Size())
	reader := bufio.NewReader(file)
	chunk := make([]byte, defaultChunkSize)
	chunkNumber, totalChunkSize := 0, 0

	for {
		fmt.Printf(
			"\rtransferred %v / %v bytes (%.2f%%)",
			totalChunkSize,
			fileSize,
			100*(float64(totalChunkSize)/float64(fileSize)),
		)

		chunkSize, err := reader.Read(chunk)
		totalChunkSize += chunkSize
		if err == io.EOF || chunkSize == 0 {
			break
		} else if err != nil {
			return err
		}
		chunkNumber++

		j := &WeChunk{crc32.ChecksumIEEE(chunk), chunkNumber, chunkSize, 0}

		b := bytes.NewBuffer(nil)
		if err := json.NewEncoder(b).Encode(j); err != nil {
			return err
		}

		response, err := http.Post(
			fmt.Sprintf(WeTransferPartPutURL, transferID, fileID),
			"application/json; charset=utf-8",
			b,
		)

		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			if Debug {
				bodyBytes, _ := ioutil.ReadAll(response.Body)
				log.Printf("UploadChunks: Error occurs while processing POST request: %s %v\n", bodyBytes, response)
			}
			return errors.New(response.Status)
		}
		if Debug {
			bodyBytes, _ := ioutil.ReadAll(response.Body)
			//reset the response body to the original unread state
			response.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
			log.Printf("UploadChunks: Received body while processing POST request: %s %v\n", bodyBytes, response)
		}

		result := &WeURL{}

		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			return err
		}

		req, err := http.NewRequest(http.MethodOptions, result.RawURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Origin", "https://wetransfer.com")
		req.Header.Set("Access-Control-Request-Method", "PUT")
		response, err = DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			if Debug {
				bodyBytes, _ := ioutil.ReadAll(response.Body)
				log.Printf("UploadChunks: Error occurs while processing OPTIONS request: %s %v\n", bodyBytes, response)
			}
			return errors.New(response.Status)
		}
		if Debug {
			bodyBytes, _ := ioutil.ReadAll(response.Body)
			//reset the response body to the original unread state
			response.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
			log.Printf("UploadChunks: Received body while processing OPTIONS request: %s %v\n", bodyBytes, response)
		}

		req, err = http.NewRequest(http.MethodPut, result.RawURL, bytes.NewBuffer(chunk))
		if err != nil {
			return err
		}
		response, err = DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			if Debug {
				bodyBytes, _ := ioutil.ReadAll(response.Body)
				log.Printf("UploadChunks: Error occurs while processing PUT request: %s %v\n", bodyBytes, response)
			}
			return errors.New(response.Status)
		}
		if Debug {
			bodyBytes, _ := ioutil.ReadAll(response.Body)
			//reset the response body to the original unread state
			response.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
			log.Printf("UploadChunks: Received body while processing PUT request: %s %v\n", bodyBytes, response)
		}
	}

	j := &WeChunkCount{chunkNumber}

	b := bytes.NewBuffer(nil)
	if err := json.NewEncoder(b).Encode(j); err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf(WeTransferFinalizeMPPURL, transferID, fileID), b)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	response, err := DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		if Debug {
			bodyBytes, _ := ioutil.ReadAll(response.Body)
			log.Printf("UploadChunks: Error occurs while processing PUT request: %s %v\n", bodyBytes, response)
		}
		return errors.New(response.Status)
	}
	if Debug {
		bodyBytes, _ := ioutil.ReadAll(response.Body)
		//reset the response body to the original unread state
		response.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
		log.Printf("UploadChunks: Received body while processing PUT request: %s %v\n", bodyBytes, response)
	}

	return nil
}

// UploadFile returns the short URL of the transfer on success.
//
// Given a list of files upload them and return the corresponding URL.
//
// Also accepts optional parameters:
//  - `message': message used as a description of the transfer
//  - `sender': email address used to receive an ACK if the upload is
// 			 successfull. For every download by the recipients an email
// 			 will be also sent
//  - `recipients': list of email addresses of recipients. When the upload
// 				 succeed every recipients will receive an email with a link
//
// If both sender and recipient parameters are passed the email upload will be
// used. Otherwise, the link upload will be used.
func UploadFile(filePaths []string, fileNames []string, message string, sender string, recipients []string, limitParallel int) (*WeShortenedURL, error) {
	transferID := ""
	if sender != "" && len(recipients) > 0 {
		// email upload
		result, err := PrepareEmailUpload(fileNames, message, sender, recipients)
		if err != nil {
			return nil, err
		}
		transferID = result.ID
	} else {
		// link upload
		result, err := PrepareLinkUpload(fileNames, message)
		if err != nil {
			return nil, err
		}
		transferID = result.ID
	}

	var wg sync.WaitGroup
	// TODO goroutine termination and error handling
	// If any of the goroutine fails, return that first error immediately,
	// and stop all goroutine
	chErr := make(chan error)
	for i, filePath := range filePaths {
		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			result, err := PrepareFileUpload(transferID, filePath)
			if err != nil {
				chErr <- err
				return
			}
			fileID := result.ID
			err = UploadChunks(transferID, fileID, filePath, WeTransferDefaultChunkSize)
			if err != nil {
				chErr <- err
				return
			}
		}(filePath)
		if (i+1)%limitParallel == 0 {
			wg.Wait()
		}
	}

	wg.Wait()
	result, err := FinalizeUpload(transferID)
	if err != nil {
		return nil, err
	}
	return result, nil
}
