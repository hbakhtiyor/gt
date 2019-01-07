package fsend

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh/terminal"
)

func PrepareDownload(url, password string, ignoreVersion bool) (*FileInfo, error) {
	fileInfo, err := NewFileInfo(url, password)
	if err != nil {
		return nil, err
	}

	if status, err := CheckVersion(fileInfo, ignoreVersion); err != nil {
		return nil, err
	} else if !status {
		return nil, errors.New("Potentially incompatible server version, use --ignore-version to disable version checks")
	}

	if info, err := Exists(fileInfo); err != nil {
		return nil, err
	} else if info.PasswordRequired && fileInfo.Password == "" {
		fmt.Print("A password is required, please enter it now: ")
		password, err := terminal.ReadPassword(0)
		if err != nil {
			return nil, err
		}
		fmt.Println()
		if err := fileInfo.SetPassword(string(password)); err != nil {
			return nil, err
		}
	}

	_, err = GetMetadata(fileInfo)
	if err != nil {
		return nil, err
	}

	return fileInfo, nil
}
