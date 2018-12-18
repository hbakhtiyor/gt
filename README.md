# gt

gt is a simple cli to download/upload files via multiple file-sharing providers, currently supported [wetransfer.com](https://wetransfer.com/).


## Usage

```
$ gt
Usage: ./gt [file] ... [url] ...
  -f string
    	Sender email.
  -l int
    	Parallel limit for uploading/downloading files (default 4)
  -m string
    	Message description for the transfer.
  -p	Only print the direct link (without downloading it)
  -t string
    	Recipient emails. Separate with comma(,)
```

Example of upload files

```
$ gt /some/file1.txt file2.txt
```

Example of download files

```
$ gt https://we.tl/t-qQz6vBtrr8
```
