package cdn_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strconv"
	"testing"

	logger "github.com/ipfs/go-log/v2"
	"github.com/plexsysio/go-msuite"
	cdn "github.com/plexsysio/msuite-services/cdn/service"
)

func TestCDNFlow(t *testing.T) {
	logger.SetLogLevel("*", "Error")

	svc, err := msuite.New(
		msuite.WithServices("CDN"),
		msuite.WithP2P(10001),
		msuite.WithHTTP(10002),
		msuite.WithFiles(),
	)
	if err != nil {
		t.Fatal(err)
	}

	err = cdn.NewCDNService(svc)
	if err != nil {
		t.Fatal(err)
	}

	baseURL := "http://localhost:10002/cdn/v1"

	err = svc.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Stop(context.Background())

	tc := []struct {
		testName  string
		format    string
		index     string
		files     []f
		reference string
	}{
		{
			testName: "single_file",
			format:   "single",
			files: []f{
				{
					name:        "test.jpeg",
					data:        getRandData(512),
					contentType: "image/jpeg",
				},
			},
		},
		{
			testName: "multiple_files",
			format:   "tar",
			files: []f{
				{
					filePath: "file1.txt",
					data:     getRandData(128),
				},
				{
					filePath: "dir1/file2.jpeg",
					data:     getRandData(512),
				},
				{
					filePath: "dir1/file3.html",
					data:     getRandData(256),
				},
				{
					filePath: "dir1/dir2/file4.txt",
					data:     getRandData(64),
				},
			},
		},
		{
			testName: "multiple_files",
			format:   "multipart",
			files: []f{
				{
					filePath:    "file1.txt",
					name:        "file1.txt",
					data:        getRandData(128),
					contentType: "text/plain",
				},
				{
					filePath:    "dir1/file2.jpeg",
					name:        "file2.jpeg",
					data:        getRandData(512),
					contentType: "image/jpeg",
				},
				{
					filePath:    "dir1/file3.html",
					name:        "file3.html",
					data:        getRandData(256),
					contentType: "text/html; charset=utf-8",
				},
				{
					filePath:    "dir1/dir2/file4.txt",
					name:        "file4.txt",
					data:        getRandData(64),
					contentType: "text/plain",
				},
			},
		},
		{
			testName: "multiple_files_with_index",
			format:   "tar",
			index:    "index.html",
			files: []f{
				{
					filePath: "index.html",
					data:     getRandData(128),
				},
				{
					filePath: "dir1/file2.jpeg",
					data:     getRandData(512),
				},
				{
					filePath: "dir1/file3.html",
					data:     getRandData(256),
				},
				{
					filePath: "dir1/dir2/file4.txt",
					data:     getRandData(64),
				},
			},
		},
	}

	for idx, c := range tc {
		t.Run(fmt.Sprintf("%s/%s/%s", "put", c.testName, c.format), func(t *testing.T) {
			postURL := baseURL + "/put"
			var (
				req *http.Request
				err error
			)
			switch c.format {
			case "single":
				req, err = http.NewRequest(
					"POST",
					fmt.Sprintf("%s?name=%s", postURL, c.files[0].name),
					bytes.NewBuffer(c.files[0].data),
				)
				req.Header.Set("Content-Type", c.files[0].contentType)
			case "tar":
				tarBuf := tarFiles(t, c.files)
				req, err = http.NewRequest(
					"POST",
					postURL,
					tarBuf,
				)
				req.Header.Set("Content-Type", "application/tar")
			case "multipart":
				mpBuf, boundary := multipartFiles(t, c.files)
				req, err = http.NewRequest(
					"POST",
					postURL,
					mpBuf,
				)
				req.Header.Set("Content-Type", fmt.Sprintf("multipart/form-data; boundary=%q", boundary))
			default:
				t.Fatal("invalid format of test")
			}

			if err != nil {
				t.Fatal(err)
			}

			if c.index != "" {
				req.Header.Set("index-document", c.index)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}

			if resp.StatusCode != http.StatusCreated {
				t.Fatal("incorrect HTTP response code")
			}

			defer resp.Body.Close()

			respBuf, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			m := &cdn.ManifestObj{}
			err = json.Unmarshal(respBuf, m)
			if err != nil {
				t.Fatal(err)
			}

			tc[idx].reference = m.Cid
		})
	}

	fetchAndCheck := func(t *testing.T, url string, exp []byte) {
		t.Helper()

		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatal("invalid response code")
		}

		respBuf, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		defer resp.Body.Close()

		if !bytes.Equal(respBuf, exp) {
			t.Fatal("invalid file served", url)
		}
	}

	for _, c := range tc {
		t.Run(fmt.Sprintf("%s/%s/%s", "get", c.testName, c.format), func(t *testing.T) {
			getURL := baseURL + "/get/" + c.reference

			indexFile := ""
			if c.format == "single" {
				indexFile = c.files[0].name
			} else {
				if c.index != "" {
					indexFile = c.index
				}
			}

			if indexFile != "" {
				var fileBuf []byte
				for _, v := range c.files {
					if v.name == indexFile || v.filePath == indexFile {
						fileBuf = v.data
						break
					}
				}
				fetchAndCheck(t, getURL, fileBuf)
			}

			for _, v := range c.files {
				getURL2 := getURL + "/" + v.filePath

				fetchAndCheck(t, getURL2, v.data)
			}
		})
	}

	t.Run("list", func(t *testing.T) {
		fetchList := func(t *testing.T, url string) []*cdn.ManifestObj {
			resp, err := http.Get(url)
			if err != nil {
				t.Fatal(err)
			}

			if resp.StatusCode != http.StatusOK {
				t.Fatal("invalid response code")
			}

			respBuf, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			listRes := []*cdn.ManifestObj{}
			err = json.Unmarshal(respBuf, &listRes)
			if err != nil {
				t.Fatal(err)
			}

			return listRes
		}

		t.Run("without params", func(t *testing.T) {
			listRes := fetchList(t, baseURL+"/list")

			if len(listRes) != 4 {
				t.Fatal("invalid count of items returned")
			}

			for _, v := range listRes {
				found := false
				for _, c := range tc {
					if c.reference == v.Cid {
						found = true
						break
					}
				}
				if !found {
					t.Fatal("got a reference which is not known")
				}
			}
		})

		t.Run("with params", func(t *testing.T) {
			listURL := fmt.Sprintf("%s/list?page=%d&limit=%d", baseURL, 0, 2)
			listRes := fetchList(t, listURL)

			if len(listRes) != 2 {
				t.Fatal("invalid count of items returned")
			}
		})

	})
}

func getRandData(size int) []byte {
	data := make([]byte, size)
	_, _ = rand.Read(data)
	return data
}

func tarFiles(t *testing.T, files []f) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for _, file := range files {
		// create tar header and write it
		hdr := &tar.Header{
			Name: file.filePath,
			Mode: 0600,
			Size: int64(len(file.data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}

		// write the file data to the tar
		if _, err := tw.Write(file.data); err != nil {
			t.Fatal(err)
		}
	}

	// finally close the tar writer
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	return &buf
}

func multipartFiles(t *testing.T, files []f) (*bytes.Buffer, string) {
	t.Helper()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	for _, file := range files {
		hdr := make(textproto.MIMEHeader)
		if file.name != "" {
			hdr.Set("Content-Disposition", fmt.Sprintf("form-data; name=%q", file.filePath))
		}

		hdr.Set("Content-Type", file.contentType)

		if len(file.data) > 0 {
			hdr.Set("Content-Length", strconv.Itoa(len(file.data)))
		}

		part, err := mw.CreatePart(hdr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.Copy(part, bytes.NewBuffer(file.data)); err != nil {
			t.Fatal(err)
		}
	}

	// finally close the tar writer
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	return &buf, mw.Boundary()
}

// struct for dir files for test cases
type f struct {
	data        []byte
	filePath    string
	name        string
	contentType string
}
