package cdn

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	ipfslite "github.com/hsanjuan/ipfs-lite"
	"github.com/ipfs/go-cid"
	"github.com/plexsysio/gkvstore"
	"github.com/plexsysio/go-msuite/core"
	"github.com/plexsysio/go-radix"
)

var DefaultTimeout time.Duration = time.Second * 10

func NewCDNService(svc core.Service) error {
	httpApi, err := svc.HTTP()
	if err != nil {
		return err
	}
	filesApi, err := svc.Files()
	if err != nil {
		return err
	}
	st, err := svc.SharedStorage("cdn", nil)
	if err != nil {
		return err
	}
	var httpPort int
	ok := svc.Repo().Config().Get("HTTPPort", &httpPort)
	if !ok {
		return errors.New("Failed to get HTTP port")
	}
	cdnsvc := &cdn{port: httpPort, p: filesApi, st: st}
	httpApi.Mux().HandleFunc("/cdn/v1/put", cdnsvc.Put)
	httpApi.Mux().HandleFunc("/cdn/v1/get/", cdnsvc.Get)
	httpApi.Mux().HandleFunc("/cdn/v1/list", cdnsvc.List)
	httpApi.Mux().HandleFunc("/cdn/v1/upload", cdnsvc.UploadForm)
	return nil
}

type cdn struct {
	p    *ipfslite.Peer
	st   gkvstore.Store
	port int
}

type ManifestObj struct {
	Cid string
}

func (f *ManifestObj) GetID() string {
	return f.Cid
}

func (f *ManifestObj) GetNamespace() string {
	return "ManifestObj"
}

func (f *ManifestObj) Marshal() ([]byte, error) {
	return json.Marshal(f)
}

func (f *ManifestObj) Unmarshal(buf []byte) error {
	return json.Unmarshal(buf, f)
}

func errorHTML(msg string, w http.ResponseWriter) {
	fmt.Fprintf(w, fmt.Sprintf("<html><body style='font-size:100px'>%s</body></html>", msg))
	return
}

type FileMetadata struct {
	Name        string
	ContentType string
	CID         string
	Created     int64
	Updated     int64
}

func (f *FileMetadata) Marshal() ([]byte, error) {
	return json.Marshal(f)
}

func (f *FileMetadata) Unmarshal(buf []byte) error {
	return json.Unmarshal(buf, f)
}

func (c *cdn) Put(w http.ResponseWriter, r *http.Request) {

	contentType := r.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		errorHTML("BadRequest: Failed parsing Content-Type Err:"+err.Error(), w)
		return
	}

	var (
		filesReader dirReader
		indexFile   = &FileMetadata{}
		addIndex    = false
	)

	switch mediaType {
	case "application/tar":
		filesReader = &tarReader{r: tar.NewReader(r.Body)}
		indexFile.Name = r.Header.Get("index-document")
	case "multipart/form-data":
		filesReader = &multipartReader{r: multipart.NewReader(r.Body, params["boundary"])}
		indexFile.Name = r.Header.Get("index-document")
	default:
		// get name from params
		name := r.URL.Query().Get("name")
		if name == "" {
			w.WriteHeader(http.StatusBadRequest)
			errorHTML("Missing filename in params for single file upload", w)
			return
		}
		filesReader = &singleFileReader{f: &FileInfo{
			Name:        name,
			Path:        name,
			ContentType: mediaType,
			Reader:      r.Body,
		}}
		indexFile.Name = name
	}

	manifest := radix.New()

	count := 0
	for {
		f, err := filesReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			w.WriteHeader(http.StatusInternalServerError)
			errorHTML("Failed to get input file Err:"+err.Error(), w)
			return
		}

		nd, err := c.p.AddFile(r.Context(), f.Reader, nil)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			errorHTML("InternalError: "+err.Error(), w)
			return
		}

		manifest.Insert(f.Path, &FileMetadata{
			Name:        f.Name,
			ContentType: f.ContentType,
			CID:         nd.Cid().String(),
			Created:     time.Now().Unix(),
		})

		if f.Path == indexFile.Name {
			indexFile.ContentType = f.ContentType
			indexFile.CID = nd.Cid().String()
			indexFile.Created = time.Now().Unix()
			addIndex = true
		}
		count++
	}

	if count == 1 && indexFile.Name == "" {
		for _, v := range manifest.ToMap() {
			indexF, ok := v.(*FileMetadata)
			if ok {
				indexFile.Name = indexF.Name
				indexFile.ContentType = indexF.ContentType
				indexFile.CID = indexF.CID
				indexFile.Created = indexF.Created
				addIndex = true
				break
			}
		}
	}

	if addIndex {
		manifest.Insert("/", indexFile)
	}

	manifestBuf := new(bytes.Buffer)
	err = manifest.Save(manifestBuf)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorHTML("Failed saving manifest: "+err.Error(), w)
		return
	}

	fmt.Printf("Manifest size %d\n", manifestBuf.Len())

	mnode, err := c.p.AddFile(r.Context(), manifestBuf, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorHTML("Failed storing manifest: "+err.Error(), w)
		return
	}

	mObj := &ManifestObj{Cid: mnode.Cid().String()}
	err = c.st.Create(r.Context(), mObj)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorHTML("Failed storing manifest object: "+err.Error(), w)
		return
	}

	resp, err := mObj.Marshal()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorHTML("Failed sending response: "+err.Error(), w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

type FileInfo struct {
	Path        string
	Name        string
	ContentType string
	Reader      io.Reader
}

type dirReader interface {
	Next() (*FileInfo, error)
}

type singleFileReader struct {
	f    *FileInfo
	done bool
}

func (s *singleFileReader) Next() (*FileInfo, error) {
	if s.done {
		return nil, io.EOF
	}
	s.done = true
	return s.f, nil
}

type tarReader struct {
	r *tar.Reader
}

func (t *tarReader) Next() (*FileInfo, error) {
	for {
		fileHeader, err := t.r.Next()
		if err != nil {
			return nil, err
		}

		fileName := fileHeader.FileInfo().Name()
		contentType := mime.TypeByExtension(filepath.Ext(fileHeader.Name))
		filePath := filepath.Clean(fileHeader.Name)

		if filePath == "." {
			continue
		}
		if runtime.GOOS == "windows" {
			// always use Unix path separator
			filePath = filepath.ToSlash(filePath)
		}
		// only store regular files
		if !fileHeader.FileInfo().Mode().IsRegular() {
			continue
		}

		return &FileInfo{
			Path:        filePath,
			Name:        fileName,
			ContentType: contentType,
			Reader:      t.r,
		}, nil
	}
}

// multipart reader returns files added as a multipart form. We will ensure all the
// part headers are passed correctly
type multipartReader struct {
	r *multipart.Reader
}

func (m *multipartReader) Next() (*FileInfo, error) {
	part, err := m.r.NextPart()
	if err != nil {
		return nil, err
	}

	fileName := part.FileName()
	if fileName == "" {
		fileName = part.FormName()
	}
	if fileName == "" {
		return nil, errors.New("filename missing")
	}

	contentType := part.Header.Get("Content-Type")
	if contentType == "" {
		return nil, errors.New("content-type missing")
	}

	return &FileInfo{
		Path:        fileName,
		Name:        fileName,
		ContentType: contentType,
		Reader:      part,
	}, nil
}

func (c *cdn) Get(w http.ResponseWriter, r *http.Request) {
	var (
		manifestID string
		filePath   string
		full       string
	)
	useIndex := false
	_, err := fmt.Sscanf(r.URL.Path, "/cdn/v1/get/%s", &full)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		errorHTML("BadRequest: Failed parsing file ID Err:"+err.Error(), w)
		return
	}
	splits := strings.Split(full, "/")
	manifestID = splits[0]
	if len(splits) > 1 {
		filePath = strings.Join(splits[1:], "/")
	}
	if filePath == "" {
		useIndex = true
	}
	mcid, err := cid.Decode(manifestID)
	if err != nil {
	}
	mrdr, err := c.p.GetFile(r.Context(), mcid)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorHTML("InternalError: Failed reading manifest file Err:"+err.Error(), w)
		return
	}
	manifest, err := radix.Load(mrdr, func(_ string) radix.Exportable {
		return &FileMetadata{}
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorHTML("InternalError: Failed loading manifest Err:"+err.Error(), w)
		return
	}
	var (
		ndInt interface{}
		found bool
	)
	if useIndex {
		ndInt, found = manifest.Get("/")
	} else {
		ndInt, found = manifest.Get(filePath)
	}
	if !found {
		w.WriteHeader(http.StatusInternalServerError)
		errorHTML("InternalError: Failed getting file to display", w)
		return
	}
	f, ok := ndInt.(*FileMetadata)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		errorHTML("InternalError: Incorrect file metadata", w)
		return
	}
	fcid, err := cid.Decode(f.CID)
	if err != nil {
	}
	frdr, err := c.p.GetFile(r.Context(), fcid)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorHTML("InternalError: Failed reading manifest file Err:"+err.Error(), w)
		return
	}
	http.ServeContent(w, r, f.Name, time.Unix(f.Created, 0), frdr)
}

func (c *cdn) List(w http.ResponseWriter, r *http.Request) {
	pg, lim := 0, 0
	p := r.URL.Query().Get("page")
	var err error
	if len(p) == 0 {
		pg = 0
	} else {
		pg, err = strconv.Atoi(p)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			errorHTML("BadRequest: Failed parsing page Err:"+err.Error(), w)
			return
		}
	}
	l := r.URL.Query().Get("limit")
	if len(l) == 0 {
		lim = 10
	} else {
		lim, err = strconv.Atoi(l)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			errorHTML("BadRequest: Failed parsing limit Err:"+err.Error(), w)
			return
		}
	}
	items, err := c.st.List(r.Context(), func() gkvstore.Item { return &ManifestObj{} }, gkvstore.ListOpt{
		Page:  int64(pg),
		Limit: int64(lim),
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorHTML("InternalError: Failed listing files Err:"+err.Error(), w)
		return
	}
	retList := []*ManifestObj{}
	for v := range items {
		if v.Err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			errorHTML("InternalError: Failed to list files", w)
			return
		}
		retList = append(retList, v.Val.(*ManifestObj))
	}
	resp, err := json.Marshal(retList)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorHTML("InternalError: Failed serializing response", w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

func (c *cdn) UploadForm(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, fmt.Sprintf(uploadForm, c.port))
}

var uploadForm = `
<html lang="en">
	<head>
	<meta charset="UTF-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1.0" />
	<meta http-equiv="X-UA-Compatible" content="ie=edge" />
		<title>Document</title>
	</head>
	<body>
		<form
			enctype="multipart/form-data"
			action="http://localhost:%d/v1/cdn/put"
			method="post"
		>
			<input type="file" name="file" />
			<input type="submit" value="upload" />
			</form>
	</body>
</html>
`
