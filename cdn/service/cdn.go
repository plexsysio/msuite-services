package cdn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/SWRMLabs/ss-store"
	"github.com/aloknerurkar/go-msuite/lib"
	ipfslite "github.com/hsanjuan/ipfs-lite"
	"github.com/ipfs/go-cid"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var DefaultTimeout time.Duration = time.Second * 10

func NewCDNService(svc msuite.Service) error {
	ndApi, err := svc.Node()
	if err != nil {
		return err
	}
	httpApi, err := svc.HTTP()
	if err != nil {
		return err
	}
	var httpPort int
	ok := svc.Repo().Config().Get("HTTPPort", &httpPort)
	if !ok {
		return errors.New("Failed to get HTTP port")
	}
	cdnsvc := &cdn{port: httpPort, p: ndApi.IPFS(), st: ndApi.Storage()}
	httpApi.Mux().HandleFunc("/v1/cdn/put", cdnsvc.Put)
	httpApi.Mux().HandleFunc("/v1/cdn/get/", cdnsvc.Get)
	httpApi.Mux().HandleFunc("/v1/cdn/list", cdnsvc.List)
	httpApi.Mux().HandleFunc("/v1/cdn/upload", cdnsvc.UploadForm)
	return nil
}

type cdn struct {
	p    *ipfslite.Peer
	st   store.Store
	port int
}

type FileObj struct {
	Name     string
	Size     int64
	Cid      string
	Uploader string
	Acl      string
	Created  int64
}

func (f *FileObj) GetId() string {
	return f.Cid
}

func (f *FileObj) GetNamespace() string {
	return "FileObj"
}

func (f *FileObj) Marshal() ([]byte, error) {
	return json.Marshal(f)
}

func (f *FileObj) Unmarshal(buf []byte) error {
	return json.Unmarshal(buf, f)
}

func (f *FileObj) Factory() store.SerializedItem {
	return f
}

func errorHTML(msg string, w http.ResponseWriter) {
	fmt.Fprintf(w, fmt.Sprintf("<html><body style='font-size:100px'>%s</body></html>", msg))
	return
}

func (c *cdn) Put(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		errorHTML("BadRequest: Failed parsing form", w)
		return
	}
	file, handler, err := r.FormFile("file")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		errorHTML("BadRequest: Failed parsing file", w)
		return
	}
	defer file.Close()

	ctx, _ := context.WithTimeout(context.Background(), DefaultTimeout)
	nd, err := c.p.AddFile(ctx, file, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorHTML("InternalError: "+err.Error(), w)
		return
	}
	nf := &FileObj{
		Name:    handler.Filename,
		Size:    handler.Size,
		Cid:     nd.Cid().String(),
		Created: time.Now().Unix(),
	}
	err = c.st.Create(nf)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorHTML("InternalError: Failed creating metadata Err:"+err.Error(), w)
		return
	}
	resp, err := json.Marshal(nf)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorHTML("InternalError: Failed serializing response", w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

func (c *cdn) Get(w http.ResponseWriter, r *http.Request) {
	fileId := strings.TrimPrefix(r.URL.Path, "/v1/cdn/get/")
	cid, err := cid.Decode(fileId)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		errorHTML("BadRequest: Failed parsing file ID Err:"+err.Error(), w)
		return
	}
	f := &FileObj{
		Cid: fileId,
	}
	err = c.st.Read(f)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		errorHTML("NotFound: Failed getting file metadata Err:"+err.Error(), w)
		return
	}
	ctx, _ := context.WithTimeout(context.Background(), DefaultTimeout)
	rdr, err := c.p.GetFile(ctx, cid)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorHTML("InternalError: Failed reading file Err:"+err.Error(), w)
		return
	}
	http.ServeContent(w, r, f.Name, time.Unix(f.Created, 0), rdr)
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
	items, err := c.st.List(&FileObj{}, store.ListOpt{
		Page:  int64(pg),
		Limit: int64(lim),
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errorHTML("InternalError: Failed listing files Err:"+err.Error(), w)
		return
	}
	retList := []*FileObj{}
	for _, v := range items {
		retList = append(retList, v.(*FileObj))
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
