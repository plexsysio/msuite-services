package ui

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/plexsysio/go-msuite/core"
)

//go:embed static/*
var staticFS embed.FS

func New(svc core.Service) error {
	t, err := template.ParseFS(staticFS, "static/templates/*.html")
	if err != nil {
		return err
	}

	httpApi, err := svc.HTTP()
	if err != nil {
		return err
	}

	assets, err := fs.Sub(staticFS, "static/assets")
	if err != nil {
		return err
	}

	httpApi.Mux().Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assets))))
	httpApi.Mux().HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		t.ExecuteTemplate(w, "login.html", nil)
	})
	httpApi.Mux().HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		t.ExecuteTemplate(w, "register.html", nil)
	})
	httpApi.Mux().HandleFunc("/user/password/forgot", func(w http.ResponseWriter, r *http.Request) {
		t.ExecuteTemplate(w, "forgotpassword.html", nil)
	})
	httpApi.Mux().HandleFunc("/user/password/reset", func(w http.ResponseWriter, r *http.Request) {
		t.ExecuteTemplate(w, "resetpassword.html", nil)
	})

	return nil
}
