package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"security-testing-toolkit/internal/csrf"
)

//go:embed public/*
var publicFiles embed.FS

var tokenPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type application struct {
	client *http.Client
	static http.Handler
}

type csrfInput struct {
	Raw     string       `json:"raw"`
	Options csrf.Options `json:"options"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func decodeJSON(request *http.Request, target any) error {
	request.Body = http.MaxBytesReader(nil, request.Body, 2_000_000)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("le corps JSON doit contenir une seule valeur")
	}
	return nil
}

func (app *application) generateCSRF(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeJSON(response, http.StatusMethodNotAllowed, errorResponse{Error: "méthode refusée"})
		return
	}
	var input csrfInput
	if err := decodeJSON(request, &input); err != nil {
		writeJSON(response, http.StatusBadRequest, errorResponse{Error: "JSON invalide : " + err.Error()})
		return
	}
	result, err := csrf.Generate(input.Raw, input.Options)
	if err != nil {
		writeJSON(response, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (app *application) fetchOAST(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeJSON(response, http.StatusMethodNotAllowed, errorResponse{Error: "méthode refusée"})
		return
	}
	token := strings.TrimPrefix(request.URL.Path, "/api/oast/")
	if !tokenPattern.MatchString(token) {
		writeJSON(response, http.StatusBadRequest, errorResponse{Error: "token Webhook.site invalide"})
		return
	}

	upstreamURL := fmt.Sprintf("https://webhook.site/token/%s/requests?sorting=newest&per_page=100", token)
	upstreamRequest, err := http.NewRequestWithContext(request.Context(), http.MethodGet, upstreamURL, nil)
	if err != nil {
		writeJSON(response, http.StatusInternalServerError, errorResponse{Error: "impossible de préparer la requête OAST"})
		return
	}
	upstreamRequest.Header.Set("Accept", "application/json")
	if apiKey := request.Header.Get("X-Webhook-Api-Key"); apiKey != "" {
		upstreamRequest.Header.Set("Api-Key", apiKey)
	}

	upstreamResponse, err := app.client.Do(upstreamRequest)
	if err != nil {
		writeJSON(response, http.StatusBadGateway, errorResponse{Error: "Webhook.site est inaccessible : " + err.Error()})
		return
	}
	defer upstreamResponse.Body.Close()

	response.Header().Set("Content-Type", upstreamResponse.Header.Get("Content-Type"))
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(upstreamResponse.StatusCode)
	_, _ = io.Copy(response, io.LimitReader(upstreamResponse.Body, 10_000_000))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(response, request)
	})
}

func (app *application) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/csrf/generate", app.generateCSRF)
	mux.HandleFunc("/api/oast/", app.fetchOAST)
	mux.Handle("/", securityHeaders(app.static))
	return mux
}

func main() {
	staticFS, err := fs.Sub(publicFiles, "public")
	if err != nil {
		log.Fatal(err)
	}
	app := &application{
		client: &http.Client{Timeout: 10 * time.Second},
		static: http.FileServer(http.FS(staticFS)),
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8787"
	}
	address := "127.0.0.1:" + port
	server := &http.Server{
		Addr:              address,
		Handler:           app.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("Security Testing Toolkit (Go) : http://%s", address)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
