package csrf

import (
	"encoding/base64"
	"strings"
	"testing"
)

func boolPointer(value bool) *bool { return &value }

func TestParseRelativeRequest(t *testing.T) {
	request, err := ParseRawRequest("POST /profile HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nname=Alice", "")
	if err != nil {
		t.Fatal(err)
	}
	if request.Method != "POST" || request.URL.String() != "https://example.test/profile" || request.Body != "name=Alice" {
		t.Fatalf("requête inattendue : %#v", request)
	}
}

func TestGenerateEncodedForm(t *testing.T) {
	result, err := Generate("POST /profile HTTP/1.1\nHost: example.test\nContent-Type: application/x-www-form-urlencoded\n\nname=Alice%20Smith&role=user", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Kind != "form" || !strings.Contains(result.HTML, `name="name" value="Alice Smith"`) {
		t.Fatalf("formulaire inattendu : %s", result.HTML)
	}
	if !strings.Contains(result.HTML, "document.getElementById('csrf-form').submit()") {
		t.Fatal("la soumission automatique est absente")
	}
}

func TestGenerateGETForm(t *testing.T) {
	result, err := Generate("GET /search?q=hello%20world HTTP/1.1\nHost: example.test", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.HTML, `action="https://example.test/search"`) ||
		!strings.Contains(result.HTML, `name="q" value="hello world"`) {
		t.Fatalf("formulaire GET inattendu : %s", result.HTML)
	}
}

func TestJSONWarnsAboutCORS(t *testing.T) {
	result, err := Generate("POST /api/profile HTTP/1.1\nHost: example.test\nContent-Type: application/json\n\n{\"admin\":true}", Options{AutoSubmit: boolPointer(false)})
	if err != nil {
		t.Fatal(err)
	}
	if result.Kind != "fetch" || result.Warning == nil || !strings.Contains(*result.Warning, "CORS") {
		t.Fatalf("avertissement JSON incorrect : %#v", result)
	}
}

func TestGenerateMultipartTextFields(t *testing.T) {
	raw := "POST /profile HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Content-Type: multipart/form-data; boundary=boundary123\r\n\r\n" +
		"--boundary123\r\n" +
		"Content-Disposition: form-data; name=\"display_name\"\r\n\r\n" +
		"Alice Smith\r\n" +
		"--boundary123--\r\n"

	result, err := Generate(raw, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.HTML, `enctype="multipart/form-data"`) ||
		!strings.Contains(result.HTML, `name="display_name" value="Alice Smith"`) {
		t.Fatalf("formulaire multipart inattendu : %s", result.HTML)
	}
	if result.Warning != nil {
		t.Fatalf("avertissement inattendu : %s", *result.Warning)
	}
}

func TestMultipartFileIsEmbeddedAsBlob(t *testing.T) {
	raw := "POST /upload HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Content-Type: multipart/form-data; boundary=boundary123\r\n\r\n" +
		"--boundary123\r\n" +
		"Content-Disposition: form-data; name=\"avatar\"; filename=\"avatar.png\"\r\n" +
		"Content-Type: image/png\r\n\r\n" +
		"fake-image-data\r\n" +
		"--boundary123--\r\n"

	result, err := Generate(raw, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Kind != "multipart-fetch" || result.Warning == nil {
		t.Fatalf("une PoC Blob avec avertissement était attendue : %#v", result)
	}
	if !strings.Contains(result.HTML, "new Blob") || !strings.Contains(result.HTML, `"avatar.png"`) {
		t.Fatalf("le fichier Blob est absent : %s", result.HTML)
	}
	if !strings.Contains(result.HTML, base64.StdEncoding.EncodeToString([]byte("fake-image-data"))) {
		t.Fatal("le contenu du fichier devrait être intégré en Base64")
	}
	if strings.Contains(result.HTML, "headers: {'Content-Type'") {
		t.Fatal("le navigateur doit générer lui-même le Content-Type et la boundary")
	}
}

func TestMultipartFileManualMode(t *testing.T) {
	raw := "POST /upload HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Content-Type: multipart/form-data; boundary=boundary123\r\n\r\n" +
		"--boundary123\r\n" +
		"Content-Disposition: form-data; name=\"avatar\"; filename=\"avatar.png\"\r\n" +
		"Content-Type: image/png\r\n\r\n" +
		"fake-image-data\r\n" +
		"--boundary123--\r\n"

	result, err := Generate(raw, Options{FileMode: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Kind != "multipart-manual" || !strings.Contains(result.HTML, `type="file"`) ||
		!strings.Contains(result.HTML, `name="avatar"`) {
		t.Fatalf("champ fichier manuel absent : %s", result.HTML)
	}
	if strings.Contains(result.HTML, ".submit()") {
		t.Fatal("la PoC manuelle ne doit pas être soumise automatiquement")
	}
}

func TestEscapesHTMLAttributes(t *testing.T) {
	result, err := Generate("POST /profile HTTP/1.1\nHost: example.test\nContent-Type: application/x-www-form-urlencoded\n\nx=%22%3E%3Cscript%3E", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.HTML, `value=""><script>`) || !strings.Contains(result.HTML, `&#34;&gt;&lt;script&gt;`) {
		t.Fatalf("valeur non échappée : %s", result.HTML)
	}
}

func TestRequiresHostForRelativeURL(t *testing.T) {
	_, err := ParseRawRequest("GET / HTTP/1.1", "")
	if err == nil {
		t.Fatal("une requête relative sans Host devrait être refusée")
	}
}
