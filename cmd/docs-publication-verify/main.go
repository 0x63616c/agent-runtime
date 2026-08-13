// docs-publication-verify checks a deployed public documentation site against
// the checked-in route manifest. It only performs bounded HTTPS reads; it
// neither builds nor deploys the site, so a passing local fixture test is not
// evidence that GitHub Pages has published a revision.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const maxPageBytes = 2 << 20

type routeManifest struct {
	SchemaVersion int      `json:"schemaVersion"`
	BasePath      string   `json:"basePath"`
	SidebarRoutes []string `json:"sidebarRoutes"`
	Routes        []route  `json:"routes"`
}

type route struct {
	Route    string `json:"route"`
	Output   string `json:"output"`
	Source   string `json:"source"`
	Contains string `json:"contains"`
	Redirect string `json:"redirect"`
}

type options struct {
	BaseURL                string
	ExpectedSHA            string
	ManifestPath           string
	WebsiteRoot            string
	RequireSourceSHAMarker bool
}

func main() {
	baseURL := flag.String("base-url", "", "required public HTTPS documentation base URL (for example https://0x63616c.github.io/agent-runtime)")
	expectedSHA := flag.String("expected-sha", "", "required lowercase 40-character source revision expected when a deployment marker is present")
	manifestPath := flag.String("manifest", "website/route-manifest.json", "checked-in route manifest")
	websiteRoot := flag.String("website-root", "website", "website source root used to derive expected public page titles")
	requireMarker := flag.Bool("require-source-sha-marker", false, "fail when the published pages do not expose a source revision marker")
	flag.Parse()
	if flag.NArg() != 0 {
		usage()
	}
	if err := run(context.Background(), options{
		BaseURL: *baseURL, ExpectedSHA: *expectedSHA, ManifestPath: *manifestPath,
		WebsiteRoot: *websiteRoot, RequireSourceSHAMarker: *requireMarker,
	}, &http.Client{Timeout: 20 * time.Second}); err != nil {
		fmt.Fprintln(os.Stderr, "docs-publication-verify:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: docs-publication-verify -base-url HTTPS_URL -expected-sha SHA [-manifest PATH] [-website-root DIR] [-require-source-sha-marker]")
	os.Exit(2)
}

func run(ctx context.Context, opts options, client *http.Client) error {
	base, err := validateOptions(opts)
	if err != nil {
		return err
	}
	manifest, err := loadManifest(opts.ManifestPath)
	if err != nil {
		return err
	}
	if base.Path != manifest.BasePath {
		return fmt.Errorf("base URL path %q must equal manifest basePath %q", base.Path, manifest.BasePath)
	}
	pages, err := expectedPages(manifest, opts.WebsiteRoot)
	if err != nil {
		return err
	}
	if client == nil {
		return errors.New("HTTP client is required")
	}
	noRedirect := *client
	noRedirect.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

	markerSeen := false
	for _, page := range pages {
		address := strings.TrimSuffix(base.String(), "/") + page.Route
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			return fmt.Errorf("create request for %s: %w", page.Route, err)
		}
		response, err := noRedirect.Do(request)
		if err != nil {
			return fmt.Errorf("fetch %s: %w", page.Route, err)
		}
		// GitHub Pages serves directory-backed static routes with one canonical
		// slash-appending redirect. Permit only that deterministic transport
		// detail; any other redirect could conceal a different publication.
		if response.StatusCode == http.StatusMovedPermanently || response.StatusCode == http.StatusPermanentRedirect {
			expectedRedirect := address + "/"
			if response.Header.Get("Location") != expectedRedirect {
				_ = response.Body.Close()
				return fmt.Errorf("published route %s redirects to %q, want only %q", page.Route, response.Header.Get("Location"), expectedRedirect)
			}
			if err := response.Body.Close(); err != nil {
				return fmt.Errorf("close redirect for %s: %w", page.Route, err)
			}
			request, err = http.NewRequestWithContext(ctx, http.MethodGet, expectedRedirect, nil)
			if err != nil {
				return fmt.Errorf("create redirected request for %s: %w", page.Route, err)
			}
			response, err = noRedirect.Do(request)
			if err != nil {
				return fmt.Errorf("fetch redirected %s: %w", page.Route, err)
			}
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxPageBytes+1))
		closeErr := response.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read %s: %w", page.Route, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close %s: %w", page.Route, closeErr)
		}
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("published route %s returned HTTP %d, want 200", page.Route, response.StatusCode)
		}
		if len(body) > maxPageBytes {
			return fmt.Errorf("published route %s exceeds %d byte response limit", page.Route, maxPageBytes)
		}
		if !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "text/html") {
			return fmt.Errorf("published route %s has Content-Type %q, want text/html", page.Route, response.Header.Get("Content-Type"))
		}
		if err := verifyPage(string(body), address, page); err != nil {
			return err
		}
		if marker, ok := sourceMarker(string(body)); ok {
			markerSeen = true
			if marker != opts.ExpectedSHA {
				return fmt.Errorf("published route %s exposes source revision %q, want %q", page.Route, marker, opts.ExpectedSHA)
			}
		}
	}
	if opts.RequireSourceSHAMarker && !markerSeen {
		return errors.New("published pages expose no source revision marker")
	}
	if markerSeen {
		fmt.Printf("verified %d canonical public docs routes at %s; source revision marker matches %s\n", len(pages), base, opts.ExpectedSHA)
	} else {
		fmt.Printf("verified %d canonical public docs routes at %s; no source revision marker was published\n", len(pages), base)
	}
	return nil
}

func validateOptions(opts options) (*url.URL, error) {
	if !validSHA(opts.ExpectedSHA) {
		return nil, errors.New("expected-sha must be an exact lowercase 40-character commit SHA")
	}
	if opts.ManifestPath == "" || opts.WebsiteRoot == "" {
		return nil, errors.New("manifest and website-root are required")
	}
	base, err := url.Parse(opts.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.RawQuery != "" || base.Fragment != "" || base.Path == "" || strings.HasSuffix(base.Path, "/") {
		return nil, errors.New("base-url must be a canonical HTTPS URL with a non-root path, no query or fragment, and no trailing slash")
	}
	return base, nil
}

func loadManifest(path string) (routeManifest, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return routeManifest{}, fmt.Errorf("read route manifest: %w", err)
	}
	var manifest routeManifest
	if err := decodeJSON(contents, &manifest); err != nil {
		return routeManifest{}, fmt.Errorf("decode route manifest: %w", err)
	}
	if manifest.SchemaVersion != 2 || !validRoute(manifest.BasePath) || len(manifest.Routes) == 0 {
		return routeManifest{}, errors.New("route manifest must be non-empty schemaVersion 2 with a canonical basePath")
	}
	return manifest, nil
}

type expectedPage struct{ Route, Title string }

func expectedPages(manifest routeManifest, websiteRoot string) ([]expectedPage, error) {
	pages := make([]expectedPage, 0, len(manifest.Routes))
	seen := map[string]bool{}
	for _, route := range manifest.Routes {
		if route.Redirect != "" || !strings.HasPrefix(route.Route, "/docs/") {
			continue
		}
		if !validRoute(route.Route) || !strings.HasPrefix(route.Source, "src/content/docs/docs/") || !strings.HasSuffix(route.Source, ".mdx") || seen[route.Route] {
			return nil, fmt.Errorf("route manifest has an invalid canonical docs route: %+v", route)
		}
		seen[route.Route] = true
		path := filepath.Join(websiteRoot, filepath.FromSlash(route.Source))
		if !within(filepath.Clean(websiteRoot), path) {
			return nil, fmt.Errorf("route source escapes website root: %q", route.Source)
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read source for %s: %w", route.Route, err)
		}
		title := frontmatterTitle(string(contents))
		if title == "" {
			return nil, fmt.Errorf("source for %s has no frontmatter title", route.Route)
		}
		pages = append(pages, expectedPage{Route: route.Route, Title: title})
	}
	if len(pages) == 0 {
		return nil, errors.New("route manifest declares no canonical public docs routes")
	}
	return pages, nil
}

func verifyPage(page, address string, expected expectedPage) error {
	if canonical := canonicalHref(page); canonical != address {
		return fmt.Errorf("published route %s has canonical URL %q, want %q", expected.Route, canonical, address)
	}
	headings := h1Pattern.FindAllStringSubmatch(page, -1)
	if len(headings) != 1 || visibleText(headings[0][1]) != expected.Title {
		return fmt.Errorf("published route %s must render exactly one H1 %q", expected.Route, expected.Title)
	}
	main := mainPattern.FindStringSubmatch(page)
	if len(main) != 2 {
		return fmt.Errorf("published route %s has no public main content", expected.Route)
	}
	for _, forbidden := range forbiddenPublicTerms {
		if forbidden.pattern.MatchString(visibleText(main[1])) {
			return fmt.Errorf("published route %s exposes internal %s", expected.Route, forbidden.description)
		}
	}
	return nil
}

var (
	h1Pattern            = regexp.MustCompile(`(?is)<h1\b[^>]*>(.*?)</h1>`)
	mainPattern          = regexp.MustCompile(`(?is)<main\b[^>]*>(.*?)</main>`)
	linkPattern          = regexp.MustCompile(`(?is)<link\b[^>]*\brel\s*=\s*["']canonical["'][^>]*>`)
	hrefPattern          = regexp.MustCompile(`(?is)\bhref\s*=\s*["']([^"']+)["']`)
	metaTag              = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	attribute            = regexp.MustCompile(`(?is)\b([a-z0-9-]+)\s*=\s*["']([^"']*)["']`)
	stripTags            = regexp.MustCompile(`(?is)<[^>]+>`)
	spaces               = regexp.MustCompile(`\s+`)
	forbiddenPublicTerms = []struct {
		pattern     *regexp.Regexp
		description string
	}{
		{regexp.MustCompile(`\bM(?:10|[0-9])\b`), "milestone label"},
		{regexp.MustCompile(`\b(?:API|DAT|DEP|DOC|ENG|EX|HITL|INF|MOD|MON|OBS|OPS-STAT|PAY|SBX|TMP|TOL|TST)-\d{3}\b`), "requirement identifier"},
		{regexp.MustCompile(`(?i)\brequirements ledger\b`), "requirements ledger reference"},
	}
)

func canonicalHref(page string) string {
	link := linkPattern.FindString(page)
	if link == "" {
		return ""
	}
	found := hrefPattern.FindStringSubmatch(link)
	if len(found) != 2 {
		return ""
	}
	return found[1]
}

func sourceMarker(page string) (string, bool) {
	for _, tag := range metaTag.FindAllString(page, -1) {
		attributes := htmlAttributes(tag)
		if (attributes["name"] == "agent-runtime-source-sha" || attributes["name"] == "agent-runtime-source-revision") && validSHA(attributes["content"]) {
			return attributes["content"], true
		}
	}
	for _, found := range attribute.FindAllStringSubmatch(page, -1) {
		if (found[1] == "data-agent-runtime-source-sha" || found[1] == "data-agent-runtime-source-revision") && validSHA(found[2]) {
			return found[2], true
		}
	}
	return "", false
}

func htmlAttributes(tag string) map[string]string {
	attributes := make(map[string]string)
	for _, found := range attribute.FindAllStringSubmatch(tag, -1) {
		attributes[strings.ToLower(found[1])] = found[2]
	}
	return attributes
}

func frontmatterTitle(source string) string {
	found := regexp.MustCompile(`(?m)^title:\s*(.+?)\s*$`).FindStringSubmatch(source)
	if len(found) != 2 {
		return ""
	}
	return strings.Trim(strings.TrimSpace(found[1]), `"'`)
}

func visibleText(value string) string {
	return strings.TrimSpace(spaces.ReplaceAllString(stripTags.ReplaceAllString(value, " "), " "))
}

func decodeJSON(contents []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func validSHA(value string) bool {
	return len(value) == 40 && strings.Trim(value, "0123456789abcdef") == ""
}
func validRoute(value string) bool {
	return strings.HasPrefix(value, "/") && value != "/" && !strings.HasSuffix(value, "/") && !strings.Contains(value, "..") && !strings.Contains(value, `\`)
}
func within(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
