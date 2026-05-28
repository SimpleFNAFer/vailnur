package crawler

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// Request represents a crawled HTTP request (from a link or form).
type Request struct {
	Method string
	URL    string
	Params map[string][]string
}

// Crawler performs a BFS crawl starting from a seed URL.
type Crawler struct {
	MaxDepth int
	MaxPages int
}

type queueItem struct {
	rawURL string
	depth  int
}

// Crawl starts BFS from seedURL and returns all discovered requests.
func (c *Crawler) Crawl(seedURL string) ([]Request, int, error) {
	base, err := url.Parse(seedURL)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid seed URL: %w", err)
	}

	visited := make(map[string]bool)
	var requests []Request
	pagesCrawled := 0

	queue := []queueItem{{rawURL: seedURL, depth: 0}}

	for len(queue) > 0 && pagesCrawled < c.MaxPages {
		item := queue[0]
		queue = queue[1:]

		if visited[item.rawURL] {
			continue
		}
		visited[item.rawURL] = true

		pageReqs, links, err := fetchAndParse(item.rawURL, base)
		if err != nil {
			// skip pages that fail to fetch
			continue
		}
		pagesCrawled++
		requests = append(requests, pageReqs...)

		if item.depth < c.MaxDepth {
			for _, link := range links {
				if !visited[link] {
					queue = append(queue, queueItem{rawURL: link, depth: item.depth + 1})
				}
			}
		}
	}

	return requests, pagesCrawled, nil
}

// fetchAndParse GETs a URL, parses HTML, and extracts requests + outbound links.
func fetchAndParse(rawURL string, base *url.URL) ([]Request, []string, error) {
	resp, err := http.Get(rawURL) //nolint:gosec // intentional for scanner tool
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	var requests []Request
	var links []string

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				href := attrVal(n, "href")
				resolved := resolveURL(base, href)
				if resolved != "" && sameDomain(base, resolved) {
					links = append(links, resolved)
					u, err := url.Parse(resolved)
					qp := map[string][]string{}
					if err == nil && u.RawQuery != "" {
						if parsed, e := url.ParseQuery(u.RawQuery); e == nil {
							qp = parsed
						}
						// strip query from URL so params dict is the canonical source
						u.RawQuery = ""
						resolved = u.String()
					}
					requests = append(requests, Request{
						Method: "GET",
						URL:    resolved,
						Params: qp,
					})
				}
			case "form":
				req := parseForm(n, base, rawURL)
				if req != nil {
					requests = append(requests, *req)
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)

	return requests, links, nil
}

// parseForm extracts a Request from a <form> element.
func parseForm(n *html.Node, base *url.URL, pageURL string) *Request {
	action := attrVal(n, "action")
	method := strings.ToUpper(attrVal(n, "method"))
	if method == "" {
		method = "GET"
	}

	var actionURL string
	if action == "" {
		actionURL = pageURL
	} else {
		actionURL = resolveURL(base, action)
		if actionURL == "" {
			return nil
		}
	}

	params := extractInputs(n)

	return &Request{
		Method: method,
		URL:    actionURL,
		Params: params,
	}
}

// extractInputs collects all form field values: <input>, <textarea>, <select>.
func extractInputs(form *html.Node) map[string][]string {
	params := make(map[string][]string)
	skipTypes := map[string]bool{
		"submit": true, "button": true, "reset": true, "image": true,
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "input":
				if skipTypes[strings.ToLower(attrVal(n, "type"))] {
					break
				}
				if name := attrVal(n, "name"); name != "" {
					params[name] = append(params[name], attrVal(n, "value"))
				}
			case "textarea":
				if name := attrVal(n, "name"); name != "" {
					// collect inner text as default value
					var sb strings.Builder
					for c := n.FirstChild; c != nil; c = c.NextSibling {
						if c.Type == html.TextNode {
							sb.WriteString(c.Data)
						}
					}
					params[name] = append(params[name], strings.TrimSpace(sb.String()))
				}
			case "select":
				if name := attrVal(n, "name"); name != "" {
					// use value of first <option selected>, or first option
					val := firstSelectValue(n)
					params[name] = append(params[name], val)
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(form)
	return params
}

// firstSelectValue returns the value of the selected <option>, or first option's value.
func firstSelectValue(selectNode *html.Node) string {
	var first, selected string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "option" {
			v := attrVal(n, "value")
			if v == "" && n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
				v = strings.TrimSpace(n.FirstChild.Data)
			}
			if first == "" {
				first = v
			}
			if attrVal(n, "selected") != "" {
				selected = v
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(selectNode)
	if selected != "" {
		return selected
	}
	return first
}

// resolveURL resolves href against base; returns "" for schemes to skip.
func resolveURL(base *url.URL, href string) string {
	href = strings.TrimSpace(href)
	if href == "" {
		return ""
	}
	lower := strings.ToLower(href)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(href, "#") {
		return ""
	}

	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}

	resolved := base.ResolveReference(ref)
	// Strip fragment
	resolved.Fragment = ""
	return resolved.String()
}

// sameDomain checks that resolved URL has the same host as base.
func sameDomain(base *url.URL, rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Host == base.Host
}

// attrVal returns the value of an attribute by name, or "".
func attrVal(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if a.Key == name {
			return a.Val
		}
	}
	return ""
}
