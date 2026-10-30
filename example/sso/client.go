// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
)

func startTestClient(addr, issuer string, connectors []string, store *MemoryStore) {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(resp http.ResponseWriter, req *http.Request) {
		var links string
		for _, name := range connectors {
			params := url.Values{
				"response_type": {"code"},
				"client_id":     {"example"},
				"redirect_uri":  {"http://localhost:8081/callback"},
				"scope":         {"openid profile email"},
				"connection":    {name},
				"state":         {"test-state"},
			}
			loginURL := issuer + "/authorize?" + params.Encode()
			links += fmt.Sprintf(`<a class="btn" href="%s">Login with %s</a>`+"\n", loginURL, name)
		}

		resp.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(resp, `<!DOCTYPE html>
<html>
<head><title>Athens SSO Example</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto; text-align: center; }
a.btn { display: inline-block; padding: 12px 32px; margin: 8px; background: #2563eb; color: white; text-decoration: none; border-radius: 6px; font-size: 16px; }
a.btn:hover { background: #1d4ed8; }
</style>
</head>
<body>
<h1>Athens SSO Example</h1>
<p>Choose a connector to authenticate with.</p>
%s
<hr style="margin: 32px 0">
<p><a class="btn" href="/device" style="background: #7c3aed">Device Flow Demo</a></p>
</body>
</html>`, links)
	})

	mux.HandleFunc("GET /callback", func(resp http.ResponseWriter, req *http.Request) {
		code := req.URL.Query().Get("code")
		state := req.URL.Query().Get("state")

		if errType := req.URL.Query().Get("error"); errType != "" {
			resp.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(resp, `<!DOCTYPE html>
<html><head><title>Error</title></head>
<body><h1>Error: %s</h1><p>%s</p><a href="/">Try again</a></body></html>`,
				errType, req.URL.Query().Get("error_description"))
			return
		}

		tokenResp, err := http.PostForm(issuer+"/oauth/token", url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"http://localhost:8081/callback"},
			"client_id":     {"example"},
			"client_secret": {"example-secret"},
		})
		if err != nil {
			http.Error(resp, err.Error(), http.StatusInternalServerError)
			return
		}
		defer tokenResp.Body.Close()

		var tokens map[string]any
		if err := json.NewDecoder(tokenResp.Body).Decode(&tokens); err != nil {
			http.Error(resp, err.Error(), http.StatusInternalServerError)
			return
		}

		pretty, _ := json.MarshalIndent(tokens, "", "  ")

		accessToken, _ := tokens["access_token"].(string)

		// Build a link to exchange the token at the service
		exchangeParams := url.Values{
			"access_token": {accessToken},
		}

		resp.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(resp, `<!DOCTYPE html>
<html>
<head><title>Authenticated</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; }
pre { background: #f1f5f9; padding: 20px; border-radius: 8px; overflow-x: auto; }
.meta { color: #64748b; margin-bottom: 20px; }
a.btn { display: inline-block; padding: 10px 24px; margin: 8px 8px 8px 0; background: #059669; color: white; text-decoration: none; border-radius: 6px; }
a.btn:hover { background: #047857; }
</style>
</head>
<body>
<h1>Authenticated!</h1>
<p class="meta">state: %s</p>
<h2>SSO Token Response</h2>
<pre>%s</pre>
<a class="btn" href="/exchange?%s">Exchange at Service (federation)</a>
<a href="/">Login again</a>
</body>
</html>`, state, pretty, exchangeParams.Encode())
	})

	mux.HandleFunc("GET /device", func(resp http.ResponseWriter, req *http.Request) {
		// Initiate device flow
		deviceResp, err := http.PostForm(issuer+"/oauth/device", url.Values{
			"client_id": {"example"},
			"scope":     {"openid email"},
		})
		if err != nil {
			http.Error(resp, err.Error(), http.StatusInternalServerError)
			return
		}
		defer deviceResp.Body.Close()

		var device map[string]any
		json.NewDecoder(deviceResp.Body).Decode(&device)

		userCode, _ := device["user_code"].(string)
		deviceCode, _ := device["device_code"].(string)

		resp.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(resp, `<!DOCTYPE html>
<html>
<head><title>Device Flow</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto; text-align: center; }
code { font-size: 2em; letter-spacing: 0.2em; background: #f1f5f9; padding: 12px 24px; border-radius: 8px; }
a.btn { display: inline-block; padding: 10px 24px; margin: 16px 8px; background: #2563eb; color: white; text-decoration: none; border-radius: 6px; }
</style>
</head>
<body>
<h1>Device Flow</h1>
<p>Enter this code on the verification page:</p>
<p><code>%s</code></p>
<a class="btn" href="/verify?user_code=%s" target="_blank">Open Verification Page</a>
<a class="btn" href="/device/poll?device_code=%s">Check for Token</a>
</body>
</html>`, userCode, url.QueryEscape(userCode), url.QueryEscape(deviceCode))
	})

	mux.HandleFunc("GET /verify", func(resp http.ResponseWriter, req *http.Request) {
		userCode := req.URL.Query().Get("user_code")
		resp.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(resp, `<!DOCTYPE html>
<html>
<head><title>Verify Device</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto; text-align: center; }
input { font-size: 1.5em; padding: 8px 16px; text-align: center; letter-spacing: 0.2em; text-transform: uppercase; }
button { padding: 12px 32px; background: #059669; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; margin-top: 16px; }
</style>
</head>
<body>
<h1>Verify Device</h1>
<form method="POST" action="/verify">
<p>Enter the code shown on your device:</p>
<input name="user_code" value="%s" placeholder="XXXX-XXXX"><br>
<button type="submit">Approve</button>
</form>
</body>
</html>`, userCode)
	})

	mux.HandleFunc("POST /verify", func(resp http.ResponseWriter, req *http.Request) {
		req.ParseForm()
		userCode := req.Form.Get("user_code")

		user, _ := store.GetOrCreateUser(req.Context(), "device", "device-user", map[string]any{
			"name": "Device User",
		})
		err := store.ApproveDeviceAuth(req.Context(), userCode, user.Subject)
		resp.Header().Set("Content-Type", "text/html")
		if err != nil {
			fmt.Fprintf(resp, `<!DOCTYPE html>
<html><body><h1>Error</h1><p>%s</p><a href="/verify">Try again</a></body></html>`, err.Error())
			return
		}
		fmt.Fprintf(resp, `<!DOCTYPE html>
<html>
<head><style>body { font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto; text-align: center; }</style></head>
<body><h1>Approved!</h1><p>You can close this tab. The device will receive its token shortly.</p></body></html>`)
	})

	mux.HandleFunc("GET /device/poll", func(resp http.ResponseWriter, req *http.Request) {
		deviceCode := req.URL.Query().Get("device_code")

		tokenResp, err := http.PostForm(issuer+"/oauth/token", url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {deviceCode},
			"client_id":   {"example"},
		})
		if err != nil {
			http.Error(resp, err.Error(), http.StatusInternalServerError)
			return
		}
		defer tokenResp.Body.Close()

		var result map[string]any
		json.NewDecoder(tokenResp.Body).Decode(&result)

		if errCode, ok := result["error"]; ok {
			resp.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(resp, `<!DOCTYPE html>
<html>
<head><title>Waiting...</title>
<style>body { font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto; text-align: center; }
a.btn { display: inline-block; padding: 10px 24px; margin: 16px; background: #2563eb; color: white; text-decoration: none; border-radius: 6px; }</style>
</head>
<body>
<h1>Waiting for approval...</h1>
<p>Status: <code>%s</code></p>
<a class="btn" href="/device/poll?device_code=%s">Check Again</a>
</body></html>`, errCode, url.QueryEscape(deviceCode))
			return
		}

		pretty, _ := json.MarshalIndent(result, "", "  ")
		resp.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(resp, `<!DOCTYPE html>
<html>
<head><title>Device Authenticated</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; }
pre { background: #f1f5f9; padding: 20px; border-radius: 8px; overflow-x: auto; }
</style>
</head>
<body>
<h1>Device Authenticated!</h1>
<pre>%s</pre>
<a href="/">Start over</a>
</body></html>`, pretty)
	})

	mux.HandleFunc("GET /exchange", func(resp http.ResponseWriter, req *http.Request) {
		accessToken := req.URL.Query().Get("access_token")
		if accessToken == "" {
			http.Error(resp, "missing access_token", http.StatusBadRequest)
			return
		}

		// Exchange the SSO token at the service via RFC 8693
		serviceURL := "http://localhost:8082/oauth/token"
		exchangeResp, err := http.PostForm(serviceURL, url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":      {accessToken},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			"client_id":          {"service-client"},
			"client_secret":      {"service-secret"},
		})
		if err != nil {
			http.Error(resp, err.Error(), http.StatusInternalServerError)
			return
		}
		defer exchangeResp.Body.Close()

		var result map[string]any
		if err := json.NewDecoder(exchangeResp.Body).Decode(&result); err != nil {
			http.Error(resp, err.Error(), http.StatusInternalServerError)
			return
		}

		pretty, _ := json.MarshalIndent(result, "", "  ")

		resp.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(resp, `<!DOCTYPE html>
<html>
<head><title>Token Exchange</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; }
pre { background: #f1f5f9; padding: 20px; border-radius: 8px; overflow-x: auto; }
</style>
</head>
<body>
<h1>Token Exchange (Federation)</h1>
<p>Exchanged SSO token at <code>%s</code></p>
<h2>Service Token Response</h2>
<pre>%s</pre>
<a href="/">Start over</a>
</body>
</html>`, serviceURL, pretty)
	})

	log.Printf("test client on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
