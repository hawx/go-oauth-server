package oauth

import (
	"net/http"
	"net/url"
)

const codeType = "code"

func Auth(policy *Policy, codeStorage CodeStorage) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}

		var (
			clientID     = r.FormValue("client_id")     // THISCLIENT
			redirectURI  = r.FormValue("redirect_uri")  // http://...
			responseType = r.FormValue("response_type") // code
			// scope        = r.FormValue("scope")         // user.profile
			state = r.FormValue("state") // state
		)

		parsedURL, err := url.Parse(redirectURI)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		query := parsedURL.Query()

		if state != "" {
			query.Add("state", state)
		}

		if responseType != codeType {
			query.Add("error", "unsupported_response_type")
			redirect(w, r, parsedURL, query)
			return
		}

		if !policy.IsAllowedClient(clientID) {
			query.Add("error", "unauthorized_client")
			redirect(w, r, parsedURL, query)
			return
		}

		// Redirect to a login page
		loginURL, err := url.Parse(policy.LoginURL)
		if err != nil {
			query.Add("error", "server_error")
			redirect(w, r, parsedURL, query)
			return
		}
		loginQuery := loginURL.Query()

		if state != "" {
			loginQuery.Add("state", state)
		}
		loginQuery.Add("redirect_uri", redirectURI)

		redirect(w, r, loginURL, loginQuery)
	})
}

func Code(policy *Policy, codeStorage CodeStorage) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}

		var (
			redirectURI = r.FormValue("redirect_uri")
			state       = r.FormValue("state")
		)

		parsedURL, err := url.Parse(redirectURI)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		query := parsedURL.Query()

		if state != "" {
			query.Add("state", state)
		}

		// Return a generated code
		code, err := randomCode(24)
		if err != nil {
			query.Add("error", "server_error")
			redirect(w, r, parsedURL, query)
			return
		}
		query.Add("code", code)

		codeStorage.Store(redirectURI, code)

		redirect(w, r, parsedURL, query)
	})
}
