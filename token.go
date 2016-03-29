package oauth

import (
	"encoding/json"
	"net/http"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func Token(policy *Policy, codeStorage CodeStorage, storage Storage) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}

		var (
			grantType   = r.PostFormValue("grant_type")   // authorization_code
			code        = r.PostFormValue("code")         // the code from /auth
			redirectURI = r.PostFormValue("redirect_uri") // http://...
		)

		enc := json.NewEncoder(w)

		if grantType != "authorization_code" {
			w.WriteHeader(400)
			w.Header().Add("Content-Type", "application/json")
			enc.Encode(errorResponse{Error: "invalid_grant"})
			return
		}

		if !codeStorage.Verify(redirectURI, code) {
			w.WriteHeader(400)
			w.Header().Add("Content-Type", "application/json")
			enc.Encode(errorResponse{Error: "invalid_grant"})
			return
		}

		// Return response
		accessToken, err := randomCode(24)
		if err != nil {
			w.WriteHeader(500)
			w.Header().Add("Content-Type", "application/json")
			enc.Encode(errorResponse{Error: "server_error"})
		}
		refreshToken, err := randomCode(24)
		if err != nil {
			w.WriteHeader(500)
			w.Header().Add("Content-Type", "application/json")
			enc.Encode(errorResponse{Error: "server_error"})
		}

		response := tokenResponse{
			AccessToken:  accessToken,
			TokenType:    "bearer",
			ExpiresIn:    3600,
			RefreshToken: refreshToken,
		}

		storage.Store(response.AccessToken)

		w.Header().Add("Cache-Control", "no-store")
		w.Header().Add("Pragma", "no-cache")
		w.Header().Add("Content-Type", "application/json")

		enc.Encode(response)
	})
}
