package oauth

import (
	"net/http"
	"strings"
)

const bearer = "Bearer"

func Protect(storage Storage, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		parts := strings.Split(auth, " ")

		if parts[0] != bearer || !storage.Verify(parts[1]) {
			w.WriteHeader(401)
			return
		}

		h.ServeHTTP(w, r)
	})
}
