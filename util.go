package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
)

func randomCode(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)

	return base64.StdEncoding.EncodeToString(b), err
}

func redirect(w http.ResponseWriter, r *http.Request, u *url.URL, q url.Values) {
	u.RawQuery = q.Encode()
	redirectURI := u.String()

	http.Redirect(w, r, redirectURI, http.StatusFound)
}
