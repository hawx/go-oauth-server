package oauth

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
	"hawx.me/code/assert"
)

func TestAuth(t *testing.T) {
	const state = "somesharedstate"

	redirectReq := make(chan *http.Request, 1)

	policy := &Policy{
		Clients: []string{"TestClientId-5843943954"},
	}
	codeStorage := NewMemoryCodeStorage()
	storage := NewMemoryStorage()

	authServer := httptest.NewServer(Auth(policy, codeStorage))
	codeServer := httptest.NewServer(Auth(policy, codeStorage))
	tokenServer := httptest.NewServer(Token(policy, codeStorage, storage))

	defer authServer.Close()
	defer codeServer.Close()
	defer tokenServer.Close()

	l := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, codeServer.URL, http.StatusFound)
	}))
	u := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectReq <- r
	}))
	s := httptest.NewServer(Protect(storage, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "securecontent")
	})))

	defer l.Close()
	defer u.Close()
	defer s.Close()

	policy.LoginURL = l.URL

	conf := &oauth2.Config{
		ClientID:     policy.Clients[0],
		ClientSecret: "SEKRET",
		Endpoint: oauth2.Endpoint{
			AuthURL:  authServer.URL,
			TokenURL: tokenServer.URL,
		},
		RedirectURL: u.URL,
		Scopes:      []string{"test.scope"},
	}

	redirectURL := conf.AuthCodeURL(state, oauth2.AccessTypeOnline)

	// 1. Redirect to auth server
	_, err := http.Get(redirectURL)
	if !assert.Nil(t, err) {
		return
	}

	// 2. Verify a code was returned
	req := <-redirectReq
	assert.Equal(t, state, req.FormValue("state"))
	code := req.FormValue("code")
	assert.NotEmpty(t, code)

	// 3. Exchange code for a token
	tok, err := conf.Exchange(oauth2.NoContext, code)
	if !assert.Nil(t, err) {
		return
	}

	// 4. Create client with token
	client := conf.Client(oauth2.NoContext, tok)

	// 5. Verify secure access
	info, err := client.Get(s.URL)
	if !assert.Nil(t, err) {
		return
	}

	body, _ := ioutil.ReadAll(info.Body)
	assert.Equal(t, 200, info.StatusCode)
	assert.Equal(t, "securecontent", string(body))
}
