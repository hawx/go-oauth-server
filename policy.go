package oauth

type Policy struct {
	// LoginURL is redirected to when determining if to issue a code.
	LoginURL string

	// Clients is a list of known clients able to request codes.
	Clients []string
}

func (p Policy) IsAllowedClient(client string) bool {
	for _, c := range p.Clients {
		if client == c {
			return true
		}
	}

	return false
}
