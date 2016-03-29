package oauth

import "sync"

type CodeStorage interface {
	Store(redirectURI, code string)
	Verify(redirectURI, code string) bool
}

func NewMemoryCodeStorage() CodeStorage {
	return &memoryCodeStorage{rs: map[string][]string{}}
}

type memoryCodeStorage struct {
	mu sync.RWMutex

	// map of {redirectURI: [code1, code2, ...]} values
	rs map[string][]string
}

func (s *memoryCodeStorage) Store(redirectURI, code string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if codes, ok := s.rs[redirectURI]; ok {
		s.rs[redirectURI] = append(codes, code)
		return
	}

	s.rs[redirectURI] = []string{code}
}

func (s *memoryCodeStorage) Verify(redirectURI, code string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	codes, ok := s.rs[redirectURI]
	if !ok {
		return false
	}

	for _, c := range codes {
		if code == c {
			return true
		}
	}

	return false
}
