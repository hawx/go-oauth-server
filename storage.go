package oauth

type Storage interface {
	Store(token string)
	Verify(token string) bool
}

func NewMemoryStorage() Storage {
	return &memoryStorage{}
}

type memoryStorage []string

func (l *memoryStorage) Store(token string) {
	*l = append(*l, token)
}

func (l *memoryStorage) Verify(token string) bool {
	for _, r := range *l {
		if r == token {
			return true
		}
	}
	return false
}
