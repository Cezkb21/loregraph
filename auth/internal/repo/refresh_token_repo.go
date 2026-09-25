package repo

import (
	"context"
	"loregraph_auth/internal/config"
	"loregraph_auth/internal/domain"
	"sync"
	"time"
)

type RefreshTokenRepo struct {
	mu     sync.RWMutex
	saveMu sync.Mutex

	tokens map[string]*domain.RefreshTokenModel
	path   string
}

func NewRefreshTokenRepo(cfg config.RefreshTokenRepoConfig) *RefreshTokenRepo {
	r := &RefreshTokenRepo{
		tokens: make(map[string]*domain.RefreshTokenModel),
		path:   cfg.Path,
	}
	if err := r.load(); err != nil {
		panic(err)
	}
	return r
}

type refreshTokenFile struct {
	Tokens []*domain.RefreshTokenModel `json:"tokens"`
}

func (r *RefreshTokenRepo) load() error {
	var f refreshTokenFile
	if err := readJSON(r.path, &f); err != nil {
		return err
	}
	for _, t := range f.Tokens {
		if t != nil && t.HashedToken != "" {
			r.tokens[t.HashedToken] = t
		}
	}
	return nil
}

func (r *RefreshTokenRepo) save() error {
	r.saveMu.Lock()
	defer r.saveMu.Unlock()

	r.mu.RLock()
	snapshot := make([]*domain.RefreshTokenModel, 0, len(r.tokens))
	for _, t := range r.tokens {
		snapshot = append(snapshot, t)
	}
	r.mu.RUnlock()

	return atomicWriteJSON(r.path, refreshTokenFile{Tokens: snapshot})
}

func (r *RefreshTokenRepo) Create(ctx context.Context, token *domain.RefreshTokenModel) error {

	r.mu.Lock()
	r.cleanupLocked(token.UserID)
	r.tokens[token.HashedToken] = token
	r.mu.Unlock()

	return r.save()
}

func (r *RefreshTokenRepo) Get(ctx context.Context, hashedToken string) (*domain.RefreshTokenModel, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, ok := r.tokens[hashedToken]
	if !ok {
		return nil, domain.ErrTokenNotFound
	}
	return t, nil
}

func (r *RefreshTokenRepo) Revoke(ctx context.Context, hashedToken string) error {
	r.mu.Lock()
	t, ok := r.tokens[hashedToken]
	if !ok {
		r.mu.Unlock()
		return domain.ErrTokenNotFound
	}
	now := time.Now()
	t.RevokedAt = &now
	r.mu.Unlock()

	return r.save()
}

func (r *RefreshTokenRepo) RevokeAll(ctx context.Context, userID string) error {
	r.mu.Lock()
	now := time.Now()
	changed := false
	for _, t := range r.tokens {
		if t.UserID == userID && t.RevokedAt == nil {
			t.RevokedAt = &now
			changed = true
		}
	}
	r.mu.Unlock()

	if !changed {
		return nil
	}
	return r.save()
}

func (r *RefreshTokenRepo) cleanupLocked(userID string) {
	now := time.Now()
	for h, t := range r.tokens {
		if t.UserID != userID {
			continue
		}
		if t.RevokedAt != nil || t.ExpiresAt.Before(now) {
			delete(r.tokens, h)
		}
	}
}
