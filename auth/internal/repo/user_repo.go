package repo

import (
	"context"
	"loregraph_auth/internal/config"
	"loregraph_auth/internal/domain"
	"sync"
)

type UserRepo struct {
	muAuth sync.RWMutex
	muRole sync.RWMutex
	saveMu sync.Mutex

	usersAuth map[string]*domain.User
	usersRole map[string]string

	path string
}

func NewUserRepo(cfg config.UserRepoConfig) *UserRepo {
	r := &UserRepo{
		usersAuth: make(map[string]*domain.User),
		usersRole: make(map[string]string),
		path:      cfg.Path,
	}
	if err := r.load(); err != nil {
		panic(err)
	}
	return r
}

type userRepoFile struct {
	UsersAuth map[string]*domain.User `json:"users_auth"`
	UsersRole map[string]string       `json:"users_role"`
}

func (r *UserRepo) load() error {
	var f userRepoFile
	if err := readJSON(r.path, &f); err != nil {
		return err
	}
	for k, v := range f.UsersAuth {
		r.usersAuth[k] = v
	}
	for k, v := range f.UsersRole {
		r.usersRole[k] = v
	}
	return nil
}

func (r *UserRepo) save() error {
	r.saveMu.Lock()
	defer r.saveMu.Unlock()

	r.muAuth.RLock()
	defer r.muAuth.RUnlock()
	r.muRole.RLock()
	defer r.muRole.RUnlock()

	auth := make(map[string]*domain.User, len(r.usersAuth))
	for k, v := range r.usersAuth {
		auth[k] = v
	}
	role := make(map[string]string, len(r.usersRole))
	for k, v := range r.usersRole {
		role[k] = v
	}

	return atomicWriteJSON(r.path, userRepoFile{UsersAuth: auth, UsersRole: role})
}

func (r *UserRepo) Create(ctx context.Context, u *domain.User) error {
	r.muAuth.Lock()
	r.usersAuth[u.Email] = u

	r.muRole.Lock()
	r.usersRole[u.ID] = u.Role
	r.muRole.Unlock()
	r.muAuth.Unlock()

	return r.save()
}

func (r *UserRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	r.muAuth.RLock()
	defer r.muAuth.RUnlock()

	u, ok := r.usersAuth[email]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}

func (r *UserRepo) Update(ctx context.Context, u *domain.User) error {
	r.muAuth.Lock()
	r.usersAuth[u.Email] = u
	r.muAuth.Unlock()

	return r.save()
}

func (r *UserRepo) FindRoleByUserID(ctx context.Context, userID string) (string, error) {
	r.muRole.RLock()
	defer r.muRole.RUnlock()

	role, ok := r.usersRole[userID]
	if !ok {
		return "", domain.ErrUserNotFound
	}
	return role, nil
}

func (r *UserRepo) CreateRoleByID(ctx context.Context, userID, role string) error {
	r.muRole.Lock()
	r.usersRole[userID] = role
	r.muRole.Unlock()

	return r.save()
}

// Count returns how many users are stored. Under the read lock that Create
// holds while writing, so the value cannot change mid-read. There is still a
// theoretical race between this and a following Create (two concurrent
// registers could both see count = 9 and both create) — accepted because the
// cost of preventing it (a transactional create-if-under-limit) is not worth
// it at the scale this service is built for.
func (r *UserRepo) Count(ctx context.Context) (int, error) {
	r.muAuth.RLock()
	defer r.muAuth.RUnlock()
	return len(r.usersAuth), nil
}
