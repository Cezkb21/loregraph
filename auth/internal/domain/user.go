package domain

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"
	"uuid"
)

type User struct {
	ID             string
	Email          string
	HashedPassword string
	Role           string
	CreatedAt      time.Time
}

func NewUser(email, hashedPassword string) *User {
	user := &User{
		ID:             uuid.New().String(),
		Email:          email,
		HashedPassword: hashedPassword,
		Role:           "user",
		CreatedAt:      time.Now(),
	}
	return user
}

type UserRepo interface {
	Create(ctx context.Context, user *User) (err error)
	FindByEmail(ctx context.Context, email string) (user *User, err error)
	FindRoleByUserID(ctx context.Context, userID string) (role string, err error)
	Update(ctx context.Context, user *User) (err error)
	CreateRoleByID(ctx context.Context, userID, role string) error
	Count(ctx context.Context) (int, error)
}

var (
	ErrUserNotFound           = errors.New("user not found")
	ErrUserInvalidCredentials = errors.New("invalid credentials")
	ErrUserAlreadyExists      = errors.New("user already exists")
	ErrUserLimitReached       = errors.New("user limit reached")
)

func IsValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func IsValidPassword(password string) bool {
	password = strings.TrimSpace(password)
	count := utf8.RuneCountInString(password)
	return count >= 8 && count <= 32
}
