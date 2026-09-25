package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"loregraph_auth/internal/app/security"
	"loregraph_auth/internal/domain"
	"time"
)

type AuthService struct {
	userRepo  domain.UserRepo
	tokenRepo domain.RefreshTokenRepo

	// maxUsers caps how many accounts may exist. 0 disables the check.
	maxUsers int

	passwordHasher Hasher
	tokenHasher    Hasher
	tokenManager   TokenManager

	logger *slog.Logger
}

func NewAuthService(
	userDB domain.UserRepo,
	tokenDB domain.RefreshTokenRepo,

	maxUsers int,

	hasherForPass Hasher,
	hasherForToken Hasher,
	tokenManager TokenManager,

	logger *slog.Logger,
) *AuthService {
	return &AuthService{
		userRepo:  userDB,
		tokenRepo: tokenDB,

		maxUsers: maxUsers,

		passwordHasher: hasherForPass,
		tokenHasher:    hasherForToken,
		tokenManager:   tokenManager,

		logger: logger,
	}
}

func (s *AuthService) Login(ctx context.Context, email, password string) (string, string, string, error) {
	s.logger.InfoContext(ctx, "[AuthService] Login", slog.String("email", email))

	if !domain.IsValidEmail(email) || !domain.IsValidPassword(password) {
		s.logger.InfoContext(ctx, "[AuthService] Login: invalid credentials",
			slog.String("email", email),
			slog.String("password", password))
		return "", "", "", domain.ErrUserInvalidCredentials
	}

	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			s.logger.WarnContext(ctx, "[AuthService] Login: user not found", slog.String("email", email))
			return "", "", "", domain.ErrUserInvalidCredentials
		}
		s.logger.ErrorContext(ctx, "[AuthService] Login: db error", slog.String("email", email), slog.Any("error", err))
		return "", "", "", fmt.Errorf("db find by email: %w", err)
	}

	ok, err := s.passwordHasher.Verify(password, user.HashedPassword)
	if err != nil {
		s.logger.ErrorContext(ctx, "[AuthService] Login: password verification error", slog.String("email", email), slog.Any("error", err))
		return "", "", "", fmt.Errorf("password verification error: %w", err)
	}
	if !ok {
		s.logger.WarnContext(ctx, "[AuthService] Login: invalid password", slog.String("email", email))
		return "", "", "", domain.ErrUserInvalidCredentials
	}

	access, refresh, err := s.generateTokenPair(ctx, user.ID, user.Role)
	if err != nil {
		return "", "", "", err
	}

	s.logger.InfoContext(ctx, "[AuthService] Login: success", slog.String("user_id", user.ID))
	return access, refresh, user.ID, nil
}

func (s *AuthService) Register(ctx context.Context, email, password string) (string, string, string, error) {
	s.logger.InfoContext(ctx, "[AuthService] Register:",
		slog.String("email", email))

	if !domain.IsValidEmail(email) || !domain.IsValidPassword(password) {
		s.logger.InfoContext(ctx, "[AuthService] Register: invalid credentials",
			slog.String("email", email),
			slog.String("password", password))
		return "", "", "", domain.ErrUserInvalidCredentials
	}

	user, err := s.userRepo.FindByEmail(ctx, email)
	if err == nil {
		s.logger.WarnContext(ctx, "[AuthService] Register: [db] user already registered",
			slog.String("email", email))
		return "", "", "", domain.ErrUserAlreadyExists
	} else if !errors.Is(err, domain.ErrUserNotFound) {
		s.logger.ErrorContext(ctx, "[AuthService] Register: [db] user lookup error",
			slog.String("email", email), slog.Any("error", err))
		return "", "", "", fmt.Errorf("db error: %w", err)
	}

	if s.maxUsers > 0 {
		count, err := s.userRepo.Count(ctx)
		if err != nil {
			s.logger.ErrorContext(ctx, "[AuthService] Register: count users error",
				slog.Any("error", err))
			return "", "", "", fmt.Errorf("count users error: %w", err)
		}
		if count >= s.maxUsers {
			s.logger.WarnContext(ctx, "[AuthService] Register: user limit reached",
				slog.Int("count", count), slog.Int("limit", s.maxUsers))
			return "", "", "", domain.ErrUserLimitReached
		}
	}

	hashed, err := s.passwordHasher.Hash(password)
	if err != nil {
		s.logger.ErrorContext(ctx, "[AuthService] Register: password hashing error", slog.String("email", email),
			slog.Any("error", err))
		return "", "", "", fmt.Errorf("hash error: %w", err)
	}

	user = domain.NewUser(email, hashed)
	if err = s.userRepo.Create(ctx, user); err != nil {
		s.logger.ErrorContext(ctx, "[AuthService] Register: failed to create user in DB",
			slog.String("email", email),
			slog.Any("error", err))
		return "", "", "", fmt.Errorf("user create error: %w", err)
	}

	access, refresh, err := s.generateTokenPair(ctx, user.ID, user.Role)
	if err != nil {
		return "", "", "", err
	}

	s.logger.InfoContext(ctx, "[AuthService] Register: success", slog.String("user_id", user.ID))
	return access, refresh, user.ID, nil
}

func (s *AuthService) Refresh(ctx context.Context, oldRefreshToken string) (string, string, error) {
	s.logger.InfoContext(ctx, "[AuthService] Refresh starting")

	userID, hashedToken, err := s.validateRefreshTokenWithDB(ctx, oldRefreshToken)
	if err != nil {
		return "", "", err
	}

	role, err := s.getUserRole(ctx, userID)
	if err != nil {
		return "", "", err
	}

	newAccessToken, newRefreshToken, err := s.generateTokenPair(ctx, userID, role)
	if err != nil {
		return "", "", err
	}

	err = s.tokenRepo.Revoke(ctx, hashedToken)
	if err != nil {
		s.logger.ErrorContext(ctx, "[AuthService] Refresh: failed to revoke refresh token",
			slog.String("old_refresh_token", tokenPrefix(oldRefreshToken)))
		return "", "", fmt.Errorf("revoke old refresh token error: %w", err)
	}
	s.logger.InfoContext(ctx, "[AuthService] Refresh: success",
		slog.String("user_id", userID),
		slog.String("old_refresh_token", tokenPrefix(oldRefreshToken)),
		slog.String("new_refresh_token", tokenPrefix(newRefreshToken)))
	return newAccessToken, newRefreshToken, nil
}

func (s *AuthService) ValidateToken(ctx context.Context, accessToken string) (string, error) {
	s.logger.InfoContext(ctx, "[AuthService] ValidateToken starting")
	userID, err := s.tokenManager.ValidateAccessToken(accessToken)
	if err != nil {
		switch {
		case errors.Is(err, security.ErrInvalidToken):
			s.logger.WarnContext(ctx, "[AuthService] ValidateToken: invalid access token",
				slog.String("token_prefix", tokenPrefix(accessToken)))
			return "", security.ErrInvalidToken
		case errors.Is(err, security.ErrTokenExpired):
			s.logger.WarnContext(ctx, "[AuthService] ValidateToken: access token expired",
				slog.String("token_prefix", tokenPrefix(accessToken)))
			return "", security.ErrTokenExpired
		default:
			s.logger.ErrorContext(ctx, "[AuthService] ValidateToken: unexpected error",
				slog.String("token_prefix", tokenPrefix(accessToken)), slog.Any("error", err))
			return "", fmt.Errorf("token validation error: %w", err)
		}
	}

	s.logger.DebugContext(ctx, "[AuthService] ValidateToken: success", slog.String("user_id", userID))
	return userID, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	s.logger.InfoContext(ctx, "[AuthService] Logout", slog.String("token_prefix", tokenPrefix(refreshToken)))

	_, hashedToken, err := s.validateRefreshTokenWithDB(ctx, refreshToken)
	if err != nil {
		return err
	}

	err = s.tokenRepo.Revoke(ctx, hashedToken)
	if err != nil {
		if errors.Is(err, domain.ErrTokenNotFound) {
			s.logger.WarnContext(ctx, "[AuthService] Logout: token not found", slog.String("token_prefix", tokenPrefix(refreshToken)))
			return domain.ErrTokenNotFound
		}
		s.logger.ErrorContext(ctx, "[AuthService] Logout: failed to revoke token", slog.String("token_prefix", tokenPrefix(refreshToken)), slog.Any("error", err))
		return fmt.Errorf("refresh token revoke error: %w", err)
	}

	s.logger.InfoContext(ctx, "[AuthService] Logout: success", slog.String("token_prefix", tokenPrefix(refreshToken)))
	return nil
}

func (s *AuthService) LogoutAll(ctx context.Context, refreshToken string) error {
	s.logger.InfoContext(ctx, "[AuthService] LogoutAll",
		slog.String("refresh_token", tokenPrefix(refreshToken)))

	userID, _, err := s.validateRefreshTokenWithDB(ctx, refreshToken)
	if err != nil {
		return err
	}

	err = s.tokenRepo.RevokeAll(ctx, userID)
	if err != nil {
		s.logger.ErrorContext(ctx, "[AuthService] LogoutAll: failed to revoke all tokens",
			slog.String("user_id", userID),
			slog.Any("error", err))
		return fmt.Errorf("refresh token revoke all error: %w", err)
	}

	s.logger.InfoContext(ctx, "[AuthService] LogoutAll: success", slog.String("user_id", userID))
	return nil
}

func (s *AuthService) generateTokenPair(ctx context.Context, userID, role string) (string, string, error) {
	s.logger.DebugContext(ctx, "[AuthService] generateTokenPair", slog.String("user_id", userID))

	access, err := s.tokenManager.GenerateAccessToken(userID, role)
	if err != nil {
		s.logger.ErrorContext(ctx, "[AuthService] generateTokenPair: failed to generate access token", slog.String("user_id", userID), slog.Any("error", err))
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	refresh, expiresAt, err := s.tokenManager.GenerateRefreshToken(userID)
	if err != nil {
		s.logger.ErrorContext(ctx, "[AuthService] generateTokenPair: failed to generate refresh token", slog.String("user_id", userID), slog.Any("error", err))
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	hashed, err := s.tokenHasher.Hash(refresh)
	if err != nil {
		s.logger.ErrorContext(ctx, "[AuthService] generateTokenPair: failed to hash refresh token", slog.String("user_id", userID), slog.Any("error", err))
		return "", "", fmt.Errorf("failed to hash refresh token: %w", err)
	}

	model := domain.NewRefreshTokenModel(userID, hashed, expiresAt)

	err = s.tokenRepo.Create(ctx, model)
	if err != nil {
		s.logger.ErrorContext(ctx, "[AuthService] generateTokenPair: failed to save refresh token to DB", slog.String("user_id", userID), slog.Any("error", err))
		return "", "", fmt.Errorf("failed to save refresh token to DB: %w", err)
	}

	s.logger.DebugContext(ctx, "[AuthService] generateTokenPair: success", slog.String("user_id", userID))
	return access, refresh, nil
}
func (s *AuthService) getUserRole(ctx context.Context, userID string) (string, error) {
	s.logger.DebugContext(ctx, "[AuthService] getUserRole", slog.String("user_id", userID))

	role, err := s.userRepo.FindRoleByUserID(ctx, userID)
	if err == nil {
		s.logger.DebugContext(ctx, "[AuthService] getUserRole: from DB",
			slog.String("user_id", userID),
			slog.String("role", role))
		return role, nil
	}

	if errors.Is(err, domain.ErrUserNotFound) {
		s.logger.InfoContext(ctx, "[AuthService] getUserRole: user not found in DB", slog.String("user_id", userID))
		return "", domain.ErrUserNotFound
	}

	s.logger.ErrorContext(ctx, "[AuthService] getUserRole: DB error", slog.String("user_id", userID), slog.Any("error", err))
	return "", fmt.Errorf("failed to get user role: %w", err)
}
func (s *AuthService) validateRefreshTokenWithDB(ctx context.Context, refreshToken string) (userID string, hashedToken string, err error) {
	userID, err = s.tokenManager.ValidateRefreshToken(refreshToken)
	if err != nil {
		s.logger.WarnContext(ctx, "[AuthService] validateRefreshTokenWithDB: failed to validate refresh token",
			slog.String("refresh_token", tokenPrefix(refreshToken)),
			slog.Any("error", err))
		return "", "", fmt.Errorf("failed to validate refresh token: %w", err)
	}

	hashedToken, err = s.tokenHasher.Hash(refreshToken)
	if err != nil {
		s.logger.ErrorContext(ctx, "[AuthService] validateRefreshTokenWithDB: failed to hash refresh token",
			slog.String("refresh_token", tokenPrefix(refreshToken)),
			slog.Any("error", err))
		return "", "", fmt.Errorf("failed to hash refresh token: %w", err)
	}

	tokenModel, err := s.tokenRepo.Get(ctx, hashedToken)
	if err != nil {
		if errors.Is(err, domain.ErrTokenNotFound) {
			s.logger.WarnContext(ctx, "[AuthService] validateRefreshTokenWithDB: refresh token not found",
				slog.String("refresh_token", tokenPrefix(refreshToken)))
			return "", "", domain.ErrTokenNotFound
		}
		s.logger.ErrorContext(ctx, "[AuthService] validateRefreshTokenWithDB: failed to find refresh token",
			slog.String("refresh_token", tokenPrefix(refreshToken)))
		return "", "", fmt.Errorf("refresh token fetch error: %w", err)
	}

	switch {
	case userID != tokenModel.UserID:
		s.logger.WarnContext(ctx, "[AuthService] validateRefreshTokenWithDB: user id not match")
		return "", "", security.ErrUserIDNotMatch
	case tokenModel.RevokedAt != nil:
		s.logger.WarnContext(ctx, "[AuthService] validateRefreshTokenWithDB: refresh token revoked")
		return "", "", domain.ErrTokenRevoked
	case tokenModel.ExpiresAt.Before(time.Now()):
		s.logger.WarnContext(ctx, "[AuthService] validateRefreshTokenWithDB: refresh token expired")
		return "", "", security.ErrTokenExpired
	}

	s.logger.DebugContext(ctx, "[AuthService] validateRefreshTokenWithDB: refresh token validated")
	return userID, hashedToken, nil
}

func tokenPrefix(token string) string {
	if len(token) >= 8 {
		return token[:8]
	}
	return token
}
