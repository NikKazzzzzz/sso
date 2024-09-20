// internal/service/auth/auth.go

package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/NikKazzzzzz/sso/internal/domain/models"
	"github.com/NikKazzzzzz/sso/internal/lib/jwt"
	"github.com/NikKazzzzzz/sso/internal/lib/logger/sl"
	"github.com/NikKazzzzzz/sso/internal/storage"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"time"
)

type Auth struct {
	log         *slog.Logger
	usrSaver    UserSaver
	usrProvider UserProvider
	appProvider AppProvider
	tokenTTl    time.Duration
	tokenSaver  TokenSaver
}

type UserSaver interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (uid int64, err error)
}

type TokenSaver interface {
	SaveToken(ctx context.Context, token string, userID int64, appID int, expiresAt time.Time) error
	GetTokenByUser(ctx context.Context, userID int64, appID int) (string, error)
	RefreshToken(ctx context.Context, token string, userID int64, expiresAt time.Time) error
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	UserByID(ctx context.Context, userID int64) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
	Logout(ctx context.Context, token string) error
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidAppID       = errors.New("app not found")
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidToken       = errors.New("invalid token")
)

// New returns a new instance of the Auth service.
func New(log *slog.Logger, userSaver UserSaver, userProvider UserProvider,
	appProvider AppProvider, tokenTTl time.Duration, tokenSaver TokenSaver) *Auth {
	return &Auth{
		usrSaver:    userSaver,
		usrProvider: userProvider,
		log:         log,
		appProvider: appProvider,
		tokenTTl:    tokenTTl,
		tokenSaver:  tokenSaver,
	}
}

// Login checks if user with given credentials exists in the system and returns access token.
//
// If user exists, but password is incorrect, returns error.
// If user doesn't exist, returns error.
func (a *Auth) Login(ctx context.Context, email string, password string, appID int) (string, error) {
	const op = "Auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("username", email),
	)

	log.Info("attempting to login user")

	// Получаем пользователя
	user, err := a.usrProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found")
			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}
		a.log.Error("failed to get user", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	// Проверяем пароль
	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid credentials", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	// Получаем информацию об приложении
	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	// Проверяем наличие существующего токена
	existingToken, err := a.tokenSaver.GetTokenByUser(ctx, user.ID, appID)
	if err != nil {
		if errors.Is(err, storage.TokenNotFound) {
			log.Info("no token found for user", slog.Int64("user_id", user.ID), slog.Int("app_id", appID))
		} else {
			a.log.Error("failed to get existing token", sl.Err(err))
			return "", fmt.Errorf("%s: %w", op, err)
		}
	}

	// Если токен существует, проверяем его действительность
	if existingToken != "" {
		valid, _, err := a.ValidateToken(ctx, existingToken, appID)
		if err == nil && valid {
			// Если токен действителен, просто возвращаем его
			a.log.Info("existing token found and valid, returning it")
			return existingToken, nil
		}

		// Если токен истек или недействителен, создаем новый
		a.log.Info("existing token found but invalid or expired, creating a new token")
		token, err := jwt.NewToken(user, app, a.tokenTTl)
		if err != nil {
			a.log.Error("failed to generate new token", sl.Err(err))
			return "", fmt.Errorf("%s: %w", op, err)
		}
		expiresAt := time.Now().UTC().Add(a.tokenTTl)
		if err := a.tokenSaver.SaveToken(ctx, token, user.ID, appID, expiresAt); err != nil {
			a.log.Error("failed to save token", sl.Err(err))
			return "", fmt.Errorf("%s: %w", op, err)
		}
		return token, nil
	}

	// Если токен не найден, создаем новый
	token, err := jwt.NewToken(user, app, a.tokenTTl)
	if err != nil {
		a.log.Error("failed to generate token", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}
	expiresAt := time.Now().UTC().Add(a.tokenTTl)
	if err := a.tokenSaver.SaveToken(ctx, token, user.ID, appID, expiresAt); err != nil {
		a.log.Error("failed to save token", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

// RegisterNewUser registers new user in the system and returns user ID.
// If user with given username already exists, returns error.
func (a *Auth) RegisterNewUser(ctx context.Context, email string, pass string) (int64, error) {
	const op = "Auth.registerNewUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registering new user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate hash password", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.usrSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("user already exists", sl.Err(err))

			return 0, fmt.Errorf("%s: %w", op, ErrUserExists)
		}
		log.Error("failed to save user", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user registered")

	return id, nil
}

// IsAdmin checks if user is admin.
func (a *Auth) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "Auth.isAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("checking if user is admin")

	isAdmin, err := a.usrProvider.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("user not found", sl.Err(err))

			return false, fmt.Errorf("%s: %w", op, ErrInvalidAppID)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked if user is admin", slog.Bool("is_admin", isAdmin))

	return isAdmin, nil
}

func (a *Auth) Logout(ctx context.Context, token string) error {
	const op = "Auth.logout"

	log := a.log.With(
		slog.String("op", op),
		slog.String("token", token),
	)

	log.Info("logout")

	if token == "" {
		log.Warn("invalid token")
		return fmt.Errorf("%s: %w", op, ErrInvalidToken)
	}

	err := a.usrProvider.Logout(ctx, token)
	if err != nil {
		log.Error("failed to invalidate token", sl.Err(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged out successfully")
	return nil
}

func (a *Auth) ValidateToken(ctx context.Context, token string, appID int) (bool, int64, error) {
	const op = "Auth.ValidateToken"

	log := a.log.With(
		slog.String("op", op),
		slog.String("token", token),
	)

	log.Info("validating token")

	// Получаем приложение по идентификатору
	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		log.Error("failed to get app", sl.Err(err))
		return false, 0, nil
	}

	claims, err := jwt.ParseToken(token, app.Secret) // Передаем оба аргумента
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			// Токен истек, создаем новый
			newToken, _, refreshErr := a.RefreshToken(ctx, token, appID)
			if refreshErr != nil {
				log.Error("failed to refresh token", sl.Err(refreshErr))
				return false, 0, fmt.Errorf("%s: %w", op, ErrInvalidToken)
			}
			log.Info("token refreshed successfully", slog.String("new_token", newToken))
			return true, claims.UserID, nil
		}
		log.Error("failed to parse token", sl.Err(err))
		return false, 0, fmt.Errorf("%s: %w", op, ErrInvalidToken)
	}

	userID := claims.UserID

	log.Info("token validated", slog.Int64("user_id", userID))

	return true, userID, nil
}

func (a *Auth) RefreshToken(ctx context.Context, oldToken string, appID int) (newToken string, expiresAt time.Time, err error) {
	const op = "Auth.RefreshToken"

	log := a.log.With(
		slog.String("op", op),
		slog.String("oldToken", oldToken),
		slog.Int("app_id", appID),
	)

	log.Info("refreshing token")

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		log.Error("failed to get app", sl.Err(err))
		return "", time.Time{}, fmt.Errorf("%s: %w", op, err)
	}

	claims, err := jwt.ParseToken(oldToken, app.Secret)
	if err != nil {
		log.Error("failed to parse old token", sl.Err(err))
		return "", time.Time{}, fmt.Errorf("%s: %w", op, ErrInvalidToken)
	}

	userID := claims.UserID

	user, err := a.usrProvider.UserByID(ctx, userID)
	if err != nil {
		log.Error("failed to get user", sl.Err(err))
		return "", time.Time{}, fmt.Errorf("%s: %w", op, err)
	}

	newToken, err = jwt.NewToken(user, app, a.tokenTTl)
	if err != nil {
		log.Error("failed to generate token", sl.Err(err))
		return "", time.Time{}, fmt.Errorf("%s: %w", op, err)
	}

	expiresAt = time.Now().UTC().Add(a.tokenTTl)

	err = a.tokenSaver.SaveToken(ctx, newToken, userID, appID, expiresAt)
	if err != nil {
		log.Error("failed to save new token", sl.Err(err))
		return "", time.Time{}, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("token refreshed successfully", slog.String("new_token", newToken), slog.Time("expires_at", expiresAt))

	return newToken, expiresAt, nil
}
