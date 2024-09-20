// internal/storage/postgres/postgres.go

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/NikKazzzzzz/sso/internal/domain/models"
	"github.com/NikKazzzzzz/sso/internal/lib/logger/sl"
	"github.com/NikKazzzzzz/sso/internal/storage"
	"github.com/lib/pq"
	"log/slog"
	"time"
)

type Storage struct {
	db  *sql.DB
	log *slog.Logger
}

// New creates a new instance of the SQLite storage.
func New(connectionString string, log *slog.Logger) (*Storage, error) {
	const op = "storage.postgres.New"

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("%s: failed to cnnect to database: %w", op, err)
	}

	return &Storage{db: db, log: log}, nil
}

func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "storage.postgres.SaveUser"

	stmt, err := s.db.Prepare("INSERT INTO users (email, pass_hash) VALUES ($1, $2) RETURNING id")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	var id int64
	err = stmt.QueryRowContext(ctx, email, passHash).Scan(&id)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
		}

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

// User returns user by email
func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.postgres.User"

	stmt, err := s.db.Prepare("SELECT id, email, pass_hash FROM users WHERE email = $1")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, email)

	var user models.User
	err = row.Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

func (s *Storage) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "storage.postgres.IsAdmin"

	stmt, err := s.db.Prepare("SELECT is_admin FROM users WHERE id = $1")
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, userID)

	var isAdmin bool

	err = row.Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}

		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}

func (s *Storage) App(ctx context.Context, id int) (models.App, error) {
	const op = "storage.postgres.App"

	stmt, err := s.db.Prepare("SELECT id, name, secret FROM apps WHERE id = $1")
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, id)

	var app models.App
	err = row.Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}

		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}

func (s *Storage) Logout(ctx context.Context, token string) error {
	const op = "storage.postgres.Logout"

	stmt, err := s.db.Prepare("DELETE FROM user_tokens WHERE token = $1")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	_, err = stmt.ExecContext(ctx, token)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) SaveToken(ctx context.Context, token string, userID int64, appID int, expiresAt time.Time) error {
	const op = "storage.postgres.SaveToken"

	stmt, err := s.db.Prepare("INSERT INTO user_tokens (token, user_id, app_id, expires_at) VALUES ($1, $2, $3, $4)")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	_, err = stmt.ExecContext(ctx, token, userID, appID, expiresAt)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) IsTokenValid(ctx context.Context, token string) (bool, error) {
	const op = "storage.postgres.IsTokenValid"

	var expiresAt time.Time
	stmt, err := s.db.Prepare("SELECT expires_at FROM user_tokens WHERE token = $1")
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, token)
	err = row.Scan(&expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return time.Now().Before(expiresAt), nil
}

func (s *Storage) GetTokenByUser(ctx context.Context, userID int64, appID int) (string, error) {
	const op = "storage.postgres.GetTokenByUser"

	stmt, err := s.db.Prepare("SELECT token FROM user_tokens WHERE user_id = $1 AND app_id = $2")
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	var token string
	err = stmt.QueryRowContext(ctx, userID, appID).Scan(&token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if s.log != nil {
				s.log.Info("No token found for user", slog.Int64("user_id", userID), slog.Int("app_id", appID))
			}
			return "", storage.TokenNotFound
		}
		if s.log != nil {
			s.log.Error("Failed to get token", sl.Err(err))
		}
		return "", fmt.Errorf("%s: %w", op, err)
	}

	if s.log != nil {
		s.log.Info("Token retrieved", slog.String("token", token))
	}
	return token, nil
}

func (s *Storage) RefreshToken(ctx context.Context, token string, userID int64, expiresAT time.Time) error {
	const op = "storage.postgres.UpdateToken"

	stmt, err := s.db.Prepare("UPDATE user_tokens SET expires_at = $1 WHERE token = $2")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	_, err = stmt.ExecContext(ctx, expiresAT, token)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) UserByID(ctx context.Context, userID int64) (models.User, error) {
	const op = "storage.postgres.UserByID"

	stmt, err := s.db.Prepare("SELECT id, email, pass_hash FROM users WHERE id = $1")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, userID)

	var user models.User
	err = row.Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}
