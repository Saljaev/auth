package postgres

import (
	"auth/internal/models"
	"context"
	"database/sql"
	"fmt"
)

type UserRepo struct {
	*sql.DB
}

func NewUserRepo(db *sql.DB) *UserRepo {
	return &UserRepo{db}
}

func (u UserRepo) Add(ctx context.Context, user *models.User) error {
	const op = "UserRepo - Add"

	query := "INSERT INTO users (id, token) " +
		"VALUES ($1, $2) ON CONFLICT (id) DO UPDATE " +
		"SET token = excluded.token"

	err := u.QueryRowContext(ctx, query, user.ID.String(), user.Token).Err()
	if err != nil {
		return fmt.Errorf("%s - u.QueryRowContext: %w", op, err)
	}

	return nil
}

func (u UserRepo) GetByGUID(ctx context.Context, GUID string) (string, error) {
	const op = "UserRepo - GetByGUID"

	query := "SELECT token FROM users " +
		"WHERE id = $1"

	rows, err := u.QueryContext(ctx, query, GUID)
	if err != nil {
		return "", fmt.Errorf("%s - u.QueryContext :%w", op, err)
	}

	defer rows.Close()

	var token string

	rows.Next()
	rows.Scan(&token)

	return token, err
}
