package usecase

import (
	"auth/internal/models"
	"auth/internal/usecase/repo/postgres"
	"context"
	"fmt"
	"github.com/google/uuid"
)

type UserUseCase struct {
	repo UsersRepo
}

var _ UsersRepo = (*postgres.UserRepo)(nil)

func NewUserUseCase(repo UsersRepo) *UserUseCase {
	return &UserUseCase{repo: repo}
}

type UsersRepo interface {
	Add(ctx context.Context, user *models.User) error
	GetByGUID(ctx context.Context, GUID string) (string, error)
}

func (u UserUseCase) Add(ctx context.Context, user *models.User) error {
	const op = "UserUseCase - Add"

	err := u.repo.Add(ctx, user)
	if err != nil {
		return fmt.Errorf("%s - u.repo.Add: %w", op, err)
	}

	return nil
}

func (u UserUseCase) GetByGUID(ctx context.Context, GUID string) (*models.User, error) {
	const op = "UserUseCase - GetByGUID"

	token, err := u.repo.GetByGUID(ctx, GUID)
	if err != nil {
		return nil, fmt.Errorf("%s - u.repo.GetByGUID: %w", op, err)
	}

	ID, err := uuid.Parse(GUID)
	if err != nil {
		return nil, fmt.Errorf("%s - uuid.Parse: %w", op, err)
	}

	user := &models.User{
		ID:    ID,
		Token: token,
	}

	return user, nil
}
