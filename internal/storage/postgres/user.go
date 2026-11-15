package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/codebyallan/auth-api/internal/common"
	"github.com/codebyallan/auth-api/internal/user"
	"github.com/jackc/pgx/v5/pgconn"
)

const uniqueViolation = "23505"

type UserRepo struct {
	db *sql.DB
}

func NewUserRepo(db *sql.DB) *UserRepo {
	return &UserRepo{db: db}
}

var _ user.UserRepository = (*UserRepo)(nil)

func (r *UserRepo) Create(ctx context.Context, u *user.User) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, created_at)
         VALUES ($1, $2, $3, $4)`,
		u.ID, u.Email, u.PasswordHash, u.CreatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return common.ErrEmailInUse
		}
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (r *UserRepo) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	var u user.User
	err := r.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, created_at
         FROM users
         WHERE email = $1`,
		email,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, common.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user by email: %w", err)
	}
	return &u, nil
}
