package security

import (
	"context"
	"errors"
	"github.com/DABronskikh/ago-1/cmd/service/app/dto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrUserDuplication = errors.New("username already used")
	ErrRequiredLogin   = errors.New("required parameter is missing: login")
	ErrRequiredPass    = errors.New("required parameter is missing: password")
	ErrDB              = errors.New("error db")
	ErrNoAccess        = errors.New("no access")
)

const (
	RoleAdmin = "ADMIN"
	RoleUser  = "USER"
)

type Service struct {
	pool *pgxpool.Pool
}

type UserDetails struct {
	ID    int64
	Login string
	Roles []string
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// Возвращает профиль пользователя по id
func (s *Service) UserDetails(ctx context.Context, id *string) (interface{}, error) {
	details := &UserDetails{}
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.login, u.roles FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.id = $1
	`, id).Scan(&details.ID, &details.Login, &details.Roles)

	if err == pgx.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	return details, nil
}

// Проверяет, есть ли у пользователя соответствующая роль
func (s *Service) HasAnyRole(ctx context.Context, userDetails interface{}, roles ...string) bool {
	details, ok := userDetails.(*UserDetails)
	if !ok {
		return false
	}

	for _, role := range roles {
		for _, r := range details.Roles {
			if role == r {
				return true
			}
		}
	}

	return false
}

func (s *Service) Login(ctx context.Context, login string, password string) (*string, error) {
	var userID int64
	var hash []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, password FROM users WHERE login = $1
	`, login).Scan(&userID, &hash)

	if err == pgx.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err != nil {
		return nil, ErrUserNotFound
	}

	token := uuid.New().String()
	_, err = s.pool.Exec(ctx, `INSERT INTO tokens (id, user_id) VALUES ($1, $2)`, token, userID)

	if err != nil {
		return nil, err
	}

	return &token, nil
}

func (s *Service) Register(ctx context.Context, login string, password string) (*int64, error) {
	hashPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	var id int64
	err = s.pool.QueryRow(ctx, `
		INSERT INTO users(login, password, roles) VALUES($1, $2, $3) ON CONFLICT DO NOTHING RETURNING id
		`, login, string(hashPass), "{USER}").Scan(&id)

	if err == pgx.ErrNoRows {
		return nil, ErrUserDuplication
	}
	if err != nil {
		return nil, err
	}

	return &id, nil
}

func (s *Service) GetCardsUser(ctx context.Context, userID int64) ([]*dto.CardDTO, error) {
	cardDB := []*dto.CardDTO{}
	rows, err := s.pool.Query(ctx, `
		SELECT id, number, balance, issuer, holder, user_id, status, created
		FROM cards 
		WHERE user_id = $1
		LIMIT 50
	`, userID)
	defer rows.Close()

	for rows.Next() {
		cardEl := &dto.CardDTO{}
		err = rows.Scan(&cardEl.Id, &cardEl.Number, &cardEl.Balance, &cardEl.Issuer, &cardEl.Holder, &cardEl.UserId, &cardEl.Status, &cardEl.Created)
		if err != nil {
			return nil, ErrDB
		}
		cardDB = append(cardDB, cardEl)
	}

	if err != nil {
		return nil, ErrDB
	}

	return cardDB, nil
}

func (s *Service) GetCardsAdmin(ctx context.Context) ([]*dto.CardDTO, error) {
	cardDB := []*dto.CardDTO{}
	rows, err := s.pool.Query(ctx, `
		SELECT id, number, balance, issuer, holder, user_id, status, created
		FROM cards
		LIMIT 50
	`)
	defer rows.Close()

	for rows.Next() {
		cardEl := &dto.CardDTO{}
		err = rows.Scan(&cardEl.Id, &cardEl.Number, &cardEl.Balance, &cardEl.Issuer, &cardEl.Holder, &cardEl.UserId, &cardEl.Status, &cardEl.Created)
		if err != nil {
			return nil, ErrDB
		}
		cardDB = append(cardDB, cardEl)
	}

	if err != nil {
		return nil, ErrDB
	}

	return cardDB, nil
}
