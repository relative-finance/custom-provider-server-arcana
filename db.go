package main

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	_ "github.com/lib/pq" // PostgreSQL driver
)

const TELEGRAM_PROVIDER = "telegram"

func generateUniqueUserID(db *sql.DB) (string, error) {
	var userID string
	const length = 255
	for {
		userID = uuid.New().String()
		exists, err := checkIfUserIDExists(db, userID)
		if err != nil {
			return "", err
		}
		if !exists {
			break
		}
	}
	return userID, nil
}

func checkIfUserIDExists(db *sql.DB, userID string) (bool, error) {
	var exists bool
	// Changed placeholder from '?' to '$1' for PostgreSQL
	query := "SELECT EXISTS (SELECT 1 FROM provider_users WHERE user_id = $1)"
	err := db.QueryRow(query, userID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

type UserStore interface {
	CreateNewUser(localUserID, provider string) error
	GetUserID(localUserID, provider string) (string, error)
	LinkToExistingUser(localUserID, provider, userID string) error
	GetConnectedAccounts(userID string) ([]Account, error)

	AddSteamSession(clientID, redirect, state string) (err error)
	GetSteamSession(state string) (session SteamSession, err error)
	GetSteamSessionByCode(code string) (session SteamSession, err error)
	UpdateSteamSession(id int, steamID, code string) (err error)
	DeleteSteamSession(id int) (err error)

	AddSteamProfile(s *SteamPlayer) error
	GetSteamProfile(steamID string) (*SteamPlayer, error)

	CreateLichessToken(name string, lichessToken string) error
	GetLichessToken(name string) (string, error)
	GetMultipleLichessTokens(names []string, useUserIdQuery bool) (GetLichessUserInfoRes, error)
	GetLinkedTelegramIDFromShowdownID(showdownUserID string) (string, error)
	GetLinkedShowdownIDFromTelegramID(telegramUserID string) (string, error)
	GetTelegramUsersByShowdownIDs(showdownUserIDs []string) ([]TelegramUser, error)
	UpsertTelegramUser(telegramID string, firstName, lastName, username string) error
}

type PostgresDB struct {
	*sql.DB
}

func connectToDB(connectionUrl string) (*PostgresDB, error) {
	// Changed driver name from 'mysql' to 'postgres'
	db, err := sql.Open("postgres", connectionUrl)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(20)
	db.SetConnMaxLifetime(5 * time.Minute)

	err = db.Ping()
	if err != nil {
		return nil, err
	}
	store := &PostgresDB{db}
	return store, nil
}

func (s *PostgresDB) CreateNewUser(localUserID, provider string) error {

	// Changed SQL syntax to match PostgreSQL
	var id int
	err := s.QueryRow("INSERT INTO users (name) VALUES ($1) RETURNING id", localUserID).Scan(&id)
	if err != nil {
		return err
	}

	userID, err := generateUniqueUserID(s.DB)
	if err != nil {
		return err
	}

	// Changed SQL syntax to match PostgreSQL
	rows, err := s.Query("INSERT INTO provider_users (user_id, local_id, provider) VALUES ($1, $2, $3)", userID, localUserID, provider)
	if err != nil {
		return err
	}
	defer rows.Close()

	return nil
}

func (s *PostgresDB) GetUserID(localUserID, provider string) (string, error) {
	var id string
	// Changed placeholders from '?' to '$1', '$2'
	err := s.QueryRow("SELECT user_id FROM provider_users WHERE local_id=$1 AND provider=$2", localUserID, provider).Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return id, nil
}

type Account struct {
	Provider string `json:"provider"`
	ID       string `json:"id"`
}

func (s *PostgresDB) GetConnectedAccounts(userID string) ([]Account, error) {
	var data []Account
	// Changed placeholders from '?' to '$1'
	rows, err := s.Query("SELECT provider, local_id FROM provider_users WHERE user_id=$1", userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return data, nil
		}
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var provider, localID string
		if err := rows.Scan(&provider, &localID); err != nil {
			continue
		}
		fmt.Println("provider", provider, "localID", localID)
		data = append(data, Account{provider, localID})
	}
	return data, nil
}

func (s *PostgresDB) LinkToExistingUser(localUserID, provider, userID string) error {
	// Changed placeholders from '?' to '$1', '$2', '$3'
	rows, err := s.Query("INSERT INTO provider_users (user_id, local_id, provider) VALUES ($1, $2, $3)", userID, localUserID, provider)
	if err != nil {
		return err
	}
	defer rows.Close()
	return nil
}

func (s *PostgresDB) AddSteamSession(clientID, redirect, state string) (err error) {
	// Changed placeholders from '?' to '$1', '$2', '$3'
	rows, err := s.Query(`
	INSERT INTO steam_login (client_id, redirect_uri, state) VALUES ($1, $2, $3)
	`, clientID, redirect, state)
	if err != nil {
		return
	}
	defer rows.Close()
	return
}

func (s *PostgresDB) GetSteamSession(state string) (session SteamSession, err error) {
	// Changed placeholders from '?' to '$1'
	err = s.QueryRow(`
	SELECT id, client_id, redirect_uri, state, code FROM steam_login WHERE state = $1
	`, state).Scan(&session.ID, &session.ClientID, &session.RedirectURI, &session.State, &session.Code)
	if err != nil {
		if err == sql.ErrNoRows {
			return session, errors.New("No session found")
		}
		return session, err
	}
	return
}

func (s *PostgresDB) GetSteamSessionByCode(code string) (session SteamSession, err error) {
	// Changed placeholders from '?' to '$1'
	err = s.QueryRow(`
	SELECT id, steam_id, client_id, redirect_uri, state, code FROM steam_login WHERE code = $1
	`, code).Scan(&session.ID, &session.SteamID, &session.ClientID, &session.RedirectURI, &session.State, &session.Code)
	if err != nil {
		if err == sql.ErrNoRows {
			return session, errors.New("No session found")
		}
		return session, err
	}
	return
}
func (s *PostgresDB) UpdateSteamSession(id int, steamID, code string) error {
	// Changed placeholders from '?' to '$1', '$2', '$3'
	rows, err := s.Query(`
	UPDATE steam_login SET code = $1, steam_id = $2 WHERE id = $3
	`, code, steamID, id)
	if err != nil {
		return err
	}
	defer rows.Close()

	return nil
}

func (s *PostgresDB) DeleteSteamSession(id int) (err error) {
	// Changed placeholder from '?' to '$1'
	rows, err := s.Query("DELETE FROM steam_login WHERE id = $1", id)
	if err != nil {
		return
	}
	defer rows.Close()
	return
}

func (s *PostgresDB) GetSteamProfile(steamID string) (*SteamPlayer, error) {
	var profile SteamPlayer
	// Changed placeholder from '?' to '$1'
	err := s.QueryRow(`
	SELECT name, avatar, steam_id FROM steam_profile WHERE steam_id = $1
	`, steamID).Scan(&profile.Name, &profile.Avatar, &profile.SteamID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("profile not found")
		}
		return nil, err
	}
	return &profile, nil
}

func (s *PostgresDB) AddSteamProfile(v *SteamPlayer) error {
	// Changed placeholders from '?' to '$1', '$2', '$3'
	rows, err := s.Query(`
	INSERT INTO steam_profile (name, avatar, steam_id) VALUES ($1, $2, $3)
	`, v.Name, v.Avatar, v.SteamID)
	if err != nil {
		return err
	}
	defer rows.Close()
	return nil
}

func (s *PostgresDB) CreateLichessToken(name string, lichessToken string) error {
	var getLichessToken string
	// Changed placeholder from '?' to '$1'
	err := s.QueryRow(`
	SELECT lichess_token FROM lichess_profile WHERE name = $1
	`, name).Scan(&getLichessToken)
	if err != nil {
		if err == sql.ErrNoRows {
			// Changed placeholders from '?' to '$1', '$2'
			rows, err := s.Query(`
			INSERT INTO lichess_profile (name, lichess_token) VALUES ($1, $2)
			`, name, lichessToken)
			if err != nil {
				return err
			}
			defer rows.Close()
			return nil
		} else {
			return err
		}
	} else {
		if getLichessToken != lichessToken {
			// Changed placeholders from '?' to '$1', '$2'
			rows, err := s.Query(`
				UPDATE lichess_profile SET lichess_token=$1 WHERE name=$2
				`, lichessToken, name)
			if err != nil {
				return err
			}
			defer rows.Close()
			return nil
		} else {
			return nil
		}
	}
}

func (s *PostgresDB) GetMultipleLichessTokens(names []string, isShowdownUserIdQuery bool) (GetLichessUserInfoRes, error) {
	lichessTokens := make(GetLichessUserInfoRes)

	var query string

	if isShowdownUserIdQuery {
		query = `
	SELECT u.user_id, l.name, l.lichess_token
	FROM provider_users u
	JOIN lichess_profile l ON u.local_id = l.name
	WHERE u.user_id = ANY($1);
	`
	} else {
		query = `
	SELECT name, lichess_token FROM lichess_profile WHERE name = ANY($1);
	`
	}

	rows, err := s.Query(query, pq.Array(names))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if isShowdownUserIdQuery {
		for rows.Next() {
			var showdownUserId string
			var lichessId string
			var lichessToken string
			if err := rows.Scan(&showdownUserId, &lichessId, &lichessToken); err != nil {
				return nil, err
			}
			lichessTokens[showdownUserId] = LichessUserInfo{LichessId: lichessId, LichessToken: lichessToken}
		}
	} else {
		for rows.Next() {
			var name string
			var lichessToken string
			if err := rows.Scan(&name, &lichessToken); err != nil {
				return nil, err
			}
			lichessTokens[name] = LichessUserInfo{LichessId: name, LichessToken: lichessToken}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return lichessTokens, nil
}

func (s *PostgresDB) GetLichessToken(name string) (string, error) {
	var lichessToken string
	// Changed placeholder from '?' to '$1'
	err := s.QueryRow(`
	SELECT lichess_token FROM lichess_profile WHERE name=$1;
	`, name).Scan(&lichessToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.New("profile not found")
		}
		return "", err
	}
	return lichessToken, nil
}

func (s *PostgresDB) GetLinkedTelegramIDFromShowdownID(showdownUserID string) (string, error) {
	var telegramID string
	err := s.QueryRow(`
		SELECT local_id FROM provider_users WHERE user_id = $1 AND provider = $2
	`, showdownUserID, TELEGRAM_PROVIDER).Scan(&telegramID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return telegramID, nil
}

func (s *PostgresDB) GetLinkedShowdownIDFromTelegramID(telegramUserID string) (string, error) {
	var showdownUserID string
	err := s.QueryRow(`
		SELECT user_id FROM provider_users WHERE local_id = $1 AND provider = $2
	`, telegramUserID, TELEGRAM_PROVIDER).Scan(&showdownUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return showdownUserID, nil
}

func (s *PostgresDB) GetTelegramUsersByShowdownIDs(showdownUserIDs []string) ([]TelegramUser, error) {
	var results []TelegramUser

	query := `
		SELECT t.telegram_id, t.first_name, t.last_name, t.username
		FROM provider_users p
		JOIN telegram_users t ON p.local_id = t.telegram_id
		WHERE p.user_id = ANY($1) AND p.provider = $2
	`

	rows, err := s.Query(query, pq.Array(showdownUserIDs), TELEGRAM_PROVIDER)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var user TelegramUser
		err := rows.Scan(
			&user.TelegramID,
			&user.FirstName,
			&user.LastName,
			&user.Username,
		)
		if err != nil {
			continue
		}
		results = append(results, user)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

func (s *PostgresDB) UpsertTelegramUser(telegramID string, firstName, lastName, username string) error {
	query := `
		INSERT INTO telegram_users (telegram_id, first_name, last_name, username)
		VALUES ($1, $2, $3, $4)
	`
	rows, err := s.Query(query, telegramID, firstName, lastName, username)
	if err != nil {
		return err
	}
	defer rows.Close()
	return nil
}

/*
-- PostgreSQL schema changes:

CREATE TABLE steam_login (
  id SERIAL PRIMARY KEY,
  client_id VARCHAR(255) NOT NULL,
  redirect_uri VARCHAR(255) DEFAULT '',
  state VARCHAR(3000) NOT NULL,
  code VARCHAR(255) DEFAULT '',
  steam_id VARCHAR(255) DEFAULT ''
);

CREATE TABLE steam_profile (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) DEFAULT NULL,
  avatar VARCHAR(1000) DEFAULT NULL,
  steam_id VARCHAR(255) DEFAULT NULL
);

CREATE TABLE lichess_profile (
  name VARCHAR(255) PRIMARY KEY,
  lichess_token VARCHAR(3000) NOT NULL
);

CREATE TABLE provider_users (
  user_id VARCHAR(255) NOT NULL,
  local_id VARCHAR(255) NOT NULL,
  provider VARCHAR(255) NOT NULL,
  id SERIAL PRIMARY KEY
);

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) DEFAULT NULL
);

CREATE TABLE telegram_users (
    telegram_id VARCHAR(255) PRIMARY KEY,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    username VARCHAR(255),
);
*/
