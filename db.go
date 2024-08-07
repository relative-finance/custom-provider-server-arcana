package main

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

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
	query := "SELECT EXISTS (SELECT 1 FROM provider_users WHERE user_id = ?)"
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
}

type MySQLDB struct {
	*sql.DB
}

func connectToDB(connectionUrl string) (*MySQLDB, error) {
	db, err := sql.Open("mysql", connectionUrl)
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
	store := &MySQLDB{db}
	return store, nil
}

func (s *MySQLDB) CreateNewUser(localUserID, provider string) error {

	rows, err := s.Query("INSERT INTO users (name) VALUES (?)", localUserID)
	if err != nil {
		return err
	}
	rows.Close()
	var id int
	err = s.QueryRow("SELECT id FROM users WHERE name=?", localUserID).Scan(&id)
	if err != nil {
		return err
	}

	userID, err := generateUniqueUserID(s.DB)
	if err != nil {
		return err
	}

	rows, err = s.Query("INSERT INTO provider_users (user_id, local_id, provider) VALUE (?,?,?)", userID, localUserID, provider)
	if err != nil {
		return err
	}
	rows.Close()
	return nil
}

func (s *MySQLDB) GetUserID(localUserID, provider string) (string, error) {
	var id string
	err := s.QueryRow("SELECT user_id FROM provider_users WHERE local_id=? AND provider=?", localUserID, provider).Scan(&id)
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

func (s *MySQLDB) GetConnectedAccounts(userID string) ([]Account, error) {
	var data []Account
	rows, err := s.Query("SELECT provider, local_id FROM provider_users WHERE user_id=?", userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return data, nil
		}
		return nil, err
	}
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

func (s *MySQLDB) LinkToExistingUser(localUserID, provider, userID string) error {
	rows, err := s.Query("INSERT INTO provider_users (user_id, local_id, provider) VALUE (?,?,?)", userID, localUserID, provider)
	if err != nil {
		return err
	}
	rows.Close()
	return nil
}

func (s *MySQLDB) AddSteamSession(clientID, redirect, state string) (err error) {
	rows, err := s.Query(`
	INSERT INTO steam_login (client_id, redirect_uri, state) VALUES (?,?,?)
	`, clientID, redirect, state)
	if err != nil {
		return
	}
	defer rows.Close()
	return
}

func (s *MySQLDB) GetSteamSession(state string) (session SteamSession, err error) {
	err = s.QueryRow(`
	SELECT id, client_id, redirect_uri, state, code FROM steam_login WHERE state = ?
	`, state).Scan(&session.ID, &session.ClientID, &session.RedirectURI, &session.State, &session.Code)
	if err != nil {
		if err == sql.ErrNoRows {
			return session, errors.New("No session found")
		}
		return session, err
	}
	return
}

func (s *MySQLDB) GetSteamSessionByCode(code string) (session SteamSession, err error) {
	err = s.QueryRow(`
	SELECT id, steam_id, client_id, redirect_uri, state, code FROM steam_login WHERE code = ?
	`, code).Scan(&session.ID, &session.SteamID, &session.ClientID, &session.RedirectURI, &session.State, &session.Code)
	if err != nil {
		if err == sql.ErrNoRows {
			return session, errors.New("No session found")
		}
		return session, err
	}
	return
}
func (s *MySQLDB) UpdateSteamSession(id int, steamID, code string) error {
	rows, err := s.Query(`
	UPDATE steam_login SET code = ?, steam_id = ? WHERE id = ?
	`, code, steamID, id)
	if err != nil {
		return err
	}
	defer rows.Close()

	return nil
}

func (s *MySQLDB) DeleteSteamSession(id int) (err error) {
	rows, err := s.Query("DELETE FROM steam_login WHERE id = ?", id)
	if err != nil {
		return
	}
	defer rows.Close()
	return
}

func (s *MySQLDB) GetSteamProfile(steamID string) (*SteamPlayer, error) {
	var profile SteamPlayer
	err := s.QueryRow(`
	SELECT name, avatar, steam_id FROM steam_profile WHERE steam_id = ?
	`, steamID).Scan(&profile.Name, &profile.Avatar, &profile.SteamID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("profile not found")
		}
		return nil, err
	}
	return &profile, nil
}

func (s *MySQLDB) AddSteamProfile(v *SteamPlayer) error {
	rows, err := s.Query(`
	INSERT INTO steam_profile (name, avatar, steam_id) VALUES (?,?,?)
	`, v.Name, v.Avatar, v.SteamID)
	if err != nil {
		return err
	}
	defer rows.Close()
	return nil
}

func (s *MySQLDB) CreateLichessToken(name string, lichessToken string) error {
	var getLichessToken string
	err := s.QueryRow(`
	SELECT lichess_token FROM lichess_profile WHERE name = ?
	`, name).Scan(&getLichessToken)
	if err != nil {
		if err == sql.ErrNoRows {
			rows, err := s.Query(`
			INSERT INTO lichess_profile (name, lichess_token) VALUES (?,?)
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
			rows, err := s.Query(`
				UPDATE lichess_profile SET lichess_token=? WHERE name=?
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

func (s *MySQLDB) GetLichessToken(name string) (string, error) {
	var lichessToken string
	err := s.QueryRow(`
	SELECT lichess_token FROM lichess_profile WHERE name=?;
	`, name).Scan(&lichessToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.New("profile not found")
		}
		return "", err
	}
	return lichessToken, nil
}

/*

CREATE TABLE `steam_login` (
  `id` int NOT NULL AUTO_INCREMENT,
  `client_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `redirect_uri` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT '""',
  `state` varchar(3000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `code` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT '""',
  `steam_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT '""',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `steam_profile` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  `avatar` varchar(1000) DEFAULT NULL,
  `steam_id` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `lichess_profile` (
  `name` varchar(255) NOT NULL,
  `lichess_token` varchar(3000) NOT NULL,
  PRIMARY KEY (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

create table `provider_users` (
`user_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
`local_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
`provider` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
`id` int NOT NULL AUTO_INCREMENT,
PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

create table `users` (
`id` int NOT NULL AUTO_INCREMENT,
`name` varchar(255) DEFAULT NULL,
PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
*/
