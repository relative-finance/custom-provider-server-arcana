package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type UserStore interface {
	CreateNewUser(localUserID, provider string) error
	GetUserID(localUserID, provider string) (int, error)
	LinkToExistingUser(localUserID, provider, userID string) error
	GetConnectedAccounts(userID string) ([]Account, error)
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

	rows, err = s.Query("INSERT INTO provider_users (user_id, local_id, provider) VALUE (?,?,?)", id, localUserID, provider)
	if err != nil {
		return err
	}
	rows.Close()
	return nil
}

func (s *MySQLDB) GetUserID(localUserID, provider string) (int, error) {
	var id int
	err := s.QueryRow("SELECT user_id FROM provider_users WHERE local_id=? AND provider=?", localUserID, provider).Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
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
