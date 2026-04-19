package models

import (
	"database/sql"
)

type User struct {
	ID        int64
	Email     string
	Username  string
	PassHash  []byte
	DeletedAt sql.NullTime
}
