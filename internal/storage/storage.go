package storage

import "errors"

var (
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")
	ErrAppNotFound  = errors.New("app not found")
	ErrAppExists    = errors.New("app already exists")
	//ErrEmptyDB       = errors.New("database is empty")
	ErrUserDeleted   = errors.New("user deleted")
	ErrTokenNotFound = errors.New("token not found")
)
