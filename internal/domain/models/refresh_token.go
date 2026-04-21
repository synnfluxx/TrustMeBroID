package models

type RefreshTokenFields struct {
	UserID int64 `redis:"uid"`
	AppId  int64 `redis:"aid"`
	AppSecret string `redis:"secret"` // TODO: 
}
