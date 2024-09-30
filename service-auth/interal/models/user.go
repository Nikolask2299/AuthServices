package models

type User struct {
	GUID  uint32
	Email string 
	IP string
	Password []byte
	RefreshToken []byte
}