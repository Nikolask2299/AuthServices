package postgres

import (
	"database/sql"
	"fmt"
	"service-auth/interal/models"

	_ "github.com/lib/pq"
)

type Postgres struct {
    db *sql.DB
}

func NewPostgres(user, password, dbname, host, port string) (*Postgres, error) {
	psqlInfo := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=disable", user, password, dbname, host, port)
    db, err := sql.Open("postgres", psqlInfo)
    if err!= nil {
        return nil, err
    }

    err = db.Ping()
    if err!= nil {
        return nil, err
    }

    return &Postgres{db: db}, nil
}

func (p *Postgres) CreateUser(GUID uint32, email, ip string, password, refresh []byte) error {
    query := "INSERT INTO users (guid, email, ip, pass_hash, refr_hash) VALUES ($1, $2, $3, $4, $5, $6)"
    _, err := p.db.Exec(query, GUID, email, ip, password, refresh)
    return err
}

func (p *Postgres) GetUserByGUID(GUID uint32) (*models.User, error) {
    query := "SELECT guid, email, ip, pass_hash, refr_hash FROM users WHERE guid=$1"
    row := p.db.QueryRow(query, GUID)
    var u models.User
    err := row.Scan(&u.GUID, &u.Email, &u.IP, &u.Password, &u.RefreshToken)
    if err == sql.ErrNoRows {
        return nil, fmt.Errorf("user not found")
    } else if err!= nil {
        return nil, err
    }

    return &u, nil
}

func (p *Postgres) UpdateUserRefresh(GUID uint32,refresh []byte) error {
    query := "UPDATE users SET refr_hash=$1 WHERE guid=$2"
    _, err := p.db.Exec(query, refresh, GUID)
    return err
}

func (p *Postgres) GetUserByIP(GUID string) (string, error) {
    query := "SELECT guid FROM users WHERE ip=$1"
    row := p.db.QueryRow(query, GUID)
    var u models.User
    err := row.Scan(&u.IP)
    if err == sql.ErrNoRows {
        return "", fmt.Errorf("user not found")
    } else if err!= nil {
        return "", err
    }
    return u.IP, nil 
}