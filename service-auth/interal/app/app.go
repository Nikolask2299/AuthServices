package app

import (
	"context"
	"hash/fnv"
	"log/slog"
	"service-auth/interal/models"
	"service-auth/pkg/jwt"
	"service-auth/pkg/sql/postgres"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type App struct {
	log *slog.Logger
	db *postgres.Postgres
}

func NewApp(log *slog.Logger, db *postgres.Postgres) *App {
    return &App{log: log, db: db}
}

func (a *App) Register(ctx context.Context, email, ip, password string) (uint32, error) {
	const op = "app.Register"

	log := a.log.With(
		slog.String("op", op),
        slog.String("email", email),
	)

	log.Info("Registering user")

	passhash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err!= nil {
		log.Error("Error generating password hash", slog.String("Error", err.Error()))
        return 0, err
    }

	hashedGUID := hash(email + ip)

	err = a.db.CreateUser(hashedGUID, email, ip, passhash, []byte("none"))
	if err != nil {
		log.Error("Error creating user", slog.String("Error", err.Error()))
		return 0, err
    }

	return hashedGUID, nil
}

func (a *App) Login(ctx context.Context, GUID uint32, password string) (string, string, error) {
	const op = "app.Login"

    log := a.log.With(
        slog.String("op", op),
        slog.Int("guid", int(GUID)),
    )

	log.Info("Logging in user")

	user, err := a.db.GetUserByGUID(GUID)
	if err != nil {
        log.Error("Error getting user by GUID", slog.String("Error", err.Error()))
        return "", "", err
    }

	err = bcrypt.CompareHashAndPassword(user.Password, []byte(password))
	if err!= nil {
        log.Error("Error comparing password hashes", slog.String("Error", err.Error()))
        return "", "", err
    }
	log.Info("Successful authenticated user")

	accessToken, refreshToken, err := a.GenerateTokens(log, *user)
	if err!= nil {
        log.Error("Error generating JWT tokens", slog.String("Error", err.Error()))
        return "", "", err
    }

	return accessToken, refreshToken, nil
}

func (a *App) RefreshToken(ctx context.Context, ip, acctoken, reftoken string) (string, string, error) {
	const op = "app.RefreshToken"

    log := a.log.With(
        slog.String("op", op),
        slog.String("ip", ip),
    )

    log.Info("Refreshing JWT tokens")

	parseAcces, err := jwt.ParseAccessToken(acctoken)
	if err != nil {
        log.Error("Error parsing access token", slog.String("Error", err.Error()))
        return "", "", err
    }

	parseRefres, err := jwt.ParseToken(reftoken)
	if err!= nil {
        log.Error("Error parsing refresh token", slog.String("Error", err.Error()))
        return "", "", err
    }

	if parseRefres["sub"].(uint32) != parseAcces["sub"].(uint32) {
		log.Error("Refresh and access token is incorrect")
        return "", "", err
    }
	
	user, err := a.db.GetUserByGUID(parseAcces["sub"].(uint32))
	if err != nil {
        log.Error("Error getting user by GUID", slog.String("Error", err.Error()))
        return "", "", err
    }

	if err := bcrypt.CompareHashAndPassword(user.RefreshToken, []byte(reftoken)); err != nil {
		log.Error("Error comparing refresh token hashes", slog.String("Error", err.Error()))
        return "", "", err
    }
	
	if ip != user.IP {
		log.Error("IP address does not match")
        return "", "", err
    }
	
	accessToken, refreshToken, err := a.GenerateTokens(log, *user)
	if err!= nil {
        log.Error("Error generating JWT tokens", slog.String("Error", err.Error()))
        return "", "", err
    }

	return accessToken, refreshToken, nil
}

func (a *App) GenerateTokens(log *slog.Logger, user models.User) (string, string, error) {
	
	refreshToken, err := jwt.NewJWToken(user, time.Duration(time.Minute * 10))
	if err!= nil {
        log.Error("Error creating refresh token", slog.String("Error", err.Error()))
        return "", "", err
    }
	
	accessToken, err := jwt.NewJWToken(user, time.Duration(time.Minute))
	if err != nil {
        log.Error("Error creating access token", slog.String("Error", err.Error()))
        return "", "", err
    }

	log.Info("Successfully created JWT tokens")

	refreshash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err!= nil {
		log.Error("Error generating password hash", slog.String("Error", err.Error()))
        return "", "", err
    }

	err = a.db.UpdateUserRefresh(user.GUID, refreshash)
	if err!= nil {
		log.Error("Error updating user refresh token", slog.String("Error", err.Error()))
        return "", "", err
    }

	return accessToken, refreshToken, nil
}

func hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}	

