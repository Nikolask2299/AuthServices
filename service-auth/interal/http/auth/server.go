package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"service-auth/interal/app"
	"service-auth/pkg/jwt"
	"strconv"
	"time"
)

type AuthService struct {
    app *app.App
	logger *slog.Logger
}

func NewAuthService(app *app.App, logger *slog.Logger) *AuthService {
    return &AuthService{app: app, logger: logger}
}

func (au *AuthService) RegisterUser(w http.ResponseWriter, r *http.Request) {
	const op = "auth.RegisterUser"
	log := au.logger.With(
		slog.String("op", op),
		slog.String("method", r.Method),
        slog.String("url", r.URL.String()),
	)
	IP, _, _ := net.SplitHostPort(r.RemoteAddr)
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Second * 5)
	defer cancel()

	email, password := r.URL.Query().Get("email"), r.URL.Query().Get("password")
	if email == "" || password == "" {
        http.Error(w, "Missing email or password", http.StatusBadRequest)
        return
    }

	log.Info("Registering user")
	GUID, err := au.app.Register(ctx, email, IP, password)
	if err!= nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

	fmt.Fprintln(w, GUID)
}

func (au *AuthService) LoginUser(w http.ResponseWriter, r *http.Request) {
	const op = "auth.LoginUser"
    log := au.logger.With(
        slog.String("op", op),
        slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
    )

    ctx, cancel := context.WithTimeout(context.Background(), time.Second * 5)
    defer cancel()

    GUID := r.URL.Query().Get("GUID")
	id, _ := strconv.Atoi(GUID)
	password := r.URL.Query().Get("password")

	accesToken, refreshToken, err := au.app.Login(ctx, uint32(id), password)
	if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error("Generation token faeld", slog.String("Error", err.Error()))
        return
    }

	http.SetCookie(w, &http.Cookie{
		Name: "AccessToken",
		Value: accesToken,
        HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name: "RefreshToken",
        Value: refreshToken,
        HttpOnly: true,
	})

	fmt.Fprintln(w, "Login success")
}

func (au *AuthService) RefreshTocken(w http.ResponseWriter, r *http.Request) {
	const op = "auth.RefreshTocken"
	
	log := au.logger.With(
        slog.String("op", op),
        slog.String("method", r.Method),
        slog.String("url", r.URL.String()),
    )

	ctx, cancel := context.WithTimeout(context.Background(), time.Second * 5)
    defer cancel()

	IP := r.Header.Get("X-Forwarded-For")

	acctoken, err := r.Cookie("AccessToken")
	if err != nil {
		http.Error(w, "Missing AccessToken", http.StatusUnauthorized)
		log.Error("Missing AccessToken", slog.String("Error", err.Error()))
        return
	}

	reftoken, err := r.Cookie("RefreshToken")
	if err!= nil {
        http.Error(w, "Missing RefreshToken", http.StatusUnauthorized)
        log.Error("Missing RefreshToken", slog.String("Error", err.Error()))
        return
    }

	accesToken, refreshToken, err := au.app.RefreshToken(ctx, IP, acctoken.Value, reftoken.Value)
	if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error("Generation token faeld", slog.String("Error", err.Error()))
        return
    }

	http.SetCookie(w, &http.Cookie{
		Name: "AccessToken",
		Value: accesToken,
        HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name: "RefreshToken",
        Value: refreshToken,
        HttpOnly: true,
	})

	fmt.Fprintln(w, "Refresh success")
}

func (au *AuthService) Authenticate(w http.ResponseWriter, r *http.Request) {

	const op = "auth.Authenticate"

	log := au.logger.With(
        slog.String("op", op),
        slog.String("method", r.Method),
        slog.String("url", r.URL.String()),
    )

	acctoken, err := r.Cookie("AccessToken")
	if err!= nil {
        http.Error(w, "Missing AccessToken", http.StatusUnauthorized)
        log.Error("Missing AccessToken", slog.String("Error", err.Error()))
        return
    }

	parsetoken, err := jwt.ParseToken(acctoken.Value)
	if err!= nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        log.Error("Error parsing access token", slog.String("Error", err.Error()))
        return
    }

	fmt.Fprintln(w, "Authorization", uint32(parsetoken["sub"].(float64)))
}

