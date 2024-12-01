package main

import (
	"log/slog"
	"net/http"
	"os"
	"service-auth/cmd/migration"
	"service-auth/interal/app"
	"service-auth/interal/http/auth"
	"service-auth/pkg/sql/postgres"
)

const (
    envLocal = "local"
    envDev   = "dev"
    envProd  = "prod"
)

func main() {
    migration.Migrations()

	loger := setupLogger("local")
	loger = loger.With(slog.String("env", "local"))

	loger.Info("initializing server", slog.String("address", "localhost")) 
    loger.Debug("logger debug mode enabled")
    
    postgres, err := postgres.NewPostgres("postgres_admin", "q1w2e3r4t5y6u7i8o9p0", "postgres", "postgres-db", "5432")
    if err != nil {
        loger.Debug("error initializing postgres", slog.String("error", err.Error()))
       panic(err)
    }

    app := app.NewApp(loger, postgres)
    auth := auth.NewAuthService(app, loger)

    http.HandleFunc("/", auth.Authenticate)
    http.HandleFunc("/login", auth.LoginUser)
    http.HandleFunc("/register", auth.RegisterUser)
    http.HandleFunc("/refresh", auth.RefreshTocken)

    err = http.ListenAndServe(":80", nil) 
    if err!= nil {
        loger.Debug("error starting server", slog.String("error",err.Error()))
        panic(err)
    }
}

func setupLogger(env string) *slog.Logger {
	var logger *slog.Logger

    switch env {
    case envLocal:
        logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
    case envDev:
        logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
    case envProd:
        logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
    default:
        logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
    }

    return logger
}