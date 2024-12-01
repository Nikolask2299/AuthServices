package migration

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func Migrations() {

	m, err := migrate.New(
		"file://"+ Dir("migration"), 
		fmt.Sprintf("postgres://%s:%s@%s:%s/%s?x-migrations-table=%s&sslmode=disable", "postgres_admin", "q1w2e3r4t5y6u7i8o9p0", "postgres-db", "5432", "postgres", "migrate"),
	)
	 
	if err != nil {
		panic(err)
	}

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Println("No migrations were applied to the database")
			return
		}
		panic(err)
	}

	fmt.Println("Migrations applied to the database successfully")
}


func Dir(envFile string) string {
	currentDir, err := os.Getwd()
	if err != nil {
		panic(err)
	}    
    currentDir = strings.Replace(currentDir, filepath.Join("service-auth", "cmd", "migration"), "", -1)
    return filepath.Join(currentDir, envFile)
}