// internal/app/app.go

package app

import (
	grpcapp "github.com/NikKazzzzzz/sso/internal/app/grpc"
	"github.com/NikKazzzzzz/sso/internal/services/auth"
	"github.com/NikKazzzzzz/sso/internal/storage/postgres"
	"log/slog"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(log *slog.Logger, grpcPort int, storagePath string, tokenTTL time.Duration) *App {
	storage, err := postgres.New(storagePath, log)
	if err != nil {
		panic(err)
	}

	authService := auth.New(log, storage, storage, storage, tokenTTL, storage)

	grpcApp := grpcapp.New(log, authService, grpcPort)

	return &App{
		GRPCSrv: grpcApp,
	}
}
