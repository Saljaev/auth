package app

import (
	"auth/internal/api/auth"
	"auth/internal/config"
	"auth/internal/token"
	"auth/internal/usecase"
	"auth/internal/usecase/repo/postgres"
	"context"
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func Run() {
	logger := setupLogger()

	cfg, err := config.Read("config/config.yaml")
	if err != nil {
		logger.Error("failed to read config file", slog.Any("error", err.Error()))
		os.Exit(1)
	}

	storagePath := fmt.Sprintf("postgres://%s:%s@%s:5432/%s?sslmode=disable", cfg.Storage.PG_User,
		cfg.Storage.PG_Password, cfg.Storage.PG_Database, cfg.Storage.ContainerName)

	db, err := sql.Open("postgres", storagePath)
	if err != nil {
		logger.Error("failed to connect db: ", err)
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		logger.Error("failed to check db connection")
	} else {
		logger.Info("successful connect to db")
	}

	jwtSrv := token.NewJWTService(&cfg.JWT)

	users := postgres.NewUserRepo(db)

	userUseCase := usecase.NewUserUseCase(users)

	authHandler := auth.NewAuthHandler(logger, jwtSrv, userUseCase, cfg.JWT.TokenTTL, cfg.JWT.SessionTTL, cfg.JWT.RefreshTokenLength)

	r := http.NewServeMux()

	r.HandleFunc("GET /token.get/", authHandler.Get)
	r.HandleFunc("GET /token.refresh/", authHandler.Refresh)

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	srv := &http.Server{
		Addr:         cfg.Server.Address,
		Handler:      r,
		ReadTimeout:  cfg.Server.Timeout,
		WriteTimeout: cfg.Server.Timeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	go func() {
		srv.ListenAndServe()
	}()

	logger.Info("server started")

	<-done
	logger.Info("stopping server")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("failed to stop server: ", err)

		return
	}

	logger.Info("server stopped")
}

func setupLogger() *slog.Logger {
	var log *slog.Logger

	log = slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
	)

	return log
}
