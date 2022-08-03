package middleware

import (
	"io"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

func Setup(app *fiber.App) {
	setupLogger(app)
}

func setupLogger(app *fiber.App) {
	date := time.Now().String()
	apiFile, err := os.OpenFile("./logs/api-log-"+date+".log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	fiberFile, err := os.OpenFile("./logs/fiber-log-"+date+".log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer apiFile.Close()
	wrt := io.MultiWriter(os.Stdout, apiFile)
	log.SetOutput(wrt)

	loggerConfig := logger.Config{
		Output: fiberFile,
	}

	app.Use(logger.New(loggerConfig))
}
