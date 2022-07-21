package router

import (
	"github.com/gofiber/fiber/v2"
)

// Sets up the routes for the API.
func Setup(app *fiber.App) {
	api := app.Group("/api")
	SetupVuln(&api)
}
