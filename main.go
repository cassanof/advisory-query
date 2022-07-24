package main

import (
	"github.com/cassanof/advisory-query/middleware"
	"github.com/cassanof/advisory-query/model"
	"github.com/cassanof/advisory-query/router"
	"github.com/gofiber/fiber/v2"
)

func main() {
	// Start a new fiber app
	app := fiber.New()

	// Init cache
	go model.StartCache()

	// Setup routes
	router.Setup(app)

	// Setup middleware
	middleware.Setup(app)

	// Listen on PORT 13400
	app.Listen(":13400")
}
