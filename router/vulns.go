package router

import (
	"github.com/cassanof/advisory-query/handlers"
	"github.com/gofiber/fiber/v2"
)

// Vuln endpoint. at api/vuln/
func SetupVuln(router *fiber.Router) {
	handlers.InitHandler()
	cached := (*router).Group("/cached")
	vuln := (*router).Group("/vuln")
	// endpoint for getting vulns for a package, e.g. api/vuln/jquery
	vuln.Get("/:ecosystem/:packageName/*", handlers.GetPackageVulnsTemporary)
	cached.Get("/:ecosystem/:packageName/*", handlers.GetPackageVulnsPersistant)
}
