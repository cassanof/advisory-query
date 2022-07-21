package handlers

import (
	"context"

	"github.com/cassanof/advisory-query/config"
	"github.com/cassanof/advisory-query/model"
	"github.com/gofiber/fiber/v2"
	"github.com/hasura/go-graphql-client"
	"golang.org/x/oauth2"
)

var gqlClient *graphql.Client

func InitGQLClient() {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: config.Config("GITHUB_API_KEY")},
	)
	httpClient := oauth2.NewClient(context.Background(), src)

	gqlClient = graphql.NewClient("https://api.github.com/graphql", httpClient)
}

func GetPackageVulns(c *fiber.Ctx) error {
	packageName := c.Params("packageName")

	variables := map[string]interface{}{
		"packageName": graphql.String(packageName),
	}

	qry := model.SecurityVulnQueryNPM{}
	err := gqlClient.Query(context.Background(), &qry, variables)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"status": "error", "message": "Bad request"})
	}

	vulns := qry.GetVulnerabilities()

	// If no note is present return an error
	return c.JSON(vulns)
}
