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
	extraAfterSlash := c.Params("*")
	ecosystem := c.Params("ecosystem")

	if extraAfterSlash != "" {
		packageName = packageName + "/" + extraAfterSlash
	}

	variables := map[string]interface{}{
		"packageName": graphql.String(packageName),
	}

	var err error
	var qry model.SecurityVulnQuery
	switch ecosystem {
	case "npm":
		query := model.SecurityVulnQueryNPM{}
		err = gqlClient.Query(context.Background(), &query, variables)
		qry = query
	case "rust":
		query := model.SecurityVulnQueryRUST{}
		err = gqlClient.Query(context.Background(), &query, variables)
		qry = query
	case "pip":
		query := model.SecurityVulnQueryPIP{}
		err = gqlClient.Query(context.Background(), &query, variables)
		qry = query
	default:
		return c.Status(404).JSON(fiber.Map{"status": "error", "message": "The given ecosystem is not supported"})
	}

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"status": "error", "message": "Bad request"})
	}

	vulns := qry.GetVulnerabilities()

	// If no note is present return an error
	return c.JSON(vulns)
}
