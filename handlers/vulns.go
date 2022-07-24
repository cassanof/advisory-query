package handlers

import (
	"context"
	"log"

	"github.com/cassanof/advisory-query/config"
	"github.com/cassanof/advisory-query/model"
	"github.com/gofiber/fiber/v2"
	"github.com/hasura/go-graphql-client"
	"golang.org/x/oauth2"
)

var gqlClient *graphql.Client

func InitHandler() {
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
	fullpath := ecosystem + "/" + packageName

	cachedVulns := model.GetCachedVuln(fullpath)
	if cachedVulns != nil {
		log.Println("Cache hit for " + fullpath)
		return c.JSON(cachedVulns)
	}

	variables := map[string]interface{}{
		"packageName": graphql.String(packageName),
	}

	vulnList := make([]model.Vulnerability, 0)
	firstRun := true
	for {
		var err error
		var qry model.SecurityVulnQuery
		switch ecosystem {
		case "npm":
			if firstRun {
				query := model.SecurityVulnQueryNPM{}
				err = gqlClient.Query(context.Background(), &query, variables)
				qry = query
			} else {
				query := model.SecurityVulnQueryNPMRest{}
				err = gqlClient.Query(context.Background(), &query, variables)
				qry = query
			}
		case "rust":
			if firstRun {
				query := model.SecurityVulnQueryRUST{}
				err = gqlClient.Query(context.Background(), &query, variables)
				qry = query
			} else {
				query := model.SecurityVulnQueryRUSTRest{}
				err = gqlClient.Query(context.Background(), &query, variables)
				qry = query
			}
		case "pip":
			if firstRun {
				query := model.SecurityVulnQueryPIP{}
				err = gqlClient.Query(context.Background(), &query, variables)
				qry = query
			} else {
				query := model.SecurityVulnQueryPIPRest{}
				err = gqlClient.Query(context.Background(), &query, variables)
				qry = query
			}
		default:
			return c.Status(404).JSON(fiber.Map{"status": "error", "message": "The given ecosystem is not supported"})
		}

		if err != nil {
			log.Println("Got error: ", err)
			return c.Status(404).JSON(fiber.Map{"status": "error", "message": "Bad request"})
		}

		vulnQuery := qry.GetVulnerabilities()

		vulnList = append(vulnList, vulnQuery.Unwrap()...)

		variables["cursor"] = graphql.String(vulnQuery.PageInfo.EndCursor)
		firstRun = false

		if !vulnQuery.HasNextPage {
			break
		}
	}

	model.CacheVuln(fullpath, vulnList)

	// If no note is present return an error
	return c.JSON(vulnList)
}
