package handlers

import (
	"context"
	"log"
	"strings"
	"sync"

	"github.com/cassanof/advisory-query/config"
	"github.com/cassanof/advisory-query/database"
	"github.com/cassanof/advisory-query/model"
	"github.com/gofiber/fiber/v2"
	"github.com/hasura/go-graphql-client"
	"golang.org/x/oauth2"
)

type cacheType = int

const (
	PERSISTANT_CACHE cacheType = iota
	TEMPORARY_CACHE
)

var gqlClient *graphql.Client
var apiKeys []string
var currentApiKeyIndex int
var apiKeyMutex sync.Mutex

func rotateApiKey() {
	log.Println("Rotating API key")
	apiKeyMutex.Lock()
	currentApiKeyIndex = (currentApiKeyIndex + 1) % len(apiKeys)
	initGQLClient()
	apiKeyMutex.Unlock()
}

func initGQLClient() {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: apiKeys[currentApiKeyIndex]},
	)
	httpClient := oauth2.NewClient(context.Background(), src)

	gqlClient = graphql.NewClient("https://api.github.com/graphql", httpClient)
}

func InitHandler() {
	configStr := config.Config("GITHUB_API_KEYS")
	apiKeys = strings.Split(configStr, ", ")
	if len(apiKeys) == 0 {
		log.Fatal("No GitHub API keys found")
	}
	currentApiKeyIndex = 0
	initGQLClient()
}

func GetPackageVulnsPersistant(c *fiber.Ctx) error {
	return getPackageVulns(c, PERSISTANT_CACHE)
}

func GetPackageVulnsTemporary(c *fiber.Ctx) error {
	return getPackageVulns(c, TEMPORARY_CACHE)
}

func getPackageVulns(c *fiber.Ctx, cacheType cacheType) error {
	packageName := c.Params("packageName")
	extraAfterSlash := c.Params("*")
	ecosystem := c.Params("ecosystem")
	if extraAfterSlash != "" {
		packageName = packageName + "/" + extraAfterSlash
	}
	fullpath := ecosystem + "/" + packageName

	log.Println("Getting vulnerabilities for ", fullpath)

	var cachedVulns []model.Vulnerability
	switch cacheType {
	case PERSISTANT_CACHE:
		cachedVulns = database.DB.Get(fullpath)
	case TEMPORARY_CACHE:
		cachedVulns = model.GetTempCachedVuln(fullpath)
	}

	if cachedVulns != nil {
		log.Println("Cache hit for " + fullpath)
		return c.JSON(cachedVulns)
	}

	variables := map[string]interface{}{
		"packageName": graphql.String(packageName),
	}

	vulnList := make([]model.Vulnerability, 0)
	firstRun := true
	rotatedAfterRateLimit := false
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

			// if the error is a rate limit error, rotate the API key and try again
			if strings.Contains(err.Error(), "API rate limit exceeded") && !rotatedAfterRateLimit {
				rotateApiKey()
				rotatedAfterRateLimit = true
				continue
			}
			return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Bad request"})
		}
		rotatedAfterRateLimit = false // we got a successful response, so we can reset the retry flag

		vulnQuery := qry.GetVulnerabilities()

		vulnList = append(vulnList, vulnQuery.Unwrap()...)

		variables["cursor"] = graphql.String(vulnQuery.PageInfo.EndCursor)
		firstRun = false

		if !vulnQuery.HasNextPage {
			break
		}
	}

	switch cacheType {
	case PERSISTANT_CACHE:
		err := database.DB.Insert(fullpath, vulnList)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"status": "error", "message": "DB error"})
		}
	case TEMPORARY_CACHE:
		model.TempCacheVuln(fullpath, vulnList)
	}

	// If no note is present return an error
	return c.JSON(vulnList)
}
