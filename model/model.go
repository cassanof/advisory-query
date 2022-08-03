package model

import (
	"log"
	"time"

	"github.com/goark/go-cvss/v3/metric"
	"github.com/hasura/go-graphql-client"
)

type QueryNode struct {
	VulnerableVersionRange graphql.String
	Severity               graphql.String
	Advisory               struct {
		WithdrawnAt time.Time
		CVSS        struct {
			VectorString graphql.String
		}
	}
}

type QueryNodes = []QueryNode

type SecurityVulnQuery interface {
	GetVulnerabilities() *SecurityVulnerabilities
}

type PageInfo struct {
	StartCursor graphql.String
	HasNextPage graphql.Boolean
	EndCursor   graphql.String
}

type SecurityVulnerabilities struct {
	PageInfo   `graphql:"pageInfo"`
	QueryNodes `graphql:"nodes"`
}

type SecurityVulnQueryNPM struct {
	SecurityVulnerabilities `graphql:"securityVulnerabilities(first: 1, package: $packageName, ecosystem: NPM)"`
}

type SecurityVulnQueryPIP struct {
	SecurityVulnerabilities `graphql:"securityVulnerabilities(first: 1, package: $packageName, ecosystem: PIP)"`
}

type SecurityVulnQueryRUST struct {
	SecurityVulnerabilities `graphql:"securityVulnerabilities(first: 1, package: $packageName, ecosystem: RUST)"`
}

type SecurityVulnQueryNPMRest struct {
	SecurityVulnerabilities `graphql:"securityVulnerabilities(first: 10, after: $cursor, package: $packageName, ecosystem: NPM)"`
}

type SecurityVulnQueryPIPRest struct {
	SecurityVulnerabilities `graphql:"securityVulnerabilities(first: 10, after: $cursor, package: $packageName, ecosystem: PIP)"`
}

type SecurityVulnQueryRUSTRest struct {
	SecurityVulnerabilities `graphql:"securityVulnerabilities(first: 10, after: $cursor, package: $packageName, ecosystem: RUST)"`
}

type Vulnerability struct {
	Range   string  `json:"range"`
	Badness float32 `json:"badness"`
}

// gets the badness of a vulnerability, instead of failing on errors, we just return 0
func (n QueryNode) getBadness() float32 {
	if !n.Advisory.WithdrawnAt.IsZero() {
		return 0.0 // skip if withdrawn
	}
	// if we don't have a precise CVSS score, we have to approximate via severity
	cvssString := string(n.Advisory.CVSS.VectorString)
	if cvssString == "" {
		// approximation from: https://nvd.nist.gov/vuln-metrics/cvss
		switch string(n.Severity) {
		case "LOW":
			return 2.0 // (0.1 + 3.9) / 2
		case "MODERATE":
			return 5.45 // (4.0 + 6.9) / 2
		case "HIGH":
			return 7.95 // (7.0 + 8.9) / 2
		case "CRITICAL":
			return 9.5 // (9.0 + 10.0) / 2
		default:
			return 0.0
		}
	}
	bm, err := metric.NewBase().Decode(cvssString)
	if err != nil {
		log.Println(err)
		return 0.0
	}

	if err != nil {
		return 0.0
	}

	return (float32)(bm.Score())
}

func getVulnsFromNodes(nodes *QueryNodes) []Vulnerability {
	vulnerabilities := []Vulnerability{}
	for _, node := range *nodes {
		// skip if withdrawn, we don't want to count it
		if !node.Advisory.WithdrawnAt.IsZero() {
			continue
		}

		badness := node.getBadness()
		verRange := string(node.VulnerableVersionRange)

		vulnerabilities = append(vulnerabilities, Vulnerability{
			Range:   verRange,
			Badness: badness,
		})
	}
	return vulnerabilities
}

func (vulns *SecurityVulnerabilities) Unwrap() []Vulnerability {
	return getVulnsFromNodes(&vulns.QueryNodes)
}

func (q SecurityVulnQueryNPM) GetVulnerabilities() *SecurityVulnerabilities {
	return &q.SecurityVulnerabilities
}

func (q SecurityVulnQueryPIP) GetVulnerabilities() *SecurityVulnerabilities {
	return &q.SecurityVulnerabilities
}

func (q SecurityVulnQueryRUST) GetVulnerabilities() *SecurityVulnerabilities {
	return &q.SecurityVulnerabilities
}

func (q SecurityVulnQueryNPMRest) GetVulnerabilities() *SecurityVulnerabilities {
	return &q.SecurityVulnerabilities
}

func (q SecurityVulnQueryPIPRest) GetVulnerabilities() *SecurityVulnerabilities {
	return &q.SecurityVulnerabilities
}

func (q SecurityVulnQueryRUSTRest) GetVulnerabilities() *SecurityVulnerabilities {
	return &q.SecurityVulnerabilities
}
