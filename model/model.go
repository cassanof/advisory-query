package model

import (
	"fmt"
	"strconv"
	"strings"
	"time"

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

type SecurityVulnQueryNPM struct {
	SecurityVulnerabilities struct {
		QueryNodes `graphql:"nodes"`
	} `graphql:"securityVulnerabilities(first: 100, package: $packageName, ecosystem: NPM)"`
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
	// otherwise, we use the CVSS score
	trimmed := strings.SplitN(cvssString, "CVSS:", 2)[1]
	trimmed = strings.SplitN(trimmed, "/", 2)[0]
	score, err := strconv.ParseFloat(trimmed, 32)

	if err != nil {
		return 0.0
	}

	return (float32)(score)
}

func (q SecurityVulnQueryNPM) GetPackages() QueryNodes {
	return q.SecurityVulnerabilities.QueryNodes
}

func (q SecurityVulnQueryNPM) PrettyPrint() {
	for i, node := range q.GetPackages() {
		fmt.Printf("--------- %d ---------\n", i)
		fmt.Println(string(node.VulnerableVersionRange))
		fmt.Println(string(node.Severity))
		if node.Advisory.WithdrawnAt.IsZero() {
			fmt.Println("Withdrawn: its nil")
		} else {
			fmt.Println("Withdrawn:", node.Advisory.WithdrawnAt)
		}

		cvssString := string(node.Advisory.CVSS.VectorString)
		if cvssString == "" {
			fmt.Println("CVSS: its nil")
		} else {
			fmt.Println("CVSS: ", cvssString)
		}
		fmt.Println("----------------------")
	}
}

func (q SecurityVulnQueryNPM) GetVulnerabilities() []Vulnerability {
	vulnerabilities := []Vulnerability{}
	for _, node := range q.GetPackages() {
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
