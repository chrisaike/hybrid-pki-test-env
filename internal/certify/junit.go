package certify

import (
	"encoding/xml"
	"fmt"
	"time"
)

// JUnit XML structures (the widely-supported surefire-style schema that CI
// systems — Jenkins, GitLab, GitHub Actions test reporters — consume).

type junitTestSuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Time     string           `xml:"time,attr"`
	Suites   []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Time      string          `xml:"time,attr"`
	Timestamp string          `xml:"timestamp,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

// JUnitXML renders the certification report as JUnit XML (Requirement 9.6).
// Each check maps to a <testcase>; its requirement id becomes the classname so
// CI dashboards group checks by requirement.
func (r *Report) JUnitXML() ([]byte, error) {
	secs := func(ms int64) string { return fmt.Sprintf("%.3f", float64(ms)/1000.0) }

	cases := make([]junitTestCase, 0, len(r.Checks))
	for _, c := range r.Checks {
		tc := junitTestCase{
			Name:      c.Name,
			Classname: "requirement." + c.Requirement,
			Time:      "0.000",
		}
		if !c.Pass {
			tc.Failure = &junitFailure{
				Message: "certification check failed",
				Type:    "CertificationFailure",
				Text:    c.Detail,
			}
		}
		cases = append(cases, tc)
	}

	suite := junitTestSuite{
		Name:      "pki-certification",
		Tests:     len(r.Checks),
		Failures:  r.Failed,
		Time:      secs(r.DurationMS),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		TestCases: cases,
	}
	suites := junitTestSuites{
		Name:     "hybrid-pki-test-env",
		Tests:    len(r.Checks),
		Failures: r.Failed,
		Time:     secs(r.DurationMS),
		Suites:   []junitTestSuite{suite},
	}

	out, err := xml.MarshalIndent(suites, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}
