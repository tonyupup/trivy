package cpe

import (
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
)

type Comparer struct {
}

func (n Comparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return false
}
