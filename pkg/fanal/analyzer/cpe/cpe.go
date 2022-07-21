package cpe

import (
	"context"
	"os"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

func init() {
	analyzer.RegisterAnalyzer(&CPE{})
}

type CPE struct {
}

func (a CPE) Analyze(c context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	catalogers := cataloger.AllCatalogers(cataloger.DefaultConfig())
	catlogs, _, err := cataloger.Catalog(source.NewContentResolver(input), nil, catalogers...)
	if err != nil {
		return nil, err
	}
	return toAnalysisResult("cpe", input.FilePath, catlogs)
}
func (a CPE) Type() analyzer.Type {
	return analyzer.TypeCPE
}

func (a CPE) Version() int {
	return 1
}
func (a CPE) Required(filePath string, info os.FileInfo) bool {
	return true
}

func toAnalysisResult(fileType, filePath string, catlogs *pkg.Catalog) (*analyzer.AnalysisResult, error) {
	if catlogs.PackageCount() == 0 {
		return nil, nil
	}

	var cpesMap = make(map[string][]string)
	for _, lib := range catlogs.Iter() {
		cpes := make([]string, 0, len(lib.CPEs))
		for _, cpe := range lib.CPEs {
			cpes = append(cpes, cpe.BindToFmtString())
		}
		cpesMap[lib.PURL] = cpes
	}
	return &analyzer.AnalysisResult{CPE: cpesMap}, nil
}
