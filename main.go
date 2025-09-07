package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"
)

var (
	policyPath = flag.String("policy", "policy.rego", "path to policy .rego file")
	reportPath = flag.String("report", "", "path to report JSON file (defaults to stdin if empty)")
	flagHash   = flag.String("hash", "", "expected SHA-256 of report (hex)")
)

func init() {
	// inspect.print_report_strings(input) -> string
	rego.RegisterBuiltin1(
		&rego.Function{
			Name:    "inspect.print_report_strings",
			Decl:    types.NewFunction(types.Args(types.A), types.S),
			Memoize: true,
		},
		func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
			var input map[string]interface{}
			if err := ast.As(a.Value, &input); err != nil {
				return nil, err
			}
			rep, ok := input["report"].(map[string]interface{})
			if !ok {
				return ast.StringTerm(""), nil
			}
			keys := make([]string, 0, len(rep))
			for k := range rep {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			strip := regexp.MustCompile(`[\s\r\n\t]+`)
			var sb strings.Builder
			for _, k := range keys {
				sb.WriteString(strip.ReplaceAllString(k, ""))
				b, _ := json.Marshal(rep[k]) // compact JSON
				sb.WriteString(strip.ReplaceAllString(string(b), ""))
			}
			return ast.StringTerm(sb.String()), nil
		},
	)
}

func readReportBytes() ([]byte, error) {
	// prefer -report file, else stdin
	if *reportPath != "" {
		return os.ReadFile(*reportPath)
	}
	return io.ReadAll(os.Stdin)
}

func parseJSON(data []byte) (interface{}, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var in interface{}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, err
	}
	return in, nil
}

func calcSHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return strings.ToLower(hex.EncodeToString(sum[:]))
}

func findHashInJSON(v interface{}) (string, bool) {
	// looks for common keys: sha256 or hash at top level or under "report"
	getFromMap := func(m map[string]interface{}) (string, bool) {
		for _, k := range []string{"sha256", "hash", "sha256sum"} {
			if val, ok := m[k]; ok {
				if s, ok := val.(string); ok && s != "" {
					return strings.ToLower(s), true
				}
			}
		}
		return "", false
	}

	switch t := v.(type) {
	case map[string]interface{}:
		if h, ok := getFromMap(t); ok {
			return h, true
		}
		if rep, ok := t["report"].(map[string]interface{}); ok {
			if h, ok := getFromMap(rep); ok {
				return h, true
			}
		}
	}
	return "", false
}

func main() {
	flag.Parse()

	// read report bytes
	reportBytes, err := readReportBytes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read report error: %v\n", err)
		os.Exit(1)
	}

	// compute hash of raw report bytes
	calculated := calcSHA256Hex(reportBytes)

	// decide expected hash
	expected := strings.ToLower(strings.TrimSpace(*flagHash))
	if expected == "" {
		in, err := parseJSON(reportBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "report JSON parse error: %v\n", err)
			os.Exit(1)
		}
		var ok bool
		expected, ok = findHashInJSON(in)
		if !ok || expected == "" {
			fmt.Fprintf(os.Stderr, "no expected hash provided and none found in report JSON\n")
			os.Exit(1)
		}
	}

	// compare
	if calculated != expected {
		fmt.Fprintf(os.Stderr, "hash mismatch: expected %s got %s\n", expected, calculated)
		os.Exit(1)
	}

	// decode input for OPA from the report JSON
	in, err := parseJSON(reportBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "input error: %v\n", err)
		os.Exit(1)
	}

	// load policy from -policy
	policyBytes, err := os.ReadFile(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read policy error: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	r := rego.New(
		rego.Query("data.report.verify.result"),
		rego.Module(*policyPath, string(policyBytes)),
	)

	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prepare error: %v\n", err)
		os.Exit(1)
	}

	rs, err := pq.Eval(ctx, rego.EvalInput(in))
	if err != nil {
		fmt.Fprintf(os.Stderr, "eval error: %v\n", err)
		os.Exit(1)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		fmt.Println(`{"result":"empty"}`)
		return
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rs[0].Expressions[0].Value); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %v\n", err)
		os.Exit(1)
	}
}
