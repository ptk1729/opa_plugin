package main

import (
	"context"
	"encoding/json"
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

func readInput() (interface{}, error) {
	//
	var r io.Reader = os.Stdin
	if len(os.Args) > 1 {
		f, err := os.Open(os.Args[1])
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var in interface{}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, err
	}
	return in, nil
}

func main() {

	in, err := readInput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "input error: %v\n", err)
		os.Exit(1)
	}

	// load policy.rego from disk
	policyBytes, err := os.ReadFile("policy.rego")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read policy error: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	r := rego.New(
		rego.Query("data.report.verify.result"),
		rego.Module("policy.rego", string(policyBytes)),
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
