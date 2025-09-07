package report.verify

import rego.v1

# --- config -----------------------------------------------------
default required := {
  "linting":                 true,
  "formatting":              true,
  "vulnerability_check":     false,
  "commit_verification":     false,
  "env_variables_check":     true,
  "slsa_check":              true,
  "custom:Dockerfile Best Practices": false,
}

default warn_as_fail := {
  "linting": false,
}
# ---------------------------------------------------------------

flat_report := inspect.print_report_strings(input)

default stored_hash := ""
stored_hash := s if {
  input.metadata
  s := input.metadata.report_sha256
  s != null
  s != ""
}

missing_stored if stored_hash == ""

calculated_hash := crypto.sha256(flat_report)

hash_match if {
  not missing_stored
  stored_hash == calculated_hash
}

# helpers
is_required(name) := b if {
  b := required[name]
} else := false

status_bad(name, s) if s == "FAILED"
status_bad(name, s) if {
  warn_as_fail[name]
  s == "WARNING"
}

# failures from first-class sections under input.report
section_failures := {
  k: sect |
  some k
  sect := input.report[k]
  is_required(k)
  status_bad(k, sect.status)
}

# failures from input.report.custom_checks[]
custom_failures := {
  sprintf("custom:%s", [item.name]): item |
  some i
  item := input.report.custom_checks[i]
  n := sprintf("custom:%s", [item.name])
  is_required(n)
  status_bad(n, item.status)
}

# unified failures object
failures := object.union(section_failures, custom_failures)

# denies
deny contains msg if {
  missing_stored
  msg := "metadata.report_sha256 is missing"
}

deny contains msg if {
  not missing_stored
  calculated_hash != stored_hash
  msg := sprintf("hash mismatch: stored=%s calculated=%s", [stored_hash, calculated_hash])
}

deny contains msg if {
  some k
  failures[k]
  msg := sprintf("required check failed: %s", [k])
}

summary := {
  "hash": {
    "stored":     stored_hash,
    "calculated": calculated_hash,
    "match":      hash_match,
  },
  "required":     required,
  "warn_as_fail": warn_as_fail,
  "deny":         deny,
  "ok":           count(deny) == 0,
}

result := {
  "summary":  summary,
  "failures": failures,
}
