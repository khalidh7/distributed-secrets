package policy

import "path"

type Rule struct {
	Path         string   `json:"path"`
	Capabilities []string `json:"capabilities"`
	Deny         bool     `json:"deny,omitempty"`
}
type Policy struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

func Allowed(policies []Policy, capability, secretPath string) bool {
	allowed := false
	for _, p := range policies {
		for _, rule := range p.Rules {
			matched := rule.Path == "**"
			var err error
			if !matched {
				matched, err = path.Match(rule.Path, secretPath)
			}
			if err != nil || !matched {
				continue
			}
			for _, cap := range rule.Capabilities {
				if cap == capability || cap == "sudo" {
					if rule.Deny {
						return false
					}
					allowed = true
				}
			}
		}
	}
	return allowed
}
