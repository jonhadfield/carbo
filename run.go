package carbo

import (
	"fmt"
	"github.com/jonhadfield/carbo/policy"
	"log"
	"strings"
)

// preflight
// check that all custom rules sit in correct ranges
// check if any rules exist out of order
// check no limits exceeded for block, allow, log

type RunActionsInput struct {
	Path   string
	DryRun bool
	Debug  bool
}

func runActions(as []policy.Action, stopOnFailure, dryRun bool) (err error) {
	for _, a := range as {
		switch strings.ToLower(a.ActionType) {
		case "log":
			rid := policy.ParseResourceID(a.Policy)

			log.Printf("running LOG action for Policy: %s\n", rid.Name)
			log.Printf("loaded %d addresses from paths: %s\n", len(a.Nets), strings.Join(a.Paths, ","))

			err = policy.ApplyIPChanges(policy.ApplyIPsInput{
				RID:      rid,
				Output:   false,
				Action:   "Log",
				Filepath: "",
				DryRun:   dryRun,
				Nets:     a.Nets,
				MaxRules: a.MaxRules,
			})

			if err != nil {
				return
			}
		case "allow":
			rid := policy.ParseResourceID(a.Policy)

			log.Printf("running ALLOW action for Policy: %s\n", rid.Name)
			log.Printf("loaded %d addresses from paths: %s\n", len(a.Nets), strings.Join(a.Paths, ","))

			err = policy.ApplyIPChanges(policy.ApplyIPsInput{
				RID:      rid,
				Output:   false,
				Action:   "Allow",
				Filepath: "",
				DryRun:   dryRun,
				Nets:     a.Nets,
				MaxRules: a.MaxRules,
			})

			if err != nil {
				return
			}
		case "block":
			rid := policy.ParseResourceID(a.Policy)

			log.Printf("running BLOCK action for Policy: %s\n", rid.Name)
			log.Printf("loaded %d addresses from paths: %s\n", len(a.Nets), strings.Join(a.Paths, ","))

			err = policy.ApplyIPChanges(policy.ApplyIPsInput{
				RID:      rid,
				Output:   false,
				Action:   "Block",
				Filepath: "",
				DryRun:   dryRun,
				Nets:     a.Nets,
				MaxRules: a.MaxRules,
			})

			if err != nil {
				return
			}

		default:
			return fmt.Errorf("action type '%s' is not supported", a.ActionType)
		}
	}

	return nil
}

func RunActions(i RunActionsInput) error {
	actions, err := policy.LoadActionsFromPath(i.Path)
	if err != nil {
		return err
	}

	return runActions(actions, true, i.DryRun)
}
