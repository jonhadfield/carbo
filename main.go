package carbo

import (
	"os"

	"github.com/sirupsen/logrus"
)

func init() {
	lvl, ok := os.LookupEnv("CARBO_LOG")
	// LOG_LEVEL not set, default to info
	if !ok {
		lvl = "info"
	}

	ll, err := logrus.ParseLevel(lvl)
	if err != nil {
		ll = logrus.InfoLevel
	}

	logrus.SetLevel(ll)
}

// type BlockIPsInput struct {
// 	RID      data.ResourceID
// 	Output   bool
// 	DryRun   bool
// 	Filepath string
// 	Nets     policy.IPNets
// 	MaxRules int
// 	Debug    bool
// }
//
// type LogIPsInput struct {
// 	RID      data.ResourceID
// 	Output   bool
// 	DryRun   bool
// 	Filepath string
// 	Nets     policy.IPNets
// 	MaxRules int
// 	Debug    bool
// }
