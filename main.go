package carbo

import (
	"os"

	"github.com/sirupsen/logrus"
)

const (
	// Order is:
	// - 1: Log (manual 0-999, carbo 1000-1999)
	// - 2: Allow (manual 2000-2999, carbo 3000-3999)
	// - 3: Block (manual 4000-4999, carbo 5000-5999)

	// MaxPoliciesToFetch is the maximum number to attempt to retrieve (not an Azure limit)
	MaxPoliciesToFetch = 200
	// MaxFrontDoorsToFetch is the maximum number to attempt to retrieve (not an Azure limit)
	MaxFrontDoorsToFetch = 100
	// MaxCustomRules is the hard limit on the number of allowed custom rules
	MaxCustomRules = 90
	// MaxLogNetsRules is the maximum number of custom rules to create from Azure's hard limit of 90 per Policy
	MaxLogNetsRules = 10
	// MaxBlockNetsRules is the maximum number of custom rules to create from Azure's hard limit of 90 per Policy
	MaxBlockNetsRules = 40
	// MaxAllowNetsRules is the maximum number of custom rules to create from Azure's hard limit of 90 per Policy
	MaxAllowNetsRules = 10
	// MaxIPMatchValues is Azure's hard limit on IPMatch values per rule
	MaxIPMatchValues = 600

	// LogNetsPrefix is the prefix for Custom Rules used for logging IP networks
	LogNetsPrefix = "LogNets"
	// LogNetsPriorityStart is the first custom rule priority number
	// Manual log rules should be numbered below 1000
	LogNetsPriorityStart = 1000

	// AllowNetsPrefix is the prefix for Custom Rules used for allowing IP networks
	AllowNetsPrefix = "AllowNets"
	// AllowNetsPriorityStart is the first custom rule priority number
	// Manual allow rules should be numbered 2000-2999
	AllowNetsPriorityStart = 3000

	// BlockNetsPrefix is the prefix for Custom Rules used for blocking IP networks
	BlockNetsPrefix = "BlockNets"
	// BlockNetsPriorityStart is the first custom rule priority number
	// Manual block rules should be numbered 4000-4999
	BlockNetsPriorityStart = 5000

	// MaxMatchValuesPerColumn is the number of match values to output per column when showing policies and rules
	MaxMatchValuesPerColumn = 3
	// MaxMatchValuesOutput is the maximum number of match values to output when showing policies and rules
	MaxMatchValuesOutput = 9
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

type BlockIPsInput struct {
	RID      ResourceID
	Output   bool
	DryRun   bool
	Filepath string
	Nets     IPNets
	MaxRules int
	Debug    bool
}

type LogIPsInput struct {
	RID      ResourceID
	Output   bool
	DryRun   bool
	Filepath string
	Nets     IPNets
	MaxRules int
	Debug    bool
}

type DeleteCustomRulesInput struct {
	RID      ResourceID
	Prefix   string
	MaxRules int
	Debug    bool
}

func DeleteCustomRules(dcri DeleteCustomRulesInput) (err error) {
	// preflight checks
	s := session{}

	return deleteCustomRules(&s, dcri)
}
