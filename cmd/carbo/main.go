package main

import (
	"fmt"
	. "github.com/jonhadfield/carbo/backup"
	. "github.com/jonhadfield/carbo/helpers"
	. "github.com/jonhadfield/carbo/policy"
	"os"
	"time"

	. "github.com/jonhadfield/carbo"
	"github.com/urfave/cli/v2"
)

var version, versionOutput, tag, sha, buildDate string

func main() {
	if tag != "" && buildDate != "" {
		versionOutput = fmt.Sprintf("[%s-%s] %s UTC", tag, sha, buildDate)
	} else {
		versionOutput = version
	}

	app := cli.NewApp()
	app.EnableBashCompletion = true

	app.Name = "carbo"
	app.Version = versionOutput
	app.Compiled = time.Now()
	app.Authors = []*cli.Author{
		{
			Name:  "Jon Hadfield",
			Email: "jon@lessknown.co.uk",
		},
	}
	app.HelpName = "-"
	app.Usage = "Azure WAF Manager"
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:     "subscription-id",
			Usage:    "specify the subscription id containing the policies",
			EnvVars:  []string{"AZURE_SUBSCRIPTION_ID"},
			Aliases:  []string{"s", "subscription"},
			Required: false,
		},
		&cli.BoolFlag{Name: "quiet", Usage: "suppress output"},
	}
	app.Commands = []*cli.Command{
		{
			Name:  "copy",
			Usage: "copy waf policy rules",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "source", Usage: "source policy resource id", Aliases: []string{"s"}, Required: true},
				&cli.StringFlag{Name: "target", Usage: "target policy resource id", Aliases: []string{"f"}, Required: true},
				&cli.BoolFlag{Name: "custom-rules", Usage: "copy custom rules only", Aliases: []string{"custom", "c"}},
				&cli.BoolFlag{Name: "managed-rules", Usage: "copy managed rules only", Aliases: []string{"managed", "m"}},
				&cli.BoolFlag{Name: "async", Usage: "push resulting policy without waiting for completion", Aliases: []string{"a"}},
			},
			Action: func(c *cli.Context) error {
				input := c.Args().Slice()
				if len(input) > 0 {
					if err := ValidateResourceIDs(input); err != nil {
						_ = cli.ShowSubcommandHelp(c)

						return err
					}
				}

				return CopyRules(CopyRulesInput{
					SubscriptionID:   c.String("subscription-id"),
					Source:           c.String("source"),
					Target:           c.String("target"),
					ManagedRulesOnly: c.Bool("managed-rules"),
					CustomRulesOnly:  c.Bool("custom-rules"),
					Async:            c.Bool("async"),
					Quiet:            c.Bool("quiet"),
				})
			},
		},
		{
			Name:  "backup",
			Usage: "backup waf policies",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "path", Usage: "where to write backups", Aliases: []string{"p"}, Required: false},
				&cli.StringFlag{Name: "storage-account-id", Usage: "resource id of storage account to backup to", Aliases: []string{"s"}, Required: false},
				&cli.StringFlag{Name: "container-url", Usage: "container url to backup to, ex: https://mystorageacc.blob.core.windows.net/mycontainer", Aliases: []string{"c"}, Required: false},
				&cli.BoolFlag{Name: "fail-fast", Usage: "exit if any error encountered", Aliases: []string{"f"}, Required: false},
			},
			Action: func(c *cli.Context) error {
				input := c.Args().Slice()
				if len(input) > 0 {
					if err := ValidateResourceIDs(input); err != nil {
						_ = cli.ShowSubcommandHelp(c)

						return err
					}
				}

				if c.String("subscription-id") == "" && len(input) == 0 {
					return fmt.Errorf("subscription-id required if resource ids not specified")
				}

				return BackupPolicies(BackupPoliciesInput{
					RIDs:                     input,
					SubscriptionID:           c.String("subscription-id"),
					Path:                     c.String("path"),
					StorageAccountResourceID: c.String("storage-account-id"),
					ContainerURL:             c.String("container-url"),
					AppVersion:               versionOutput,
					FailFast:                 c.Bool("fail-fast"),
					Quiet:                    c.Bool("quiet"),
				})
			},
		},
		{
			Name:  "restore",
			Usage: "restore waf policies",
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: "custom-rules", Usage: "restore custom rules only", Aliases: []string{"custom", "c"}},
				&cli.BoolFlag{Name: "managed-rules", Usage: "restore managed rules only", Aliases: []string{"managed", "m"}},
				&cli.StringFlag{Name: "target", Usage: "restore a backup policy's rules (custom and/or managed) over an existing policy", Aliases: []string{"t"}},
				&cli.StringFlag{Name: "resource-group", Usage: "resource group to restore new policies to", Aliases: []string{"r"}},
				&cli.BoolFlag{Name: "force", Usage: "make changes without first prompting"},
				&cli.BoolFlag{Name: "fail-fast", Usage: "exit if any error encountered", Aliases: []string{"f"}},
			},
			Action: func(c *cli.Context) error {
				// require either backup path/paths
				if len(c.Args().Slice()) == 0 {
					return fmt.Errorf("no backup paths provided")
				}

				if c.String("subscription-id") != "" {
					return RestorePolicies(RestorePoliciesInput{
						SubscriptionID:   c.String("subscription-id"),
						BackupsPaths:     c.Args().Slice(),
						Force:            c.Bool("force"),
						CustomRulesOnly:  c.Bool("custom-rules"),
						ManagedRulesOnly: c.Bool("managed-rules"),
						TargetPolicy:     c.String("target"),
						ResourceGroup:    c.String("resource-group"),
						FailFast:         c.Bool("fail-fast"),
						Quiet:            c.Bool("quiet"),
					})
				}

				_ = cli.ShowSubcommandHelp(c)

				return nil
			},
		},
		{
			Name:    "run",
			Aliases: []string{"r"},
			Usage:   "run actions",
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: "dry-run", Usage: "show changes without applying", Aliases: []string{"d"}},
				&cli.BoolFlag{Name: "no-verify", Usage: "skip manual verification", Aliases: []string{"n"}},
			},
			Action: func(c *cli.Context) error {
				input := c.Args().First()
				if input == "" {
					_ = cli.ShowSubcommandHelp(c)

					return fmt.Errorf("actions path undefined")
				}

				return RunActions(RunActionsInput{
					Path:   input,
					DryRun: c.Bool("dry-run"),
				})
			},
		},
		{
			Name:    "delete",
			Aliases: []string{"d"},
			Usage:   "delete custom-rules",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "prefix", Usage: "custom-rule prefixes", Aliases: []string{"p"}},
			},
			Action: func(c *cli.Context) error {
				input := c.Args().First()
				if input != "" {
					// TODO: check if extended or not and allow specification of custom-rule?
					if err := ValidateResourceID(input, false); err != nil {
						_ = cli.ShowSubcommandHelp(c)

						return err
					}
					return DeleteCustomRules(DeleteCustomRulesInput{
						RID:    ParseResourceID(input),
						Prefix: c.String("prefix"),
					})
				}
				_ = cli.ShowSubcommandHelp(c)

				return nil
			},
		},
		{
			Name:    "block",
			Aliases: []string{"b"},
			Usage:   "block requests",
			Subcommands: []*cli.Command{
				{
					Name:  "ips",
					Usage: "specify list(s) of IPs to block",
					Flags: []cli.Flag{
						&cli.StringFlag{Name: "file", Usage: "path to file or directory of ips", Aliases: []string{"f"}, Required: true},
						&cli.IntFlag{Name: "max-rules", Usage: "maximum number of custom rules to create", Aliases: []string{"m"}, Value: MaxBlockNetsRules},
						&cli.BoolFlag{Name: "output", Usage: "create and output new policy without applying", Aliases: []string{"o"}},
						&cli.BoolFlag{Name: "dry-run", Usage: "show changes without applying", Aliases: []string{"d"}},
					},
					Aliases: []string{"i"},
					Action: func(c *cli.Context) error {
						input := c.Args().First()
						if input != "" {
							// TODO: check if extended or not and allow specification of custom-rule?
							if err := ValidateResourceID(input, false); err != nil {
								_ = cli.ShowSubcommandHelp(c)

								return err
							}
							return ApplyIPChanges(ApplyIPsInput{
								Action:   "Block",
								RID:      ParseResourceID(input),
								DryRun:   c.Bool("dry-run"),
								Output:   c.Bool("output"),
								Filepath: c.String("file"),
								MaxRules: c.Int("max-rules"),
							})
						}
						_ = cli.ShowSubcommandHelp(c)

						return nil
					},
				},
			},
		},
		{
			Name:    "allow",
			Aliases: []string{"a"},
			Usage:   "allow requests",
			Subcommands: []*cli.Command{
				{
					Name:  "ips",
					Usage: "specify list(s) of IPs to allow",
					Flags: []cli.Flag{
						&cli.StringFlag{Name: "file", Usage: "path to file or directory of ips", Aliases: []string{"f"}, Required: true},
						&cli.IntFlag{Name: "max-rules", Usage: "maximum number of custom rules to create", Aliases: []string{"m"}, Value: MaxAllowNetsRules},
						&cli.BoolFlag{Name: "output", Usage: "create and output new policy without applying", Aliases: []string{"o"}},
						&cli.BoolFlag{Name: "dry-run", Usage: "show changes without applying", Aliases: []string{"d"}},
					},
					Aliases: []string{"i"},
					Action: func(c *cli.Context) error {
						input := c.Args().First()
						if input != "" {
							// TODO: check if extended or not and allow specification of custom-rule?
							if err := ValidateResourceID(input, false); err != nil {
								_ = cli.ShowSubcommandHelp(c)

								return err
							}
							return ApplyIPChanges(ApplyIPsInput{
								Action:   "Allow",
								RID:      ParseResourceID(input),
								DryRun:   c.Bool("dry-run"),
								Output:   c.Bool("output"),
								Filepath: c.String("file"),
								MaxRules: c.Int("max-rules"),
							})
						}
						_ = cli.ShowSubcommandHelp(c)

						return nil
					},
				},
			},
		},
		{
			Name:  "log",
			Usage: "log requests",
			Subcommands: []*cli.Command{
				{
					Name:  "ips",
					Usage: "specify list(s) of IPs to log",
					Flags: []cli.Flag{
						&cli.StringFlag{Name: "file", Usage: "path to file or directory of ips", Aliases: []string{"f"}, Required: true},
						&cli.IntFlag{Name: "max-rules", Usage: "maximum number of custom rules to create", Aliases: []string{"m"}, Value: MaxLogNetsRules},
						&cli.BoolFlag{Name: "output", Usage: "create and output new policy without applying", Aliases: []string{"o"}},
						&cli.BoolFlag{Name: "dry-run", Usage: "show changes without applying", Aliases: []string{"d"}},
					},
					Aliases: []string{"i"},
					Action: func(c *cli.Context) error {
						input := c.Args().First()
						if input != "" {
							// TODO: check if extended or not and allow specification of custom-rule?
							if err := ValidateResourceID(input, false); err != nil {
								_ = cli.ShowSubcommandHelp(c)

								return err
							}

							return ApplyIPChanges(ApplyIPsInput{
								Action:   "Log",
								RID:      ParseResourceID(input),
								DryRun:   c.Bool("dry-run"),
								Output:   c.Bool("output"),
								Filepath: c.String("file"),
								MaxRules: c.Int("max-rules"),
							})
						}
						_ = cli.ShowSubcommandHelp(c)

						return nil
					},
				},
			},
		},
		{
			Name:    "list",
			Aliases: []string{"l"},
			Usage:   "list resources",
			Action: func(c *cli.Context) error {
				_ = cli.ShowSubcommandHelp(c)

				return nil
			},
			Subcommands: []*cli.Command{
				{
					Name:    "frontdoors",
					Usage:   "list front doors",
					Aliases: []string{"f"},
					Action: func(c *cli.Context) error {
						if c.String("subscription-id") == "" {
							return fmt.Errorf("subscription-id required")
						}

						return ListFrontDoors(c.String("subscription-id"))
					},
				},
				{
					Name:    "policies",
					Usage:   "list waf policies",
					Aliases: []string{"p", "policy"},
					Flags: []cli.Flag{
						&cli.IntFlag{Name: "top", Aliases: []string{"max"}, Usage: "number of policies to list", Value: MaxPoliciesToFetch},
					},
					Action: func(c *cli.Context) error {
						if c.String("subscription-id") == "" {
							return fmt.Errorf("subscription-id required")
						}

						return ListPolicies(c.String("subscription-id"), versionOutput, c.Int("max"))
					},
				},
			},
		},
		{
			Name:    "show",
			Aliases: []string{"s"},
			Usage:   "show policy",
			Action: func(c *cli.Context) error {
				_ = cli.ShowAppHelp(c)

				return nil
			},
			Subcommands: []*cli.Command{
				{
					Name:    "policy",
					Usage:   "show policy <policy resource id>",
					Aliases: []string{"p"},
					Flags: []cli.Flag{
						&cli.StringFlag{Name: "rule-name", Usage: "filter by specific rule", Hidden: true},
						&cli.BoolFlag{Name: "show-full", Usage: "show all match conditions"},
					},
					Action: func(c *cli.Context) error {
						if c.String("rule-name") != "" {
							// TODO: filter by rule-name
							fmt.Println("not yet implemented")
						}
						policyID := c.Args().First()
						if err := ValidateResourceID(policyID, false); err != nil {
							_ = cli.ShowSubcommandHelp(c)

							return err
						}

						return ShowPolicy(policyID, c.Bool("show-full"))
					},
				},
			},
		},
		{
			Name:    "get",
			Aliases: []string{"g"},
			Usage:   "get policy data",
			Action: func(c *cli.Context) error {
				_ = cli.ShowAppHelp(c)

				return nil
			},
			Subcommands: []*cli.Command{
				{
					Name:    "policy",
					Usage:   "get policy using resource id",
					Aliases: []string{"p"},
					Action: func(c *cli.Context) error {
						// get custom rule match-value field using format "<policy id>|<rule-name>"
						input := c.Args().First()

						if err := ValidateResourceID(input, false); err != nil {
							_ = cli.ShowSubcommandHelp(c)

							return err
						}

						return PrintPolicy(input)
					},
				},
				{
					Name:    "custom-rule",
					Usage:   "get custom-rule using format \"<policy id>|<rule-name>\"",
					Aliases: []string{"c"},
					Flags: []cli.Flag{
						&cli.StringFlag{Name: "output", Usage: "save custom-rule to path"},
					},
					Action: func(c *cli.Context) error {
						// get custom rule match-value field using format "<policy id>|<rule-name>"
						input := c.Args().First()

						if err := ValidateResourceID(input, true); err != nil {
							_ = cli.ShowSubcommandHelp(c)

							return err
						}

						return PrintPolicyCustomRule(input)
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Println()
		fmt.Printf("error: %v\n\n", err)
	}
}
