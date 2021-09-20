package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	gpgkms "github.com/mlaventure/gpg-kms"
	gpgaws "github.com/mlaventure/gpg-kms/aws"
)

var (
	awsFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "region",
			Usage: "AWS region where key is stored",
			Value: "us-west-2",
		},
	}

	awsCommand = &cli.Command{
		Name: "aws",
		Subcommands: []*cli.Command{
			{
				Name:   "export",
				Action: awsExport,
				Flags:  awsFlags,
			},
			{
				Name:   "sign",
				Action: awsSign,
				Flags:  awsFlags,
			},
		},
	}
)

func init() {
	awsCommand.Subcommands[0].Flags = append(awsCommand.Subcommands[0].Flags, commonExportFlags...)
	awsCommand.Subcommands[1].Flags = append(awsCommand.Subcommands[1].Flags, commonSignFlags...)
	globalCommands = append(globalCommands, awsCommand)
}

func awsSign(c *cli.Context) error {
	config := aws.NewConfig()
	if region := c.String("region"); region != "" {
		config = config.WithRegion(region)
	}
	config.CredentialsChainVerboseErrors = aws.Bool(true)

	kmsEntity, err := gpgaws.New(c.String("key"), config)
	if err != nil {
		return errors.Wrap(err, "could not create KMS Entity")
	}

	return sign(c, gpgkms.New(kmsEntity))
}

func awsExport(c *cli.Context) error {
	config := aws.NewConfig()
	if region := c.String("region"); region != "" {
		config = config.WithRegion(region)
	}

	kmsEntity, err := gpgaws.New(c.String("key"), config)
	if err != nil {
		return errors.Wrap(err, "could not create KMS Entity")
	}

	return export(c, gpgkms.New(kmsEntity))
}
