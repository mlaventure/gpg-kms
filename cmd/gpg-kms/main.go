package main

import (
	"fmt"
	"io"
	"os"

	gpgkms "github.com/mlaventure/gpg-kms"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

var (
	globalCommands []*cli.Command

	commonExportFlags = []cli.Flag{
		&cli.StringFlag{
			Name:     "key",
			Usage:    "Name of key within the KMS to use",
			Required: true,
		},
		&cli.BoolFlag{
			Name:  "armor",
			Usage: "Export in ASCII armored format",
		},
		&cli.StringFlag{
			Name:     "name",
			Usage:    "Name of key owner",
			Required: true,
		},
		&cli.StringFlag{
			Name:  "comment",
			Usage: "Comment to associate with key",
		},
		&cli.StringFlag{
			Name:     "email",
			Usage:    "E-mail of key owner",
			Required: true,
		},
	}
	commonSignFlags = []cli.Flag{
		&cli.StringFlag{
			Name:     "key",
			Usage:    "Name of key within the KMS to use",
			Required: true,
		},
		&cli.BoolFlag{
			Name:  "armor",
			Usage: "Create ASCII armored output",
		},
		&cli.BoolFlag{
			Name:  "clear-sign",
			Usage: "Create clear text signature",
		},
		&cli.BoolFlag{
			Name:  "detach-sign",
			Usage: "Create detached signature",
		},
	}
)

func main() {
	app := &cli.App{
		Name:     "gpg-kms",
		Usage:    "Bridge KMS system and PGP",
		Commands: globalCommands,
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func export(c *cli.Context, converter *gpgkms.Converter) error {
	var w io.Writer = os.Stdout

	if file := c.Args().First(); file != "" && file != "-" {
		f, err := os.Create(file)
		if err != nil {
			return errors.Wrap(err, "failed to create destination file")
		}
		defer f.Close()

		w = f
	}

	b, err := converter.Export(c.String("name"), c.String("comment"), c.String("email"), c.Bool("armor"))
	if err != nil {
		return err
	}

	if c.Bool("armor") {
		// append new line
		b = append(b, '\n')
	}

	if _, err = w.Write(b); err != nil {
		return errors.Wrap(err, "failed to write key")
	}

	return nil
}

func sign(c *cli.Context, converter *gpgkms.Converter) error {
	var (
		r io.Reader = os.Stdin
		w io.Writer = os.Stdout
	)

	input := c.Args().First()
	if input == "" {
		return errors.New("no input was provided for signing")
	}

	if input != "-" {
		f, err := os.Open(input)
		if err != nil {
			return errors.Wrap(err, "failed to open input file")
		}
		defer f.Close()

		r = f
	}

	output := c.Args().Get(1)
	if output != "" && output != "-" {
		f, err := os.Create(output)
		if err != nil {
			return errors.Wrap(err, "failed to create destination file")
		}
		defer f.Close()

		w = f
	}

	b, err := converter.Sign(r, c.Bool("clear-sign"), c.Bool("detach-sign"), c.Bool("armor"))
	if err != nil {
		return err
	}

	if (c.Bool("detach-sign") && c.Bool("armor")) || c.Bool("clear-sign") {
		// append a new line
		b = append(b, '\n')
	}

	if _, err := w.Write(b); err != nil {
		return errors.Wrap(err, "failed to write signature out")
	}

	return nil
}
