package gpgkms

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/packet"
)

// Converter allows exporting an openpgp entity public key
//
// It also allow using said entity for signing
type Converter struct {
	entity *openpgp.Entity
	cfg    packet.Config
}

func New(entity *openpgp.Entity) *Converter {
	return &Converter{
		entity: entity,
	}
}

// Sign creates a signature for the provided data
//
// if `clearsigned` is true, a plain text signature is generated
// if `detached` is true, a detacged signture is created
// if `armored` is true and `detached` is true, the created detached signature
// will be in armor format
func (c *Converter) Sign(data io.Reader, clearsigned, detached, armored bool) ([]byte, error) {
	var bb bytes.Buffer

	switch {
	case detached && armored:
		err := openpgp.ArmoredDetachSign(&bb, c.entity, data, &c.cfg)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate detached armored signature")
		}
	case detached:
		if err := openpgp.DetachSign(&bb, c.entity, data, &c.cfg); err != nil {
			return nil, errors.Wrap(err, "failed to generate detached signature")
		}
	default:
		// not detached, we ignore the value of `armored` in this case
		var (
			err error
			wc  io.WriteCloser
		)
		if clearsigned {
			wc, err = clearsign.Encode(&bb, c.entity.PrivateKey, &c.cfg)
			if err != nil {
				return nil, errors.Wrap(err, "failed create clearsign writer")
			}
		} else {
			var fileHints openpgp.FileHints

			// if we have a file as input create some hints
			if f, ok := data.(*os.File); ok {
				fileHints.FileName = filepath.Base(f.Name())
				if fi, err := f.Stat(); err != nil {
					fileHints.ModTime = fi.ModTime()
				}
			}

			wc, err = openpgp.Sign(&bb, c.entity, &fileHints, &c.cfg)
			if err != nil {
				return nil, errors.Wrap(err, "failed to create signature writer")
			}
		}

		if _, err = io.Copy(wc, data); err != nil {
			wc.Close()
			return nil, errors.Wrap(err, "failed to sign data")
		}

		if err = wc.Close(); err != nil {
			return nil, errors.Wrap(err, "failed to finalize signature")
		}
	}

	return bb.Bytes(), nil
}

// Export generates a pgp compatible public key
//
// If `armored` is true, the key is generated in armor format
func (c *Converter) Export(name, comment, email string, armored bool) ([]byte, error) {
	uid := packet.NewUserId(name, comment, email)
	if uid == nil {
		return nil, errors.New("failed to create PGP User ID")
	}

	primary := true
	c.entity.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Id,
		UserId: uid,
		SelfSignature: &packet.Signature{
			SigType:      packet.SigTypePositiveCert, // assume we can trust this fully
			PubKeyAlgo:   c.entity.PrimaryKey.PubKeyAlgo,
			Hash:         c.cfg.Hash(),
			CreationTime: c.entity.PrimaryKey.CreationTime,
			IssuerKeyId:  &c.entity.PrimaryKey.KeyId,
			IsPrimaryId:  &primary,
			FlagsValid:   true,
			FlagCertify:  true,
			FlagSign:     true,
		},
	}

	err := c.entity.Identities[uid.Id].SelfSignature.SignUserId(uid.Id, c.entity.PrimaryKey, c.entity.PrivateKey, &c.cfg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to self-sign public key")
	}

	var bb bytes.Buffer
	if armored {
		wc, err := armor.Encode(&bb, "PGP PUBLIC KEY BLOCK", nil)
		if err != nil {
			return nil, errors.Wrap(err, "failed to created armored writer")
		}

		if err := c.entity.Serialize(wc); err != nil {
			wc.Close()
			return nil, errors.Wrap(err, "failed serialize armored public key")
		}

		if err := wc.Close(); err != nil {
			return nil, errors.Wrap(err, "failed to dump armored key")
		}
	} else {
		if err := c.entity.Serialize(&bb); err != nil {
			return nil, errors.Wrap(err, "failed serialize public key")
		}
	}

	return bb.Bytes(), nil
}
