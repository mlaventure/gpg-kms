package aws

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/pkg/errors"
)

// New returns a new openpgp.Entity wrapping AWS KMS for the given `key`
func New(key string, cfgs ...*aws.Config) (*openpgp.Entity, error) {
	return NewWithContext(context.Background(), key, cfgs...)
}

// NewWithContext returns a new openpgp.Entity wrapping AWS KMS for the given `key`
func NewWithContext(ctx context.Context, key string, cfgs ...*aws.Config) (*openpgp.Entity, error) {
	session, err := session.NewSessionWithOptions(session.Options{
		// download credentials from ~/.aws/config too (e.g sso)
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not create aws session")
	}
	kmsSVC := kms.New(session, cfgs...)

	ki, err := kmsSVC.DescribeKeyWithContext(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(key),
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not get key information")
	}

	pk, err := kmsSVC.GetPublicKey(&kms.GetPublicKeyInput{
		KeyId: aws.String(key),
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not retrieve public key")
	}

	decodedPK, err := x509.ParsePKIXPublicKey(pk.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not convert public key from DER")
	}
	ecdsaPK, ok := decodedPK.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.Wrap(err, "public key is not in ECDSA format")
	}

	signer := newSigner(kmsSVC, key, decodedPK)
	entity := &openpgp.Entity{
		PrimaryKey: packet.NewECDSAPublicKey(*ki.KeyMetadata.CreationDate, ecdsaPK),
		PrivateKey: packet.NewSignerPrivateKey(*ki.KeyMetadata.CreationDate, signer),
		Identities: make(map[string]*openpgp.Identity),
	}

	return entity, nil
}
