package aws

import (
	"crypto"
	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/pkg/errors"
)

type signer struct {
	kms       *kms.KMS
	keyID     string
	publicKey crypto.PublicKey
}

func newSigner(kms *kms.KMS, keyID string, pubKey crypto.PublicKey) *signer {
	return &signer{
		kms:       kms,
		keyID:     keyID,
		publicKey: pubKey,
	}
}

func (s *signer) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if len(digest) != crypto.SHA256.Size() || opts != crypto.SHA256 {
		return nil, errors.New("only SHA-256 digest are supported")
	}

	so, err := s.kms.Sign(&kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest,
		MessageType:      aws.String("DIGEST"),
		SigningAlgorithm: aws.String("ECDSA_SHA_256"),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign digest")
	}

	return so.Signature, nil
}
