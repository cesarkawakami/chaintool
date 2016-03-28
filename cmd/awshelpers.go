package cmd

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
)

func iamCertificateExists(iamSvc *iam.IAM, name string) (bool, error) {
	_, err := iamSvc.GetServerCertificate(&iam.GetServerCertificateInput{
		ServerCertificateName: aws.String(name),
	})
	switch err := err.(type) {
	case nil:
		return true, nil
	case awserr.Error:
		if err.Code() == "NoSuchEntity" {
			return false, nil
		} else {
			return false, fmt.Errorf("Error checking if certificate already exists: %s", err)
		}
	default:
		return false, fmt.Errorf("Error checking if certificate already exists: %s", err)
	}
}
