package cmd

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/cesarkawakami/pflaghelpers"
	"github.com/spf13/cobra"
)

var awsDeleteCmd = &cobra.Command{
	Use:   "aws:delete <certificate name>",
	Short: "Deletes a certificate from AWS IAM",
	Long: `
aws:delete deletes a certificate from AWS IAM.

Given the certificate name, it does a basic check for usage in other
services (currently supports ELB and CloudFront), then deletes the
certificate.

Example:

  chaintool aws:delete my_cert
`,
	Run: runAWSDelete,
}

func init() {
	RootCmd.AddCommand(awsDeleteCmd)

	awsDeleteCmd.PersistentFlags().String("region", DefaultAWSRegion, "AWS Region")
	awsDeleteCmd.PersistentFlags().Bool("yes", false, "Don't ask for confirmation")
}

func runAWSDelete(cmd *cobra.Command, args []string) {
	awsRegion := pflaghelpers.MustGetString(cmd.Flags(), "region", false)
	dontConfirm := pflaghelpers.MustGetBool(cmd.Flags(), "yes")

	if len(args) != 1 {
		cmd.Usage()

		msg("")
		fatal("certificate name is required")
	}
	certName := args[0]

	iamSvc := iam.New(session.New(&aws.Config{Region: aws.String(awsRegion)}))

	certArn := ""
	certId := ""
	if resp, err := iamSvc.GetServerCertificate(&iam.GetServerCertificateInput{
		ServerCertificateName: aws.String(certName),
	}); err != nil {
		if err, ok := err.(awserr.Error); ok && err.Code() == "NoSuchEntity" {
			fatal("Couldn't find a certificate with name '%s'", certName)
		} else {
			fatal("Failed fetching certificate from IAM: %s", err)
		}
	} else {
		if serverCertificate := resp.ServerCertificate; serverCertificate != nil {
			if metadata := serverCertificate.ServerCertificateMetadata; metadata != nil {
				if metadataArn := metadata.Arn; metadataArn != nil {
					certArn = *metadataArn
				} else {
					fatal("Internal error: Arn is nil")
				}
				if metadataId := metadata.ServerCertificateId; metadataId != nil {
					certId = *metadataId
				} else {
					fatal("Internal error: ServerCertificateId is nil")
				}
			} else {
				fatal("Internal error: ServerCertificateMetadata is nil")
			}
		} else {
			fatal("Internal error: ServerCertificate is nil")
		}
	}

	usagesFound := false

	elbSvc := elb.New(session.New(&aws.Config{Region: aws.String(awsRegion)}))

	if err := elbSvc.DescribeLoadBalancersPages(&elb.DescribeLoadBalancersInput{
		PageSize: aws.Int64(400),
	}, func(page *elb.DescribeLoadBalancersOutput, lastPage bool) bool {
		for _, description := range page.LoadBalancerDescriptions {
			for _, listenerDescription := range description.ListenerDescriptions {
				if l := listenerDescription.Listener; l != nil {
					if l.SSLCertificateId != nil && *l.SSLCertificateId == certArn {
						usagesFound = true
						msg("ELB '%s' is still using this certificate",
							*description.LoadBalancerName)
					}
				} else {
					fatal("Internal error: Listener is nil")
				}
			}
		}
		return true
	}); err != nil {
		fatal("Error while describing ELBs: %s", err)
	}

	cfSvc := cloudfront.New(session.New(&aws.Config{Region: aws.String(awsRegion)}))

	if err := cfSvc.ListDistributionsPages(
		&cloudfront.ListDistributionsInput{},
		func(page *cloudfront.ListDistributionsOutput, lastPage bool) bool {
			if distributionsList := page.DistributionList; distributionsList != nil {
				for _, distributionSummary := range distributionsList.Items {
					if distributionSummary.ViewerCertificate != nil {
						vc := distributionSummary.ViewerCertificate
						if arn := vc.ACMCertificateArn; arn != nil && *arn == certArn {
							usagesFound = true
							msg("CloudFront distribution '%s' is still using this certificate",
								*distributionSummary.Id)
						}
						if ici := vc.IAMCertificateId; ici != nil && *ici == certId {
							usagesFound = true
							msg("CloudFront distribution '%s' is still using this certificate",
								*distributionSummary.Id)
						}
					}
				}
			} else {
				fatal("Internal error: DistributionsList is nil")
			}
			return true
		},
	); err != nil {
		fatal("Error while listing CloudFront distributions: %s", err)
	}

	msg("")
	if usagesFound {
		msg("This certificate is still being used in some places!!!")
	} else {
		msg("No usages for this certificate were found in ELB or CloudFront, it all appears OK.")
	}
	msg("")

	if !dontConfirm {
		for {
			fmt.Printf("Go ahead with deletion? (yes/no) ")
			response := ""
			fmt.Scan(&response)
			response = strings.ToLower(strings.Trim(response, " \t\r\n"))
			if strings.HasPrefix(response, "y") {
				msg("")
				break
			} else if strings.HasPrefix(response, "n") {
				fatal("\nAborted.")
			} else {
				msg("\nInvalid response.\n")
			}
		}
	}

	if _, err := iamSvc.DeleteServerCertificate(&iam.DeleteServerCertificateInput{
		ServerCertificateName: aws.String(certName),
	}); err != nil {
		fatal("Failed while deleting certificate: %s", err)
	} else {
		msg("Certificate deletion successful!")
	}
}
