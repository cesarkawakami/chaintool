// Copyright © 2016 Cesar Kawakami <cesarkawakami@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"fmt"
	"os"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/cesarkawakami/chaintool/core"
	"github.com/cesarkawakami/pflaghelpers"
	"github.com/spf13/cobra"
)

var awsListCmd = &cobra.Command{
	Use:   "aws:list",
	Short: "Lists and checks all certificates on AWS IAM",
	Long: `
aws:list lists and checks all certificates on AWS IAM.

For each certificate, it emits the same warnings and verification
results the verify command emits, allowing one to quickly check all
certificates in the AWS region without manually verifying one by one.
`,
	Run: runAWSList,
}

func init() {
	RootCmd.AddCommand(awsListCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// awsListCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// awsListCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	awsListCmd.PersistentFlags().String("region", DefaultAWSRegion, "AWS Region")
	awsListCmd.PersistentFlags().BoolP("short", "s", false, "Short output, one line per certificate")
}

func runAWSList(cmd *cobra.Command, args []string) {
	region := pflaghelpers.MustGetString(cmd.Flags(), "region", false)
	shortOutput := pflaghelpers.MustGetBool(cmd.Flags(), "short")

	iamSvc := iam.New(session.New(&aws.Config{
		Region: aws.String(region),
	}))

	certificates, err := iamAllServerCertificates(iamSvc)
	if err != nil {
		fatal("Unable to fetch certificates: %s", err)
	}

	filters := []*regexp.Regexp{}
	for _, pattern := range args {
		re, err := regexp.Compile(pattern)
		if err != nil {
			fatal("`%s` is not a valid regexp: %s", pattern, err)
		}
		filters = append(filters, re)
	}

	if len(certificates) <= 0 {
		fatal("No certificates found.")
	}

	for _, awsCertificate := range certificates {
		meta := awsCertificate.ServerCertificateMetadata
		if len(filters) != 0 {
			found := false
			for _, re := range filters {
				if re.MatchString(*meta.ServerCertificateName) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		chain, err := core.ChainFromAWS(awsCertificate)
		if err != nil {
			fatal("%s", err)
		}

		err = chain.Verify("")

		if shortOutput {
			results := "PASS"
			description := ""

			if err != nil {
				results = "FAIL"
				description = fmt.Sprintf("%T", err)
			}

			msg("%-40s%-6s%s", *meta.ServerCertificateName, results, description)
		} else {
			title(*meta.ServerCertificateName)

			msg("ID:          %s", *meta.ServerCertificateId)
			msg("Name:        %s", *meta.ServerCertificateName)
			msg("Uploaded at: %s", meta.UploadDate)

			chain.InfoLines(80).Write(os.Stdout)

			msg("")

			if err != nil {
				msg("Verification results: FAILED.")
				msg("")
				msg("%s", err)
			} else {
				msg("Verification results: PASSED!")
			}

			msg("")
		}
	}
}

func iamAllServerCertificates(iamSvc *iam.IAM) ([]*iam.ServerCertificate, error) {
	metadataList := []*iam.ServerCertificateMetadata{}

	err := iamSvc.ListServerCertificatesPages(
		&iam.ListServerCertificatesInput{
			MaxItems: aws.Int64(1000),
		},
		func(page *iam.ListServerCertificatesOutput, lastPage bool) bool {
			metadataList = append(metadataList, page.ServerCertificateMetadataList...)
			return true
		},
	)
	if err != nil {
		return nil, err
	}

	rv := []*iam.ServerCertificate{}
	for _, metadata := range metadataList {
		result, err := iamSvc.GetServerCertificate(&iam.GetServerCertificateInput{
			ServerCertificateName: metadata.ServerCertificateName,
		})
		if err != nil {
			return nil, err
		}
		rv = append(rv, result.ServerCertificate)
	}

	return rv, nil
}
