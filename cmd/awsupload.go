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
	"io/ioutil"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/cesarkawakami/chaintool/core"
	"github.com/cesarkawakami/pflaghelpers"
	"github.com/spf13/cobra"
)

var awsUploadCmd = &cobra.Command{
	Use:   "aws:upload",
	Short: "Uploads a new certificate to AWS IAM",
	Long: `
aws:upload uploads a new certificate to AWS IAM.

It receives the certificate and key and downloads and checks the
certificate chain, uploading a file in the correct format to AWS IAM.

Simple usage would entail something like this:

  chaintool aws:upload \
    --region us-west-1 \
    --cert my_cert.crt \
	--key my_cert.key \
	--name my.cert.com.2016.01.01

You can then use the resulting 'my.cert.com.2016.01.01' certificate in
other AWS services like ELB or Beanstalk.
`,
	Run: runAWSUpload,
}

func init() {
	RootCmd.AddCommand(awsUploadCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// awsUploadCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// awsUploadCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	awsUploadCmd.PersistentFlags().String("region", DefaultAWSRegion, "AWS Region")
	awsUploadCmd.PersistentFlags().String("cert", "", "Path to cert file (required)")
	awsUploadCmd.PersistentFlags().String("key", "", "Path to private key file (required)")
	awsUploadCmd.PersistentFlags().String(
		"name", "", "Name with which to upload the certificate (required)")

	awsUploadCmd.PersistentFlags().String(
		"chain", "",
		"Certificate intermediates file (optional, will fetch from internet if able and absent)")
}

func runAWSUpload(cmd *cobra.Command, args []string) {
	awsRegion := pflaghelpers.MustGetString(cmd.Flags(), "region", false)
	certDataPath := pflaghelpers.MustGetString(cmd.Flags(), "cert", false)
	privateKeyDataPath := pflaghelpers.MustGetString(cmd.Flags(), "key", false)
	chainDataPath := pflaghelpers.MustGetString(cmd.Flags(), "chain", true)
	uploadedName := pflaghelpers.MustGetString(cmd.Flags(), "name", false)

	cert, err := core.CertificateWithKeyFromFiles(certDataPath, privateKeyDataPath)
	if err != nil {
		fatal("Failed loading certificate/key pair: %s", err)
	}

	var chain *core.CertificateChain
	if chainDataPath != "" {
		intermediatesData, err := ioutil.ReadFile(chainDataPath)
		if err != nil {
			fatal("Unable to read intermediates file: %s", err)
		}

		chain, err = core.ChainFromCertificateAndIntermediatesData(cert, intermediatesData)
		if err != nil {
			fatal("Unable to build certificate chain from given file: %s", err)
		}
	} else {
		chain, err = core.ChainFromCertificateAndInternet(cert)
		if err != nil {
			fatal("Unable to build certificate chain from internet: %s", err)
		}
	}

	chain.InfoLines(80).Write(os.Stdout)

	msg("")

	if err := chain.Verify(""); err != nil {
		msg("Error: built certificate chain, but verification failed:")
		fatal("%s", err)
	}

	iamSvc := iam.New(session.New(&aws.Config{Region: aws.String(awsRegion)}))

	if exists, err := iamCertificateExists(iamSvc, uploadedName); err != nil {
		fatal("%s", err)
	} else if exists {
		fatal("A certificate with the name '%s' already exists", uploadedName)
	}

	encodedPrivateKey, err := chain.Leaf.PrivateKeyToPEM()
	if err != nil {
		fatal("Unable to encode private key: %s", err)
	}
	_, err = iamSvc.UploadServerCertificate(&iam.UploadServerCertificateInput{
		CertificateBody:       aws.String(string(chain.Leaf.CertificateToPEM())),
		PrivateKey:            aws.String(string(encodedPrivateKey)),
		ServerCertificateName: aws.String(uploadedName),
		CertificateChain:      aws.String(string(chain.IntermediatesToPEM())),
	})
	if err != nil {
		fatal("Failed uploading certificate to AWS: %s", err)
	}

	msg("Certificate uploaded successfully.")
}
