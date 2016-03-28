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
	"net"
	"os"

	"github.com/cesarkawakami/chaintool/core"
	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify [hostname[:port]]",
	Short: "verifies if a server's certificate is correctly configured",
	Long: `
verify receives a target hostname and port (optionally) and verifies if the
served certificates are valid and correctly configured.
`,
	Run: runVerify,
}

func init() {
	RootCmd.AddCommand(verifyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// verifyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// verifyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}

func runVerify(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		cmd.Usage()
		os.Exit(1)
	}

	host, port, err := net.SplitHostPort(args[0])
	if err != nil {
		host, port, err = net.SplitHostPort(args[0] + ":443")
		if err != nil {
			fatal("'%s' is not in the 'hostname:port' format", args[0])
		} else {
			msg("Port not given, assuming 443.")
		}
	}

	msg("")

	title("Certificate Information")

	chain, err := core.FetchCertificateChain(host, port)
	if err != nil {
		fatal("Unable to fetch certificates: %s", err)
	}

	chain.InfoLines(80).Write(os.Stdout)

	msg("")

	title("Certificate Verification")

	err = chain.Verify(host)
	if err != nil {
		msg("Result: FAILED.")
		msg("")
		msg("%s", err)
	} else {
		msg("Result: PASSED!")
	}
}
