package cmd

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/cesarkawakami/chaintool/core"
	"github.com/cesarkawakami/chaintool/heroku"
	"github.com/cesarkawakami/pflaghelpers"
	"github.com/dickeyxxx/netrc"
	"github.com/spf13/cobra"
)

var herokuListCmd = &cobra.Command{
	Use:   "heroku:list",
	Short: "Lists and checks all SSL certificates on Heroku",
	Long: `
heroku:list lists and checks all certificates on Heroku.
`,
	Run: runHerokuList,
}

func init() {
	RootCmd.AddCommand(herokuListCmd)

	herokuListCmd.PersistentFlags().Bool(
		"auto-join", false, "Joins unjoined organization apps automatically")
}

func runHerokuList(cmd *cobra.Command, args []string) {
	autoJoin := pflaghelpers.MustGetBool(cmd.Flags(), "auto-join")

	login, password, err := getHerokuLogin()
	if err != nil {
		msg("Unable to load Heroku credentials: %s", err)
		fatal("Perhaps running `heroku login` would help?")
	}

	herokuClient := heroku.NewClient(login, password)

	userAccount, err := herokuClient.Account()
	if err != nil {
		fatal("Unable to fetch user account data: %s", err)
	}
	userEmail := userAccount.Email

	if apps, err := herokuClient.AllApps(); err != nil {
		fatal("Failed loading apps: %s", err)
	} else {
		for _, app := range apps {
			msg("%s, owner: (%s, %s)", app.Name, app.Owner.Email, app.Owner.ID)

			if isOrganizationEmail(app.Owner.Email) {
				collabs, err := herokuClient.AllOrganizationAppCollaborators(app.ID)
				if err != nil {
					fatal("Unable to fetch organization app collaborators: %s", err)
				}

				joined := false
				for _, collab := range collabs {
					if collab.User.Email == userEmail {
						joined = true
						break
					}
				}

				if !joined {
					if !autoJoin {
						msg("  - unjoined and no auto-join, skipping...")
						continue
					} else {
						msg("  - unjoined with auto-join, but that's not implemented, skipping...")
						continue
					}
				}
			}

			if sslEndpoints, err := herokuClient.AllSSLEndpoints(app.ID); err != nil {
				fatal("Failed loading SSL Endpoints: %s", err)
			} else {
				for _, sslEndpoint := range sslEndpoints {
					msg("  - %s", sslEndpoint.CName)

					chain, err := core.ChainFromFullChainData([]byte(sslEndpoint.CertificateChain))
					if err != nil {
						fatal("Failed to parse cert data: %s", err)
					}
					chain.InfoLines(80).Write(os.Stdout)
				}
			}
		}
	}
}

func getHerokuLogin() (string, string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", "", fmt.Errorf("Unable to get current user: %s", err)
	}

	netrcData, err := netrc.Parse(filepath.Join(currentUser.HomeDir, ".netrc"))
	if err != nil {
		return "", "", fmt.Errorf("Unable to load or parse ~/.netrc file: %s", err)
	}

	machine := netrcData.Machine("api.heroku.com")
	if machine == nil {
		return "", "", fmt.Errorf("Credentials for `api.heroku.com` weren't found.")
	}

	login := machine.Get("login")
	password := machine.Get("password")

	if login == "" || password == "" {
		return "", "", fmt.Errorf("Credentials for `api.heroku.com` weren't found.")
	}

	return login, password, nil
}

var organizationCache map[string]*heroku.Organization

func organization(client *heroku.Client, name string) (*heroku.Organization, error) {
	if _, ok := organizationCache[name]; !ok {
		if org, err := client.OrganizationByName(name); err != nil {
			return nil, err
		} else {
			organizationCache[name] = org
		}
	}
	return organizationCache[name], nil
}

func organizationFromEmail(client *heroku.Client, email string) (*heroku.Organization, error) {
	return organization(client, strings.TrimSuffix(email, "@herokumanager.com"))
}

func isOrganizationEmail(email string) bool {
	return strings.HasSuffix(email, "@herokumanager.com")
}
