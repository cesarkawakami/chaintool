package heroku

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

type Client struct {
	Login, Password string
	Http            *http.Client
}

func NewClient(login, password string) *Client {
	return &Client{
		Login:    login,
		Password: password,
		Http:     &http.Client{},
	}
}

func (c *Client) ConfigureRequest(r *http.Request) {
	r.SetBasicAuth(c.Login, c.Password)
	r.Header.Set("Accept", "application/vnd.heroku+json; version=3")
}

func (c *Client) fetch(r *http.Request) (*http.Response, []byte, error) {
	resp, err := c.Http.Do(r)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf(
			"%s %s: Response with status %d is outside the expected range. Body: %s",
			resp.Request.Method, resp.Request.URL.String(),
			resp.StatusCode, body)
	}

	return resp, body, nil
}

func (c *Client) fetchJSON(r *http.Request, data interface{}) (*http.Response, error) {
	httpResp, respBody, err := c.fetch(r)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(respBody, data); err != nil {
		fmt.Printf("data: %s\n", respBody)
		return nil, err
	}

	return httpResp, nil
}

type App struct {
	ArchivedAt                   interface{} `json:"archived_at"`
	BuildpackProvidedDescription string      `json:"buildpack_provided_description"`
	CreatedAt                    time.Time   `json:"created_at"`
	ID                           string      `json:"id"`
	GitURL                       string      `json:"git_url"`
	Maintenance                  bool        `json:"maintenance"`
	Name                         string      `json:"name"`
	Space                        interface{} `json:"space"`
	ReleasedAt                   time.Time   `json:"released_at"`
	RepoSize                     int         `json:"repo_size"`
	SlugSize                     int         `json:"slug_size"`
	UpdatedAt                    time.Time   `json:"updated_at"`
	WebURL                       string      `json:"web_url"`

	BuildStack struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"build_stack"`
	Owner struct {
		Email string `json:"email"`
		ID    string `json:"id"`
	} `json:"owner"`
	Region struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"region"`
	Stack struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"stack"`
}

func (c *Client) fetchRangedJSON(
	url string,
	newData func() interface{},
	cb func(interface{}),
) error {
	currentRange := "id ..; max=100;"
	for {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return err
		}
		c.ConfigureRequest(req)
		if currentRange != "" {
			req.Header.Set("Range", currentRange)
		}

		data := newData()
		resp, err := c.fetchJSON(req, data)
		if err != nil {
			return err
		}
		cb(data)

		nextRange := resp.Header.Get("Next-Range")
		if nextRange != "" {
			currentRange = nextRange
		} else {
			break
		}
	}
	return nil
}

func (c *Client) AllApps() ([]*App, error) {
	rv := []*App{}
	if err := c.fetchRangedJSON(
		"https://api.heroku.com/apps",
		func() interface{} {
			return &[]*App{}
		},
		func(data interface{}) {
			chunk := data.(*[]*App)
			rv = append(rv, *chunk...)
		},
	); err != nil {
		return nil, err
	}
	return rv, nil
}

type SSLEndpoint struct {
	CertificateChain string    `json:"certificate_chain"`
	CName            string    `json:"cname"`
	CreatedAt        time.Time `json:"created_at"`
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (c *Client) AllSSLEndpoints(appID string) ([]*SSLEndpoint, error) {
	rv := []*SSLEndpoint{}
	if err := c.fetchRangedJSON(
		fmt.Sprintf("https://api.heroku.com/apps/%s/ssl-endpoints", appID),
		func() interface{} {
			return &[]*SSLEndpoint{}
		},
		func(data interface{}) {
			chunk := data.(*[]*SSLEndpoint)
			rv = append(rv, *chunk...)
		},
	); err != nil {
		return nil, err
	}
	return rv, nil
}

type Organization struct {
	CreatedAt             time.Time `json:"created_at"`
	CreditCardCollections bool      `json:"credit_card_collections"`
	Default               bool      `json:"default"`
	Name                  string    `json:"name"`
	ProvisionedLicenses   bool      `json:"provisioned_licenses"`
	Role                  string    `json:"role"`
	UpdatedAt             time.Time `json:"updated_at"`
}

func (c *Client) AllOrganizations() ([]*Organization, error) {
	rv := []*Organization{}
	if err := c.fetchRangedJSON(
		"https://api.heroku.com/organizations",
		func() interface{} {
			return &[]*Organization{}
		},
		func(data interface{}) {
			chunk := data.(*[]*Organization)
			rv = append(rv, *chunk...)
		},
	); err != nil {
		return nil, err
	}
	return rv, nil
}

func (c *Client) OrganizationByName(name string) (*Organization, error) {
	req, err := http.NewRequest(
		"GET", fmt.Sprintf("https://api.heroku.com/organizations/%s", name), nil)
	if err != nil {
		return nil, err
	}
	c.ConfigureRequest(req)

	rv := &Organization{}
	_, err = c.fetchJSON(req, rv)
	if err != nil {
		return nil, err
	}
	return rv, nil
}

type OrganizationAppCollaborator struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
	Role      string    `json:"role"`
	UpdatedAt time.Time `json:"updated_at"`

	App struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	} `json:"app"`
	Privileges struct {
		Description string `json:"description"`
		Name        string `json:"name"`
	} `json:"privileges"`
	User struct {
		Email string `json:"email"`
		ID    string `json:"id"`
	} `json:"user"`
}

func (c *Client) AllOrganizationAppCollaborators(appID string) (
	[]*OrganizationAppCollaborator, error,
) {
	rv := []*OrganizationAppCollaborator{}
	if err := c.fetchRangedJSON(
		fmt.Sprintf("https://api.heroku.com/organizations/apps/%s/collaborators", appID),
		func() interface{} {
			return &[]*OrganizationAppCollaborator{}
		},
		func(data interface{}) {
			chunk := data.(*[]*OrganizationAppCollaborator)
			rv = append(rv, *chunk...)
		},
	); err != nil {
		return nil, err
	}
	return rv, nil
}

type Account struct {
	AllowTracking           bool       `json:"allow_tracking"`
	Beta                    bool       `json:"beta"`
	CreatedAt               time.Time  `json:"created_at"`
	Email                   string     `json:"email"`
	ID                      string     `json:"id"`
	LastLogin               time.Time  `json:"last_login"`
	Name                    string     `json:"name"`
	SmsNumber               string     `json:"sms_number"`
	SuspendedAt             *time.Time `json:"suspended_at"`
	DelinquentAt            *time.Time `json:"delinquent_at"`
	TwoFactorAuthentication bool       `json:"two_factor_authentication"`
	UpdatedAt               time.Time  `json:"updated_at"`
	Verified                bool       `json:"verified"`

	DefaultOrganization struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"default_organization"`
}

func (c *Client) Account() (*Account, error) {
	req, err := http.NewRequest("GET", "https://api.heroku.com/account", nil)
	if err != nil {
		return nil, err
	}
	c.ConfigureRequest(req)

	rv := &Account{}
	_, err = c.fetchJSON(req, rv)
	if err != nil {
		return nil, err
	}
	return rv, nil
}
