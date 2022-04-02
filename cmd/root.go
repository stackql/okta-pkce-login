/*

Copyright © 2022 stackql javen@stackql.io

*/

package cmd

import (
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/gookit/color"
	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	envPrefix = "OKTA_PKCE"
)

var scopes = [...]string{"openid", "profile", "email"}

var clientid string
var issuer string
var redirecturi string

var codeChallenge string
var codeVerifier string
var state string
var authUrl string
var authorizationCode string

var rootCmd = &cobra.Command{
	Use:   "okta-pkce-login",
	Short: "Command line tool to test pkce login with Okta",
	Long:  `Command line tool to test pkce login with Okta`,
	Run: func(cmd *cobra.Command, args []string) {
		executeAuthFlow(clientid, issuer, redirecturi)
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {

	viper := viper.New()

	// define flag for clientid and bind to variable OKTA_PKCE_CLIENTID
	rootCmd.PersistentFlags().StringVarP((&clientid), "clientid", "c", "", "Okta client (Application) id [REQUIRED if not supplied through env var OKTA_PKCE_CLIENTID]")
	viper.BindPFlag("clientid", rootCmd.PersistentFlags().Lookup("clientid"))

	// define flag for issuer and bind to variable OKTA_PKCE_ISSUER
	rootCmd.PersistentFlags().StringVarP((&issuer), "issuer", "i", "", "OAuth issuer (e.g. https://{yourOktaDomain}.com/oauth2) [REQUIRED if not supplied through env var OKTA_PKCE_ISSUER]")
	viper.BindPFlag("issuer", rootCmd.PersistentFlags().Lookup("issuer"))

	// define flag for redirecturi and bind to variable OKTA_PKCE_REDIRECTURI
	rootCmd.PersistentFlags().StringVarP((&redirecturi), "redirecturi", "r", "http://localhost:8080/callback", "Redirect uri (must be configured in the Application in Okta), can also be supplied using env var OKTA_PKCE_REDIRECT_URI")
	viper.BindPFlag("redirecturi", rootCmd.PersistentFlags().Lookup("redirecturi"))

	rootCmd.MarkPersistentFlagRequired("clientid")
	rootCmd.MarkPersistentFlagRequired("issuer")

}

//
// Initiate Auth Flow
//

func generateCodeChallenge() (string, string) {
	// generate uuid for codeChallenge
	log.Println("Generating codeChallenge")
	codeVerifier = uuid.New().String() + uuid.New().String()
	hash := sha256.Sum256([]byte(codeVerifier))
	return b64.RawURLEncoding.EncodeToString(hash[:]), codeVerifier
}

func buildAuthorizeUrl(clientid string, issuer string, redirecturi string, codeChallenge string, scopes []string) (string, string) {
	log.Println("Building authorize url")

	// create url encoded string for scope param
	scopesString := url.QueryEscape(scopes[0])
	for i := 1; i < len(scopes); i++ {
		scopesString += "%20" + url.QueryEscape(scopes[i])
	}

	state = uuid.New().String()

	// generate url for login
	return fmt.Sprintf("%s/authorize?"+
		"response_type=code"+
		"&client_id=%s"+
		"&redirect_uri=%s"+
		"&code_challenge_method=S256"+
		"&code_challenge=%s"+
		"&scope=%s"+
		"&state=%s", issuer, clientid, url.QueryEscape(redirecturi), codeChallenge, scopesString, state), state
}

func openAuthUrl(authUrl string) {
	log.Printf("Opening auth url: %s", authUrl)

	// open a browser window to the authorizationURL
	err := open.Start(authUrl)
	if err != nil {
		log.Fatal(fmt.Printf("Unable to open browser to URL %s: %s", authUrl, err))
		os.Exit(1)
	}
}

//
// Get Access Token from Code
//

func getAccessToken(issuer string, clientID string, codeVerifier string, authorizationCode string, callbackURL string) (string, error) {

	// set the url and form-encoded data for the POST to the access token endpoint
	url := fmt.Sprintf("%s/token", issuer)

	log.Printf("Exchanging authz code for access token at: %s", url)

	data := fmt.Sprintf(
		"grant_type=authorization_code&client_id=%s"+
			"&code_verifier=%s"+
			"&code=%s"+
			"&redirect_uri=%s",
		clientID, codeVerifier, authorizationCode, callbackURL)
	payload := strings.NewReader(data)

	// create the request and execute it
	req, _ := http.NewRequest("POST", url, payload)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(fmt.Printf("HTTP error: %s", err))
		return "", err
	}

	// process the response
	defer res.Body.Close()
	var responseData map[string]interface{}
	body, _ := ioutil.ReadAll(res.Body)

	respCode := res.StatusCode

	log.Printf("HTTP response code: %d", respCode)

	// unmarshal the response
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		log.Fatal(fmt.Printf("Error unmarshaling responsebody: %s", err))
		return "", err
	}

	if respCode != 200 {
		jsonString, _ := json.Marshal(responseData)
		return string(jsonString), nil
	} else {
		accessToken := responseData["access_token"].(string)
		return accessToken, nil
	}

}

//
// Get user info using token
//

func getUserInfo(issuer string, accessToken string) (string, error) {

	// set the url and form-encoded data for the POST to the access token endpoint
	url := fmt.Sprintf("%s/userinfo", issuer)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", "Bearer "+accessToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(fmt.Printf("HTTP error: %s", err))
		return "", err
	}

	// process the response
	defer res.Body.Close()
	var responseData map[string]interface{}
	body, _ := ioutil.ReadAll(res.Body)

	respCode := res.StatusCode

	log.Printf("HTTP response code: %d", respCode)

	if respCode != 200 {
		jsonString, _ := json.Marshal(responseData)
		return string(jsonString), nil
	} else {
		// unmarshal the response
		err = json.Unmarshal(body, &responseData)
		if err != nil {
			log.Fatal(fmt.Printf("Error unmarshaling responsebody: %s", err))
			return "", err
		}
		jsonString, _ := json.MarshalIndent(responseData, "", "  ")
		return string(jsonString), nil
	}

}

// close the HTTP server
func cleanup(server *http.Server) {
	go server.Close()
}

//
// main
//

func executeAuthFlow(clientid string, issuer string, redirecturi string) {

	// output formatting
	//blueOnWhite := chalk.Blue.NewStyle().WithBackground(chalk.White)

	// generate code challenge
	codeChallenge, codeVerifier = generateCodeChallenge()

	// build authorize url and get state
	authUrl, state = buildAuthorizeUrl(clientid, issuer, redirecturi, codeChallenge, scopes[:])

	// parse the redirect URL for the port number
	u, err := url.Parse(redirecturi)
	if err != nil {
		log.Fatal(fmt.Printf("Error parsing redirecturi: %s", err))
		os.Exit(1)
	}
	addr := fmt.Sprintf(":%s", u.Port())

	// start the server, get auth code, exchange for token and stop the server
	server := &http.Server{Addr: addr}

	// define a handler that will get the authorization code, call the token endpoint, and close the HTTP server
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// get the authorization code
		code := r.URL.Query().Get("code")
		if code == "" {
			log.Fatal("No authorization code received")
			io.WriteString(w, "Error: could not find 'code' URL parameter\n")

			// close the HTTP server and return
			cleanup(server)
			return
		}

		// trade the authorization code and the code verifier for an access token
		token, err := getAccessToken(issuer, clientid, codeVerifier, code, redirecturi)
		if err != nil {
			log.Fatal(fmt.Printf("Could not get access token: %s", err))
			io.WriteString(w, "Error: could not retrieve access token\n")

			// close the HTTP server and return
			cleanup(server)
			return
		}

		// print access token

		color.Cyan.Println("Access Token:")
		color.Yellow.Println(token)

		// get user info
		userInfo, err := getUserInfo(issuer, token)
		color.Cyan.Println("User info:")
		color.Yellow.Println(userInfo)

		// return an indication of success to the caller
		io.WriteString(w, `
		<html>
			<body>
				<h1>Login successful!</h1>
				<h2>You can close this window.</h2>
			</body>
		</html>`)

		fmt.Println("Successfully authenticated.")

		// close the HTTP server
		cleanup(server)
	})

	// set up a listener on the redirect port
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(fmt.Printf("Unable to listen to port %s: %s\n", addr, err))
		os.Exit(1)
	}

	// open a browser window to the authorizationURL
	openAuthUrl(authUrl)

	// start the blocking web server loop
	// this will exit when the handler gets fired and calls server.Close()
	server.Serve(l)

}
