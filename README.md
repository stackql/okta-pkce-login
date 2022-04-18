## Okta PKCE Login CLI Example

This repository demonstrates a simple command line utility to login to an authorization server (Okta in this case).  

A step by step explanation is provided at [Simple CLI Application to Login to Okta using PKCE](https://fullstackchronicles.io/simple-cli-pkce-auth-using-okta).  

![PKCE Authorization to Okta using an AD IdP](/assets/images/okta-pkce-cli-login.png)

This can be used to illustrate the authorization/authentication flow discussed in [Simple SSO with an external IdP using Active Directory and Okta](https://fullstackchronicles.io/simple-sso-with-an-external-idp-using-active-directory-and-okta).  A flow which is pictured here:  

![PKCE Authorization to Okta using an AD IdP](/assets/images/seqdiagram.png)

with inspiration from...

- [Auth0 PKCE flow for a CLI built in golang](https://gist.github.com/ogazitt/f749dad9cca8d0ac6607f93a42adf322)
- [Golang sample for a CLI obtaining an access token using the PKCE flow](https://community.auth0.com/t/golang-sample-for-a-cli-obtaining-an-access-token-using-the-pkce-flow/40922)
- [oktadev/okta-node-cli-example](https://github.com/oktadev/okta-node-cli-example)
- [Build a Command Line Application with Node.js](https://developer.okta.com/blog/2019/06/18/command-line-app-with-nodejs)
- [About the Authorization Code grant with PKCE](https://developer.okta.com/docs/guides/implement-grant-type/authcodepkce/main/#about-the-authorization-code-grant-with-pkce)
