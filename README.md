# Approov QuickStart - GoLang Token Check

[Approov](https://approov.io) is an API security solution used to verify that requests received by your backend services originate from trusted versions of your mobile apps.

This repo implements the Approov server-side request verification code in GoLang (framework agnostic), which performs the verification check before allowing valid traffic to be processed by the API endpoint.


## Approov Integration Quickstart

The quickstart was tested with the following Operating Systems:

* Ubuntu 20.04
* MacOS Big Sur
* Windows 10 WSL2 - Ubuntu 20.04

First, setup the [Approov CLI](https://approov.io/docs/latest/approov-installation/index.html#initializing-the-approov-cli).

Now, register the API domain for which Approov will issues tokens:

```bash
approov api -add api.example.com
```

Next, enable your Approov `admin` role with:

```bash
eval `approov role admin`
````

Now, get your Approov Secret with the [Approov CLI](https://approov.io/docs/latest/approov-installation/index.html#initializing-the-approov-cli):

```bash
approov secret -get base64
```

Next, add the [Approov secret](https://approov.io/docs/latest/approov-usage-documentation/#account-secret-key-export) to your project `.env` file:

```env
APPROOV_BASE64_SECRET=approov_base64_secret_here
```

Now, add to your dependencies the [golang-jwt/jwt](github.com/dgrijalva/jwt-gohttps://github.com/golang-jwt/jwt) package:

```bash
go get github.com/golang-jwt/jwt/v4
go mod tidy
```

Next, import the dependency:

```go
import (
    jwt "github.com/golang-jwt/jwt/v4"
)
```

Now, add the `verifyApproovToken` function:

```go
func verifyApproovToken(request *http.Request, base64Secret string)  (*jwt.Token, error) {
    approovToken := request.Header["Approov-Token"]

    if approovToken == nil {
        return nil, fmt.Errorf("token is missing in the request headers.")
    }

    token, err := jwt.Parse(approovToken[0], func(token *jwt.Token) (interface{}, error) {

        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("token signing method mismatch.")
        }

        secret, err := base64.StdEncoding.DecodeString(base64Secret)

        if err != nil {
            return nil, fmt.Errorf(err.Error())
        }

        return secret, nil
    })

    return token, err
}
```

Next, create an Approov token check handler:

```go
func makeApproovCheckerHandler(handler func(http.ResponseWriter, *http.Request), base64Secret string) http.Handler {
    return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {

        token, err := verifyApproovToken(request, base64Secret)

        if err != nil {
            // You may want to remove logging, replace or change how its logging
            //log.Println("Approov: " + err.Error())
            errorResponse(response, http.StatusUnauthorized, err.Error())
            return
        }

        if ! token.Valid {
            // You may want to remove logging, replace or change how its logging
            //log.Println("Approov: " + err.Error())
            errorResponse(response, http.StatusUnauthorized, "Approov: token is invalid.")
            return
        }

        handler(response, request)
    })
}
```

Now you just need to invoke it for each API endpoint you want to protect:

```go
http.Handle("/", makeApproovCheckerHandler(endpointHandler, base64Secret))
```

Not enough details in the bare bones quickstart? No worries, check the [detailed quickstarts](QUICKSTARTS.md) that contain a more comprehensive set of instructions, including how to test the Approov integration.


## More Information

* [Approov Overview](OVERVIEW.md)
* [Detailed Quickstarts](QUICKSTARTS.md)
* [Examples](EXAMPLES.md)
* [Testing](TESTING.md)

### System Clock

In order to correctly check for the expiration times of the Approov tokens is very important that the backend server is synchronizing automatically the system clock over the network with an authoritative time source. In Linux this is usually done with a NTP server.


## Issues

If you find any issue while following our instructions then just report it [here](https://github.com/approov/quickstart-golang-token-check/issues), with the steps to reproduce it, and we will sort it out and/or guide you to the correct path.


## Useful Links

If you wish to explore the Approov solution in more depth, then why not try one of the following links as a jumping off point:

* [Approov Free Trial](https://approov.io/signup)(no credit card needed)
* [Approov QuickStarts](https://approov.io/docs/latest/approov-integration-examples/)
* [Approov Get Started](https://approov.io/product/demo)
* [Approov Docs](https://approov.io/docs)
* [Approov Blog](https://approov.io/blog/)
* [Approov Resources](https://approov.io/resource/)
* [Approov Customer Stories](https://approov.io/customer)
* [Approov Support](https://approov.io/contact)
* [About Us](https://approov.io/company)
* [Contact Us](https://approov.io/contact)
