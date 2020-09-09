# Approov QuickStart - GoLang Token Check

[Approov](https://approov.io) is an API security solution used to verify that requests received by your backend services originate from trusted versions of your mobile apps.

This repo implements the Approov server-side request verification code in GoLang (framework agnostic), which performs the verification check before allowing valid traffic to be processed by the API endpoint.


## TOC - Table of Contents

* [Why?](#why)
* [How it Works?](#how-it-works)
* [Quickstarts](#approov-integration-quickstarts)
* [Examples](#approov-integration-examples)
* [Useful Links](#useful-links)


## Why?

You can learn more about Approov, the motives for adopting it, and more detail on how it works by following this [link](https://approov.io/product). In brief, Approov:

* Ensures that accesses to your API come from official versions of your apps; it blocks accesses from republished, modified, or tampered versions
* Protects the sensitive data behind your API; it prevents direct API abuse from bots or scripts scraping data and other malicious activity
* Secures the communication channel between your app and your API with [Approov Dynamic Certificate Pinning](https://approov.io/docs/latest/approov-usage-documentation/#approov-dynamic-pinning). This has all the benefits of traditional pinning but without the drawbacks
* Removes the need for an API key in the mobile app
* Improves the network layer DDoS protection provided by Cloudflare with an application layer provided by Approov

[TOC](#toc---table-of-contents)


## How it works?

This is a brief overview of how the Approov cloud service and the GoLang server fit together from a backend perspective. For a complete overview of how the mobile app and backend fit together with the Approov cloud service and the Approov SDK we recommend to read the [Approov overview](https://approov.io/product) page on our website.

### Approov Cloud Service

The Approov cloud service attests that a device is running a legitimate and tamper-free version of your mobile app.

* If the integrity check passes then a valid token is returned to the mobile app
* If the integrity check fails then a legitimate looking token will be returned

In either case, the app, unaware of the token's validity, adds it to every request it makes to the Approov protected API(s).

### GoLang Backend Server

The GoLang backend server ensures that the token supplied in the `Approov-Token` header is present and valid. The validation is done by using a shared secret known only to the Approov cloud service and the GoLang backend server.

The request is handled such that:

* If the Approov Token is valid, the request is allowed to be processed by the API endpoint
* If the Approov Token is invalid, an HTTP 401 Unauthorized response is returned

You can choose to log JWT verification failures, but that typically has to go to another provider or you can use the Cloudflare `wrangler tail` command to see the logs from your computer, but that requires a subscription of another Cloudflare service.

[TOC](#toc---table-of-contents)


## Approov Integration Quickstarts

The quickstart code for the Approov GoLang server is split into two implementations. The first gets you up and running with basic token checking. The second uses a more advanced Approov feature, _token binding_. Token binding may be used to link the Approov token with other properties of the request, such as user authentication (more details can be found [here](https://approov.io/docs/latest/approov-usage-documentation/#token-binding)).
* [Approov token check quickstart](/docs/APPROOV_TOKEN_QUICKSTART.md)
* [Approov token check with token binding quickstart](/docs/APPROOV_TOKEN_BINDING_QUICKSTART.md)

Both the quickstarts are built from the unprotected example server defined [here](/src/unprotected-server/hello-server-unprotected.go), thus you can use Git to see the code differences between them.

Code difference between the Approov token check quickstart and the original unprotected server:

```
git diff --no-index src/unprotected-server/hello-server-unprotected.go src/approov-protected-server/token-check/hello-server-protected.go
```

You can do the same for the Approov token binding quickstart:

```
git diff --no-index src/unprotected-server/hello-server-unprotected.go src/approov-protected-server/token-binding-check/hello-server-protected.go
```

Or you can compare the code difference between the two quickstarts:

```
git diff --no-index src/approov-protected-server/token-check/hello-server-protected.go src/approov-protected-server/token-binding-check/hello-server-protected.go
```

[TOC](#toc---table-of-contents)


## Approov Integration Examples

The code examples for the Approov quickstarts are extracted from this simple [Approov integration examples](/src/approov-protected-server), that you can run from your computer to play around with the Approov integration and gain a better understating of how simple and easy it is to integrate Approov in a GoLang API server.

### Testing with Postman

A ready-to-use Postman collection can be found [here](https://raw.githubusercontent.com/approov/postman-collections/master/quickstarts/hello-world/hello-world.postman_collection.json). It contains a comprehensive set of example requests to send to the GoLang server for testing. The collection contains requests with valid and invalid Approov tokens, and with and without token binding.

### Testing with Curl

An alternative to the Postman collection is to use cURL to make the API requests. Check some examples [here](https://github.com/approov/postman-collections/blob/master/quickstarts/hello-world/hello-world.postman_curl_requests_examples.md).

### The Dummy Secret

The valid Approov tokens in the Postman collection and cURL requests examples were signed with a dummy secret that was generated with `openssl rand -base64 64 | tr -d '\n'; echo`, therefore not a production secret retrieved with `approov secret -get base64`, thus in order to use it you need to set the `APPROOV_BASE64_SECRET`, in the `.env` file for each [Approov integration example](/src/approov-protected-server), to the following value: `h+CX0tOzdAAR9l15bWAqvq7w9olk66daIH+Xk+IAHhVVHszjDzeGobzNnqyRze3lw/WVyWrc2gZfh3XXfBOmww==`.

[TOC](#toc---table-of-contents)


## Useful Links

If you wish to explore the Approov solution in more depth, then why not try one of the following links as a jumping off point:

* [Approov Free Trial](https://approov.io/signup)(no credit card needed)
* [Approov QuickStarts](https://approov.io/docs/latest/approov-integration-examples/)
* [Approov Live Demo](https://approov.io/product/demo)
* [Approov Docs](https://approov.io/docs)
* [Approov Blog](https://blog.approov.io)
* [Approov Resources](https://approov.io/resource/)
* [Approov Customer Stories](https://approov.io/customer)
* [Approov Support](https://approov.zendesk.com/hc/en-gb/requests/new)
* [About Us](https://approov.io/company)
* [Contact Us](https://approov.io/contact)


[TOC](#toc---table-of-contents)
