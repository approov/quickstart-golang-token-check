# Unprotected Server Example

The unprotected example is the base reference to build the [Approov protected servers](/src/approov-protected-server/). This a very basic Hello World server.


## TOC - Table of Contents

* [Why?](#why)
* [How it Works?](#how-it-works)
* [Requirements](#requirements)
* [Try It](#try-it)


## Why?

To be the starting building block for the [Approov protected servers](/src/approov-protected-server/), that will show you how to lock down your API server to your mobile app. Please read the brief summary in the [README](/README.md#why) at the root of this repo or visit our [website](https://approov.io/product.html) for more details.

[TOC](#toc---table-of-contents)


## How it works?

The GoLang server is very simple and is defined in the file [src/uprotected-server/hello-server-unprotected.go](/src/unprotected-server/hello-server-unprotected.go).

The server only replies to the endpoint `/` with the message:

```json
{"message": "Hello, World!"}
```

[TOC](#toc---table-of-contents)


## Requirements

To run this example you will need to have GoLang installed. If you don't have then please follow the official installation instructions from [here](https://golang.org/doc/install) to download and install it.

[TOC](#toc---table-of-contents)


## Try It

You can run this example from the `src/unprotected-server` folder with:

```text
go run hello-server-unprotected.go
```

Now you can test that it works with:

```text
curl -iX GET 'http://localhost:8002'
```

The response will be:

```text
HTTP/1.1 200 OK
Content-Type: application/json
Date: Tue, 08 Sep 2020 16:05:53 GMT
Content-Length: 28

{"message": "Hello, World!"}
```

[TOC](#toc---table-of-contents)
