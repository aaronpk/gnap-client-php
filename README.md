# Sample GNAP client in PHP

This is a minimal GNAP client in PHP to demonstrate interacting with a GNAP Authorization Server.

This is tested agains the [Java XYZ Server](https://github.com/bspk/oauth.xyz-java)


## How to Run

Generate a private key:

```
openssl ecparam -genkey -name prime256v1 -noout -out ec256-key.pem
```

Install the dependencies:

```
composer install
```

Then run the client from the command line:

```
php gnap-cli.php
```

