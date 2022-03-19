# Sample GNAP client in PHP

This is a minimal GNAP client in PHP to demonstrate interacting with a GNAP Authorization Server.

This is tested against the [Java GNAP Server](https://github.com/bspk/oauth.xyz-java) hosted at https://gnap-as.herokuapp.com/


## Setup

Install PHP dependencies:

```bash
sudo apt install php8.1 php8.1-mbstring php8.1-curl redis-server
```

Install the required libraries:

```bash
composer require phpseclib/phpseclib:~3.0
composer require web-token/jwt-key-mgmt web-token/jwt-signature
composer require predis/predis
```

or just

```bash
composer install
```


## How to Run

Generate a private key:

```bash
php gnap-cli.php keygen
```

This will generate an RSA private key and save it in a file `private.pem`, and the corresponding public key in `public.pem` and the JWK public key in `public-key.json`.


Start a new request:

```bash
php gnap-cli.php start
```

If everything works, you should see a URL printed in the console. Open that URL in your browser to authorize the client.

Poll the transaction endpoint until the client gets a token:

```bash
php gnap-cli.php poll
```

After you authorize the client, you should get an access token in the response!

