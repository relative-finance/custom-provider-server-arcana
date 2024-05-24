# Custom provider server example

This example serves as just an example.

## To run the server

- Generate a ECC private key

```sh
openssl ecparam -name prime256v1 -genkey -noout -out private.oauth.ec.key
openssl pkcs8 -topk8 -nocrypt -in private.oauth.ec.key -out priv.key
```

- Update your `config.toml` with required details and then run

```sh
go run .
```
