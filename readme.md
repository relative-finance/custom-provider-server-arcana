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
docker compose up -d --build
```

- add the tables to the db instance
```
docker exec -it 3216a9ff21ed bin/bash
psql -U myuser -d mydatabase
\c mydatabase;
\l

<!-- create all the tables based on the commands in the comments in db.go -->
```
