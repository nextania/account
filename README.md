<h1 align="center">Nextflow SSO authentication system</h1>
<div align="center">
  
[![License](https://img.shields.io/github/license/Nextflow-Cloud/sso-system)](https://github.com/Nextflow-Cloud/sso-system/blob/main/LICENSE)

</div>

## About
The Nextflow SSO authentication system allows you to log in to all Nextflow services with a single account. It aims to be modern and fast for users to log in and manage their account. The system is built with technologies such as Rust and MongoDB.

This server is built with security in mind and supports TOTP two-factor authentication. In the future, we also aim to support OPAQUE, an asymmetric password authenticated key exchange protocol, as well as WebAuthn, allowing the use of passkeys and physical security keys. 

This is the Rust-based backend. For the SolidJS-based frontend, please check out [sso-system-client](https://github.com/Nextflow-Cloud/sso-system-client).

## Hosting the server

### Set up database
This service uses MongoDB as a database, so you will need a MongoDB cluster or self-hosted MongoDB server. More information can be found on [their website](https://mongodb.com/).

### Run with Docker
Running with Docker is the recommended method for hosting this service. It allows you to easily configure and automatically start the service in a container. If you need an included database server, use Docker. Please check [their website](https://docs.docker.com/engine/install/) for more detailed documentation on how to install Docker and configuration. You will need to have the Docker Compose plugin installed along with Docker itself.

Copy `docker-compose.example.yml` into your own `docker-compose.yml` and modify it as needed. If you have an existing MongoDB instance, you may remove the `sso-system-mongodb` entry and point the `MONGODB_URI` and `MONGODB_DATABASE` variables to your own instance. Otherwise, keep the entry to use the included database server.

Populate the other environment variables as necessary. Currently, all variables are required for intended operation of the server.

To start the container, run `docker compose up -d` (with sudo as necessary).

### Run without Docker 
Although Docker is the preferred method of running the server, you can do so without Docker as well. You will need to run a MongoDB instance separately or obtain a cluster. 

Before running, you should populate the environment variables with the following:
* `MONGODB_URI`: URI pointing to the MongoDB instance or cluster.
* `MONGODB_DATABASE`: The database to use in MongoDB.
* `CDN_MONGODB_DATABASE`: The MongoDB database used by the CDN.
* `JWT_SECRET`: A 32-byte key to encode JWT tokens.
* `HCAPTCHA_SECRET`: A secret from hCaptcha to verify hCaptcha tokens.
* `CORS_ORIGINS`: A list of origins to allow CORS requests from, separated by commas.
* `HOST`: The host to bind the server to.
* `PUBLIC_ROOT`: The outward-facing domain name (including port, if non-standard).
* `SERVICE_NAME`: The outward-facing name of the service.
* `RP_ID`: The domain name that passkeys are authorized to.
* `SMTP_SERVER`: The SMTP server to send from.
* `SMTP_USERNAME`: The username to use with the SMTP server.
* `SMTP_PASSWORD`: The password to use with the SMTP server.
* `SMTP_FROM`: The email address to send from, such as `System <system@nextflow.cloud>`.

With the exception of the mail server, all variables are required. Setting the mail server variables will allow the reset password feature to function.

After doing so, run `cargo run --release` to build and run the server. It may take a while to build, especially on ARM64 systems.

## Contribute
Nextflow Cloud Technologies is committed to open-source software and free use. This means that you are free to view, modify, contribute, and support the project. Making a pull request with something useful is highly encouraged as this project is made possible by contributors like you who support the project.
