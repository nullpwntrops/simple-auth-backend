# Simple NestJS Starter Kit

This is a comprehensive starter kit built using the [NestJS](https://nestjs.com)
framework and [TypeScript](https://www.typescriptlang.org).  It features JWT
authentication including 2FA support, enhanced security, database integration,
and follows industry best practices.

## Project Overview

This comprehensive starter kit can serve as a foundation for building server-side
applications. It includes a wide range of production-ready features to aid in
backend development.

**Key features include:**

* Built using the [NestJS](https://nestjs.com) framework with [Express](https://expressjs.com/) under the hood
* Written in [TypeScript](https://www.typescriptlang.org)
* [PostgreSQL](https://www.postgresql.org) integration via [TypeORM](https://typeorm.io/)
* [Dockerized](https://www.docker.com) development environment
* [JWT-based](https://jwt.io/introduction) authentication system
* Two-Factor Authentication (2FA) support via email
* Account lockout after multiple failed attempts
* Token rotation with hashed storage
* Environment variable management and run-time validation
* Modular architecture
* Pino Logger is used for logging
* Support for serving static content or Single Page Application (SPA)

## Features

### Dockerized Local Development

This project includes a Docker-based development environment, which includes a 
local PostgreSQL database and [MailHog](https://github.com/mailhog/MailHog) for
email testing.

The application can be run completely containerized within Docker or locally 
with Docker managing only the PostgreSQL and MailHog services.

### Database Integration

The project uses [PostgreSQL](https://www.postgresql.org) for its database
and [TypeORM](https://typeorm.io) for object-relational mapping. TypeORM is
used to construct database queries, which can help mitigate SQL injection
risks compared to writing raw SQL.  This helps improve overall application
security.

### Configuration via ENV Variables

Application configuration is managed through `.env.<environment>` files and
the `docker-compose.yml` file.  This follows 
[The 12 Factor App](https://12factor.net/config) principles, which recommends
keeping configuration data separate from the application code.  This approach
allows the use of different configuration files for development, testing, 
and production environments.

The [`Joi`](https://joi.dev/api/?v=17.13.3) schema validator is used to 
validate environment variables at runtime, ensuring data integrity and 
preventing invalid configurations.

### Logging with Pino

This project utilizes [Pino Logger](https://getpino.io/) via the
[`nestjs-pino`](https://github.com/iamolegga/nestjs-pino) module for
application logging.  Logging verbosity can be controlled via the
`.env` file.  Each request/response is tagged with a unique request ID
to aid in debugging. 

### Validation and Transformation via DTOs

A global `ValidationPipe` is applied to all incoming requests to enforce data
integrity and prevent invalid input.  Validation is performed by the 
[`class-validator`](https://github.com/typestack/class-validator#readme)
library.

For outgoing responses, serialization and transformation are handled by the
`ResponseInterceptor`.  This function checks to make sure that only explicitily
exposed properties are included in the final response.  Transformation is performed
using the [`class-transformer`](https://github.com/typestack/class-transformer/tree/develop)
library. To guarantee consistent behavior, all outgoing response DTOs should
extend the `BaseResponseDto` and use the `@Expose()` decorator to mark
properties that should appear in the final response.

To prevent conflicts between incoming validation and outgoing transformation,
use separate DTO classes.

### JWT Authentication

JWT-based authentication is used to secure all API endpoints except for those
marked with `@Public` or `@SemiPublic` decorators.   All authorization and
authentication logic, including role-based access control, is centralized in
a single function.  This makes it easy to manage and modify as needed.

* **Public routes:** No authentication or authorization is required.
  * Examples: root path

* **Semi-public routes:** Require a valid application API key for access.
  * Examples: sign up or login paths

* **Protected routes:**  The following authentication steps are performed:
  * Verify that the application API key is valid
  * Check the request header for a bearer token
  * Validate the token's signature using the JWT secret
  * If a route requires a specific role, verify that the user has the appropriate role and access permissions
  * Confirm that the user exists in the database and is still logged in
  * Compare the JWT token against the user's saved (hashed) copy
  * Ensure the user's API key matches

This project uses the `@nestjs/jwt` library for JWT operations, like signing
and verification, instead of using a broader authentication middleware like
[Passport](https://www.passportjs.org).

### Two-Factor Authentication Support

This project includes support for two-factor authentication (2FA) via 
email.  When a user with 2FA enabled, successfully logs in, a 4-digit
verification code is sent to their registered email address.  Full access 
to all protected APIs is granted only after the user enters the correct 
code and completes the verification process.  This additional layer of
security helps prevent unauthorized access, even if the user's login
credentials are compromised.

The length of the verification code and its expiration period are both
configurable through the `.env` file.

While the current implementation uses email, the system can be easily adapted
to send 2FA codes via other methods, such as SMS.

### Refresh and Access Tokens

This project uses a rotating access and refresh token scheme to maintain
strong security.  After a successful login, the server issues both a
short-lived access token and a longer-lived refresh token.  Tokens are
stored securely in the database using a one-way hash.  For added security,
different secrets are used to sign the access and refresh tokens.

Each subsequent API call returns a new pair of tokens, ensuring tokens remain
fresh.  New APIs added to this project should follow the same pattern of 
issuing a new pair of access and refresh tokens.  Frequent token rotation
helps reduce the risk of man-in-the-middle attacks.

Upon logout, the tokens are invalidated in the database to prevent reuse.

### Security

Passwords and JWT tokens are stored securely in the database using the
[`bcrypt`](https://www.npmjs.com/package/bcrypt) library to generate 
a one-way hash. This approach prevents hackers from recovering the
original password or reusing a token in the event of a data breach.

To protect against brute-force attacks, this application implements
an account lockout mechanism. If a user exceeds a defined number of
consecutive failed login attempts, their account will be temporarily
suspended.  Both the maximum number of attempts and the duration of
this lockout period are configurable via the `.env` file.

When deploying the application to production, it is important to store
sensitive data, like the application API key and JWT secrets, according
to the security best practices recommended by the hosting provider.

### Email Support and Testing

Email functionality is implemented using [`nodemailer`](https://nodemailer.com/about/),
a popular Node.js library for sending emails.

For local development and testing, [MailHog](https://github.com/mailhog/MailHog)
is included as a Docker container.  MailHog acts as a fake SMTP server
to capture outgoing emails without actually delivering them.  It listens
on port `1025` for SMTP traffic and stores captured emails in-memory within
the Docker container.

To view captured emails using MailHog's friendly web interface, simply start
the application and open your browser at: http://localhost:8025

See the `docker-compose.yml` file for setup and configuration details.

### Verification Email

Upon successful registration, a verification email containing a secure link is
sent to the provided email address.  By default, the link is valid for 24 hours,
but this duration is configurable via the `.env` file.  If the user does not
verify their email within that timeframe, they can request a new one.

Currently, the system does not enforce any restrictions for unverified email 
addresses.  It is left up to the client applications integrating with this system
to determine how they wish to handle unverified accounts.

### Static Landing Page

This application includes support for serving static content.  It can be a
simple informational page to describe the application or serve as the entry
point for a Single Page Application (SPA).

## Project Setup

### Getting Started

Clone the repository.

```
git clone https://github.com/hhung01/simple-auth-backend.git
cd simple-auth-backend
```

### Prerequisites

The project assumes the following are installed on your local computer.

* [Docker for desktop](https://www.docker.com/products/docker-desktop/) is installed and that the daemon is running.
* [Node.js](https://nodejs.org/en/download) (>=20.x)
* [npm](https://docs.npmjs.com/cli/v11/configuring-npm/install)

### Setup the Environment Files

1. Copy the `example.env` file to `.env.docker` and/or `.env.development`.

```console
cp example.env .env.docker
cp example.env .env.development
```

Acceptable extensions are:
* `.env.docker`
* `.env.development`
* `.env.test`
* `.env.sandbox`
* `.env.staging`
* `.env.production`

2. Copy the `docker-compose.example.yml` file to `docker-compose.yml`

```console
cp docker-compose.example.yml docker-compose.yml
```

3. Update the files with your details.  

#### Docker Environment

When running the application entirely within Docker, the `.env.docker`
environment file is used to configure the environment variables.
The following environment keys should be set as follows:

* `DB_HOST` and `MAIL_HOST`:
   Should be set to `host.docker.internal` to allow Docker containers to
   communicate with services running on the host machine.
* `SERVICE_URL`:
   Should be set to `localhost:2000`

**Notes:** 
* `host.docker.internal` is the special DNS name used by Docker to allow
containers to access services, like PostgreSQL and MailHog, from within
containers on the host machine.
* Port `2000` is defined in the `docker-compose.yml` file and is used
to expose the application when running in a full Docker environment.

#### Other Environments (Partial Docker)

When running the application on your local machine and using Docker **only** for
services like the database and MailHog, use the appropriate `.env` file
(e.g. `.env.development`).  The following environment variables should be set as
follows:

* `DB_HOST` and `MAIL_HOST`: Should be set to `localhost`
* `SERVICE_URL`: Should be set to `localhost:3000`

**Notes:** 
* Use `localhost` when developing entirely on a local machine.
* If the database and/or SMTP server are hosted externally (e.g. in a corporate setting, 
testing, or sandbox environments), configure those keys accordingly.
* Port `3000` is set by the `PORT` key.  If this is changed, the port
used by `SERVICE_URL` as well as the port in the `docker-compose.yml` file
should be changed as well.

### Install Dependencies

```console
npm install
```

## Compile and Run the Project

### Running the Application Within Docker

* Assumes that the Docker daemon is running.

To run the application completely within Docker, execute the following command.

```console
npm run start:docker
```

* Point your browser to: http://localhost:2000
* MailHog UI can be found at: http://localhost:8025

### Running the Application Locally

* Assumes that the PostgreSQL and MailHog images are downloaded and installed in Docker.
* Assumes that the images are up and running in Docker.

To run the application locally with Docker hosting the database and MailHog, 
run one of the following commands.

To download the images and install them in Docker:

```
npm run docker:create
```

Use the Docker Desktop to run the images.

To run the application:

```console
# development mode
npm run start

# watch mode
npm run start:dev

# debug mode
npm run start:debug
```

* Point your browser to: http://localhost:3000
* MailHog UI can be found at: http://localhost:8025

## Project Structure

This project follows a modular structure based on NestJS objects.

```
src/
├── common/               # Global utilities and helpers
│   ├── classes/          # Custom classes
│   ├── config/           # Configuration settings
│   ├── constants/        # Application constants and enums
│   ├── exceptions/       # Application exceptions
│   ├── interfaces/       # Application interfaces
│   └── utilities/        # Utility functions
├── database/             # Database setup and migration
│   ├── dto/              # Global DTOs
│   ├── entities/         # Database entities
│   └── migrations/       # Migration files
├── modules/              # Application modules/features
│   ├── app/              # Top-level application module
│   ├── auth/             # Authentication module
│   │   └── dto/          # Auth-specific DTOs
│   ├── global/           # Global modules
│   ├── hash/             # Hash module
│   ├── health/           # Health module
│   ├── mailer/           # Mailer module
│   └── user/             # User management module
├── providers/            # Custom providers
│   ├── decorators/       # Custom decorators
│   ├── filters/          # Custom filters
│   ├── guards/           # Custom guards
│   ├── interceptors/     # Custom interceptors
│   ├── pipes/            # Custom pipes
│   └── validators/       # Custom validators
├── public/               # Static HTML page(s)
└── main.ts               # Application entry point
```

New features should be added under its own subdirectories in the `modules/` folder.

## Future Development

* Integration tests
* Swagger documentation

## License

This project is covered by the [MIT license](https://mit-license.org).
