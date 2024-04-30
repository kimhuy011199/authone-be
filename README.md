# AuthOne Backend

This project is a backend authentication service. It provides APIs for user registration, login, and account management.

- Visit [production version]()
- AuthOne [FE repository]()

## Tech Stack

This project is built with the following technologies:

- Node.js: A JavaScript runtime built on Chrome's V8 JavaScript engine.
- Express.js: A fast, unopinionated, and minimalist web framework for Node.js.
- TypeScript: A typed superset of JavaScript that compiles to plain JavaScript.
- MongoDB: A source-available cross-platform document-oriented database program.

## APIs

This project provides the following APIs:

| Method | Endpoint             | Description                                                 |
| ------ | -------------------- | ----------------------------------------------------------- |
| POST   | /register            | Register a new user.                                        |
| POST   | /login               | Login a user.                                               |
| GET    | /users/me            | Get the current user's information.                         |
| PUT    | /users/me            | Update the current user's information.                      |
| PUT    | /users/me/password   | Update the current user's password.                         |
| GET    | /mfa/qrcode          | Get the QR code for enabling MFA.                           |
| PUT    | /mfa                 | Toggle MFA for the current user.                            |
| POST   | /mfa                 | Verify MFA for the current user.                            |
| POST   | /account/otp         | Send the verification email for the current user's account. |
| POST   | /account/otp/verify  | Verify the email for the current user's account.            |
| POST   | /password/reset-link | Request a password reset link.                              |
| POST   | /password/reset      | Verify the reset password request and reset the password.   |

## Getting Started

To get started with this project, clone the repository and install the dependencies:

```
git clone https://github.com/kimhuy011199/authone-be.git
cd authone-be
npm install
```

Create `.env` file and set the required environment variables listed inside `.env.development` file. Then, start the server:

```
npm run dev
```

The server will start on http://localhost:5001.
