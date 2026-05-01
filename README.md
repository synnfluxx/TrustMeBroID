TrustMeBroID - it's a best sso service designed for best pet projects

---

## API

### gRPC

Admin methods require the `x-admin-token` metadata header.

| Method        | Auth  | Description                             |
| ------------- | ----- | --------------------------------------- |
| `Register`    | —     | Register a new user in an App           |
| `Login`       | —     | Login by email or username, returns JWT |
| `IsAdmin`     | —     | Check if a user has admin role          |
| `RegisterApp` | admin | Create a new App                        |
| `DeleteApp`   | admin | Delete an App                           |
| `DeleteUser`  | admin | Delete a user by email / username / ID  |
| `DeleteAdmin` | admin | Revoke admin role                       |
| `MakeAdmin`   | admin | Add Admin user from existing one        |

### HTTP

| Endpoint                      | Method | Description                                  |
| ----------------------------- | ------ | -------------------------------------------- |
| `/auth/github/login?app_id=X` | GET    | Redirect to GitHub OAuth                     |
| `/auth/github/callback`       | GET    | OAuth callback, redirects to `uri?token=JWT` |
