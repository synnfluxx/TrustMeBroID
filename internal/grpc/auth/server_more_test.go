package authgrpc

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/synnfluxx/TrustMeBroID/internal/services/auth"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
	ssov1 "gitlab.com/synnfluxx/protos/sso/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newAPI() (*serverAPI, *MockAuth) {
	m := new(MockAuth)
	return &serverAPI{auth: m}, m
}

// --------------------------------------------------------------- validate ---

func TestValidate_PasswordPolicy(t *testing.T) {
	cases := []struct {
		name     string
		password string
		valid    bool
	}{
		{"meets the policy", "Password1", true},
		{"too short", "Pass1", false},
		{"no uppercase", "password1", false},
		{"no digit", "Passwordd", false},
		{"empty", "", false},
		{"over 32 characters", "Password1Password1Password1Password1", false},
		{"exactly 8", "Passwor1", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validate("", tc.password)
			if tc.valid {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, PassErr)
		})
	}
}

func TestValidate_EmailFormat(t *testing.T) {
	require.NoError(t, validate("user@example.com", "Password1"))
	require.Error(t, validate("not-an-address", "Password1"))
	// An empty address skips the check: the username login path passes "".
	require.NoError(t, validate("", "Password1"))
}

// ------------------------------------------------------- redirect_uri -------

func TestValidateRedirectURI(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		env  string
		ok   bool
	}{
		{"https in prod", "https://app.test/callback", "prod", true},
		{"http in prod is refused", "http://app.test/callback", "prod", false},
		{"http outside prod", "http://localhost:3000/callback", "local", true},
		{"https outside prod", "https://app.test/callback", "local", true},
		{"no host", "https:///callback", "prod", false},
		{"embedded credentials", "https://user:pw@app.test/callback", "prod", false},
		{"fragment", "https://app.test/callback#frag", "prod", false},
		{"not a url", "://nonsense", "prod", false},
		{"empty", "", "prod", false},
		{"custom scheme in prod", "auralift://callback", "prod", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.ok, validateRedirectURI(tc.uri, tc.env))
		})
	}
}

// Any https host is accepted, so app registration does not restrict where a
// user can be redirected. Registration is admin-gated, which is what limits it.
func TestValidateRedirectURI_AcceptsAnyHTTPSHost(t *testing.T) {
	require.True(t, validateRedirectURI("https://attacker.test/collect", "prod"))
}

// ---------------------------------------------------------------- Register --

func TestRegister(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		api, m := newAPI()
		m.On("RegisterNewUser", mock.Anything, "user@example.com", "octocat", "Password1", int64(1)).
			Return(int64(42), nil)

		resp, err := api.Register(context.Background(), &ssov1.RegisterRequest{
			Email: "user@example.com", Username: "octocat", Password: "Password1", AppId: 1,
		})

		require.NoError(t, err)
		require.Equal(t, int64(42), resp.GetUserId())
	})

	t.Run("duplicate account", func(t *testing.T) {
		api, m := newAPI()
		m.On("RegisterNewUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(int64(0), auth.ErrUserExists)

		_, err := api.Register(context.Background(), &ssov1.RegisterRequest{
			Email: "user@example.com", Username: "octocat", Password: "Password1", AppId: 1,
		})

		require.Equal(t, codes.AlreadyExists, status.Code(err))
	})

	t.Run("rejects a weak password before calling the service", func(t *testing.T) {
		api, m := newAPI()

		_, err := api.Register(context.Background(), &ssov1.RegisterRequest{
			Email: "user@example.com", Username: "octocat", Password: "weak", AppId: 1,
		})

		require.Equal(t, codes.InvalidArgument, status.Code(err))
		m.AssertNotCalled(t, "RegisterNewUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("username is required", func(t *testing.T) {
		api, _ := newAPI()

		_, err := api.Register(context.Background(), &ssov1.RegisterRequest{
			Email: "user@example.com", Password: "Password1", AppId: 1,
		})

		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})
}

// --------------------------------------------------------------- IsAdmin ----

func TestIsAdmin(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		api, m := newAPI()
		m.On("IsAdmin", mock.Anything, int64(42), int64(1)).Return(true, nil)

		resp, err := api.IsAdmin(context.Background(), &ssov1.IsAdminRequest{UserId: 42, AppId: 1})

		require.NoError(t, err)
		require.True(t, resp.GetIsAdmin())
	})

	t.Run("user id is required", func(t *testing.T) {
		api, _ := newAPI()

		_, err := api.IsAdmin(context.Background(), &ssov1.IsAdminRequest{AppId: 1})

		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("unknown user", func(t *testing.T) {
		api, m := newAPI()
		m.On("IsAdmin", mock.Anything, int64(42), int64(1)).Return(false, storage.ErrUserNotFound)

		_, err := api.IsAdmin(context.Background(), &ssov1.IsAdminRequest{UserId: 42, AppId: 1})

		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})
}

// ------------------------------------------------------------- MakeAdmin ----

// Every other handler returns a fixed message; this one passes err.Error()
// straight to the caller, so internal detail escapes the service boundary.
func TestMakeAdmin_LeaksTheInternalErrorText(t *testing.T) {
	api, m := newAPI()
	m.On("MakeAdmin", mock.Anything, int64(42), int64(1)).
		Return(int64(0), errors.New(`pq: relation "admins" does not exist`))

	_, err := api.MakeAdmin(context.Background(), &ssov1.MakeAdminRequest{UserId: 42, AppId: 1})

	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "does not exist",
		"documents that the raw storage error reaches the client")
}

func TestMakeAdmin_Success(t *testing.T) {
	api, m := newAPI()
	m.On("MakeAdmin", mock.Anything, int64(42), int64(1)).Return(int64(9), nil)

	resp, err := api.MakeAdmin(context.Background(), &ssov1.MakeAdminRequest{UserId: 42, AppId: 1})

	require.NoError(t, err)
	require.Equal(t, int64(9), resp.GetUserId())
}

// ----------------------------------------------------------- Applications ---

func TestRegisterApp(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		t.Setenv("ENV", "prod")
		api, m := newAPI()
		m.On("RegisterApp", mock.Anything, "auralift", "https://app.test/cb").
			Return(int64(3), "app-secret", nil)

		resp, err := api.RegisterApp(context.Background(), &ssov1.RegisterAppRequest{
			AppName: "auralift", RedirectUri: "https://app.test/cb",
		})

		require.NoError(t, err)
		require.Equal(t, int64(3), resp.GetAppId())
		require.Equal(t, "app-secret", resp.GetSecret())
	})

	t.Run("plain http is refused in production", func(t *testing.T) {
		t.Setenv("ENV", "prod")
		api, m := newAPI()

		_, err := api.RegisterApp(context.Background(), &ssov1.RegisterAppRequest{
			AppName: "auralift", RedirectUri: "http://app.test/cb",
		})

		require.Equal(t, codes.InvalidArgument, status.Code(err))
		m.AssertNotCalled(t, "RegisterApp", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("duplicate application", func(t *testing.T) {
		t.Setenv("ENV", "prod")
		api, m := newAPI()
		m.On("RegisterApp", mock.Anything, mock.Anything, mock.Anything).
			Return(int64(0), "", auth.ErrAppExists)

		_, err := api.RegisterApp(context.Background(), &ssov1.RegisterAppRequest{
			AppName: "auralift", RedirectUri: "https://app.test/cb",
		})

		require.Equal(t, codes.AlreadyExists, status.Code(err))
	})
}

func TestDeleteApp(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		api, m := newAPI()
		m.On("DeleteApp", mock.Anything, int64(3)).Return(nil)

		_, err := api.DeleteApp(context.Background(), &ssov1.DeleteAppRequest{AppId: 3})

		require.NoError(t, err)
	})

	t.Run("unknown application", func(t *testing.T) {
		api, m := newAPI()
		m.On("DeleteApp", mock.Anything, int64(3)).Return(storage.ErrAppNotFound)

		_, err := api.DeleteApp(context.Background(), &ssov1.DeleteAppRequest{AppId: 3})

		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})
}

// ---------------------------------------------------------------- Logout ----

func TestLogout(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		api, m := newAPI()
		m.On("Logout", mock.Anything, "refresh").Return(nil)

		_, err := api.Logout(context.Background(), &ssov1.LogoutRequest{RefreshToken: "refresh"})

		require.NoError(t, err)
	})

	t.Run("token is required", func(t *testing.T) {
		api, _ := newAPI()

		_, err := api.Logout(context.Background(), &ssov1.LogoutRequest{})

		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("failure is internal", func(t *testing.T) {
		api, m := newAPI()
		m.On("Logout", mock.Anything, "refresh").Return(errors.New("redis down"))

		_, err := api.Logout(context.Background(), &ssov1.LogoutRequest{RefreshToken: "refresh"})

		require.Equal(t, codes.Internal, status.Code(err))
	})
}

// ---------------------------------------------------------------- Tokens ----

func TestRefreshAccessToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		api, m := newAPI()
		m.On("RefreshToken", mock.Anything, "refresh").Return("new-access", nil)

		resp, err := api.RefreshAccessToken(context.Background(), &ssov1.RefreshTokenRequest{RefreshToken: "refresh"})

		require.NoError(t, err)
		require.Equal(t, "new-access", resp.GetNewToken())
	})

	t.Run("unknown token", func(t *testing.T) {
		api, m := newAPI()
		m.On("RefreshToken", mock.Anything, "gone").Return("", storage.ErrTokenNotFound)

		_, err := api.RefreshAccessToken(context.Background(), &ssov1.RefreshTokenRequest{RefreshToken: "gone"})

		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})
}

func TestUpdateRefreshToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		api, m := newAPI()
		m.On("UpdateRefreshToken", mock.Anything, "old").Return("new", nil)

		resp, err := api.UpdateRefreshToken(context.Background(), &ssov1.UpdateRefreshTokenRequst{RefreshToken: "old"})

		require.NoError(t, err)
		require.Equal(t, "new", resp.GetRefreshToken())
	})

	t.Run("unknown token", func(t *testing.T) {
		api, m := newAPI()
		m.On("UpdateRefreshToken", mock.Anything, "gone").Return("", storage.ErrTokenNotFound)

		_, err := api.UpdateRefreshToken(context.Background(), &ssov1.UpdateRefreshTokenRequst{RefreshToken: "gone"})

		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})
}

// ---------------------------------------------------------- Verification ----

func TestVerifyUserEmail(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		api, m := newAPI()
		m.On("VerifyUserEmail", mock.Anything, "user@example.com", "code", int64(1)).
			Return("access-token", "refresh-token", nil)

		resp, err := api.VerifyUserEmail(context.Background(), &ssov1.VerifyEmailRequest{
			Email: "user@example.com", VerificationToken: "code", AppId: 1,
		})

		require.NoError(t, err)
		// Confirming proves ownership, so the response carries a session.
		require.Equal(t, "access-token", resp.GetAccessToken())
		require.Equal(t, "refresh-token", resp.GetRefreshToken())
	})

	t.Run("app id is required", func(t *testing.T) {
		api, _ := newAPI()

		_, err := api.VerifyUserEmail(context.Background(), &ssov1.VerifyEmailRequest{Email: "a@b.c"})

		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("email is required", func(t *testing.T) {
		api, _ := newAPI()

		_, err := api.VerifyUserEmail(context.Background(), &ssov1.VerifyEmailRequest{AppId: 1})

		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	// Each rejection now carries a distinct code, so the client can tell a
	// mistyped code from an expired one from an outage.
	t.Run("rejections map to distinct codes", func(t *testing.T) {
		cases := []struct {
			serviceErr error
			want       codes.Code
		}{
			{auth.ErrUserNotFound, codes.NotFound},
			{auth.ErrVerificationTokenExpired, codes.FailedPrecondition},
			{auth.ErrInvalidCredentials, codes.InvalidArgument},
			{storage.ErrAppNotFound, codes.NotFound},
			{errors.New("redis down"), codes.Internal},
		}

		for _, tc := range cases {
			api, m := newAPI()
			m.On("VerifyUserEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return("", "", tc.serviceErr)

			_, err := api.VerifyUserEmail(context.Background(), &ssov1.VerifyEmailRequest{
				Email: "user@example.com", VerificationToken: "code", AppId: 1,
			})

			require.Equal(t, tc.want, status.Code(err), "for %v", tc.serviceErr)
		}
	})

	t.Run("verification token is required", func(t *testing.T) {
		api, m := newAPI()

		_, err := api.VerifyUserEmail(context.Background(), &ssov1.VerifyEmailRequest{
			Email: "user@example.com", AppId: 1,
		})

		require.Equal(t, codes.InvalidArgument, status.Code(err))
		m.AssertNotCalled(t, "VerifyUserEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestGenerateNewVerificationToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		api, m := newAPI()
		m.On("GenerateNewVerificationToken", mock.Anything, "user@example.com", int64(1)).Return(nil)

		_, err := api.GenerateNewVerificationToken(context.Background(),
			&ssov1.GenerateNewVerificationTokenRequest{Email: "user@example.com", AppId: 1})

		require.NoError(t, err)
	})

	t.Run("required fields", func(t *testing.T) {
		api, _ := newAPI()

		_, err := api.GenerateNewVerificationToken(context.Background(),
			&ssov1.GenerateNewVerificationTokenRequest{AppId: 1})
		require.Equal(t, codes.InvalidArgument, status.Code(err))

		_, err = api.GenerateNewVerificationToken(context.Background(),
			&ssov1.GenerateNewVerificationTokenRequest{Email: "a@b.c"})
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("unknown address is reported as not found", func(t *testing.T) {
		api, m := newAPI()
		m.On("GenerateNewVerificationToken", mock.Anything, mock.Anything, mock.Anything).
			Return(auth.ErrUserNotFound)

		_, err := api.GenerateNewVerificationToken(context.Background(),
			&ssov1.GenerateNewVerificationTokenRequest{Email: "user@example.com", AppId: 1})

		require.Equal(t, codes.NotFound, status.Code(err))
	})
}

// -------------------------------------------------------------- DeleteAdmin -

func TestDeleteAdmin_EachIdentifier(t *testing.T) {
	t.Run("by email", func(t *testing.T) {
		api, m := newAPI()
		m.On("DeleteAdmin", mock.Anything, mock.Anything, int64(1)).Return(nil)

		_, err := api.DeleteAdmin(context.Background(), &ssov1.DeleteAdminRequest{
			AppId: 1, Identifier: &ssov1.DeleteAdminRequest_Email{Email: "a@b.c"},
		})

		require.NoError(t, err)
	})

	t.Run("app id is required", func(t *testing.T) {
		api, _ := newAPI()

		_, err := api.DeleteAdmin(context.Background(), &ssov1.DeleteAdminRequest{
			Identifier: &ssov1.DeleteAdminRequest_Email{Email: "a@b.c"},
		})

		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("identifier is required", func(t *testing.T) {
		api, _ := newAPI()

		_, err := api.DeleteAdmin(context.Background(), &ssov1.DeleteAdminRequest{AppId: 1})

		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})
}
