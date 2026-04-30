package authgrpc

import (
	"context"
	"errors"
	"net/url"
	"os"
	"regexp"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
	"github.com/synnfluxx/TrustMeBroID/internal/services/auth"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
	ssov1 "gitlab.com/synnfluxx/protos/sso/gen"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	emptyValue  = 0
	emptyString = ""
)

var PassErr = errors.New("password must be at least 8 characters long and include at least one uppercase letter and one number")

type Auth interface {
	Login(ctx context.Context, identifier models.UserIdentifier, password string, appID int64) (accessToken, refreshToken string, err error)
	RegisterNewUser(ctx context.Context, email string, username string, password string, appID int64) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64, appID int64) (bool, error)
	RegisterApp(ctx context.Context, appName, redirectURI string) (appID int64, secret string, err error)
	DeleteUser(ctx context.Context, identifier models.UserIdentifier, appID int64) error
	DeleteAdmin(ctx context.Context, identifier models.UserIdentifier, appID int64) error
	DeleteApp(ctx context.Context, appID int64) error
	RefreshToken(ctx context.Context, refreshToken string) (string, error)
	UpdateRefreshToken(ctx context.Context, token string) (string, error)
	MakeAdmin(ctx context.Context, userID, appID int64) (int64, error)
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) MakeAdmin(ctx context.Context, req *ssov1.MakeAdminRequest) (*ssov1.MakeAdminResponse, error) {
	uid, err := s.auth.MakeAdmin(ctx, req.GetUserId(), req.GetAppId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	
	return &ssov1.MakeAdminResponse{
		UserId: uid,
	}, nil
}

func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	if req.GetAppId() == emptyValue {
		return nil, status.Error(codes.InvalidArgument, "app_id is required")
	}
	switch req.Identifier.(type) {
	case *ssov1.LoginRequest_Email:
		email := req.GetEmail()
		if err := validate(email, req.GetPassword()); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}

		accessToken, refreshToken, err := s.auth.Login(ctx, models.UserIdentifier{Email: &email}, req.GetPassword(), req.GetAppId())
		if err != nil {
			if errors.Is(err, auth.ErrInvalidCredentials) || errors.Is(err, auth.ErrInvalidIdentifier) {
				return nil, status.Error(codes.NotFound, auth.ErrInvalidCredentials.Error())
			}
			if errors.Is(err, storage.ErrAppNotFound) {
				return nil, status.Error(codes.NotFound, "app not found")
			}
			if errors.Is(err, storage.ErrUserNotFound) {
				return nil, status.Error(codes.NotFound, "user not found")
			}

			return nil, status.Error(codes.Internal, "internal error")
		}

		return &ssov1.LoginResponse{
			RefreshToken: refreshToken,
			AccessToken:  accessToken,
		}, nil
	case *ssov1.LoginRequest_Username:
		username := req.GetUsername()
		if err := validate("", req.GetPassword()); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}

		accessToken, refreshToken, err := s.auth.Login(ctx, models.UserIdentifier{Username: &username}, req.GetPassword(), req.GetAppId())
		if err != nil {
			if errors.Is(err, auth.ErrInvalidCredentials) || errors.Is(err, auth.ErrInvalidIdentifier) {
				return nil, status.Error(codes.NotFound, auth.ErrInvalidCredentials.Error())
			}
			if errors.Is(err, storage.ErrAppNotFound) {
				return nil, status.Error(codes.NotFound, "app not found")
			}
			if errors.Is(err, storage.ErrUserNotFound) {
				return nil, status.Error(codes.NotFound, "user not found")
			}

			return nil, status.Error(codes.Internal, "internal error")
		}

		return &ssov1.LoginResponse{
			RefreshToken: refreshToken,
			AccessToken:  accessToken,
		}, nil
	default:
		return nil, status.Error(codes.InvalidArgument, "invalid identifier")
	}
}

func (s *serverAPI) RefreshToken(ctx context.Context, req *ssov1.RefreshTokenRequest) (*ssov1.RefreshTokenResponse, error) {
	token, err := s.auth.RefreshToken(ctx, req.GetRefreshToken())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return &ssov1.RefreshTokenResponse{
		NewToken: token,
	}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if err := validate(req.GetEmail(), req.GetPassword()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if req.GetUsername() == emptyString {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}

	userID, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetUsername(), req.GetPassword(), req.GetAppId())
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.RegisterResponse{
		UserId: userID,
	}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	if req.GetUserId() == emptyValue {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId(), req.GetAppId())
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}

		if errors.Is(err, storage.ErrAppNotFound) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}

func (s *serverAPI) RegisterApp(ctx context.Context, req *ssov1.RegisterAppRequest) (*ssov1.RegisterAppResponse, error) {
	if !validateRedirectURI(req.GetRedirectUri(), os.Getenv("ENV")) {
		return nil, status.Error(codes.InvalidArgument, "invalid redirect_uri")
	}

	appID, secret, err := s.auth.RegisterApp(ctx, req.GetAppName(), req.GetRedirectUri())
	if err != nil {
		if errors.Is(err, auth.ErrAppExists) {
			return nil, status.Error(codes.AlreadyExists, "app already exists")
		}

		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &ssov1.RegisterAppResponse{
		AppId:  appID,
		Secret: secret,
	}, nil
}

func (s *serverAPI) DeleteUser(ctx context.Context, req *ssov1.DeleteUserRequest) (*ssov1.Empty, error) {
	if req.GetAppId() == emptyValue {
		return nil, status.Error(codes.InvalidArgument, "app_id is required")
	}

	switch req.Identifier.(type) {
	case *ssov1.DeleteUserRequest_Email:
		email := req.GetEmail()
		err := s.auth.DeleteUser(ctx, models.UserIdentifier{Email: &email}, req.GetAppId())
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				return nil, status.Error(codes.InvalidArgument, "invalid credentials")
			}

			return nil, status.Error(codes.Internal, "internal error")
		}

		return &ssov1.Empty{}, nil
	case *ssov1.DeleteUserRequest_Username:
		username := req.GetUsername()
		err := s.auth.DeleteUser(ctx, models.UserIdentifier{Username: &username}, req.GetAppId())
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				return nil, status.Error(codes.InvalidArgument, "invalid credentials")
			}

			return nil, status.Error(codes.Internal, "internal error")
		}

		return &ssov1.Empty{}, nil
	case *ssov1.DeleteUserRequest_UserId:
		userID := req.GetUserId()
		err := s.auth.DeleteUser(ctx, models.UserIdentifier{ID: &userID}, req.GetAppId())
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				return nil, status.Error(codes.InvalidArgument, "invalid credentials")
			}

			return nil, status.Error(codes.Internal, "internal error")
		}

		return &ssov1.Empty{}, nil
	default:
		return nil, status.Error(codes.InvalidArgument, "invalid identifier")
	}
}

func (s *serverAPI) DeleteAdmin(ctx context.Context, req *ssov1.DeleteAdminRequest) (*ssov1.Empty, error) {
	if req.GetAppId() == emptyValue {
		return nil, status.Error(codes.InvalidArgument, "app_id is required")
	}

	switch req.Identifier.(type) {
	case *ssov1.DeleteAdminRequest_Email:
		email := req.GetEmail()
		err := s.auth.DeleteAdmin(ctx, models.UserIdentifier{Email: &email}, req.GetAppId())
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				return nil, status.Error(codes.InvalidArgument, "invalid credentials")
			}

			return nil, status.Error(codes.Internal, "internal server error")
		}

		return &ssov1.Empty{}, nil
	case *ssov1.DeleteAdminRequest_Username:
		username := req.GetUsername()
		err := s.auth.DeleteAdmin(ctx, models.UserIdentifier{Username: &username}, req.GetAppId())
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				return nil, status.Error(codes.InvalidArgument, "invalid credentials")
			}

			return nil, status.Error(codes.Internal, "internal server error")
		}

		return &ssov1.Empty{}, nil
	case *ssov1.DeleteAdminRequest_UserId:
		userID := req.GetUserId()
		err := s.auth.DeleteAdmin(ctx, models.UserIdentifier{ID: &userID}, req.GetAppId())
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				return nil, status.Error(codes.InvalidArgument, "invalid credentials")
			}

			return nil, status.Error(codes.Internal, "internal server error")
		}

		return &ssov1.Empty{}, nil
	default:
		return nil, status.Error(codes.InvalidArgument, "invalid identifier")
	}
}

func (s *serverAPI) DeleteApp(ctx context.Context, req *ssov1.DeleteAppRequest) (*ssov1.Empty, error) {
	err := s.auth.DeleteApp(ctx, req.GetAppId())
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			return nil, status.Error(codes.InvalidArgument, "invalid app_id")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.Empty{}, nil
}

func (s *serverAPI) UpdateRefreshToken(ctx context.Context, req *ssov1.UpdateRefreshTokenRequst) (*ssov1.UpdateRefreshTokenResponse, error) {
	token, err := s.auth.UpdateRefreshToken(ctx, req.GetRefreshToken())
	if err != nil {
		if errors.Is(err, storage.ErrTokenNotFound) {
			return nil, status.Error(codes.InvalidArgument, "refresh token not found")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.UpdateRefreshTokenResponse{
		RefreshToken: token,
	}, nil
}

func validate(email, password string) error {
	if email != "" {
		if err := validation.Validate(email, validation.Required, is.Email); err != nil {
			return err
		}
	}
	if err := validation.Validate(password, validation.Required, validation.Length(8, 32), validation.Match(regexp.MustCompile(`[0-9]`)), validation.Match(regexp.MustCompile(`[A-Z]`))); err != nil {
		return PassErr
	}

	return nil
}

func validateRedirectURI(uri string, env string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}

	if env == "prod" {
		if u.Scheme != "https" {
			return false
		}
	} else {
		if u.Scheme != "http" && u.Scheme != "https" {
			return false
		}
	}

	if u.Host == "" {
		return false
	}

	if u.User != nil {
		return false
	}

	if u.Fragment != "" {
		return false
	}

	return true
}
