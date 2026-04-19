package authgrpc

import (
	"context"
	"errors"
	"regexp"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
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
	LoginByEmail(ctx context.Context, email string, password string, appID int64) (token string, err error)
	LoginByUsername(ctx context.Context, username, password string, appID int64) (token string, err error)
	RegisterNewUser(ctx context.Context, email string, username string, password string, appID int64) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64, appID int64) (bool, error)
	RegisterApp(ctx context.Context, appName string) (appID int64, secret string, err error)
	DeleteUserByUsername(ctx context.Context, username string, appID int64) error
	DeleteUserByEmail(ctx context.Context, email string, appID int64) error
	DeleteUserByUserID(ctx context.Context, userID, appID int64) error
	DeleteAdminByUserID(ctx context.Context, appID, userID int64) error
	DeleteAdminByEmail(ctx context.Context, appID int64, email string) error
	DeleteAdminByUsername(ctx context.Context, appID int64, username string) error
	DeleteApp(ctx context.Context, appID int64) error
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	if req.GetAppId() == emptyValue {
		return nil, status.Error(codes.InvalidArgument, "app_id is required")
	}
	switch req.Identifier.(type) {
	case *ssov1.LoginRequest_Email:
		if err := validate(req.GetEmail(), req.GetPassword()); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}

		token, err := s.auth.LoginByEmail(ctx, req.GetEmail(), req.GetPassword(), req.GetAppId())
		if err != nil {
			if errors.Is(err, auth.ErrInvalidCredentials) {
				return nil, status.Error(codes.NotFound, auth.ErrInvalidCredentials.Error())
			}
			if errors.Is(err, storage.ErrAppNotFound) {
				return nil, status.Error(codes.NotFound, "app not found")
			}

			return nil, status.Error(codes.Internal, "internal error")
		}

		return &ssov1.LoginResponse{
			Token: token,
		}, nil
	case *ssov1.LoginRequest_Username:
		if err := validate("", req.GetPassword()); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}

		token, err := s.auth.LoginByUsername(ctx, req.GetUsername(), req.GetPassword(), req.GetAppId())
		if err != nil {
			if errors.Is(err, auth.ErrInvalidCredentials) {
				return nil, status.Error(codes.NotFound, auth.ErrInvalidCredentials.Error())
			}
			if errors.Is(err, storage.ErrAppNotFound) {
				return nil, status.Error(codes.NotFound, "app not found")
			}

			return nil, status.Error(codes.Internal, "internal error")
		}

		return &ssov1.LoginResponse{
			Token: token,
		}, nil
	default:
		return nil, status.Error(codes.InvalidArgument, "invalid identifier")
	}
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
			return nil, status.Error(codes.NotFound, "invalid credentials")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}

func (s *serverAPI) RegisterApp(ctx context.Context, req *ssov1.RegisterAppRequest) (*ssov1.RegisterAppResponse, error) {
	appID, secret, err := s.auth.RegisterApp(ctx, req.GetAppName())
	if err != nil {
		if errors.Is(err, auth.ErrAppExists) {
			return nil, status.Error(codes.AlreadyExists, "app already exists")
		}
	}

	return &ssov1.RegisterAppResponse{
		AppId: appID,
		Secret: secret,
	}, nil
}

func (s *serverAPI) DeleteUser(ctx context.Context, req *ssov1.DeleteUserRequest) (*ssov1.Empty, error) {
	if req.GetAppId() == emptyValue {
		return nil, status.Error(codes.InvalidArgument, "app_id is required")
	}

	switch req.Identifier.(type) {
	case *ssov1.DeleteUserRequest_Email:

		err := s.auth.DeleteUserByEmail(ctx, req.GetEmail(), req.GetAppId())
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				return nil, status.Error(codes.InvalidArgument, "invalid credentials")
			}
		}

		return &ssov1.Empty{}, nil
	case *ssov1.DeleteUserRequest_Username:
		err := s.auth.DeleteUserByUsername(ctx, req.GetUsername(), req.GetAppId())
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				return nil, status.Error(codes.InvalidArgument, "invalid credentials")
			}
		}

		return &ssov1.Empty{}, nil
	case *ssov1.DeleteUserRequest_UserId:
		err := s.auth.DeleteUserByUserID(ctx, req.GetUserId(), req.GetAppId())
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				return nil, status.Error(codes.InvalidArgument, "invalid credentials")
			}
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
		err := s.auth.DeleteAdminByEmail(ctx, req.GetAppId(), req.GetEmail())
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				return nil, status.Error(codes.InvalidArgument, "invalid credentials")
			}
		}

		return &ssov1.Empty{}, nil
	case *ssov1.DeleteAdminRequest_Username:
		err := s.auth.DeleteAdminByUsername(ctx, req.GetAppId(), req.GetUsername())
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				return nil, status.Error(codes.InvalidArgument, "invalid credentials")
			}
		}

		return &ssov1.Empty{}, nil
	case *ssov1.DeleteAdminRequest_UserId:
		err := s.auth.DeleteAdminByUserID(ctx, req.GetAppId(), req.GetUserId())
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				return nil, status.Error(codes.InvalidArgument, "invalid credentials")
			}
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
	}

	return &ssov1.Empty{}, nil
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
