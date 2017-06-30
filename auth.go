package gosocks5

import (
	"net"
	"net/url"
)

type Authenticator interface {
	ClientAuthenticator
	ServerAuthenticator
}

type ClientAuthenticator interface {
	// return supported methods
	Methods() []uint8
	// on method selected
	OnRequest(method uint8, conn net.Conn) (net.Conn, error)
}

type ServerAuthenticator interface {
	// select method
	Select(methods ...uint8) (method uint8)
	// on method selected
	OnResponse(method uint8, conn net.Conn) (net.Conn, error)
}

type Auth struct {
	methods []uint8
	users   []*url.Userinfo
}

func NewAuthenticator(users []*url.Userinfo) Authenticator {
	return &Auth{
		methods: []uint8{
			MethodNoAuth,
			MethodUserPass,
		},
		users: users,
	}
}

func (auth *Auth) Methods() []uint8 {
	return auth.methods
}

func (auth *Auth) OnRequest(method uint8, conn net.Conn) (net.Conn, error) {
	switch method {
	case MethodNoAuth:
		return conn, nil
	case MethodUserPass:
		var username, password string
		if len(auth.users) > 0 && auth.users[0] != nil {
			username = auth.users[0].Username()
			password, _ = auth.users[0].Password()
		}

		req := NewUserPassRequest(UserPassVer, username, password)
		if err := req.Write(conn); err != nil {
			return nil, err
		}

		resp, err := ReadUserPassResponse(conn)
		if err != nil {
			return nil, err
		}

		if resp.Status != Succeeded {
			return nil, ErrAuthFailure
		}
	case MethodNoAcceptable:
		return nil, ErrBadMethod
	default:
		return nil, ErrBadMethod
	}

	return conn, nil
}

func (auth *Auth) Select(methods ...uint8) uint8 {
	// when user/pass is set, auth is mandatory
	if auth.users != nil {
		return MethodUserPass
	}

	return MethodNoAuth
}

func (auth *Auth) OnResponse(method uint8, conn net.Conn) (net.Conn, error) {
	switch method {
	case MethodNoAuth:
		return conn, nil
	case MethodUserPass:
		req, err := ReadUserPassRequest(conn)
		if err != nil {
			return nil, err
		}

		valid := false
		for _, user := range auth.users {
			username := user.Username()
			password, _ := user.Password()
			if (req.Username == username && req.Password == password) ||
				(req.Username == username && password == "") ||
				(username == "" && req.Password == password) {
				valid = true
				break
			}
		}
		if len(auth.users) > 0 && !valid {
			resp := NewUserPassResponse(UserPassVer, Failure)
			if err := resp.Write(conn); err != nil {
				return nil, err
			}

			return nil, ErrAuthFailure
		}

		resp := NewUserPassResponse(UserPassVer, Succeeded)
		if err := resp.Write(conn); err != nil {
			return nil, err
		}
	case MethodNoAcceptable:
		return nil, ErrBadMethod
	default:
		return nil, ErrBadMethod
	}

	return conn, nil
}
