package auth

import "net/http"

//TODO: add postgres, sessions with token
//TODO: refresh for tokens

func (a *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	panic("implement me")
}
