//
// Copyright (c) 2017 The heketi Authors
//
// This file is licensed to you under your choice of the GNU Lesser
// General Public License, version 3 or any later version (LGPLv3 or
// later), or the GNU General Public License, version 2 (GPLv2), in all
// cases as published by the Free Software Foundation.
//

package glusterfs

import (
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/urfave/negroni"

	"github.com/heketi/heketi/middleware"
)

// Authorization function
func (a *App) Auth(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	// Value saved by the JWT middleware.
	data := context.Get(r, "jwt")

	// Need to change from interface{} to the jwt.Token type
	token := data.(*jwt.Token)
	claims := token.Claims.(*middleware.HeketiJwtClaims)

	// Check access
	if "user" == claims.Issuer && r.URL.Path != "/volumes" {
		http.Error(w, "Administrator access required", http.StatusUnauthorized)
		return
	}

	// Everything is clean
	next(w, r)
}

func (a *App) isAsyncDone(
	w negroni.ResponseWriter,
	r *http.Request) bool {

	return r.Method == http.MethodGet &&
		strings.HasPrefix(r.URL.Path, ASYNC_ROUTE) &&
		(w.Status() == http.StatusNoContent ||
			w.Status() == http.StatusSeeOther)
}
