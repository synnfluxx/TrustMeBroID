package httpApp

import "net/http"

type responseWriter struct {
	code int
	http.ResponseWriter
}

