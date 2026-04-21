package httpApp

import "net/http"

type responseWriter struct {
	code int
	http.ResponseWriter
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.code = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}
