package web

import (
	"crypto/subtle"
	"net/http"
)

const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; connect-src 'self'"

func applySecurityHeaders(header http.Header) {
	header.Set("Content-Security-Policy", contentSecurityPolicy)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	header.Set("Cache-Control", "no-store")
}

func secureHandler(expectedHost, expectedOrigin, csrfToken string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applySecurityHeaders(w.Header())
		if r.Host != expectedHost {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}

		origins := r.Header.Values("Origin")
		if len(origins) > 0 && (len(origins) != 1 || origins[0] != expectedOrigin) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		if isMutationMethod(r.Method) {
			if len(origins) != 1 || origins[0] != expectedOrigin {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
			tokens := r.Header.Values("X-AIPT-CSRF")
			if len(tokens) != 1 || !constantTimeEqual(tokens[0], csrfToken) {
				http.Error(w, "forbidden request", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isMutationMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func constantTimeEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
