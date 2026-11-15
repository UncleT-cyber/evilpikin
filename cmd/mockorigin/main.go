package main

import (
	"flag"
	"fmt"
	"net/http"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9000", "mock origin address")
	flag.Parse()

	loginPage := `<!doctype html>
<html><head><title>Mock Login</title></head>
<body>
<h1>Acme Identity Login</h1>
<form method="POST" action="/login">
  <label>Username</label><input name="username" value="victim@acme.example"/><br/>
  <label>Password</label><input name="password" type="password" value="hunter2"/><br/>
  <button type="submit">Sign in</button>
</form>
</body></html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		fmt.Fprint(w, loginPage)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "SESSION",
			Value:    "mock-session-token-abc123",
			Path:     "/",
			HttpOnly: true,
			Domain:   r.Host,
		})
		fmt.Fprint(w, "OK")
	})

	fmt.Printf("mock origin listening on %s\n", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		panic(err)
	}
}
