package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"os"
	"text/template"
	"time"

	"github.com/sputnik-systems/openvpn-oidc-wrapper/internal/certs"
	"golang.org/x/oauth2"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
)

type ConfigValues struct {
	Addr    string
	CACrt   string
	Crt     string
	Key     string
	TLSAuth string
}

type ctxKey string

var (
	provider *oidc.Provider
	config   *oauth2.Config
)

func Execute() error {
	rootCmd := &cobra.Command{
		Use:   "wrapper",
		Short: "wrapper controls openvpn certificates",
		Long: `This wrapper can control openvpn installation certificates.
                       Your certificates locations directory should be created over "make-cadir" command.`,
	}

	var certsPathPrefix string
	revokeCmd := &cobra.Command{
		Use:   "revoke",
		Short: "cli for revoking specified users certificate",
		Run: func(cmd *cobra.Command, args []string) {
			certs.Init(certsPathPrefix)
			for _, name := range args {
				if err := certs.RevokeClient(name); err != nil {
					log.Printf("failed to revoke [%s] certificate: %s", name, err)
				}
			}
		},
	}

	var oidcURL, oidcClientID, oidcClientSecret, managerPublicURL string
	managerCmd := &cobra.Command{
		Use:   "manager",
		Short: "daemon for certificate controlling",
		Long:  "This daemon run near openvnp service and control user certificates.",
		Run: func(cmd *cobra.Command, args []string) {
			certs.Init(certsPathPrefix)
			manager(oidcURL, oidcClientID, oidcClientSecret, managerPublicURL)
		},
	}
	managerCmd.PersistentFlags().StringVar(&oidcURL, "oidc.issuer-url", "", "your oidc provider issuer url")
	managerCmd.PersistentFlags().StringVar(&oidcClientID, "oidc.client-id", "", "your oidc provider client id")
	managerCmd.PersistentFlags().StringVar(&oidcClientSecret, "oidc.client-secret", "", "your oidc provider client secret")
	managerCmd.PersistentFlags().StringVar(&managerPublicURL, "manager.public-url", "", "this service public url")

	rootCmd.PersistentFlags().StringVar(&certsPathPrefix, "root.certs-path-prefix", "/etc/openvpn/easy-rsa/pki", "where certificates should located")

	rootCmd.AddCommand(managerCmd)
	rootCmd.AddCommand(revokeCmd)

	return rootCmd.Execute()
}

func manager(providerURL, clientID, clientSecret, redirectURL string) {
	var err error
	provider, err = oidc.NewProvider(context.Background(), providerURL)
	if err != nil {
		log.Fatalf("failed to initialize oidc provider: %s", err)
	}
	config = &oauth2.Config{
		Endpoint:     provider.Endpoint(),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth", authHandler)
	mux.Handle("/", authMiddleware(http.HandlerFunc(apiConfigHandler)))
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, err := r.Cookie("state")
		if err != nil {
			log.Printf("failed to read cookie: %s", err)

			if err == http.ErrNoCookie {
				http.Redirect(w, r, "/auth", http.StatusFound)
			}
			return
		}
		if qstate := r.URL.Query().Get("state"); qstate != state.Value {
			if qstate == "" {
				http.Redirect(w, r, "/auth", http.StatusFound)
			}

			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		token, err := config.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		info, err := provider.UserInfo(r.Context(), oauth2.StaticTokenSource(token))
		if err != nil {
			http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if !info.EmailVerified {
			http.Error(w, "User email not verified", http.StatusForbidden)
		}

		ctx := context.WithValue(r.Context(), ctxKey("email"), info.Email)
		next.ServeHTTP(w, r.WithContext(ctx))
	})

}

func authHandler(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		log.Printf("failed to read from random reader: %s", err)

		return
	}

	value := base64.RawURLEncoding.EncodeToString(b)
	c := &http.Cookie{
		Name:     "state",
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)

	http.Redirect(w, r, config.AuthCodeURL(value), http.StatusFound)
}

func apiConfigHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getConfig(w, r)
		// case http.MethodDelete:
		// 	revoke(w, r)
	}
}

// func revoke(w http.ResponseWriter, r *http.Request) {
// 	if err := r.ParseForm(); err != nil {
// 		log.Printf("failed to parse request: %s", err)
//
// 		return
// 	}
//
// 	name := r.Form.Get("name")
//
// 	if err := certs.RevokeClient(name); err != nil {
// 		log.Printf("failed to revoke client: %s", err)
// 	}
// }

func getConfig(w http.ResponseWriter, r *http.Request) {
	name, ok := r.Context().Value(ctxKey("email")).(string)
	if !ok {
		http.Error(w, "User email parsing error", http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	// w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.ovpn\"", name))
	w.Header().Set("Content-Disposition", "attachment; filename=\"config.ovpn\"")

	if err := certs.GenClient(name); err != nil {
		log.Printf("failed to generate new client: %s", err)
	}

	ca, err := certs.GetCaCrtData()
	if err != nil {
		log.Printf("failed to get CA cert: %s", err)

		return
	}
	key, err := certs.GetKeyDataByName(name)
	if err != nil {
		log.Printf("failed to get client key: %s", err)

		return
	}
	crt, err := certs.GetCrtDataByName(name)
	if err != nil {
		log.Printf("failed to get client cert: %s", err)

		return
	}
	tlsAuth, err := certs.GetTLSAuth()
	if err != nil {
		log.Printf("failed to get tls auth key: %s", err)

		return
	}

	values := ConfigValues{
		Addr:    "vpn.sputnik.systems",
		CACrt:   string(ca),
		Key:     string(key),
		Crt:     string(crt),
		TLSAuth: string(tlsAuth),
	}

	configTmpl, err := os.ReadFile("./templates/client.conf.tmpl")
	if err != nil {
		log.Printf("failed to read config template")

		return
	}
	tmpl, err := template.New("config").Parse(string(configTmpl))
	if err != nil {
		log.Printf("failed parse config template: %s", err)

		return
	}
	if err = tmpl.Execute(w, values); err != nil {
		log.Printf("failed to execute by template: %s", err)
	}

}
