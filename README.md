# autocertLego

Plugin replacement for golangs default autocert. It used the go-acme/lego library.
This package does not need an seperated listen port. Its use the user defined TLS listener.

# Why?

It works better with the Step CA

# Example
````
whitelistedDomains := []string{
fmt.Sprintf("%s.%s.svc.%s", config.Service, config.Namespace, config.ClusterDomain),
fmt.Sprintf("%s.%s.svc", config.Service, config.Namespace),
fmt.Sprintf("%s.%s", config.Service, config.Namespace),
}

manager := &autocertLego.Manager{
EMail:      config.EMail,
Directory:  config.CAUrl,
HostPolicy: autocertLego.HostWhitelist(whitelistedDomains...),
DirCache:   autocert.DirCache("./secret-dir/"),
}

srv := &http.Server{
Addr:      config.GetAddress(),
TLSConfig: manager.TLSConfig(),
Handler:   newRouter(config),
}
````
