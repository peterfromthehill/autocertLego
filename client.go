//
//  simplecert
//
//  Created by Philipp Mieden
//  Contact: dreadl0ck@protonmail.ch
//  Copyright © 2018 bestbytes. All rights reserved.
//

package autocertLego

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"golang.org/x/crypto/acme/autocert"
	"k8s.io/klog/v2"
)

/*
 *	ACMEClient
 */

type ClientConfiguration struct {
	SSLUser        SSLUser
	DirectoryURL   string
	TLSAddress     string
	ProviderServer *ProviderServer
	Cache          autocert.Cache
	HTTPClient     *http.Client
}

func createClient(ctx context.Context, clientConfiguration *ClientConfiguration) (lego.Client, error) {

	// create lego config
	config := lego.NewConfig(&clientConfiguration.SSLUser)
	config.CADirURL = clientConfiguration.DirectoryURL
	//config.Certificate.KeyType = certcrypto.RSA4096
	config.Certificate.KeyType = certcrypto.EC384
	if clientConfiguration.HTTPClient != nil {
		config.HTTPClient = clientConfiguration.HTTPClient
	}

	// Create a new client instance
	client, err := lego.NewClient(config)
	if err != nil {
		return lego.Client{}, fmt.Errorf("autocertLego: failed to create client: %s", err)
	}

	klog.Infof("autocertLego: client creation complete")

	// -------------------------------------------
	// TLS Challenges
	// -------------------------------------------

	if clientConfiguration.TLSAddress != "" {
		tlsSlice := strings.Split(clientConfiguration.TLSAddress, ":")
		if len(tlsSlice) != 2 {
			return *client, fmt.Errorf("autocertLego: invalid TLS address: %s", clientConfiguration.TLSAddress)
		}
		err = client.Challenge.SetTLSALPN01Provider(clientConfiguration.ProviderServer)
		if err != nil {
			return *client, fmt.Errorf("autocertLego: setting TLS challenge provider failed: %s", err)
		}

		klog.Info("autocertLego: set TLS challenge")
	}

	// register if necessary
	if clientConfiguration.SSLUser.Registration == nil {

		// Register Client and agree to TOS
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return *client, fmt.Errorf("autocertLego: failed to register client: %s", err)
		}
		clientConfiguration.SSLUser.Registration = reg
		klog.Infof("autocertLego: client registration complete: ", client)
		ub, err := json.Marshal(&clientConfiguration.SSLUser)
		clientConfiguration.Cache.Put(ctx, sslUserFileName, ub)
	}

	return *client, nil
}
