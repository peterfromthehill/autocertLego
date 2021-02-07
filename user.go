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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/go-acme/lego/v4/registration"
	"golang.org/x/crypto/acme/autocert"
)

const sslUserFileName = "SSLUser.json"

/*
 *	SSLUser
 */

// SSLUser implements the ACME User interface
type SSLUser struct {
	Email        string
	Registration *registration.Resource
	Key          *rsa.PrivateKey
}

// GetEmail returns the users email
func (u SSLUser) GetEmail() string {
	return u.Email
}

// GetRegistration returns the users registration resource
func (u SSLUser) GetRegistration() *registration.Resource {
	return u.Registration
}

// GetPrivateKey returns the users private key
func (u SSLUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

// get SSL User from cacheDir or create a new one
func getUser(ctx context.Context, sslEmail string, cache autocert.Cache) (SSLUser, error) {

	// no cached cert. start from scratch
	var u SSLUser

	// do we have a user?
	b, err := cache.Get(ctx, sslUserFileName)
	if err == nil {
		// user exists. load
		err = json.Unmarshal(b, &u)
		if err != nil {
			return u, fmt.Errorf("autocertLego: failed to unmarshal SSLUser: %s", err)
		}
		return u, nil
	}

	// create private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return u, fmt.Errorf("autocertLego: failed to generate private key: %s", err)
	}

	// Create new user
	u = SSLUser{
		Email: sslEmail,
		Key:   privateKey,
	}

	ub, err := json.Marshal(&u)
	err = cache.Put(ctx, sslUserFileName, ub)
	if err != nil {
		return SSLUser{}, err
	}

	return u, nil
}

func getUserKey() string {
	return sslUserFileName
}

// // save the user on disk
// // fatals on error
// func saveUserToDisk(u SSLUser, cacheDir string) {
// 	b, err := json.MarshalIndent(u, "", "  ")
// 	if err != nil {
// 		klog.Error("autocertLego: failed to marshal user: ", err)
// 	}
// 	err = ioutil.WriteFile(filepath.Join(cacheDir, sslUserFileName), b, 0700)
// 	if err != nil {
// 		klog.Error("autocertLego: failed to write user to disk: ", err)
// 	}
// }
