// Copyright 2018 Team 254. All Rights Reserved.
// Author: pat@patfairbank.com (Patrick Fairbank)
//
// Web routes for authenticating with the server.

package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/frc9611/cyberarena/model"
	"github.com/google/uuid"
)

// Shows the login form.
func (web *Web) loginHandler(w http.ResponseWriter, r *http.Request) {
	web.renderLogin(w, r, "")
}

// Processes the login request.
func (web *Web) loginPostHandler(w http.ResponseWriter, r *http.Request) {
	username := r.PostFormValue("username")
	if err := web.checkAuthPassword(username, r.PostFormValue("password")); err != nil {
		web.renderLogin(w, r, err.Error())
		return
	}

	session := model.UserSession{Token: uuid.New().String(), Username: username, CreatedAt: time.Now()}
	if err := web.arena.Database.CreateUserSession(&session); err != nil {
		handleWebErr(w, err)
		return
	}

	http.SetCookie(w, &http.Cookie{Name: sessionTokenCookie, Value: session.Token})
	redirectUrl := r.URL.Query().Get("redirect")
	if redirectUrl == "" {
		redirectUrl = "/"
	}
	http.Redirect(w, r, redirectUrl, 303)
}

func (web *Web) renderLogin(w http.ResponseWriter, r *http.Request, errorMessage string) {
	template, err := web.parseFiles("templates/login.html", "templates/base.html")
	if err != nil {
		handleWebErr(w, err)
		return
	}
	data := struct {
		*model.EventSettings
		ErrorMessage string
	}{web.arena.EventSettings, errorMessage}
	err = template.ExecuteTemplate(w, "base", data)
	if err != nil {
		handleWebErr(w, err)
		return
	}
}

// Returns true if the given user is authorized for admin operations. Used for HTTP cookie authentication.
func (web *Web) userIsAdmin(w http.ResponseWriter, r *http.Request) bool {
	if web.arena.EventSettings.AdminPassword == "" {
		// Disable auth if there is no password configured.
		return true
	}
	session := web.getUserSessionFromCookie(r)
	if session != nil && session.Username == adminUser {
		return true
	} else {
		redirect := r.URL.Path
		if r.URL.RawQuery != "" {
			redirect += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, "/login?redirect="+url.QueryEscape(redirect), 307)
		return false
	}
}

func (web *Web) getUserSessionFromCookie(r *http.Request) *model.UserSession {
	token, err := r.Cookie(sessionTokenCookie)
	if err != nil {
		return nil
	}
	session, _ := web.arena.Database.GetUserSessionByToken(token.Value)
	return session
}

func vernumLogin(user, password string) bool {
	url := "http://server.joaorodrigo.eu:32080/login"
	method := "POST"

	payload := strings.NewReader(`{"username": "` + user + `", "password": "` + password + `"}`)
	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		fmt.Println(err)
		return false
	}

	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return false
	}

	fmt.Println(string(body))
	var jsonMap map[string]interface{}
	json.Unmarshal([]byte(string(body)), &jsonMap)
	_, ok := jsonMap["accessToken"]
	return ok

}

func (web *Web) checkAuthPassword(user, password string) error {
	if (user == adminUser && password == web.arena.EventSettings.AdminPassword) || (vernumLogin(user, password)) {
		web.loggedUser = user
		return nil
	} else {
		return fmt.Errorf("[VERNUM SERVER] Invalid login credentials.")
	}
}
