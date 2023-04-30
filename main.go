package main

import (
	"log"
	"mfus_userManager/database"
	loginpackage "mfus_userManager/internal/loginPackage"
	"mfus_userManager/internal/userManagerH"
	"mfus_userManager/logger"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"
)

func main() {

	viper.SetConfigFile(".env")
	viper.ReadInConfig()

	//call GetMongoClient() function from database/DBConnection.go to establish connection with MongoDB
	_, err := database.GetMongoClient()
	if err != nil {
		panic(err)
	}

	//create mux route handler
	r := mux.NewRouter()

	//create the list of HTTP routes to cater the user management operations which include Login, Logout, Register, Update, Delete and refresh token
	// Set up middleware for verifying JWT token
	r.Use(userManagerH.AuthMiddlewareHandler)

	r.Handle("/api/nonauth/client/login", logger.Logger(loginpackage.Login())).Methods(http.MethodPost)
	r.Handle("/api/nonauth/client/register", logger.Logger(loginpackage.Register())).Methods(http.MethodPost)

	r.Handle("/api/client/logout", logger.Logger(userManagerH.LogoutHandler())).Methods(http.MethodPost)
	r.Handle("/api/client/update", logger.Logger(userManagerH.UpdateUserHandler())).Methods(http.MethodPut)
	r.Handle("/api/client/delete", logger.Logger(userManagerH.DeleteUserHandler())).Methods(http.MethodDelete)
	r.Handle("/api/client/userinfo", logger.Logger(userManagerH.LoggedInUserHandler())).Methods(http.MethodGet)
	r.Handle("/api/client/getuserinfo", logger.Logger(userManagerH.LoggedInUserHandler())).Methods(http.MethodGet)

	r.Handle("/api/server/refresh", logger.Logger(userManagerH.RefreshTokenHandler())).Methods(http.MethodPost)
	r.Handle("/api/server/verify", logger.Logger(userManagerH.VerifyTokenHandler())).Methods(http.MethodPost)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	log.Println("Starting server on port", port)
	err = http.ListenAndServe(":"+port, r)
	if err != nil {
		log.Fatal(err)
	}
}
