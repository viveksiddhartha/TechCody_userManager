package loginpackage

import (
	"context"
	"encoding/json"
	"fmt"
	"mfus_userManager/database"
	idgenpackage "mfus_userManager/internal/idgenPackage"

	utility "mfus_userManager/utils"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// create user registration HTTP handler
func Register() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		//call GetMongoClient() function from database/DBConnection.go to establish connection with MongoDB
		client, err := database.GetMongoClient()
		if err != nil {
			panic(err)
		}

		//create a new instance of UserModel
		var user UserModel
		//decode the incoming request to json
		err = json.NewDecoder(r.Body).Decode(&user)
		//check for error
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		//check if the username and password is empty
		if user.Username == "" || user.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		user.userID, err = idgenpackage.GenerateID(client)
		if err != nil {
			http.Error(w, "Fail to generate new ID", http.StatusInternalServerError)
			return
		}
		user.Password, err = utility.Sha256HexSumPassword(user.Password)
		if err != nil {
			http.Error(w, "Fail to hash password", http.StatusInternalServerError)
			return
		}

		// Check if user already exists in MongoDB
		collection := client.Database("userManager").Collection("users")
		ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
		err = collection.FindOne(ctx, bson.M{"username": user.Username}).Decode(&user)
		if err == nil {
			http.Error(w, "User already exists", http.StatusUnauthorized)
			return
		}

		// Insert user into MongoDB
		user.Status = "active"
		user.CreationTime = utility.GetTimestampInteger()
		user.UpdateTime = utility.GetTimestampInteger()
		user.ID = primitive.NewObjectID()
		_, err = collection.InsertOne(ctx, user)
		if err != nil {
			http.Error(w, "Error inserting user", http.StatusInternalServerError)
			return
		}

		// Create JWT token
		fmt.Println("Creating token pair", user.Username, user.userID)
		_, refreshToken, err := CreateTokenPair(user.Username, user.userID, client)
		//token, refreshToken, err := CreateTokenPair(user.Username)
		if err != nil {
			http.Error(w, "Error creating token", http.StatusInternalServerError)
			return
		}

		// Create cookie
		cookie := http.Cookie{
			Name:     "refresh_token",
			Value:    refreshToken,
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
		}

		// Set cookie
		http.SetCookie(w, &cookie)

		// Create response
		response := LoginResponse{
			ID:           user.ID,
			Name:         user.Name,
			Username:     user.Username,
			Type:         user.Type,
			Status:       user.Status,
			CreationTime: user.CreationTime,
			RefreshToken: refreshToken,
		}

		// Convert response to JSON

		// Write response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	})
}
