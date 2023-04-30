package userManagerH

import (
	"context"
	"encoding/json"
	"fmt"
	"mfus_userManager/database"
	loginpackage "mfus_userManager/internal/loginPackage"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
)

var user loginpackage.UserModel

// Handler function for getting a user by ID
func GetUserHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		params := mux.Vars(r)
		id := params["id"]

		client, err := database.GetMongoClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Get user from MongoDB
		collection := client.Database("userManager").Collection("users")
		ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
		err = collection.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(user)
	})
}

// Handler function for updating a user by ID
func UpdateUserHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		params := mux.Vars(r)
		id := params["id"]

		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		client, err := database.GetMongoClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Update user in MongoDB
		collection := client.Database("userManager").Collection("users")
		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
		result, err := collection.UpdateOne(ctx, bson.M{"_id": id}, bson.D{{Key: "$set", Value: bson.D{
			{Key: "username", Value: user.Username},
			{Key: "password", Value: user.Password},
		}}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if result.ModifiedCount == 0 {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(user)
	})
}

// Handler function for deleting a user by ID
func DeleteUserHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		params := mux.Vars(r)
		id := params["id"]

		client, err := database.GetMongoClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Delete user from MongoDB
		collection := client.Database("userManager").Collection("users")
		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
		result, err := collection.DeleteOne(ctx, bson.M{"_id": id})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if result.DeletedCount == 0 {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		fmt.Fprintf(w, "User with ID %v has been deleted", id)
	})
}
