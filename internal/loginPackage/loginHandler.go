package loginpackage

import (
	"context"
	"encoding/json"
	"fmt"

	"mfus_userManager/database"

	utility "mfus_userManager/utils"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var user UserModel
var tokenDetails RefreshToken

// create login function handler
func Login() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		//call GetMongoClient() function from database/DBConnection.go to establish connection with MongoDB
		client, err := database.GetMongoClient()
		if err != nil {
			panic(err)
		}

		//create a new instance of LoginModel
		var login LoginModel
		//decode the incoming request to json
		err = json.NewDecoder(r.Body).Decode(&login)
		//check for error
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		//check if the username and password is empty
		if login.Username == "" || login.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		login.Password, err = utility.Sha256HexSumPassword(login.Password)
		if err != nil {
			http.Error(w, "Fail to hash password", http.StatusInternalServerError)
			return
		}
		fmt.Print(login.Password)

		// Check if user exists in MongoDB
		collection := client.Database("userManager").Collection("users")
		ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
		err = collection.FindOne(ctx, bson.M{"username": login.Username, "password": login.Password}).Decode(&user)
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Check if user is active
		if user.Status != "active" {
			http.Error(w, "User is not active", http.StatusUnauthorized)
			return
		}

		//get the token details from mongodb based on token id
		tokenCollection := client.Database("userManager").Collection("refresh_tokens")
		ctx, _ = context.WithTimeout(context.Background(), 30*time.Second)
		tokenCollection.FindOne(ctx, bson.M{"username": login.Username}).Decode(&tokenDetails)

		tokenDetails.RefreshExpiry = time.Now()
		tokenDetails.TokenExpiry = time.Now()

		//update the token details in mongodb
		tokenCollection.UpdateOne(ctx, bson.M{"_id": tokenDetails.ID}, bson.M{"$set": tokenDetails})

		// Create JWT token
		fmt.Printf(user.Username, user.userID)
		token, refreshToken, err := CreateTokenPair(user.Username, user.userID, client)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userResponse := LoginResponse{
			ID:           user.ID,
			Name:         user.Name,
			Username:     user.Username,
			Type:         user.Type,
			Status:       user.Status,
			CreationTime: user.CreationTime,
			Token:        token,
			RefreshToken: refreshToken,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(userResponse)
	})
}

// Function for creating a JWT token and refresh token pair
func CreateTokenPair(username string, userID string, client *mongo.Client) (string, string, error) {

	// Create JWT token
	expirationTime := time.Now().Add(900 * time.Hour)
	claims := &ClaimsModel{
		Username: username,
		UserID:   userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	jwtKey := []byte(utility.EnvtKeyValue("jwtKey"))

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", "", err
	}

	// Create refresh token
	refreshexpirationTime := time.Now().Add(30 * time.Hour)
	refreshTokenClaims := &RefreshTokenClaimsModel{
		Username: username,
		UserID:   userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: refreshexpirationTime.Unix(),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)

	refreshTokenString, err := refreshToken.SignedString([]byte(utility.EnvtKeyValue("refreshTokenKey")))
	if err != nil {
		return "", "", err
	}
	//generate new id for refresh token
	refreshTokenID := primitive.NewObjectID()

	tokenDetails := RefreshToken{
		ID:            refreshTokenID,
		UserID:        userID,
		Username:      user.Username,
		RefreshToken:  refreshTokenString,
		Token:         tokenString,
		TokenExpiry:   expirationTime,
		RefreshExpiry: refreshexpirationTime,
		CreationTime:  time.Now().Unix(),
		UpdateTime:    time.Now().Unix(),
	}
	fmt.Print(tokenDetails)

	refreshTokenCollection := client.Database("userManager").Collection("refresh_tokens")
	_, err = refreshTokenCollection.InsertOne(context.Background(), tokenDetails)
	if err != nil {
		return "", "", err
	}

	return tokenString, refreshTokenString, nil
}
