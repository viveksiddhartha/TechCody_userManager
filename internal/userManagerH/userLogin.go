package userManagerH

import (
	"context"
	"encoding/json"
	"fmt"

	"mfus_userManager/database"
	loginpackage "mfus_userManager/internal/loginPackage"
	utility "mfus_userManager/utils"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func MongoDBOrderBookCollectionFunc() *mongo.Client {
	db, err := database.GetMongoClient()
	if err != nil {
		return nil
	}

	return db
}

// Handler function for refreshing a JWT token
func RefreshTokenHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		//var refreshTokenClaims *RefreshTokenClaimsModel
		var refreshTokenClaims *loginpackage.RefreshTokenClaimsModel
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Missing authorization header", http.StatusBadRequest)
			return
		}
		tokenString = tokenString[len("Bearer "):]
		token, err := jwt.ParseWithClaims(tokenString, &loginpackage.RefreshTokenClaimsModel{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return utility.EnvtKeyValue("refreshTokenKey"), nil
		})
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		fmt.Printf("token.Claims type: %T\n", token.Claims)
		//refreshTokenClaims, ok := token.Claims.(*RefreshTokenClaimsModel)

		refreshTokenClaims, ok := token.Claims.(*loginpackage.RefreshTokenClaimsModel)
		if !ok {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		client, err := database.GetMongoClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Check if refresh token exists in MongoDB
		refreshTokenCollection := client.Database("mydb").Collection("refresh_tokens")
		ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
		result := refreshTokenCollection.FindOne(ctx, bson.M{"username": refreshTokenClaims.Username})
		if result.Err() != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		var storedRefreshToken bson.M
		err = result.Decode(&storedRefreshToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		refreshToken, ok := storedRefreshToken["refresh_token"].(string)
		if !ok || refreshToken != tokenString {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Create new JWT token with extended expiry time
		expirationTime := time.Now().Add(30 * time.Minute)
		claims := &loginpackage.ClaimsModel{
			Username: refreshTokenClaims.Username,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}

		newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err = newToken.SignedString(utility.EnvtKeyValue("jwtKey"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
	})
}

// Middleware function for verifying JWT token
func AuthMiddlewareHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Skip authentication check for API endpoints starting with "/api/nonauth/"
		if strings.HasPrefix(r.URL.Path, "/api/nonauth/") {
			next.ServeHTTP(w, r)
			return
		}
		// Get JWT token from authorization header
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Missing authorization header", http.StatusBadRequest)
			return
		}
		tokenString = tokenString[len("Bearer "):]

		// Parse JWT token and verify signature
		token, err := jwt.ParseWithClaims(tokenString, &loginpackage.ClaimsModel{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return utility.EnvtKeyValue("jwtKey"), nil
		})
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		//validate the token that it belong to the same user
		//get the username from the token
		//get the username from the request
		//compare the two
		//if they are not the same, return unauthorized
		//if they are the same, continue

		//get the username from the token
		claims, ok := token.Claims.(*loginpackage.ClaimsModel)
		if !ok {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		//get user name from the token
		username := claims.Username

		//get the username from the request
		Rusername := r.Context().Value("username").(string)

		//compare the two
		if username != Rusername {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add claims to request context
		claims, ok = token.Claims.(*loginpackage.ClaimsModel)
		if !ok {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "claims", claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Handler function for getting the current user
func LoggedInUserHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Get username from JWT token claims

		claims, ok := r.Context().Value("claims").(*loginpackage.ClaimsModel)
		if !ok {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		username := claims.Username

		client, err := database.GetMongoClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Get user from MongoDB
		var user loginpackage.UserModel
		collection := client.Database("mydb").Collection("users")
		ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
		err = collection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(user)
	})
}

// Handler function for logging out
func LogoutHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Get refresh token from request body
		var refreshTokenString string
		err := json.NewDecoder(r.Body).Decode(&refreshTokenString)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Verify refresh token and get username
		refreshTokenClaims := &loginpackage.RefreshTokenClaimsModel{}
		token, err := jwt.ParseWithClaims(refreshTokenString, refreshTokenClaims, func(token *jwt.Token) (interface{}, error) {
			// Verify signing method and secret key
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return utility.EnvtKeyValue("refreshTokenKey"), nil
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		refreshTokenClaims, ok := token.Claims.(*loginpackage.RefreshTokenClaimsModel)
		if !ok {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		username := refreshTokenClaims.Username

		client, err := database.GetMongoClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Delete refresh token from MongoDB
		refreshTokenCollection := client.Database("mydb").Collection("refresh_tokens")
		ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
		_, err = refreshTokenCollection.DeleteOne(ctx, bson.M{"username": username, "refresh_token": refreshTokenString})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"message": "User logged out successfully"})
	})
}

// Handler function for Verify Token Handler

func VerifyTokenHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Missing authorization header", http.StatusBadRequest)
			return
		}
		tokenString = tokenString[len("Bearer "):]

		// Parse JWT token and verify signature
		token, err := jwt.ParseWithClaims(tokenString, &loginpackage.ClaimsModel{}, func(token *jwt.Token) (interface{}, error) {

			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])

			}
			return utility.EnvtKeyValue("jwtKey"), nil
		})
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		//get the username from the token
		claims, ok := token.Claims.(*loginpackage.ClaimsModel)
		if !ok {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		//get user name from the token
		username := claims.Username

		//get the username from the request
		Rusername := r.Context().Value("username").(string)

		//compare the two
		if username != Rusername {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"message": "Token is valid"})

	})
}

// Handler function for Refresh Token Handler
