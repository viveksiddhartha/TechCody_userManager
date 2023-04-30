package loginpackage

import (
	"time"

	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// LoginModel is a struct that defines the structure of a user.
type LoginModel struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// create type struct for login response body along with user Info

type LoginResponse struct {
	ID           primitive.ObjectID `json:"id,omitempty"`
	userID       string             `json:"userId,omitempty" bson:"userId,omitempty"`
	Name         string             `json:"name,omitempty"`
	Username     string             `json:"username,omitempty"`
	Type         string             `json:"type,omitempty"`
	Status       string             `json:"status,omitempty"`
	CreationTime int64              `json:"creationTime,omitempty"`
	UpdateTime   int64              `json:"updateTime,omitempty"`
	Token        string             `json:"token,omitempty"`
	RefreshToken string             `json:"refresh_token"`
}

type ClaimsModel struct {
	Username string `json:"username"`
	UserID   string `json:"userId,omitempty" bson:"userId,omitempty"`
	jwt.StandardClaims
}

type RefreshTokenClaimsModel struct {
	Username string `json:"username"`
	UserID   string `json:"userId,omitempty" bson:"userId,omitempty"`
	jwt.StandardClaims
}

type UserModel struct {
	ID           primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	userID       string             `json:"userId,omitempty" bson:"userId,omitempty"`
	Name         string             `json:"name,omitempty" bson:"name,omitempty"`
	Username     string             `json:"username,omitempty" bson:"username,omitempty"`
	Password     string             `json:"password,omitempty" bson:"password,omitempty"`
	Type         string             `json:"type" bson:"type"`
	Status       string             `json:"status" bson:"status"`
	CreationTime int64              `json:"creationTime" bson:"creationTime"`
	UpdateTime   int64              `json:"updateTime" bson:"updateTime"`
}

type RefreshToken struct {
	ID                      primitive.ObjectID `bson:"_id,omitempty"`
	UserID                  string             `json:"userId,omitempty" bson:"userId,omitempty"`
	Username                string             `bson:"username,omitempty"`
	RefreshToken            string             `bson:"refresh_token,omitempty"`
	Token                   string             `bson:"token,omitempty"`
	TokenExpiry             time.Time          `bson:"tokenExpiry,omitempty"`
	RefreshExpiry           time.Time          `bson:"refreshExpiry,omitempty"`
	CreationTime            int64              `bson:"creationTime,omitempty"`
	UpdateTime              int64              `bson:"updateTime,omitempty"`
	ClaimsModel             ClaimsModel
	RefreshTokenClaimsModel RefreshTokenClaimsModel
}
