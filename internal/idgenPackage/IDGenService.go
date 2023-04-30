package idgenpackage

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	// Initialize the random number generator
	rng = rand.New(rand.NewSource(time.Now().UnixNano()))

	// Initialize the ID counter
	counter = newCounter()

	// MongoDB client and collection variables
	db   = "userManager"
	coll = "uuidKey"
)

// Counter is a thread-safe counter that generates incrementing IDs.
type Counter struct {
	mu sync.Mutex
	i  uint32
}

// Next returns the next incrementing ID.
func (c *Counter) Next() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.i++
	return c.i
}

func newCounter() *Counter {
	return &Counter{i: 0}
}

// GenerateID generates a unique 7-digit user ID and inserts it into MongoDB.
func GenerateID(client *mongo.Client) (string, error) {

	// Generate a new ID
	id := generateID()

	// Check if the ID already exists in the database
	if err := checkDuplicate(id, client); err != nil {
		return "", fmt.Errorf("failed to generate unique ID: %w", err)
	}

	// Insert the ID into the database
	if err := insertID(id, client); err != nil {
		return "", fmt.Errorf("failed to insert ID into database: %w", err)
	}

	return id, nil
}

func generateID() string {
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)
	random := rng.Intn(100)
	counterValue := counter.Next() % 10000
	return fmt.Sprintf("%03d%02d%04d", timestamp, random, counterValue)
}

func checkDuplicate(id string, client *mongo.Client) error {

	// Check if the ID already exists in the database
	result := client.Database(db).Collection(coll).FindOne(context.Background(), bson.M{"_id": id})
	if result.Err() == nil {
		return fmt.Errorf("duplicate ID found in database: %s", id)
	}

	return nil
}

func insertID(id string, client *mongo.Client) error {
	// Create a MongoDB client if one hasn't been created already

	// Insert the ID into the database
	_, err := client.Database(db).Collection(coll).InsertOne(context.Background(), bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("failed to insert ID into database: %w", err)
	}

	return nil
}
