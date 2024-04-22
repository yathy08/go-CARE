package database

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()

// Client variable can used to save key value pairs in redis
var Client *redis.Client

// InitRedis function initializes redis server
func InitRedis() {
	var err error
	MaxRetries := 5
	RetryDelay := time.Second * 5
	for i := 0; i < MaxRetries; i++ {
		Client = redis.NewClient(&redis.Options{
			Network:  "tcp",
			Addr:     "localhost:6379",
			Password: "", // no password set
			DB:       0,  // use default DB
		})

		_, err = Client.Ping(ctx).Result()
		if err == nil {
			break
		}

		fmt.Printf("Failed to connect to Redis (Attempt %d/%d): %s\n", i+1, MaxRetries, err.Error())
		time.Sleep(RetryDelay)
	}
	if err != nil {
		panic("Failed to connect to Redis after multiple attempts: " + err.Error())
	}
	fmt.Println("connected to redis")
}

// SetRedis willset a key value in redis server
func SetRedis(key string, value any, expirationTime time.Duration) error {
	if err := Client.Set(context.Background(), key, value, expirationTime).Err(); err != nil {
		return err
	}
	return nil
}

// GetRedis will get the value from redis server using key
func GetRedis(key string) (string, error) {
	jsonData, err := Client.Get(context.Background(), key).Result()
	fmt.Println(jsonData)
	if err != nil {
		return "", err
	}
	return jsonData, nil
}
func VerifyOTPHandler() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Get the OTP entered by the user from the request
        otp := c.PostForm("otp")
        
        // Retrieve the expected OTP value from Redis based on the user's session or any identifier
        // For example, if you stored the OTP in Redis using the user's phone number as the key
        phoneNumber := c.PostForm("phone_number")
        expectedOTP, err := GetRedis(phoneNumber)
        if err != nil {
            if err == redis.Nil {
                // Key does not exist in Redis (OTP not generated or expired)
                c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP not generated or expired"})
                return
            }
            // Handle other Redis errors
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve OTP from Redis"})
            return
        }
        
        // Compare the expected OTP with the OTP entered by the user
        if otp != expectedOTP {
            // OTP is incorrect
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect OTP"})
            return
        }
        
        // OTP is correct
        c.JSON(http.StatusOK, gin.H{"message": "OTP verified successfully"})
    }
}
