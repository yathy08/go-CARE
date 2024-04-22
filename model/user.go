package model
import "time"
type UserModel struct {
	ID       uint `gorm:"primary key"`
	Name     string
	Email    string `gorm:"unique"`
	Password string
	Status   string
	Phone    string
}

type VerifyOTP struct {
	Otp   string `json:"otp"`
	Phone string `json:"phone"`
}

type DisasterReport struct {
	ID uint `json:"id" gorm:"primaryKey;autoIncrement"`
	Latitude     string `form:"Latitude" gorm:"not null"`
	Longitude    string `json:"longitude" gorm:"not null"`
	DisasterType string `json:"DisasterType" gorm:"not null"`
	Severity     string `json:"severity" gorm:"not null"`
	Description  string `json:"description"`
	FileURL      string `json:"fileURL"`
}


type AssistanceRequest struct {
	ID                uint   `json:"id" gorm:"primaryKey;autoIncrement"`
	ResourceType      string `json:"resourceType" binding:"required"`
	ResourceName      string `json:"resourceName" binding:"required"`
	Quantity          string    `json:"quantity" binding:"required"`
	AdditionalComment string `json:"additionalComment"`
}


type AlertPotentialDisasterReport struct {
	DisasterType string  `form:"disasterType" binding:"required"`
	Severity     string  `form:"severity" binding:"required,oneof=low medium high"`
	Description  string  `form:"description" binding:"required"`
	Latitude     float64 `form:"latitude" binding:"required"`
	Longitude    float64 `form:"longitude" binding:"required"`
}

type Alert struct {
	Type       string    `json:"type"`
	Severity   string    `json:"severity"`
	User       string    `json:"user"`
	Message    string    `json:"message"`
	Timestamp  time.Time `json:"timestamp"`
	Latitude   float64   `json:"latitude"`
	Longitude  float64   `json:"longitude"`
}

type Resources struct {
	ID           uint   `json:"id" gorm:"primaryKey;autoIncrement"`
    Name         string `json:"name"`
    Type         string `json:"type"`
    Availability string   `json:"availability"`
    Quantity     int    `json:"quantity"`
}

type NaturalDisaster struct {
    ID   uint   `json:"id" gorm:"primaryKey;autoIncrement"`
    Name string `json:"name"`
}

type Volunteer struct {
    ID           uint   `gorm:"primaryKey;autoIncrement"`
    Name         string `form:"name" binding:"required"`
    City         string `form:"city" binding:"required"`
    MobileNumber string `form:"mobile_number" binding:"required"`
}
