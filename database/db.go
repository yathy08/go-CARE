package database

import (
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"main.go/model"
)

var DB *gorm.DB

func DBconnect() {
	dsn := os.Getenv("DSN")

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect to database")
	}
	DB = db

	DB.AutoMigrate(&model.UserModel{}, &model.AdminModel{}, &model.DisasterReport{}, &model.AlertPotentialDisasterReport{}, &model.AssistanceRequest{}, &model.Resources{}, &model.NaturalDisaster{}, &model.Volunteer{}, &model.MessageModel{})
}
