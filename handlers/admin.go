package routes

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"main.go/database"
	"main.go/jwt"
	"main.go/model"
)

// Global variables are declared to store error messages, admin verification details, and user information.
var Err string
var Verify model.AdminModel
var UserTable []model.UserModel

// A constant RoleAdmin is declared with the value-admin
const RoleAdmin = "admin"

func Admin(c *gin.Context) {
	// Setting Cache-Control header to ensure no caching
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")

	// Retrieving session
	session := sessions.Default(c)
	check := session.Get(RoleAdmin)

	// If admin is not logged in, render the admin page with any error message
	if check == nil {
		if c.Request.Header.Get("Content-Type") == "application/json" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Admin not authenticated"})
		} else {
			c.HTML(200, "Admin.html", Err)
			Err = ""
		}
	} else {
		c.Redirect(http.StatusSeeOther, "/valadmin")
	}
}

func PostAdmin(c *gin.Context) {
	Verify = model.AdminModel{}
	database.DB.First(&Verify, "email=?", c.Request.PostFormValue("AEmail"))
	if Verify.Password == c.Request.FormValue("Apassword") {
		if c.Request.Header.Get("Content-Type") == "application/json" {
			c.JSON(http.StatusOK, gin.H{"message": "Admin logged in successfully"})
		} else {
			jwt.JwtToken(c, Verify.Email, RoleAdmin)
			c.Redirect(http.StatusSeeOther, "/valadmin")
		}
	} else {
		Err = "Invalid email or password"
		if c.Request.Header.Get("Content-Type") == "application/json" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": Err})
		} else {
			c.Redirect(http.StatusSeeOther, "/admin")
		}
	}
}

func Valadmin(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	session := sessions.Default(c)
	check := session.Get(RoleAdmin)
	if check != nil {
		// Fetch user table from the database
		database.DB.Find(&UserTable)

		// Fetch disaster reports from the database
		reports, err := FetchDisasterReportsFromDatabase()
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": err.Error()})
			return
		}

		// Fetch assistance requests from the database
		requests, err := FetchAssistanceRequestsFromDatabase()
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": err.Error()})
			return
		}

		alerts, err := FetchPotentialDisasterAlertsFromDatabase()
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": err.Error()})
			return
		}

		resources, err := FetchResourcesFromDatabase()
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": err.Error()})
			return
		}

		// Fetch disasters from the database
		disasters, err := FetchDisastersFromDatabase()
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": err.Error()})
			return
		}

		latestReport, err := FetchLatestDisasterReportFromDatabase()
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": err.Error()})
			return
		}
		volunteers, err := FetchVolunteersFromDatabase()
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": err.Error()})
			return
		}

		if c.Request.Header.Get("Content-Type") == "application/json" {
			c.JSON(200, gin.H{
				"Name":                    Verify.Name,
				"Users":                   UserTable,
				"Disasters":               disasters,
				"DisasterReports":         reports,
				"AssistanceRequests":      requests,
				"Resources":               resources,
				"LatestDisasterReport":    latestReport,
				"PotentialDisasterAlerts": alerts,
				"Volunteers":              volunteers,
				"Error":                   Err,
			})
		} else {
			c.HTML(200, "Adminhome.html", gin.H{
				"Name":                    Verify.Name,
				"Users":                   UserTable,
				"Disasters":               disasters,
				"Reports":                 reports,
				"AssistanceRequests":      requests, // Pass assistance requests to the HTML template
				"Resources":               resources,
				"LatestDisasterReport":    latestReport,
				"PotentialDisasterAlerts": alerts,
				"Volunteers":              volunteers,
				"Error":                   Err,
			})
			Error = ""
			Err = ""
		}
	} else {
		c.Redirect(http.StatusSeeOther, "/admin")
	}
}

func FetchVolunteersFromDatabase() ([]model.Volunteer, error) {
	var volunteers []model.Volunteer
	if err := database.DB.Find(&volunteers).Error; err != nil {
		return volunteers, err
	}
	return volunteers, nil
}

func GetLatestDisasterCoordinates(c *gin.Context) {
	var latestReport model.DisasterReport

	// Fetch the latest disaster report from the database ordered by the ID column
	if err := database.DB.Order("id desc").First(&latestReport).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	coordinates := struct {
		Latitude  string `json:"latitude"`
		Longitude string `json:"longitude"`
	}{
		Latitude:  latestReport.Latitude,
		Longitude: latestReport.Longitude,
	}
	fmt.Println(latestReport.Latitude)

	c.JSON(http.StatusOK, coordinates)
}

func FetchLatestDisasterReportFromDatabase() (model.DisasterReport, error) {
	var latestReport model.DisasterReport
	if err := database.DB.Order("id desc").First(&latestReport).Error; err != nil {
		return latestReport, err
	}
	return latestReport, nil
}

func FetchResourcesFromDatabase() ([]model.Resources, error) {
	var resources []model.Resources
	if err := database.DB.Find(&resources).Error; err != nil {
		return nil, err
	}
	return resources, nil
}

func FetchDisasterReportsFromDatabase() ([]model.DisasterReport, error) {
	// Fetch all the reports from the database
	var reports []model.DisasterReport
	if err := database.DB.Find(&reports).Error; err != nil {
		return nil, err
	}
	return reports, nil
}

func GetAllDisasters(c *gin.Context) {
	disasters, err := FetchDisastersFromDatabase()
	// fmt.Println(disasters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if c.Request.Header.Get("Content-Type") == "application/json" {
		c.HTML(http.StatusOK, "Adminhome.html", gin.H{"disasters": disasters})
	} else {
		c.JSON(http.StatusOK, gin.H{"disasters": disasters})
	}
}

func FetchAssistanceRequestsFromDatabase() ([]model.AssistanceRequest, error) {
	// Fetch all the assistance requests from the database
	var requests []model.AssistanceRequest
	if err := database.DB.Find(&requests).Error; err != nil {
		return nil, err
	}
	return requests, nil
}

func FetchDisastersFromDatabase() ([]model.NaturalDisaster, error) {
	var disasters []model.NaturalDisaster
	if err := database.DB.Find(&disasters).Error; err != nil {
		return nil, err
	}
	return disasters, nil
}

func FetchPotentialDisasterAlertsFromDatabase() ([]model.AlertPotentialDisasterReport, error) {
	// Fetch all the alerts from the database
	var alerts []model.AlertPotentialDisasterReport
	if err := database.DB.Find(&alerts).Error; err != nil {
		return nil, err
	}
	return alerts, nil
}

func Adminlogout(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	session := sessions.Default(c)
	session.Delete(RoleAdmin)
	session.Save()
	Err = "Successfully logged out"
	if c.Request.Header.Get("Content-Type") == "application/json" {
		c.JSON(http.StatusOK, gin.H{"message": Err})
	} else {
		c.Redirect(http.StatusSeeOther, "/admin")
	}
}

func Delete(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	session := sessions.Default(c)
	check := session.Get(RoleAdmin)
	if check != nil {
		user := c.Param("ID")
		database.DB.First(&UpdateUser, "ID=?", user)
		database.DB.Delete(&UpdateUser)
		UpdateUser = model.UserModel{}
		if c.Request.Header.Get("Content-Type") == "application/json" {
			c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
		} else {
			c.Redirect(http.StatusSeeOther, "/valadmin")
		}
	} else {
		if c.Request.Header.Get("Content-Type") == "application/json" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Admin not authenticated"})
		} else {
			c.Redirect(http.StatusSeeOther, "/admin")
		}
	}
}

func Update(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	session := sessions.Default(c)
	check := session.Get(RoleAdmin)
	if check != nil {
		user := c.Param("ID")
		if c.Request.Header.Get("Content-Type") == "application/json" {
			c.JSON(http.StatusOK, gin.H{"message": "Update user with ID: " + user})
		} else {
			c.HTML(http.StatusOK, "update.html", user)
		}
	} else {
		if c.Request.Header.Get("Content-Type") == "application/json" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Admin not authenticated"})
		} else {
			c.Redirect(http.StatusSeeOther, "/admin")
		}
	}
}

func Updateuser(c *gin.Context) {
	user := c.Param("ID")
	database.DB.First(&UpdateUser, "ID=?", user)
	UpdateUser.Name = c.Request.FormValue("name")
	UpdateUser.Email = c.Request.FormValue("email")
	database.DB.Save(&UpdateUser)
	Err = "User details updated successfully"
	if c.Request.Header.Get("Content-Type") == "application/json" {
		c.JSON(http.StatusOK, gin.H{"message": Err})
	} else {
		c.Redirect(http.StatusSeeOther, "/valadmin")
	}
}

func Block(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	session := sessions.Default(c)
	check := session.Get(RoleAdmin)
	if check != nil {
		userID := c.Param("ID") // Get the user ID from the request parameters
		var updateUser model.UserModel
		result := database.DB.First(&updateUser, "ID = ?", userID)
		if result.Error != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})
			return
		}

		// Toggle user status between Active and Blocked
		if updateUser.Status == "Active" {
			updateUser.Status = "Blocked"
		} else {
			updateUser.Status = "Active"
		}

		if err := database.DB.Save(&updateUser).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user status"})
			return
		}

		if c.Request.Header.Get("Content-Type") == "application/json" {
			c.JSON(http.StatusOK, gin.H{"message": "User status updated successfully"})
		} else {
			c.Redirect(http.StatusSeeOther, "/valadmin")
		}
	} else {
		c.Redirect(http.StatusSeeOther, "/admin")
	}
}

func Search(c *gin.Context) {
	query := c.Query("query")
	var searchResults []model.UserModel
	for _, user := range UserTable {
		if strings.Contains(strings.ToLower(user.Name), strings.ToLower(query)) ||
			strings.Contains(strings.ToLower(user.Email), strings.ToLower(query)) {
			searchResults = append(searchResults, user)
		}
	}
	if c.Request.Header.Get("Content-Type") == "application/json" {
		c.JSON(http.StatusOK, gin.H{"Results": searchResults})
	} else {
		c.HTML(http.StatusOK, "SearchResults.html", gin.H{"Results": searchResults, "Query": query})
	}
}

func AddUser(c *gin.Context) {
	name := c.PostForm("name")
	email := c.PostForm("email")
	password := c.PostForm("password")
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	newUser := model.UserModel{
		Name:     name,
		Email:    email,
		Password: string(hashedPassword),
	}
	database.DB.Create(&newUser)
	if c.Request.Header.Get("Content-Type") == "application/json" {
		c.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
	} else {
		c.Redirect(http.StatusSeeOther, "/valadmin")
	}
}
