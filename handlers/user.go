package routes

import (
	"encoding/json"
	"fmt"
	"strconv"

	// "log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/twilio/twilio-go"
	verify "github.com/twilio/twilio-go/rest/verify/v2"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"main.go/database"
	"main.go/jwt"
	"main.go/model"
)

var Error string
var Fetch model.UserModel
var UpdateUser model.UserModel

const RoleUser = "user"

func Login(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")

	// Check if the request accepts JSON
	if c.Request.Header.Get("Content-Type") == "application/json" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Please use HTML form data for login"})
		return
	}

	session := sessions.Default(c)
	check := session.Get(RoleUser)
	if check == nil {
		c.HTML(200, "login.html", Error)
		Error = ""
	} else {
		c.Redirect(http.StatusSeeOther, "/home")
	}
}

func Postlogin(c *gin.Context) {
	var user model.UserModel

	// Check if the request content type is JSON
	if c.Request.Header.Get("Content-Type") == "application/json" {
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else { // Assume HTML form data
		user.Email = c.PostForm("Email")
		password := c.PostForm("password")

		database.DB.First(&user, "email=?", user.Email)

		err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Username or Password"})
			return
		}

		if user.Status == "Blocked" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Blocked User"})
			return
		}

		jwt.JwtToken(c, user.Email, RoleUser)
		c.Redirect(http.StatusSeeOther, "/home")
		return
	}

	// Handle JSON request separately
	password := c.PostForm("password")

	database.DB.First(&user, "email=?", user.Email)

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Username or Password"})
		return
	}

	if user.Status == "Blocked" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Blocked User"})
		return
	}

	jwt.JwtToken(c, user.Email, RoleUser)
	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

func RegisterRoutes(router *gin.Engine) {
	router.POST("/api/send-otp", SendOTPHandler())
}

// Define the handler function
func SendOTPHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		phoneNumber := c.PostForm("phone_number")
		err := SendOTP(phoneNumber)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "OTP sent successfully"})
	}
}

func SendOTP(phoneNumber string) error {
	//Load Twilio credentials from enviornment variable
	accountSID := os.Getenv("TWILIO_ACCOUNT_SID")
	authToken := os.Getenv("TWILIO_AUTH_TOKEN")

	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSID,
		Password: authToken,
	})

	//Create SMS message
	from := os.Getenv("TWILIO_PHONE_NUMBER")
	params := verify.CreateVerificationParams{}
	params.SetTo("+919508223747")
	params.SetChannel("sms")
	println(from)
	response, err := client.VerifyV2.CreateVerification(os.Getenv("SERVICE_TOKEN"), &params)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	fmt.Println(response)

	return nil
}

func UserHome(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	session := sessions.Default(c)
	check := session.Get(RoleUser)
	if check != nil {
		if c.Request.Header.Get("Content-Type") == "application/json" {
			c.JSON(http.StatusOK, gin.H{
				"Name":  Fetch.Name,
				"Email": Fetch.Email,
			})
		} else {
			c.HTML(200, "user.html", gin.H{
				"Name":  Fetch.Name,
				"Email": Fetch.Email,
			})
		}
	} else {
		c.Redirect(http.StatusSeeOther, "/")
	}
}

func Signup(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")

	session := sessions.Default(c)
	check := session.Get(RoleUser)

	if check != nil {
		if c.Request.Header.Get("Content-Type") == "application/json" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Already logged in"})
		} else {
			c.Redirect(http.StatusSeeOther, "/home")
		}
	} else {
		if c.Request.Header.Get("Content-Type") == "application/json" {
			c.JSON(http.StatusOK, gin.H{"message": "Signup page"})
		} else {
			c.HTML(200, "Signup.html", Error)
			Error = ""
		}
	}
}

func Postsignup(c *gin.Context) {

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(c.Request.PostFormValue("password")), 10)
	if err != nil {

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}

	newUser := model.UserModel{
		Name:     c.Request.PostFormValue("username"),
		Email:    c.Request.PostFormValue("email"),
		Password: string(hashedPassword),
		Status:   "Block",
		Phone:    c.Request.PostFormValue("phone_number"),
	}
	fmt.Println(newUser.Phone)
	userData, err := json.Marshal(newUser)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"failed": false, "message": "Failed to marshal data"})
		return
	}

	key := fmt.Sprintf("user:%s", newUser.Phone)
	err = database.SetRedis(key, userData, time.Minute*10)
	if err != nil {
		fmt.Println("set redis", err.Error())
		fmt.Println("user :", userData)
		c.JSON(http.StatusBadRequest, gin.H{"failed": false, "message": "Failed to set data in redis"})
		return
	}

	fmt.Println("setkey: ", key)
	Error = "Successfully signed up"
	c.Redirect(http.StatusSeeOther, "/")
}
func Logout(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")

	session := sessions.Default(c)
	session.Delete(RoleUser)
	session.Save()

	Fetch = model.UserModel{}
	Error = "Successfully Logged out"

	c.Redirect(http.StatusSeeOther, "/")
}

func SignupVerify(c *gin.Context) {

	accountSID := os.Getenv("TWILIO_ACCOUNT_SID")
	authToken := os.Getenv("TWILIO_AUTH_TOKEN")
	serviceToken := os.Getenv("SERVICE_TOKEN")

	// Parse request body into VerifyOTP struct
	var verifyModel model.VerifyOTP
	if err := c.BindJSON(&verifyModel); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Failed to parse request body"})
		return
	}

	verifyModel.Phone = "+919508223747"
	// Check if OTP is provided
	if verifyModel.Otp == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "OTP is required"})
		return
	}

	// Create Twilio REST client
	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSID,
		Password: authToken,
	})

	// Create parameters for Twilio verification check
	params := verify.CreateVerificationCheckParams{}
	params.SetTo("+919508223747")
	params.SetCode(verifyModel.Otp)

	// Send Twilio verification check
	resp, err := client.VerifyV2.CreateVerificationCheck(serviceToken, &params)
	if err != nil {

		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to verify OTP with Twilio"})
		return
	}

	// Check if the verification was successful
	if resp.Status != nil && *resp.Status == "approved" {
		// OTP verified, proceed with user creation
		key := fmt.Sprintf("user:%s", verifyModel.Phone)
		fmt.Println("getkey: ", key)
		userJson, err := database.GetRedis(key)
		if err != nil {
			fmt.Println(err.Error())
			c.JSON(http.StatusBadGateway, gin.H{"failed": false, "message": "Failed to get data from redis"})
			return
		}
		var user model.UserModel
		err = json.Unmarshal([]byte(userJson), &user)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"failed": false, "message": "Failed to unmarshal data"})
			return
		}
		// user := model.UserModel{Phone: verifyModel.Phone}
		if err := database.DB.Create(&user).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Failed to create user"})
			return
		}

		// Success response
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "OTP verified successfully"})
	} else {
		// Verification failed
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Incorrect OTP"})
	}
}
func SaveReportToDatabase(report *model.DisasterReport) error {
	// Save the report to the database
	if result := database.DB.Create(report); result.Error != nil {
		return result.Error
	}
	return nil
}

func PostReportDisaster(c *gin.Context) {
	// Parse form data
	if err := c.Request.ParseForm(); err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse form data"})
		return
	}

	data := c.Request.PostForm
	report := model.DisasterReport{
		DisasterType: data.Get("DisasterType"),
		Latitude:     data.Get("Latitude"),
		Longitude:    data.Get("longitude"),
		FileURL:      data.Get("file"),
		Severity:     data.Get("severity"),
		Description:  data.Get("description"),
	}

	// Save the report to the database
	if err := SaveReportToDatabase(&report); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save report"})
		return
	}

	c.Redirect(http.StatusFound, "/")
}

func GetReportDisaster(c *gin.Context) {

	if c.Request.Header.Get("Accept") == "application/json" {

		data := gin.H{
			"message": "Welcome to the disaster reporting page",
		}
		c.JSON(http.StatusOK, data)
	} else {

		c.HTML(http.StatusOK, "ReportDisaster.html", nil)
	}
}

func GetAlertPotentialDisaster(c *gin.Context) {
	c.HTML(http.StatusOK, "AlertPotentialDisaster.html", nil)
}

func GetRequestAssistance(c *gin.Context) {
	c.HTML(http.StatusOK, "RequestAssistance.html", nil)
}

func PostRequestAssistance(c *gin.Context) {
	// Bind the form data from the request body to AssistanceRequest struct
	var request model.AssistanceRequest
	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Save the assistance request data into the database
	if err := SaveToDatabase(&request); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save assistance request"})
		return
	}

	// Return a success response
	c.JSON(http.StatusOK, gin.H{"message": "Assistance request submitted successfully"})
}

func SaveToDatabase(request *model.AssistanceRequest) error {
	// Save the request to the database
	if err := database.DB.Create(request).Error; err != nil {
		return err
	}
	return nil
}

func PostAlertPotentialDisaster(c *gin.Context) {

	var preport model.AlertPotentialDisasterReport
	if err := c.BindJSON(&preport); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		fmt.Println(err.Error())
		fmt.Println("errrrrr", preport)
		return
	}
	if err := SaveInTheDatabase(&preport); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save assistance request"})
		return
	}

	// Return a success response
	c.JSON(http.StatusOK, gin.H{"message": "Potential disaster alert request submitted successfully"})
}

func SaveInTheDatabase(preport *model.AlertPotentialDisasterReport) error {

	if err := database.DB.Create(preport).Error; err != nil {
		return err
	}
	return nil
}

func CreateResource(c *gin.Context) {
	var resource model.Resources
	if err := c.BindJSON(&resource); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		// fmt.Println(err)
		return
	}

	if err := database.DB.Create(&resource).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, resource)
}

// GetResourceByIDHandler retrieves a resource by ID
func GetResourceByID(c *gin.Context) {
	id := c.Param("id")
	var resource model.Resources
	if err := database.DB.First(&resource, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resource)
}

func UpdateResource(c *gin.Context) {
	id := c.Param("id") // Extract resource ID from URL

	// Retrieve the resource from the database by its ID
	var existingResource model.Resources
	if err := database.DB.First(&existingResource, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Resource not found"})
		return
	}

	// Bind the updated resource data from the request body
	var updatedResource model.Resources
	if err := c.BindJSON(&updatedResource); err != nil {
		fmt.Println("here", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	existingResource.Name = updatedResource.Name
	existingResource.Type = updatedResource.Type
	existingResource.Availability = updatedResource.Availability
	existingResource.Quantity = updatedResource.Quantity

	// Save the updated resource back to the database
	if err := database.DB.Save(&existingResource).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, existingResource)
}

func DeleteResource(c *gin.Context) {
	id := c.Param("id")
	var resource model.Resources
	if err := database.DB.Delete(&resource, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

func AddDisaster(c *gin.Context) {
	var disaster model.NaturalDisaster
	if err := c.BindJSON(&disaster); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Create(&disaster).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, disaster)
}

func DeleteDisaster(c *gin.Context) {
	id := c.Param("id")
	var disaster model.NaturalDisaster
	if err := database.DB.Delete(&disaster, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

func UpdateDisaster(c *gin.Context) {
	id := c.Param("id") // Extract disaster ID from URL

	// Retrieve the disaster from the database by its ID
	var existingDisaster model.NaturalDisaster
	if err := database.DB.First(&existingDisaster, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Disaster not found"})

		return
	}

	// Bind the updated disaster name from the request body
	var updatedName struct {
		Name string `json:"name"`
	}
	if err := c.BindJSON(&updatedName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})

		return
	}

	existingDisaster.Name = updatedName.Name

	// Save the updated disaster name back to the database
	if err := database.DB.Save(&existingDisaster).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		fmt.Println(err)
		return
	}

	c.JSON(http.StatusOK, existingDisaster)
}

// Handler function for resource allocation
func AllocateResource(c *gin.Context) {
	// Extract the ID of the assistance request from the URL parameter
	requestId := c.Param("id")

	// Fetch the assistance request from the database
	var request model.AssistanceRequest
	if err := database.DB.First(&request, requestId).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Assistance request not found"})
		return
	}

	// Fetch the available resources from the database based on the requested resource name
	var resource model.Resources
	if err := database.DB.Where("name = ? AND availability = ?", request.ResourceName, "true").First(&resource).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Requested resource not available"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Convert the quantity from string to int
	quantity, err := strconv.Atoi(request.Quantity)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid quantity format"})
		return
	}

	// Check if the requested quantity of resource is available
	if resource.Quantity < quantity {
		c.JSON(http.StatusNotFound, gin.H{"error": "Insufficient resources available"})
		return
	}

	// Calculate the remaining quantity of resources after allocation
	remainingQuantity := resource.Quantity - quantity

	// Update the database with the allocated resources
	if err := database.DB.Model(&resource).Update("quantity", remainingQuantity).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Delete the assistance request from the database
	if err := database.DB.Delete(&request).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Construct the success message
	successMessage := fmt.Sprintf("Successfully allocated %d %s", quantity, request.ResourceName)

	// Send the success message
	c.JSON(http.StatusOK, gin.H{"message": successMessage})
}

func SaveVolunteerToDatabase(volunteer *model.Volunteer) error {
	// Save the volunteer to the database
	if result := database.DB.Create(volunteer); result.Error != nil {
		return result.Error
	}
	return nil
}

func SubmitVolunteerForm(c *gin.Context) {
	// Parse form data
	var volunteer model.Volunteer
	if err := c.Bind(&volunteer); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse form data"})
		return
	}

	// Save the volunteer to the database
	if err := SaveVolunteerToDatabase(&volunteer); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save volunteer"})
		return
	}

	// Respond with success message
	c.JSON(http.StatusOK, gin.H{"message": "Volunteer application submitted successfully!"})
}
func GetvolunteerForm(c *gin.Context) {
	c.HTML(http.StatusOK, "volunteer.html", nil)
}

// AddVolunteer adds a new volunteer to the database
func AddVolunteer(c *gin.Context) {
	var volunteer model.Volunteer
	if err := c.ShouldBind(&volunteer); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Save the volunteer to the database
	if err := SaveVolunteerToDatabase(&volunteer); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add volunteer"})
		return
	}

	// Respond with success message
	c.JSON(http.StatusOK, gin.H{"message": "Volunteer added successfully"})
}

// DeleteVolunteerByName deletes a volunteer from the database by name
func DeleteVolunteerByName(c *gin.Context) {
	name := c.Param("name")
	if err := database.DB.Where("name = ?", name).Delete(&model.Volunteer{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete volunteer"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Volunteer deleted successfully"})
}

// GetVolunteerByName retrieves a volunteer by its name from the database
func GetVolunteerByName(c *gin.Context) {
	name := c.Param("name")
	var volunteer model.Volunteer
	if err := database.DB.Where("name = ?", name).First(&volunteer).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Volunteer not found"})
		return
	}

	c.JSON(http.StatusOK, volunteer)
}

// Function to handle sending help
func SendHelp(c *gin.Context) {
	var city string
	if err := c.ShouldBindJSON(&city); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "City is required"})
		return
	}

	// Get the database connection
	db := database.DB

	// Retrieve a volunteer from the specified city
	var volunteer model.Volunteer
	if err := db.Where("city = ?", city).First(&volunteer).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No volunteers available from the specified city"})
		return
	}

	// Display the name of the volunteer who will assist
	fmt.Printf("Volunteer %s from %s will assist you.\n", volunteer.Name, volunteer.City)

	// Respond with success message
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Volunteer %s from %s will assist you.", volunteer.Name, volunteer.City)})
}


func GetVolunteer(c *gin.Context) {
    // Get city from query parameter
    city := c.Query("city")

    // Query the database for a volunteer in the specified city
    var volunteer model.Volunteer
    result := database.DB.Where("city = ?", city).First(&volunteer)
    if result.Error != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "No volunteer found for the city " + city})
        return
    }

    // Return volunteer details as JSON response
    c.JSON(http.StatusOK, gin.H{
        "name":         volunteer.Name,
        "city":         volunteer.City,
        "mobile_number": volunteer.MobileNumber,
    })
}



func DeleteVolunteer(c *gin.Context) {
    // Extract the volunteer ID from the URL path
    volunteerID := c.Param("id")

    // Ensure volunteerID is a valid integer
    id, err := strconv.ParseUint(volunteerID, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid volunteer ID"})
        return
    }

    // Perform the deletion operation (assuming db is the Gorm database connection)
    if err := database.DB.Where("id = ?", id).Delete(&model.Volunteer{}).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete volunteer"})
        return
    }

    // Return success response
    c.JSON(http.StatusOK, gin.H{"message": "Volunteer deleted successfully"})
}

func DeleteReport(c *gin.Context) {
    // Extract the report ID from the URL path
    reportID := c.Param("id")

    // Ensure reportID is a valid integer
    id, err := strconv.ParseUint(reportID, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid report ID"})
        return
    }

    // Perform the deletion operation (assuming db is the Gorm database connection)
    if err := database.DB.Where("id = ?", id).Delete(&model.DisasterReport{}).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete report"})
        return
    }

    // Return success response
    c.JSON(http.StatusOK, gin.H{"message": "Report deleted successfully"})
}

