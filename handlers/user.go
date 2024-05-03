package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/twilio/twilio-go"
	twilioApi "github.com/twilio/twilio-go/rest/api/v2010"
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

	if c.Request.Header.Get("Content-Type") == "application/json" {
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else {
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

		jwt.JwtToken(c, user.Email, RoleUser,user.Name)
		c.Redirect(http.StatusSeeOther, "/home")
		return
	}

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

	jwt.JwtToken(c, user.Email, RoleUser,user.Name)
	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

func RegisterRoutes(router *gin.Engine) {
	router.POST("/api/send-otp", SendOTPHandler())
}

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

	accountSID := os.Getenv("TWILIO_ACCOUNT_SID")
	authToken := os.Getenv("TWILIO_AUTH_TOKEN")

	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSID,
		Password: authToken,
	})

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
	name := session.Get("username")
	// user := getUserByEmail()
	if check != nil {
		if c.Request.Header.Get("Content-Type") == "application/json" {
			c.JSON(http.StatusOK, gin.H{
				"Name":  name,
				"Email": Fetch.Email,
			})
		} else {
			c.HTML(200, "user.html", gin.H{
				"Name":  name,
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

	var verifyModel model.VerifyOTP
	if err := c.BindJSON(&verifyModel); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Failed to parse request body"})
		return
	}

	verifyModel.Phone = "+919508223747"

	if verifyModel.Otp == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "OTP is required"})
		return
	}

	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSID,
		Password: authToken,
	})

	params := verify.CreateVerificationCheckParams{}
	params.SetTo("+919508223747")
	params.SetCode(verifyModel.Otp)

	resp, err := client.VerifyV2.CreateVerificationCheck(serviceToken, &params)
	if err != nil {

		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Failed to verify OTP with Twilio"})
		return
	}

	if resp.Status != nil && *resp.Status == "approved" {

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

		if err := database.DB.Create(&user).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Failed to create user"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "OTP verified successfully"})
	} else {

		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Incorrect OTP"})
	}
}
func SaveReportToDatabase(report *model.DisasterReport) error {

	if result := database.DB.Create(report); result.Error != nil {
		return result.Error
	}
	return nil
}

func PostReportDisaster(c *gin.Context) {
	fmt.Println(c.Request)

	var datas model.DisasterReport

	fmt.Println(c.ShouldBind(datas))

	fmt.Println(datas)

	if err := c.Request.ParseForm(); err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse form data"})
		return
	}

	data := c.Request.PostForm

	fmt.Println("data :", data)
	report := model.DisasterReport{
		DisasterType: data.Get("disasterType"),
		Latitude:     data.Get("latitude"),
		Longitude:    data.Get("longitude"),
		FileURL:      data.Get("file"),
		Severity:     data.Get("severity"),
		Description:  data.Get("description"),
	}

	if err := SaveReportToDatabase(&report); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save report"})
		return
	}

	c.JSON(200, gin.H{"message": "saved data"})

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
    var request model.AssistanceRequest
    if err := c.BindJSON(&request); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    if err := SaveToDatabase(&request); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save assistance request"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Assistance request submitted successfully"})
}

func SaveToDatabase(request *model.AssistanceRequest) error {
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

		return
	}

	if err := database.DB.Create(&resource).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, resource)
}

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
	id := c.Param("id")

	var existingResource model.Resources
	if err := database.DB.First(&existingResource, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Resource not found"})
		return
	}

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
	id := c.Param("id")

	var existingDisaster model.NaturalDisaster
	if err := database.DB.First(&existingDisaster, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Disaster not found"})

		return
	}

	var updatedName struct {
		Name string `json:"name"`
	}
	if err := c.BindJSON(&updatedName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})

		return
	}

	existingDisaster.Name = updatedName.Name

	if err := database.DB.Save(&existingDisaster).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		fmt.Println(err)
		return
	}

	c.JSON(http.StatusOK, existingDisaster)
}

func AllocateResource(c *gin.Context) {

	requestId := c.Param("id")

	var request model.AssistanceRequest
	if err := database.DB.First(&request, requestId).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Assistance request not found"})
		return
	}

	var resource model.Resources
	if err := database.DB.Where("name = ? AND availability = ?", request.ResourceName, "true").First(&resource).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Requested resource not available"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	quantity, err := strconv.Atoi(request.Quantity)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid quantity format"})
		return
	}

	if resource.Quantity < quantity {
		c.JSON(http.StatusNotFound, gin.H{"error": "Insufficient resources available"})
		return
	}

	remainingQuantity := resource.Quantity - quantity

	if err := database.DB.Model(&resource).Update("quantity", remainingQuantity).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Delete(&request).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	successMessage := fmt.Sprintf("Successfully allocated %d %s", quantity, request.ResourceName)

	c.JSON(http.StatusOK, gin.H{"message": successMessage})
}

func SaveVolunteerToDatabase(volunteer *model.Volunteer) error {

	if result := database.DB.Create(volunteer); result.Error != nil {
		return result.Error
	}
	return nil
}

func SubmitVolunteerForm(c *gin.Context) {

	var volunteer model.Volunteer
	if err := c.Bind(&volunteer); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse form data"})
		return
	}

	if err := SaveVolunteerToDatabase(&volunteer); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save volunteer"})
		return
	}
	 // Check if availability is provided
	 if volunteer.Availability == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Availability not provided"})
        return
    }


	c.JSON(http.StatusOK, gin.H{"message": "Volunteer application submitted successfully!"})
}
func GetvolunteerForm(c *gin.Context) {
	c.HTML(http.StatusOK, "volunteer.html", nil)
}

func AddVolunteer(c *gin.Context) {
	var volunteer model.Volunteer
	if err := c.ShouldBind(&volunteer); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := SaveVolunteerToDatabase(&volunteer); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add volunteer"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Volunteer added successfully"})
}

func DeleteVolunteerByName(c *gin.Context) {
	name := c.Param("name")
	if err := database.DB.Where("name = ?", name).Delete(&model.Volunteer{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete volunteer"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Volunteer deleted successfully"})
}

func DeleteReport(c *gin.Context) {

	reportID := c.Param("id")

	id, err := strconv.ParseUint(reportID, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid report ID"})
		return
	}

	if err := database.DB.Where("id = ?", id).Delete(&model.DisasterReport{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete report"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Report deleted successfully"})
}
func DeletePotentialDReport(c *gin.Context) {
    // Retrieve the disaster type from the URL parameter
    disasterType := c.Param("disasterType")

    // Check if the disaster type is empty
    if disasterType == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Disaster type is required"})
        return
    }

    // Perform the deletion of the first disaster report of the specified type from the database
    if err := database.DB.Where("disaster_type = ?", disasterType).Delete(&model.AlertPotentialDisasterReport{}).Limit(1).Error; err != nil {
        // If there's an error during deletion, return an error response
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete report"})
        return
    }

    // If deletion is successful, return a success response
    c.JSON(http.StatusOK, gin.H{"message": "First report of disaster type deleted successfully"})
}


func GetUserChatMessagesHandler(c *gin.Context) {
	userId := c.Param("userId")
	var messages []model.MessageModel
	if err := database.DB.Where("user_id = ?", userId).Find(&messages).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch chat messages"})
		return
	}
	c.JSON(http.StatusOK, messages)
	fmt.Println(messages)
}

func SendMessageHandler(c *gin.Context) {
	userIdStr := c.Param("userId")
	userId, err := strconv.ParseUint(userIdStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var message struct {
		Content string `json:"content"`
	}
	if err := c.BindJSON(&message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	newMessage := model.MessageModel{
		Content:   message.Content,
		Sender:    "Admin",
		UserID:    uint(userId),
		CreatedAt: time.Now(),
	}
	if err := database.DB.Create(&newMessage).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send message"})
		return
	}
	c.Status(http.StatusOK)
}

func GetVolunteerByCityHandler(c *gin.Context) {
	// Get the city from the query parameter
	city := c.Query("city")

	// Check if the city is provided
	if city == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "City parameter is missing"})
		return
	}

	// Find the first volunteer in the specified city
	var volunteer model.Volunteer
	if err := database.DB.Where("city = ? AND availability = ?", city, "available").First(&volunteer).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No available volunteers found for the specified city"})
		return
	}

	// Set the availability of the volunteer to "not-available"
	volunteer.Availability = "not-available"
	if err := database.DB.Save(&volunteer).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update volunteer availability"})
		return
	}

	// Send a WhatsApp message to the volunteer
	err := sendWhatsAppMessage(volunteer.MobileNumber, "You should reach the location along with your team as soon as possible")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send WhatsApp message"})
		return
	}

	// Return the volunteer's details along with updated availability
	c.JSON(http.StatusOK, gin.H{
		"volunteer": gin.H{
			"name":         volunteer.Name,
			"phone":        volunteer.MobileNumber,
			"availability": volunteer.Availability,
		},
	})
}


func ChangeAvailabilityHandler(c *gin.Context) {
    // Get the name of the volunteer from the request
    name := c.PostForm("name")

    // Fetch the volunteer from the database based on the name
    var volunteer model.Volunteer
    if err := database.DB.Where("name = ?", name).First(&volunteer).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Volunteer not found"})
        return
    }

    // Update the availability status of the volunteer
    volunteer.Availability = "available"

    // Save the updated volunteer back to the database
    if err := database.DB.Save(&volunteer).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update availability status"})
        return
    }

    // Send a success response
    c.JSON(http.StatusOK, gin.H{"message": "Availability status changed successfully!"})
}

func GetVolunteerDetailsHandler(c *gin.Context) {
    // Get the volunteer name from the query parameter
    volunteerName := c.Query("name")

    // Fetch the volunteer from the database based on the name
    var volunteer model.Volunteer
    if err := database.DB.Where("name = ?", volunteerName).First(&volunteer).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Volunteer not found"})
        return
    }

    // Send the volunteer's details as the response
    c.JSON(http.StatusOK, volunteer)
}

func SendMessageToVolunteer(_, _ string) error {

	accountSID := os.Getenv("TWILIO_ACCOUNT_SID")
	authToken := os.Getenv("TWILIO_AUTH_TOKEN")

	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSID,
		Password: authToken,
	})

	params := &twilioApi.CreateMessageParams{}
	params.SetTo("whatsapp:+919508223747")
	params.SetFrom("whatsapp:+14155238886")
	params.SetBody("Hello this is the admin speaking !!  Can You provide the updates regarding the Disaster Report and When will you be available again to join??")

	_, err := client.Api.CreateMessage(params)
	if err != nil {
		fmt.Println("Error sending WhatsApp message:", err.Error())
		return err
	}

	return nil
}
// Create a handler function that matches the Gin handler signature
func SendMessageToVolunteerHandler(c *gin.Context) {
    // Get the name of the volunteer from the request
    name := c.PostForm("name")

    // Call the SendMessageToVolunteer function
    err := SendMessageToVolunteer(name,name)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    // Send a success response
    c.JSON(http.StatusOK, gin.H{"message": "WhatsApp message sent successfully"})
}



func sendWhatsAppMessage(_, _ string) error {

	accountSID := os.Getenv("TWILIO_ACCOUNT_SID")
	authToken := os.Getenv("TWILIO_AUTH_TOKEN")

	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSID,
		Password: authToken,
	})

	params := &twilioApi.CreateMessageParams{}
	params.SetTo("whatsapp:+919508223747")
	params.SetFrom("whatsapp:+14155238886")
	params.SetBody("Hello this message is from the admin.  You should reach the location along with your team as soon as possible.")

	_, err := client.Api.CreateMessage(params)
	if err != nil {
		fmt.Println("Error sending WhatsApp message:", err.Error())
		return err
	}

	return nil
}
func SendMessageToUpdateHandler(c *gin.Context) {
	// Get the name of the volunteer from the request
	name := c.PostForm("name")

	// Call the sendUpdateMessage function
	err := sendUpdateMessage(name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Send a success response
	c.JSON(http.StatusOK, gin.H{"message": "WhatsApp update message sent successfully"})
}

func sendUpdateMessage(_ string) error {
	accountSID := os.Getenv("TWILIO_ACCOUNT_SID")
	authToken := os.Getenv("TWILIO_AUTH_TOKEN")

	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSID,
		Password: authToken,
	})

	params := &twilioApi.CreateMessageParams{}
	params.SetTo("whatsapp:+919508223747")
	params.SetFrom("whatsapp:+14155238886")
	params.SetBody("Hello This is the Admin From the GO-CARE .Your Requested resources will reach to you shortly.Any more updates Visit the GO-CARE site and report. Thanks.")


	_, err := client.Api.CreateMessage(params)
	if err != nil {
		fmt.Println("Error sending WhatsApp message:", err.Error())
		return err
	}

	return nil
}


func GetDisasterTypesHandler(c *gin.Context) {
	disasters, err := FetchDisasterssFromDatabase()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": err.Error()})
		return
	}

	c.HTML(http.StatusOK, "ReportDisaster.html", gin.H{
		"Disasters": disasters,
	})
}
func FetchDisasterssFromDatabase() ([]model.NaturalDisaster, error) {
	var disasters []model.NaturalDisaster
	if err := database.DB.Find(&disasters).Error; err != nil {
		return nil, err
	}
	return disasters, nil
}
func GetAllDisasterss(c *gin.Context) {
	disasters, err := FetchDisasterssFromDatabase()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"disasters": disasters})

}
func DeleteReportHandler(c *gin.Context) {

	id := c.Param("id")

	if err := DeleteReportFromDatabase(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete report"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Report deleted successfully"})
}

func DeleteReportFromDatabase(id string) error {
	var report model.DisasterReport
	result := database.DB.Where("id = ?", id).First(&report)
	if result.Error != nil {
		return result.Error
	}
	return database.DB.Delete(&report).Error
}


func DeleteeReportHandler(c *gin.Context) {

	disasterType := c.Param("disasterType")

	if err := DeleteeReportFromDatabase(disasterType); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete report"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Report deleted successfully"})
}

func DeleteeReportFromDatabase(disasterType string) error {
	var report model.AlertPotentialDisasterReport
	result := database.DB.Where("disasterType = ?", disasterType).First(&report)
	if result.Error != nil {
		return result.Error
	}
	return database.DB.Delete(&report).Error
}
