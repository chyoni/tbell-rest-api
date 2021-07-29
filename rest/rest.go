package rest

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/chiwon99881/restapi/db"
	"github.com/chiwon99881/restapi/entity"
	"github.com/chiwon99881/restapi/jwt"
	"github.com/chiwon99881/restapi/utility"
	"github.com/gorilla/mux"
)

const (
	port string = ":4000"
)

type errResponse struct {
	ErrMessage string `json:"errMessage"`
}

type tbellHomeResponse struct {
	CorporateName string `json:"corporateName"`
	Business      string `json:"business"`
}

type tbellUserResponse struct {
	Username       string `json:"username"`
	Gender         string `json:"gender"`
	FirstName      string `json:"firstName"`
	LastName       string `json:"lastName"`
	WorkExperience string `json:"workExperience"`
}

type loginRequest struct {
	Username string
	Password string
}

type loginResponse struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

type passwordUpdateData struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// GuardRequest is check authroized.
func GuardRequest(rw http.ResponseWriter, r *http.Request) (bool, interface{}) {
	userID, _, err := jwt.ExtractTokenMetaData(r)
	exist := false

	if userID == nil {
		rw.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(rw).Encode(errResponse{ErrMessage: "you are not authorized"})
		exist = true
		return exist, nil
	}
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(errResponse{ErrMessage: err.Error()})
		exist = true
		return exist, nil
	}
	return exist, userID
}

func isAuthenticated(rw http.ResponseWriter, r *http.Request, userID interface{}) bool {
	isLogged := false

	userIDAsString := fmt.Sprintf("%v", userID)
	userIDAsInt, err := strconv.Atoi(userIDAsString)
	if err != nil {
		utility.ErrorHandler(err)
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(errResponse{ErrMessage: err.Error()})
		return isLogged
	}

	isLoggedIn := db.IsLoggedIn(uint(userIDAsInt))
	if !isLoggedIn {
		rw.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(rw).Encode(errResponse{ErrMessage: "you are not logged in"})
		return isLogged
	}
	isLogged = true
	return isLogged
}

func tbellHome(rw http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		isBreak, userID := GuardRequest(rw, r)
		if isBreak {
			return
		}
		isLogged := isAuthenticated(rw, r, userID)
		if !isLogged {
			return
		}

		responseAsBytes, err := json.Marshal(tbellHomeResponse{
			CorporateName: "TBELL",
			Business:      "Software Testing",
		})
		if err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(rw).Encode(errResponse{"somethings wrong"})
			return
		}
		rw.WriteHeader(http.StatusOK)
		fmt.Fprintf(rw, "%s", responseAsBytes)
		break
	default:
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(errResponse{"method not allowed"})
		break
	}
}

func tbellUser(rw http.ResponseWriter, r *http.Request) {
	isBreak, userID := GuardRequest(rw, r)
	if isBreak {
		return
	}
	isLogged := isAuthenticated(rw, r, userID)
	if !isLogged {
		return
	}
	vars := mux.Vars(r)
	userID = vars["user_id"]
	var user = &entity.User{}
	switch r.Method {
	case "GET":
		result := db.DB().Find(user, userID)

		if result.RowsAffected == 0 {
			rw.WriteHeader(http.StatusNoContent)
			return
		}
		if result.Error != nil {
			rw.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(rw).Encode(errResponse{ErrMessage: result.Error.Error()})
			return
		}
		rw.WriteHeader(http.StatusOK)
		json.NewEncoder(rw).Encode(tbellUserResponse{
			Username:       user.Username,
			Gender:         user.Gender,
			FirstName:      user.FirstName,
			LastName:       user.LastName,
			WorkExperience: user.WorkExperience,
		})
	case "DELETE":
		result := db.DB().Find(user, userID)
		if result.RowsAffected == 0 {
			rw.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(rw).Encode(errResponse{ErrMessage: "can't find user"})
			return
		}

		deleteQuery := db.DB().Unscoped().Delete(&entity.User{}, userID)

		if deleteQuery.Error != nil {
			rw.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(rw).Encode(errResponse{ErrMessage: result.Error.Error()})
			return
		}
		rw.WriteHeader(http.StatusOK)
		return
	}
}

func createUser(rw http.ResponseWriter, r *http.Request) {
	var user = &entity.User{}
	err := json.NewDecoder(r.Body).Decode(user)
	utility.ErrorHandler(err)

	if user.Gender != "male" && user.Gender != "female" {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(errResponse{ErrMessage: "gender field available in 'male', 'female'"})
		return
	}

	if user.Username == "" {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(errResponse{ErrMessage: "username is required"})
		return
	}

	if user.Password == "" {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(errResponse{ErrMessage: "password is required"})
		return
	}

	result := db.DB().Create(user)
	if result.Error != nil {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(errResponse{ErrMessage: result.Error.Error()})
		return
	}
	rw.WriteHeader(http.StatusCreated)
	json.NewEncoder(rw).Encode(tbellUserResponse{
		Username:       user.Username,
		FirstName:      user.FirstName,
		LastName:       user.LastName,
		Gender:         user.Gender,
		WorkExperience: user.WorkExperience,
	})
	return
}

func loginUser(rw http.ResponseWriter, r *http.Request) {
	var loginRequest = &loginRequest{}
	var user = &entity.User{}
	err := json.NewDecoder(r.Body).Decode(loginRequest)
	utility.ErrorHandler(err)
	hashedPassword := sha256.Sum256([]byte(loginRequest.Password))
	hexPassword := fmt.Sprintf("%x", hashedPassword)

	result := db.DB().Where("username = ? AND password = ?", loginRequest.Username, hexPassword).Find(user)

	if result.RowsAffected == 0 {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(errResponse{ErrMessage: "invalid user info"})
		return
	}
	if result.Error != nil {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(errResponse{ErrMessage: result.Error.Error()})
		return
	}

	token, err := jwt.GenerateToken(user.ID)
	if err != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(rw).Encode(errResponse{ErrMessage: "somethings wrong with generate token"})
	}

	user.IsLogged = true
	db.DB().Save(user)

	rw.WriteHeader(http.StatusOK)
	json.NewEncoder(rw).Encode(loginResponse{
		Username: user.Username,
		Password: user.Password,
		Token:    *token,
	})
}

func logoutUser(rw http.ResponseWriter, r *http.Request) {
	isBreak, userID := GuardRequest(rw, r)
	if isBreak {
		return
	}
	isLogged := isAuthenticated(rw, r, userID)
	if !isLogged {
		return
	}
	var user = &entity.User{}
	userIDAsString := fmt.Sprintf("%v", userID)
	userIDAsInt, err := strconv.Atoi(userIDAsString)
	if err != nil {
		utility.ErrorHandler(err)
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(errResponse{ErrMessage: "somethings wrong with this action"})
		return
	}
	result := db.DB().Where("id = ?", uint(userIDAsInt)).Find(user)

	if result.RowsAffected == 0 || result.Error != nil {
		utility.ErrorHandler(result.Error)
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(errResponse{ErrMessage: "somethings wrong with this action"})
		return
	}

	user.IsLogged = false
	db.DB().Save(user)

	rw.WriteHeader(http.StatusOK)
	return
}

func updatePassword(rw http.ResponseWriter, r *http.Request) {
	isBreak, userID := GuardRequest(rw, r)
	if isBreak {
		return
	}
	isLogged := isAuthenticated(rw, r, userID)
	if !isLogged {
		return
	}
	tokenUserID := fmt.Sprintf("%v", userID)

	vars := mux.Vars(r)
	ParamsUserID := vars["user_id"]

	if tokenUserID != ParamsUserID {
		rw.WriteHeader(http.StatusForbidden)
		json.NewEncoder(rw).Encode(errResponse{ErrMessage: "you are not have permission this action"})
		return
	}
	var passwordUpdateData = &passwordUpdateData{}
	err := json.NewDecoder(r.Body).Decode(passwordUpdateData)

	if err != nil {
		utility.ErrorHandler(err)
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(errResponse{ErrMessage: err.Error()})
		return
	}

	hashedPassword := sha256.Sum256([]byte(passwordUpdateData.NewPassword))
	hexPassword := fmt.Sprintf("%x", hashedPassword)

	result := db.DB().Model(&entity.User{}).Where("id = ?", ParamsUserID).Update("Password", hexPassword)

	if result.RowsAffected == 0 || result.Error != nil {
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(errResponse{ErrMessage: result.Error.Error()})
		return
	}

	rw.WriteHeader(http.StatusOK)
	return
}

func headerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Add("Content-Type", "application/json")
		next.ServeHTTP(rw, r)
	})
}

// Start is function of rest server execute.
func Start() {
	fmt.Printf("Server listening on http://127.0.0.1%s/tbell\n", port)
	router := mux.NewRouter().StrictSlash(true)
	router.Use(headerMiddleware)
	router.HandleFunc("/tbell", tbellHome)
	router.HandleFunc("/tbell/user/{user_id:[0-9]+}", tbellUser).Methods("GET", "DELETE")
	router.HandleFunc("/tbell/user", createUser).Methods("POST")
	router.HandleFunc("/tbell/user/login", loginUser).Methods("POST")
	router.HandleFunc("/tbell/user/logout", logoutUser)
	router.HandleFunc("/tbell/user/{user_id:[0-9]+}/password", updatePassword).Methods("PUT")
	http.ListenAndServe(port, router)
}
