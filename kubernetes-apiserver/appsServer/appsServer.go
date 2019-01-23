package appsServer

import (
	"encoding/base64"
	"encoding/json"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"strings"
)
var byPass bool = true

// Structures of users
type Person struct {
	Username  string  `json:"username"`
	FirstName string  `json:"firstname"`
	LastName  string  `json:"lastname"`
	Address   Address `json:"address"`
}

type Address struct {
	City     string `json:"city"`
	Division string `json:"division"`
}

type Worker struct {
	Person
	Position string `json:"position"`
	Salary   int    `json:"salary"`
}

// List of workers and authenticated users
var Workers = make(map[string]Worker)
var authUser = make(map[string]string)


// Handler Functions....
func ShowAllWorkers(w http.ResponseWriter, r *http.Request) {
	log.Println("ShowAllWorkers")
	if info, valid := basicAuth(r); !valid {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(info))
		return
	}
	if err := json.NewEncoder(w).Encode(Workers); err != nil {
		panic(err)
	}

	w.WriteHeader(http.StatusOK)
}

func ShowSingleWorker(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	log.Println("ShowSingleWorker-", params["username"])
	//fmt.Println("Username from parameter:", params["username"])

	if info, valid := basicAuth(r); !valid {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(info))
		return
	}

	if info, exist := Workers[params["username"]]; exist {
		_ = json.NewEncoder(w).Encode(info)
	} else {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 - Content Not Found"))
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Creating initial worker profiles
func CreateInitialWorkerProfile() {

	/*Workers = map[string]Worker{
		"masud": {Person{
			Username: "masud", FirstName:"Masudur", LastName:"Rahman", Address{City: "Madaripur", Division: "Dhaka"} },Position: "Software Engineer", Salary: 55}
	}*/

	worker := Worker{
		Person: Person{Username: "masud",
			FirstName: "Masudur",
			LastName:  "Rahman",
			Address:   Address{City: "Madaripur", Division: "Dhaka"}},
		Position: "Software Engineer",
		Salary:   55,
	}
	Workers["masud"] = worker

	worker = Worker{
		Person: Person{Username: "fahim",
			FirstName: "Fahim",
			LastName:  "Abrar",
			Address:   Address{City: "Chittagong", Division: "Chittagong"}},
		Position: "Software Engineer",
		Salary:   55,
	}
	Workers["fahim"] = worker

	worker = Worker{
		Person: Person{Username: "tahsin",
			FirstName: "Tahsin",
			LastName:  "Rahman",
			Address:   Address{City: "Chittagong", Division: "Chittagong"}},
		Position: "Software Engineer",
		Salary:   55,
	}
	Workers["tahsin"] = worker

	worker = Worker{
		Person: Person{Username: "jenny",
			FirstName: "Jannatul",
			LastName:  "Ferdows",
			Address:   Address{City: "Chittagong", Division: "Chittagong"}},
		Position: "Software Engineer",
		Salary:   55,
	}
	Workers["jenny"] = worker

	authUser["masud"] = "pass"
	authUser["admin"] = "admin"

}

func basicAuth(r *http.Request) (string, bool) {
	if byPass{
		return "", true
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "Error: Authorization Needed...!", false
	}

	authInfo := strings.SplitN(authHeader, " ", 2)

	userInfo, err := base64.StdEncoding.DecodeString(authInfo[1])

	if err != nil {
		return "Error: Error while decoding...!", false
	}
	userPass := strings.SplitN(string(userInfo), ":", 2)

	if len(userPass) != 2 {
		return "Error: Authorization failed...!", false
	}

	if pass, exist := authUser[userPass[0]]; exist {
		if pass != userPass[1] {
			return "Error: Unauthorized User", false
		} else {
			return "Success: Authorization Successful...!!", true
		}
	} else {
		return "Error: Unauthorized User...!", false
	}
}