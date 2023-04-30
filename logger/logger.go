package logger

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

var (
	WarningLogger *log.Logger
	InfoLogger    *log.Logger
	ErrorLogger   *log.Logger
)

// Error main object for error
type Error struct {
	Code    int
	Message error
}

func ErrJSONUtil(err error) []byte {
	if err == nil {
		return []byte("{}")
	}
	res, _ := json.Marshal(err)
	return res
}

// StatusCode get status code
func (err *Error) StatusCode() int {
	if err == nil {
		return http.StatusOK
	}
	return err.Code
}

func Logger(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		start := time.Now()
		tType := "HTTP Request"

		inner.ServeHTTP(w, r)
		file, err := os.OpenFile("access.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Println(err)
		}
		InfoLog := log.New(file, "INFO:", log.Ldate|log.Ltime|log.Lshortfile)

		InfoLog.Printf(
			"%s\t|\t%s\t|\t%s\t|\t%s\t|\t%s\t|\t%s\t|\t%s\t|\t%s\t|\t%s\t|\t%s\t|\t%s",
			r.Method,
			tType,
			r.RequestURI,
			time.Since(start),
			r.Header,
			r.Host,
			r.MultipartForm,
			r.Response,
			r.RemoteAddr,
			r.RemoteAddr,
			r.URL,
		)
	})
}

func LoggerFilePath() *os.File {

	file, err := os.OpenFile("debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	return file
}

func LoggerUtil(LogType string, Msg string, Err error) []byte {

	file, err := os.OpenFile("debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	switch Logging := LogType; Logging {
	case "info":
		InfoLogger = log.New(file, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
		InfoLogger.Print(Msg)
		return nil

	case "warning":
		WarningLogger = log.New(file, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
		WarningLogger.Print(Msg)
		return nil

	case "error":
		ErrorLogger = log.New(file, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
		ErrorLogger.Print(Err)
		return nil

	case "errorHTTP":
		ErrorLogger = log.New(file, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
		ErrorLogger.Print(Err)
		res := ErrJSONUtil(err)
		return res
	}
	return nil
}

func FuncLoggerInfo(funcNM string, body interface{}) {
	start := time.Now()
	tType := "Function Info"

	log.Printf(
		"%s\t%s\t%s\t%s",
		tType,
		funcNM,
		body,
		time.Since(start),
	)
}

func FuncLoggerWarning(funcNM string, body interface{}, err interface{}) {
	start := time.Now()
	tType := "Function Warning"

	log.Printf(
		"%s\t%s\t%s\t%s\t%s",
		tType,
		funcNM,
		body,
		time.Since(start),
		err,
	)
}

func FuncLoggerError(funcNM string, body string, err interface{}) {
	start := time.Now()
	tType := "Function Warning"

	log.Printf(
		"%s\t%s\t%s\t%s\t%s",
		tType,
		funcNM,
		time.Since(start),
		err,
	)

}

func FuncLoggerDebug(funcNM string, body interface{}, err string) {
	start := time.Now()
	tType := "Function Warning"

	log.Printf(
		"%s\t%s\t%s\t%s\t%s",
		tType,
		funcNM,
		body,
		time.Since(start),
		err,
	)
}
