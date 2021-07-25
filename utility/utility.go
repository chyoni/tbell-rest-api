package utility

// ErrorHandler is function of handling error.
func ErrorHandler(err error) {
	if err != nil {
		panic(err.Error())
	}
}
