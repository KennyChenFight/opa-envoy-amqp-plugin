package validator

import (
	"time"
)

func ValidateDayTimeInRange(requestTimeStr, startStr, endStr string) bool {
	requestTime, err := time.Parse("2006-01-02 15:04:05", requestTimeStr)
	if err != nil {
		return false
	}

	startTime, err := time.Parse("15:04:05", startStr)
	if err != nil {
		return false
	}
	endTime, err := time.Parse("15:04:05", endStr)
	if err != nil {
		return false
	}

	todayStartRange := time.Date(requestTime.Year(), requestTime.Month(), requestTime.Day(), startTime.Hour(), startTime.Minute(), startTime.Second(), 0, requestTime.Location())
	todayEndRange := time.Date(requestTime.Year(), requestTime.Month(), requestTime.Day(), endTime.Hour(), endTime.Minute(), endTime.Second(), 0, requestTime.Location())
	if requestTime.Unix() >= todayStartRange.Unix() && requestTime.Unix() <= todayEndRange.Unix() {
		return true
	}
	return false
}
