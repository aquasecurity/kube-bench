package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/golang/glog"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres" // database packages get blank imports
	"github.com/spf13/viper"
)

func savePgsql(jsonInfo string) {
	envVars := map[string]string{
		"PGSQL_HOST":     viper.GetString("PGSQL_HOST"),
		"PGSQL_USER":     viper.GetString("PGSQL_USER"),
		"PGSQL_DBNAME":   viper.GetString("PGSQL_DBNAME"),
		"PGSQL_SSLMODE":  viper.GetString("PGSQL_SSLMODE"),
		"PGSQL_PASSWORD": viper.GetString("PGSQL_PASSWORD"),
	}

	for k, v := range envVars {
		if v == "" {
			exitWithError(fmt.Errorf("environment variable %s is missing", envVarsPrefix+"_"+k))
		}
	}

	connInfo := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		envVars["PGSQL_HOST"],
		envVars["PGSQL_USER"],
		envVars["PGSQL_DBNAME"],
		envVars["PGSQL_SSLMODE"],
		envVars["PGSQL_PASSWORD"],
	)

	hostname, err := os.Hostname()
	if err != nil {
		exitWithError(fmt.Errorf("received error looking up hostname: %s", err))
	}

	timestamp := time.Now()

	type ScanResult struct {
		gorm.Model
		ScanHost string    `gorm:"type:varchar(63) not null"` // https://www.ietf.org/rfc/rfc1035.txt
		ScanTime time.Time `gorm:"not null"`
		ScanInfo string    `gorm:"type:jsonb not null"`
	}

	db, err := gorm.Open("postgres", connInfo)
	if err != nil {
		exitWithError(fmt.Errorf("received error connecting to database: %s", err))
	}
	defer db.Close()

	db.Debug().AutoMigrate(&ScanResult{})
	db.Save(&ScanResult{ScanHost: hostname, ScanTime: timestamp, ScanInfo: jsonInfo})
	glog.V(2).Info(fmt.Sprintf("successfully stored result to: %s", envVars["PGSQL_HOST"]))
}
