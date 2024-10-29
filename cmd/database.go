package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/golang/glog"
	"github.com/spf13/viper"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type PsqlConnInfo struct {
	Host     string
	User     string
	DbName   string
	SslMode  string
	Password string
}

func getPsqlConnInfo() (PsqlConnInfo, error) {
	var host string
	if value := viper.GetString("PGSQL_HOST"); value != "" {
		host = value
	} else {
		return PsqlConnInfo{}, fmt.Errorf("%s_PGSQL_HOST env var is required", envVarsPrefix)
	}

	var user string
	if value := viper.GetString("PGSQL_USER"); value != "" {
		user = value
	} else {
		return PsqlConnInfo{}, fmt.Errorf("%s_PGSQL_USER env var is required", envVarsPrefix)
	}

	var dbName string
	if value := viper.GetString("PGSQL_DBNAME"); value != "" {
		dbName = value
	} else {
		return PsqlConnInfo{}, fmt.Errorf("%s_PGSQL_DBNAME env var is required", envVarsPrefix)
	}

	var sslMode string
	if value := viper.GetString("PGSQL_SSLMODE"); value != "" {
		sslMode = value
	} else {
		return PsqlConnInfo{}, fmt.Errorf("%s_PGSQL_SSLMODE env var is required", envVarsPrefix)
	}

	var password string
	if value := viper.GetString("PGSQL_PASSWORD"); value != "" {
		password = value
	} else {
		return PsqlConnInfo{}, fmt.Errorf("%s_PGSQL_PASSWORD env var is required", envVarsPrefix)
	}

	return PsqlConnInfo{
		Host:     host,
		User:     user,
		DbName:   dbName,
		SslMode:  sslMode,
		Password: password,
	}, nil
}

func (c *PsqlConnInfo) toString() string {
	return fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		c.Host,
		c.User,
		c.DbName,
		c.SslMode,
		c.Password,
	)
}

func savePgsql(jsonInfo string) {
	var hostname string
	if value := viper.GetString("K8S_HOST"); value != "" {
		// Adhere to the ScanHost column definition below
		if len(value) > 63 {
			exitWithError(fmt.Errorf("%s_K8S_HOST value's length must be less than 63 chars", envVarsPrefix))
		}

		hostname = value
	} else {
		host, err := os.Hostname()
		if err != nil {
			exitWithError(fmt.Errorf("received error looking up hostname: %s", err))
		}

		hostname = host
	}

	PsqlConnInfo, err := getPsqlConnInfo()
	if err != nil {
		exitWithError(err)
	}

	db, err := gorm.Open(postgres.Open(PsqlConnInfo.toString()), &gorm.Config{})
	if err != nil {
		exitWithError(fmt.Errorf("received error connecting to database: %s", err))
	}

	timestamp := time.Now()
	type ScanResult struct {
		gorm.Model
		ScanHost string    `gorm:"type:varchar(63) not null"` // https://www.ietf.org/rfc/rfc1035.txt
		ScanTime time.Time `gorm:"not null"`
		ScanInfo string    `gorm:"type:jsonb not null"`
	}

	db.Debug().AutoMigrate(&ScanResult{})
	db.Save(&ScanResult{ScanHost: hostname, ScanTime: timestamp, ScanInfo: jsonInfo})
	glog.V(2).Info(fmt.Sprintf("successfully stored result to: %s", PsqlConnInfo.Host))
}
