package main

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// APIInfos Informations about the OpenAPI file.
type APIInfos struct {
	Title          string               `yaml:"title"`
	Description    string               `yaml:"description"`
	Version        string               `yaml:"version"`
	TermsOfService string               `yaml:"termsOfService"`
	Contact        APIInfoContact       `yaml:"contact"`
	License        APIInfoLicense       `yaml:"license"`
	Documentation  APIInfoDocumentation `yaml:"documentation"`
	API            APIInfoPath          `yaml:"api"`
}

// APIInfoContact Informations about the contact of the described API.
type APIInfoContact struct {
	Name  string `yaml:"name"`
	URL   string `yaml:"URL"`
	Email string `yaml:"email"`
}

// APIInfoLicense Informations about the license of the described API.
type APIInfoLicense struct {
	Name string `yaml:"name"`
	URL  string `yaml:"URL"`
}

// APIInfoDocumentation Informations about the documentation of the described API.
type APIInfoDocumentation struct {
	Description string `yaml:"description"`
	URL         string `yaml:"URL"`
}

// APIInfoPath Informations about the OVH API to translate.
type APIInfoPath struct {
	Path     string   `yaml:"path"`     // i.e. "https://api.ovh.com/1.0/""
	Routes   []string `yaml:"routes"`   // i.e. "/vps" or "/sms"
	Consumes []string `yaml:"consumes"` // i.e. "application/json"
	Produces []string `yaml:"produces"` // i.e. "application/json"
}

// NewAPIInfosFromPath Load the API Informations from a yaml file.
func NewAPIInfosFromPath(path string) (*APIInfos, error) {
	var content []byte
	var err error

	if content, err = ioutil.ReadFile(path); err != nil {
		return nil, err
	}

	infos := &APIInfos{}
	if err := yaml.Unmarshal(content, infos); err != nil {
		return nil, err
	}

	return infos, nil
}
