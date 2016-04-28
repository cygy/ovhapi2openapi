package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// OVHAPI Struct to get and parse the API definitions from the OVH API.
type OVHAPI struct {
	basePath string
}

// OVHAPIRoute based on the OVH API format.
type OVHAPIRoute struct {
	Format      []string `json:"format"`
	Path        string   `json:"path"`
	Schema      string   `json:"schema"`
	Description string   `json:"description"`
}

// OVHAPIRoutes based on the OVH API format.
type OVHAPIRoutes struct {
	Apis     []OVHAPIRoute `json:"apis"`
	BasePath string        `json:"basePath"`
}

// OVHAPIStatus based on the OVH API format.
type OVHAPIStatus struct {
	Value          string `json:"value"`
	Description    string `json:"description"`
	DeprecatedDate string `json:"deprecatedDate"`
	DeletionDate   string `json:"deletionDate"`
	Replacement    string `json:"replacement"`
}

// OVHAPITypeObjectProperties based on the OVH API format.
type OVHAPITypeObjectProperties struct {
	FullType    string `json:"fullType"`
	Type        string `json:"type"`
	Description string `json:"description"`
	ReadOnly    string `json:"readOnly"`  // equals to "", "0", "1"
	CanBeNull   string `json:"canBeNull"` // equals to "", "0", "1"
}

// OVHAPITypeObject based on the OVH API format.
type OVHAPITypeObject struct {
	ID          string                                `json:"id"`
	Namespace   string                                `json:"namespace"`
	Description string                                `json:"description"`
	Properties  map[string]OVHAPITypeObjectProperties `json:"properties"`
	Generics    []interface{}                         `json:"generics"`
}

// OVHAPITypeEnum based on the OVH API format.
type OVHAPITypeEnum struct {
	ID          string   `json:"id"`
	Namespace   string   `json:"namespace"`
	Description string   `json:"description"`
	EnumType    string   `json:"enumType"`
	Enum        []string `json:"enum"`
}

// OVHAPIParameter based on the OVH API format.
type OVHAPIParameter struct {
	Required    interface{} `json:"required"`
	Description string      `json:"description"`
	DataType    string      `json:"dataType"`
	ParamType   string      `json:"paramType"`
	Name        string      `json:"name"`
	FullType    string      `json:"fullType"`
	Default     interface{} `json:"default"`
}

// OVHAPIEndpointOperation based on the OVH API format.
type OVHAPIEndpointOperation struct {
	HTTPMethod       string            `json:"httpMethod"`
	APIStatus        OVHAPIStatus      `json:"apiStatus"`
	NoAuthentication interface{}       `json:"noAuthentication"`
	Description      string            `json:"description"`
	ResponseType     string            `json:"responseType"`
	Parameters       []OVHAPIParameter `json:"parameters"`
}

// OVHAPIEndpoint based on the OVH API format.
type OVHAPIEndpoint struct {
	Path        string                    `json:"path"`
	Description string                    `json:"description"`
	Operations  []OVHAPIEndpointOperation `json:"operations"`
}

// OVHAPIDefinition based on the OVH API format.
type OVHAPIDefinition struct {
	APIVersion   string                            `json:"apiVersion"`
	BasePath     string                            `json:"basePath"`
	ResourcePath string                            `json:"resourcePath"`
	Apis         []OVHAPIEndpoint                  `json:"apis"`
	RawModels    map[string]map[string]interface{} `json:"models"`
	Models       map[string]interface{}
}

// NewOVHAPI Return a new OVHAPI struct.
func NewOVHAPI(basePath string) *OVHAPI {
	api := &OVHAPI{}
	api.basePath = basePath

	return api
}

// GetRouteList Download, parse, filter and return the routes of the API.
func (api *OVHAPI) GetRouteList(filters []string) ([]string, error) {
	var err error

	var res *http.Response
	if res, err = http.Get(api.basePath); err != nil {
		return nil, err
	}

	defer res.Body.Close()

	var body []byte
	if body, err = ioutil.ReadAll(res.Body); err != nil {
		return nil, err
	}

	var result OVHAPIRoutes
	if err = json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	routes := []string{}
	for _, api := range result.Apis {
		var route = api.Path
		var fullRoute = fmt.Sprintf("%s.json", route)

		if len(filters) == 0 {
			routes = append(routes, fullRoute)
		} else {
			for _, filter := range filters {
				if filter == route {
					routes = append(routes, fullRoute)
					break
				}
			}
		}
	}

	return routes, err
}

// GetDefinition Download, parse and return a OVH API definition from the API.
func (api *OVHAPI) GetDefinition(route string) (*OVHAPIDefinition, error) {
	var err error

	var res *http.Response
	if res, err = http.Get(api.basePath + route); err != nil {
		return nil, err
	}

	defer res.Body.Close()

	var body []byte
	if body, err = ioutil.ReadAll(res.Body); err != nil {
		return nil, err
	}

	var definition OVHAPIDefinition
	if err = json.Unmarshal(body, &definition); err != nil {
		return nil, err
	}

	definition.Models = map[string]interface{}{}
	for modelName, modelProperties := range definition.RawModels {
		isEnum := false
		for modelPropertyName := range modelProperties {
			if modelPropertyName == "enum" {
				isEnum = true
				break
			}
		}

		if isEnum {
			definition.Models[modelName] = newOVHAPITypeEnum(modelProperties)
		} else {
			definition.Models[modelName] = newOVHAPITypeObject(modelProperties)
		}
	}
	definition.RawModels = nil

	return &definition, err
}

// newOVHAPITypeEnum Return a new OVHAPITypeEnum struct.
func newOVHAPITypeEnum(parameter map[string]interface{}) OVHAPITypeEnum {
	enum := OVHAPITypeEnum{}
	enum.ID = stringFromStringOrNil(parameter["id"])
	enum.EnumType = stringFromStringOrNil(parameter["enumType"])
	enum.Description = stringFromStringOrNil(parameter["description"])
	enum.Namespace = stringFromStringOrNil(parameter["namespace"])
	enum.Enum = []string{}

	for _, value := range parameter["enum"].([]interface{}) {
		enum.Enum = append(enum.Enum, stringFromStringOrNil(value))
	}

	return enum
}

// newOVHAPITypeObject Return a new OVHAPITypeObject struct.
func newOVHAPITypeObject(parameter map[string]interface{}) OVHAPITypeObject {
	object := OVHAPITypeObject{}
	object.ID = stringFromStringOrNil(parameter["id"])
	object.Description = stringFromStringOrNil(parameter["description"])
	object.Namespace = stringFromStringOrNil(parameter["namespace"])
	switch t := parameter["generics"].(type) {
	case nil:
	case []interface{}:
		object.Generics = parameter["generics"].([]interface{})
	default:
		logWarn(fmt.Sprintf("unhandled generics type: %T", t))
	}
	//object.Generics = parameter["generics"]
	object.Properties = map[string]OVHAPITypeObjectProperties{}

	for name, property := range parameter["properties"].(map[string]interface{}) {
		object.Properties[name] = newOVHAPITypeObjectProperties(property.(map[string]interface{}))
	}

	return object
}

// newOVHAPITypeObjectProperties Return a new OVHAPITypeObjectProperties struct.
func newOVHAPITypeObjectProperties(parameter map[string]interface{}) OVHAPITypeObjectProperties {
	properties := OVHAPITypeObjectProperties{}
	properties.FullType = stringFromStringOrNil(parameter["fullType"])
	properties.Type = stringFromStringOrNil(parameter["type"])
	properties.Description = stringFromStringOrNil(parameter["description"])
	properties.ReadOnly = stringFromIntOrNil(parameter["readOnly"])
	properties.CanBeNull = stringFromIntOrNil(parameter["canBeNull"])

	return properties
}

// Util functions.
func stringFromStringOrNil(value interface{}) string {
	if value == nil {
		return ""
	}

	return value.(string)
}

func stringFromIntOrNil(value interface{}) string {
	if value == nil {
		return ""
	}

	return fmt.Sprintf("%.0f", value.(float64))
}
