package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	// OpenAPIRefTypeDefinitions definitions
	OpenAPIRefTypeDefinitions = "definitions"
	// OpenAPIRefTypeParameters parameters
	OpenAPIRefTypeParameters = "parameters"
	// OpenAPIRefTypeResponses responses
	OpenAPIRefTypeResponses = "responses"

	// OpenAPIParameterInPath path
	OpenAPIParameterInPath = "path"
	// OpenAPIParameterInBody body
	OpenAPIParameterInBody = "body"
	// OpenAPIParameterInHeader header
	OpenAPIParameterInHeader = "header"

	// OpenAPIPathMethodGet get
	OpenAPIPathMethodGet = "get"
	// OpenAPIPathMethodPost post
	OpenAPIPathMethodPost = "post"
	// OpenAPIPathMethodPut put
	OpenAPIPathMethodPut = "put"
	// OpenAPIPathMethodDelete delete
	OpenAPIPathMethodDelete = "delete"
	// OpenAPIPathMethodHead head
	OpenAPIPathMethodHead = "head"
	// OpenAPIPathMethodOptions options
	OpenAPIPathMethodOptions = "options"
	// OpenAPIPathMethodPatch patch
	OpenAPIPathMethodPatch = "path"

	// OpenAPITypeInteger integer
	OpenAPITypeInteger = "integer"
	// OpenAPITypeNumber number
	OpenAPITypeNumber = "number"
	// OpenAPITypeString string
	OpenAPITypeString = "string"
	// OpenAPITypeBoolean boolean
	OpenAPITypeBoolean = "boolean"
	// OpenAPITypeObject object
	OpenAPITypeObject = "object"
	// OpenAPITypeArray array
	OpenAPITypeArray = "array"

	// OpenAPIFormatInt32 int32
	OpenAPIFormatInt32 = "int32"
	// OpenAPIFormatInt64 int64
	OpenAPIFormatInt64 = "int64"
	// OpenAPIFormatFloat float
	OpenAPIFormatFloat = "float"
	// OpenAPIFormatDouble double
	OpenAPIFormatDouble = "double"
	// OpenAPIFormatByte byte
	OpenAPIFormatByte = "byte"
	// OpenAPIFormatBinary binary
	OpenAPIFormatBinary = "binary"
	// OpenAPIFormatDate date
	OpenAPIFormatDate = "date"
	// OpenAPIFormatDateTime date-time
	OpenAPIFormatDateTime = "date-time"
	// OpenAPIFormatPassword password
	OpenAPIFormatPassword = "password"

	// OpenAPIBodyParameterName bodyParameter
	OpenAPIBodyParameterName = "bodyParameter"

	// OVHAPIResponseTypeVoid void
	OVHAPIResponseTypeVoid = "void"
	// OVHAPIEndpointStatusInternal INTERNAL
	OVHAPIEndpointStatusInternal = "INTERNAL"
	// OVHNamespace OVH
	OVHNamespace = "OVH"
	// OVHErrorKey error
	OVHErrorKey = "error"
	// OVHApplicationKey key
	OVHApplicationKey = "application.key"
	// OVHTimestamp timestamp
	OVHTimestamp = "timestamp"
	// OVHConsumerKey key
	OVHConsumerKey = "consumer.key"
	// OVHSignature signature
	OVHSignature = "signature"

	// OpenAPIDotsInNameAllowed name of the models can contain dots.
	OpenAPIDotsInNameAllowed = true
	// OpenAPIAddAuthenticationHeaders the headers for authentication are added to the requests.
	OpenAPIAddAuthenticationHeaders = false
	// OpenAPIHeaderTypeCanOnlyBeString header values of the request can only be of type 'string'
	OpenAPIHeaderTypeCanOnlyBeString = false
)

type incompleteDefinition struct {
	name         string
	object       OVHAPITypeObject
	genericTypes []string
}

var (
	enums                 = map[string]OpenAPISchema{}
	generics              = map[string]OVHAPITypeObject{}
	undefinedGenerics     = []string{}
	usedDefinitions       = []string{}
	incompleteDefinitions = []incompleteDefinition{}

	nameReplaces = map[string]string{
		"ipLoadbalancing": "iplb",
	}
)

// OpenAPIExample Based on the Open API format.
type OpenAPIExample map[string]interface{}

// OpenAPISecurity Based on the Open API format.
type OpenAPISecurity []map[string][]string

// OpenAPIValue Generic value.
type OpenAPIValue interface{}

// OpenAPIXML Based on the Open API format.
type OpenAPIXML struct {
	Name      string `yaml:"name,omitempty"`
	Namespace string `yaml:"namespace,omitempty"`
	Prefix    string `yaml:"prefix,omitempty"`
	Attribute bool   `yaml:"attribute,omitempty"`
	Wrapped   bool   `yaml:"wrapped,omitempty"`
}

// OpenAPIContact Based on the Open API format.
type OpenAPIContact struct {
	Name  string `yaml:"name,omitempty"`
	URL   string `yaml:"url,omitempty"`
	Email string `yaml:"email,omitempty"`
}

// OpenAPILicense Based on the Open API format.
type OpenAPILicense struct {
	Name string `yaml:"name,omitempty"`
	URL  string `yaml:"url,omitempty"`
}

// OpenAPIInfo Based on the Open API format.
type OpenAPIInfo struct {
	Title          string         `yaml:"title,omitempty"`
	Description    string         `yaml:"description,omitempty"`
	TermsOfService string         `yaml:"termsOfService,omitempty"`
	Version        string         `yaml:"version,omitempty"`
	Contact        OpenAPIContact `yaml:"contact,omitempty"`
	License        OpenAPILicense `yaml:"license,omitempty"`
}

// OpenAPIExternalDocs Based on the Open API format.
type OpenAPIExternalDocs struct {
	URL         string `yaml:"url,omitempty"`
	Description string `yaml:"description,omitempty"`
}

// OpenAPITag Based on the Open API format.
type OpenAPITag struct {
	Name         string              `yaml:"name,omitempty"`
	Description  string              `yaml:"description,omitempty"`
	ExternalDocs OpenAPIExternalDocs `yaml:"externalDocs,omitempty"`
}

// OpenAPISecurityScheme Based on the Open API format.
type OpenAPISecurityScheme struct {
	Type             string            `yaml:"type,omitempty"`
	Description      string            `yaml:"description,omitempty"`
	Name             string            `yaml:"name,omitempty"`
	In               string            `yaml:"in,omitempty"`
	Flow             string            `yaml:"flow,omitempty"`
	AuthorizationURL string            `yaml:"authorizationUrl,omitempty"`
	TokenURL         string            `yaml:"tokenUrl,omitempty"`
	Scopes           map[string]string `yaml:"scopes,omitempty"`
}

// OpenAPIOperation Based on the Open API format.
type OpenAPIOperation struct {
	Tags         []string               `yaml:"tags,omitempty"`
	Summary      string                 `yaml:"summary,omitempty"`
	Description  string                 `yaml:"description,omitempty"`
	ExternalDocs OpenAPIExternalDocs    `yaml:"externalDocs,omitempty"`
	OperationID  string                 `yaml:"operationId,omitempty"`
	Consumes     []string               `yaml:"consumes,omitempty"`
	Produces     []string               `yaml:"produces,omitempty"`
	Parameters   []interface{}          `yaml:"parameters,omitempty"` // array of OpenAPIParameter/OpenAPIRef
	Responses    map[string]interface{} `yaml:"responses,omitempty"`  // map of OpenAPIResponse/OpenAPIRef
	Schemes      []string               `yaml:"schemes,omitempty"`
	Deprecated   bool                   `yaml:"deprecated,omitempty"`
	Security     OpenAPISecurity        `yaml:"security,omitempty"`
}

// OpenAPIPath Based on the Open API format.
type OpenAPIPath struct {
	Ref        string           `yaml:"$ref,omitempty"`
	Parameters []interface{}    `yaml:"parameters,omitempty"`
	Get        OpenAPIOperation `yaml:"get,omitempty"`
	Put        OpenAPIOperation `yaml:"put,omitempty"`
	Post       OpenAPIOperation `yaml:"post,omitempty"`
	Delete     OpenAPIOperation `yaml:"delete,omitempty"`
	Options    OpenAPIOperation `yaml:"options,omitempty"`
	Head       OpenAPIOperation `yaml:"head,omitempty"`
	Patch      OpenAPIOperation `yaml:"patch,omitempty"`
}

// OpenAPIParameter Based on the Open API format.
type OpenAPIParameter struct {
	Name             string         `yaml:"name,omitempty"`
	In               string         `yaml:"in,omitempty"`
	Description      string         `yaml:"description,omitempty"`
	Required         bool           `yaml:"required,omitempty"`
	Schema           OpenAPISchema  `yaml:"schema,omitempty"`
	Type             string         `yaml:"type,omitempty"`
	Format           string         `yaml:"format,omitempty"`
	AllowEmptyValue  bool           `yaml:"allowEmptyValue,omitempty"`
	Items            *OpenAPIItem   `yaml:"items,omitempty"`
	CollectionFormat string         `yaml:"collectionFormat,omitempty"`
	Default          OpenAPIValue   `yaml:"default,omitempty"`
	Maximum          float64        `yaml:"maximum,omitempty"`
	ExclusiveMaximum bool           `yaml:"exclusiveMaximum,omitempty"`
	Minimum          float64        `yaml:"minimum,omitempty"`
	ExclusiveMinimum bool           `yaml:"exclusiveMinimum,omitempty"`
	MaxLength        int            `yaml:"maxLength,omitempty"`
	MinLength        int            `yaml:"minLength,omitempty"`
	Pattern          string         `yaml:"pattern,omitempty"`
	MaxItems         int            `yaml:"maxItems,omitempty"`
	MinItems         int            `yaml:"minItems,omitempty"`
	UniqueItems      bool           `yaml:"uniqueItems,omitempty"`
	Enum             []OpenAPIValue `yaml:"enum,omitempty"`
	MultipleOf       float64        `yaml:"multipleOf,omitempty"`
}

// OpenAPISchema Based on the Open API format.
type OpenAPISchema struct {
	Description      string                    `yaml:"description,omitempty"`
	Ref              string                    `yaml:"$ref,omitempty"`
	Type             string                    `yaml:"type,omitempty"`
	Format           string                    `yaml:"format,omitempty"`
	Title            string                    `yaml:"title,omitempty"`
	Default          OpenAPIValue              `yaml:"default,omitempty"`
	MultipleOf       float64                   `yaml:"multipleOf,omitempty"`
	Maximum          float64                   `yaml:"maximum,omitempty"`
	ExclusiveMaximum bool                      `yaml:"exclusiveMaximum,omitempty"`
	Minimum          float64                   `yaml:"minimum,omitempty"`
	ExclusiveMinimum bool                      `yaml:"exclusiveMinimum,omitempty"`
	MaxLength        int                       `yaml:"maxLength,omitempty"`
	MinLength        int                       `yaml:"minLength,omitempty"`
	Pattern          string                    `yaml:"pattern,omitempty"`
	MaxItems         int                       `yaml:"maxItems,omitempty"`
	MinItems         int                       `yaml:"minItems,omitempty"`
	UniqueItems      bool                      `yaml:"uniqueItems,omitempty"`
	MaxProperties    int                       `yaml:"maxProperties,omitempty"`
	MinProperties    int                       `yaml:"minProperties,omitempty"`
	Required         []string                  `yaml:"required,omitempty"`
	ReadOnly         bool                      `yaml:"readOnly,omitempty"`
	Enum             []OpenAPIValue            `yaml:"enum,omitempty"`
	Discriminator    string                    `yaml:"discriminator,omitempty"`
	ExternalDocs     OpenAPIExternalDocs       `yaml:"externalDocs,omitempty"`
	XML              OpenAPIXML                `yaml:"xml,omitempty"`
	Example          OpenAPIExample            `yaml:"example,omitempty"`
	Items            *OpenAPIItem              `yaml:"items,omitempty"`
	Properties       map[string]*OpenAPISchema `yaml:"properties,omitempty"`
}

// OpenAPIItem Based on the Open API format.
type OpenAPIItem struct {
	Ref              string         `yaml:"$ref,omitempty"`
	Type             string         `yaml:"type,omitempty"`
	Format           string         `yaml:"format,omitempty"`
	Items            *OpenAPIItem   `yaml:"items,omitempty"`
	CollectionFormat string         `yaml:"collectionFormat,omitempty"`
	Default          OpenAPIValue   `yaml:"default,omitempty"`
	Maximum          float64        `yaml:"maximum,omitempty"`
	ExclusiveMaximum bool           `yaml:"exclusiveMaximum,omitempty"`
	Minimum          float64        `yaml:"minimum,omitempty"`
	ExclusiveMinimum bool           `yaml:"exclusiveMinimum,omitempty"`
	MaxLength        int            `yaml:"maxLength,omitempty"`
	MinLength        int            `yaml:"minLength,omitempty"`
	Pattern          string         `yaml:"pattern,omitempty"`
	MaxItems         int            `yaml:"maxItems,omitempty"`
	MinItems         int            `yaml:"minItems,omitempty"`
	UniqueItems      bool           `yaml:"uniqueItems,omitempty"`
	Enum             []OpenAPIValue `yaml:"enum,omitempty"`
	MultipleOf       float64        `yaml:"multipleOf,omitempty"`
}

// OpenAPIResponseHeader Based on the Open API format.
type OpenAPIResponseHeader struct {
	Description      string         `yaml:"description,omitempty"`
	Type             string         `yaml:"type,omitempty"`
	Format           string         `yaml:"format,omitempty"`
	Items            *OpenAPIItem   `yaml:"items,omitempty"`
	CollectionFormat string         `yaml:"collectionFormat,omitempty"`
	Default          OpenAPIValue   `yaml:"default,omitempty"`
	Maximum          float64        `yaml:"maximum,omitempty"`
	ExclusiveMaximum bool           `yaml:"exclusiveMaximum,omitempty"`
	Minimum          float64        `yaml:"minimum,omitempty"`
	ExclusiveMinimum bool           `yaml:"exclusiveMinimum,omitempty"`
	MaxLength        int            `yaml:"maxLength,omitempty"`
	MinLength        int            `yaml:"minLength,omitempty"`
	Pattern          string         `yaml:"pattern,omitempty"`
	MaxItems         int            `yaml:"maxItems,omitempty"`
	MinItems         int            `yaml:"minItems,omitempty"`
	UniqueItems      bool           `yaml:"uniqueItems,omitempty"`
	Enum             []OpenAPIValue `yaml:"enum,omitempty"`
	MultipleOf       float64        `yaml:"multipleOf,omitempty"`
}

// OpenAPIResponse Based on the Open API format.
type OpenAPIResponse struct {
	Description string                           `yaml:"description,omitempty"`
	Schema      OpenAPISchema                    `yaml:"schema,omitempty"`
	Headers     map[string]OpenAPIResponseHeader `yaml:"headers,omitempty"`
	Examples    OpenAPIExample                   `yaml:"examples,omitempty"`
}

// OpenAPIRef Based on the Open API format.
type OpenAPIRef struct {
	Ref string `yaml:"$ref,omitempty"`
}

// OpenAPI Based on the Open API format.
type OpenAPI struct {
	Swagger             string                           `yaml:"swagger"`
	Info                OpenAPIInfo                      `yaml:"info,omitempty"`
	Host                string                           `yaml:"host,omitempty"`
	BasePath            string                           `yaml:"basePath,omitempty"`
	Schemes             []string                         `yaml:"schemes,omitempty"`
	Consumes            []string                         `yaml:"consumes,omitempty"`
	Produces            []string                         `yaml:"produces,omitempty"`
	ExternalDocs        OpenAPIExternalDocs              `yaml:"externalDocs,omitempty"`
	Tags                []OpenAPITag                     `yaml:"tags,omitempty"`
	SecurityDefinitions map[string]OpenAPISecurityScheme `yaml:"securityDefinitions,omitempty"`
	Security            OpenAPISecurity                  `yaml:"security,omitempty"`
	Paths               map[string]OpenAPIPath           `yaml:"paths,omitempty"`
	Definitions         map[string]OpenAPISchema         `yaml:"definitions,omitempty"`
	Parameters          map[string]OpenAPIParameter      `yaml:"parameters,omitempty"`
	Responses           map[string]OpenAPIResponse       `yaml:"responses,omitempty"`
}

// OpenAPITypeFormat Annex struct, not in the Open API model.
type OpenAPITypeFormat struct {
	Type, Format, EnumName     string
	IsRef, IsArray, IsGenerics bool
}

// OpenAPIFromAPIInformations Return a Open API object from a APIInfos object.
func OpenAPIFromAPIInformations(infos *APIInfos) *OpenAPI {
	var oapi = &OpenAPI{}

	oapi.Swagger = "2.0"

	// Informations about the API.
	oapi.Info.Title = infos.Title
	oapi.Info.Description = infos.Description
	oapi.Info.Version = infos.Version
	oapi.Info.TermsOfService = infos.TermsOfService

	// Contact of the API.
	oapi.Info.Contact.Name = infos.Contact.Name
	oapi.Info.Contact.URL = infos.Contact.URL
	oapi.Info.Contact.Email = infos.Contact.Email

	// License of the API.
	oapi.Info.License.Name = infos.License.Name
	oapi.Info.License.URL = infos.License.URL

	// Documentation of the API.
	oapi.ExternalDocs.Description = infos.Documentation.Description
	oapi.ExternalDocs.URL = infos.Documentation.URL

	// The mime-types that the API consumes and produces.
	oapi.Consumes = infos.API.Consumes
	oapi.Produces = infos.API.Produces

	// The global definitions, parameters and responses.
	oapi.Definitions = map[string]OpenAPISchema{}
	oapi.Paths = map[string]OpenAPIPath{}
	oapi.Parameters = map[string]OpenAPIParameter{}
	oapi.Responses = map[string]OpenAPIResponse{}

	// Define the error response object.
	errorResponse := OpenAPIResponse{}
	errorResponse.Description = "Unexpected error"
	errorResponse.Schema.Type = OpenAPITypeObject
	errorResponse.Schema.Properties = map[string]*OpenAPISchema{}

	errorCode := OpenAPISchema{}
	errorCode.Type = OpenAPITypeInteger
	errorCode.Format = OpenAPIFormatInt32
	errorResponse.Schema.Properties["errorCode"] = &errorCode

	httpCode := OpenAPISchema{}
	httpCode.Type = OpenAPITypeInteger
	httpCode.Format = OpenAPIFormatInt32
	errorResponse.Schema.Properties["httpCode"] = &httpCode

	message := OpenAPISchema{}
	message.Type = OpenAPITypeString
	errorResponse.Schema.Properties["message"] = &message

	oapi.Responses[getOpenAPINameFromOVHAPI(OVHNamespace, OVHErrorKey)] = errorResponse

	// Define the authentication header parameters.
	if OpenAPIAddAuthenticationHeaders {
		applicationKeyParameter := OpenAPIParameter{}
		applicationKeyParameter.Name = "X-Ovh-Application"
		applicationKeyParameter.In = OpenAPIParameterInHeader
		applicationKeyParameter.Description = "The application key"
		applicationKeyParameter.Type = OpenAPITypeString
		applicationKeyParameter.Required = true

		oapi.Parameters[getOpenAPINameFromOVHAPI(OVHNamespace, OVHApplicationKey)] = applicationKeyParameter

		timestampParameter := OpenAPIParameter{}
		timestampParameter.Name = "X-Ovh-Timestamp"
		timestampParameter.In = OpenAPIParameterInHeader
		timestampParameter.Description = "The timestamp of the request"
		if OpenAPIHeaderTypeCanOnlyBeString {
			timestampParameter.Type = OpenAPITypeString
		} else {
			timestampParameter.Type = OpenAPITypeInteger
			timestampParameter.Format = OpenAPIFormatInt64
		}
		timestampParameter.Required = true

		oapi.Parameters[getOpenAPINameFromOVHAPI(OVHNamespace, OVHTimestamp)] = timestampParameter

		consumerKeyParameter := OpenAPIParameter{}
		consumerKeyParameter.Name = "X-Ovh-Consumer"
		consumerKeyParameter.In = OpenAPIParameterInHeader
		consumerKeyParameter.Description = "The consumer key"
		consumerKeyParameter.Type = OpenAPITypeString
		consumerKeyParameter.Required = true

		oapi.Parameters[getOpenAPINameFromOVHAPI(OVHNamespace, OVHConsumerKey)] = consumerKeyParameter

		signatureParameter := OpenAPIParameter{}
		signatureParameter.Name = "X-Ovh-Signature"
		signatureParameter.In = OpenAPIParameterInHeader
		signatureParameter.Description = "The request signature"
		signatureParameter.Type = OpenAPITypeString
		signatureParameter.Required = true

		oapi.Parameters[getOpenAPINameFromOVHAPI(OVHNamespace, OVHSignature)] = signatureParameter
	}

	return oapi
}

// AddOVHAPIDefinitionToOpenAPI Add models, oeprations, enums... from an OVHAPIDefinition object to a Open API object.
func AddOVHAPIDefinitionToOpenAPI(definition *OVHAPIDefinition, oapi *OpenAPI, keepInternalEndpoints bool) error {
	// Get the host of the API.
	var URL *url.URL
	var err error
	if URL, err = url.Parse(definition.BasePath); err != nil {
		return err
	}

	oapi.Host = URL.Host
	oapi.Schemes = []string{URL.Scheme}
	oapi.BasePath = URL.Path

	// Some enums refer to another enum, for these cases
	// the enum type is completed after parsing all the enums.
	incompleteEnumNames := []string{}

	// First all the enums are parsed because some models can refer to enums.
	for _, model := range definition.Models {
		switch model.(type) {
		case OVHAPITypeEnum:
			modelEnum := model.(OVHAPITypeEnum)
			name := getOpenAPINameFromOVHAPI(modelEnum.Namespace, modelEnum.ID)
			enum, referredEnumName := getOpenAPIEnumFromOVHAPIEnum(modelEnum)

			if len(referredEnumName) > 0 {
				enum.Type = referredEnumName
				incompleteEnumNames = append(incompleteEnumNames, name)
			}

			enums[name] = *enum
		}
	}

	// Complete the type and format of the enums that referred to another enum.
	for _, incompleteEnumName := range incompleteEnumNames {
		incompleteEnum := enums[incompleteEnumName]
		currentType := incompleteEnum.Type
		currentFormat := incompleteEnum.Format

		for true {
			if len(currentType) == 0 {
				logWarn(fmt.Sprintf("unknown type for enum '%s'", incompleteEnumName))
				break
			}
			if enum, ok := enums[currentType]; ok {
				currentType = enum.Type
				currentFormat = enum.Format
			} else {
				incompleteEnum.Type = currentType
				incompleteEnum.Format = currentFormat
				enums[incompleteEnumName] = incompleteEnum
				break
			}
		}
	}

	// Then the objects are parsed.
	for _, model := range definition.Models {
		switch model.(type) {
		case OVHAPITypeObject:
			modelObject := model.(OVHAPITypeObject)
			name := getOpenAPINameFromOVHAPI(modelObject.Namespace, modelObject.ID)
			object := getOpenAPIObjectFromOVHAPIObject(modelObject, name, oapi)

			if object != nil {
				oapi.Definitions[name] = *object
			}
		}
	}

	// Parse the paths.
	for _, APIEndpoint := range definition.Apis {
		path := OpenAPIPath{}

		// Each request must send the application key.
		if OpenAPIAddAuthenticationHeaders {
			applicationKeyParameterRef := OpenAPIRef{}
			applicationKeyParameterRef.Ref = getOpenAPIRefFromOVHAPI(OVHNamespace, OVHApplicationKey, OpenAPIRefTypeParameters)
			path.Parameters = append(path.Parameters, applicationKeyParameterRef)
		}

		// An operation = GET / POST / PUT ...
		for _, APIOperation := range APIEndpoint.Operations {
			// Skip the internal endpoints.
			if !keepInternalEndpoints && APIOperation.APIStatus.Value == OVHAPIEndpointStatusInternal {
				continue
			}

			isAuthenticationRequired := (APIOperation.NoAuthentication == false || APIOperation.NoAuthentication == 0.0 || APIOperation.NoAuthentication == 0)

			operation := OpenAPIOperation{}
			operation.Summary = APIOperation.Description
			operation.Description = APIOperation.APIStatus.Value
			if len(APIOperation.APIStatus.Replacement) > 0 {
				operation.Description = fmt.Sprintf("%s (see '%s')", operation.Description, APIOperation.APIStatus.Replacement)
			}
			if isAuthenticationRequired {
				operation.Description = fmt.Sprintf("%s - authentication required", operation.Description)
			}
			operation.Responses = map[string]interface{}{}

			// Add references to the authentication parameters if needed
			if OpenAPIAddAuthenticationHeaders && isAuthenticationRequired {
				consumerKeyParameterRef := OpenAPIRef{}
				consumerKeyParameterRef.Ref = getOpenAPIRefFromOVHAPI(OVHNamespace, OVHConsumerKey, OpenAPIRefTypeParameters)
				operation.Parameters = append(operation.Parameters, consumerKeyParameterRef)

				timestampParameterRef := OpenAPIRef{}
				timestampParameterRef.Ref = getOpenAPIRefFromOVHAPI(OVHNamespace, OVHTimestamp, OpenAPIRefTypeParameters)
				operation.Parameters = append(operation.Parameters, timestampParameterRef)

				signatureParameterRef := OpenAPIRef{}
				signatureParameterRef.Ref = getOpenAPIRefFromOVHAPI(OVHNamespace, OVHSignature, OpenAPIRefTypeParameters)
				operation.Parameters = append(operation.Parameters, signatureParameterRef)
			}

			// Parse the parameters
			for _, APIParameter := range APIOperation.Parameters {
				parameter := getOpenAPIParameterFromOVHAPIParameter(APIParameter, oapi)

				// All the in-path parameters are moved to the path item definition.
				if parameter.In == OpenAPIParameterInPath {
					found := false
					for _, p := range path.Parameters {
						switch p.(type) {
						case *OpenAPIParameter:
							if p.(*OpenAPIParameter).Name == parameter.Name {
								found = true
								break
							}
						}
					}

					if !found {
						path.Parameters = append(path.Parameters, parameter)
					}
				} else {
					addBodyParameterToOperation(parameter, &operation)
				}
			}

			// Change the name of the parameter 'bodyParameter'
			if regexp, err := regexp.Compile("(\\/\\{[a-zA-Z0-9_-]+\\})"); err != nil {
				logWarn(fmt.Sprintf("Can not create regular expression: %+v", err))
			} else {
				for index, parameter := range operation.Parameters {
					switch parameter.(type) {
					case OpenAPIParameter, *OpenAPIParameter:
						if parameter.(OpenAPIParameter).Name == OpenAPIBodyParameterName {
							parameterName := fmt.Sprintf("%s/%s", APIEndpoint.Path, strings.ToLower(APIOperation.HTTPMethod))
							parameterName = regexp.ReplaceAllString(parameterName, "")

							parts := formatStrings(strings.Split(parameterName, "/"))

							parameterName = strings.Join(parts, "")
							parameterName = fmt.Sprintf("%s%s", strings.ToLower(parameterName[:1]), parameterName[1:])

							OpenAPIParameter := parameter.(OpenAPIParameter)
							OpenAPIParameter.Name = parameterName

							firstParameters := operation.Parameters[:index]
							lastParameters := operation.Parameters[index+1:]
							operation.Parameters = append(firstParameters, OpenAPIParameter)

							if len(lastParameters) > 0 {
								operation.Parameters = append(operation.Parameters, lastParameters)
							}
						}
					}
				}
			}

			// Parse the responses
			defaultResponse := OpenAPIRef{}
			defaultResponse.Ref = getOpenAPIRefFromOVHAPI(OVHNamespace, OVHErrorKey, OpenAPIRefTypeResponses)
			operation.Responses["default"] = defaultResponse

			var response = getOpenAPIResponseFromOVHAPIResponseType(APIOperation.ResponseType, oapi)
			if response != nil {
				operation.Responses["200"] = response
			}

			switch strings.ToLower(APIOperation.HTTPMethod) {
			case OpenAPIPathMethodGet:
				path.Get = operation
			case OpenAPIPathMethodPost:
				path.Post = operation
			case OpenAPIPathMethodPut:
				path.Put = operation
			case OpenAPIPathMethodHead:
				path.Get = operation
			case OpenAPIPathMethodDelete:
				path.Delete = operation
			case OpenAPIPathMethodOptions:
				path.Options = operation
			case OpenAPIPathMethodPatch:
				path.Patch = operation
			}
		}

		oapi.Paths[APIEndpoint.Path] = path
	}

	// Complete the generic types.
	for _, undefinedGeneric := range undefinedGenerics {
		createOpenAPIDefinitionFromOVHAPIComplexType(undefinedGeneric, oapi)
	}

	// Complete the definitions.
	for _, incompleteDefinition := range incompleteDefinitions {
		object := generateOpenAPIObjectFromOVHAPIObjectAndGenerics(incompleteDefinition.object, incompleteDefinition.genericTypes, incompleteDefinition.name, oapi)
		if object != nil {
			oapi.Definitions[incompleteDefinition.name] = *object
		}
	}

	return nil
}

// CleanOpenAPI Remove the unused model objects from a Open API object.
func CleanOpenAPI(oapi *OpenAPI) {
	allDefinitions := []string{}
	for definition := range oapi.Definitions {
		allDefinitions = append(allDefinitions, definition)
	}

	for _, definition := range allDefinitions {
		found := false

		for i, usedDefinition := range usedDefinitions {
			if usedDefinition == definition {
				usedDefinitions = append(usedDefinitions[:i], usedDefinitions[i+1:]...)
				found = true
				break
			}
		}

		if !found {
			delete(oapi.Definitions, definition)
		}
	}
}

// Log.
func logWarn(message string) {
	fmt.Printf("[WARN] %s\n", message)
}

// Return a Open API object name from a OVH API object name.
func getOpenAPINameFromOVHAPI(namespace, name string) string {
	var fullName string
	if len(namespace) > 0 {
		fullName = namespace
	}
	if len(name) > 0 {
		if len(fullName) > 0 {
			fullName = fullName + "."
		}
		fullName = fullName + name
	}

	fullName = strings.Replace(fullName, "<", ".", -1)
	fullName = strings.Replace(fullName, ">", "", -1)
	fullName = strings.Replace(fullName, "[", "", -1)
	fullName = strings.Replace(fullName, "]", "", -1)

	parts := formatStrings(strings.Split(fullName, "."))

	if OpenAPIDotsInNameAllowed {
		return strings.Join(parts, ".")
	}

	return strings.Join(parts, "")
}

// Return a Open API ref string from a OVH API object name.
func getOpenAPIRefFromOVHAPI(namespace, name, refType string) string {
	objectName := getOpenAPINameFromOVHAPI(namespace, name)

	if refType == OpenAPIRefTypeDefinitions {
		found := false

		for _, usedDefinition := range usedDefinitions {
			if usedDefinition == objectName {
				found = true
				break
			}
		}

		if !found {
			usedDefinitions = append(usedDefinitions, objectName)
		}
	}

	return fmt.Sprintf("#/%s/%s", refType, objectName)
}

// Return a Open API type format from a OVH API type.
func getOpenAPITypeFormatFromOVHAPIType(baseType string) OpenAPITypeFormat {
	typeFormat := OpenAPITypeFormat{}

	typeFormat.IsArray = strings.HasSuffix(baseType, "[]")
	ovhType := strings.Replace(baseType, "[]", "", -1)

	if strings.Contains(ovhType, ":") {
		parts := strings.Split(ovhType, ":")
		logWarn(fmt.Sprintf("Got unknown type: '%s', retain type '%s'", ovhType, parts[len(parts)-1]))
		ovhType = parts[len(parts)-1]
	}

	switch strings.ToLower(ovhType) {
	case "string", "text", "ip", "ipblock", "ipv4block", "ipv4", "ipv6", "time", "phonenumber", "ipinterface":
		typeFormat.Type = OpenAPITypeString
	case "password":
		typeFormat.Type = OpenAPITypeString
		typeFormat.Format = OpenAPIFormatPassword
	case "date":
		typeFormat.Type = OpenAPITypeString
		typeFormat.Format = OpenAPIFormatDate
	case "datetime":
		typeFormat.Type = OpenAPITypeString
		typeFormat.Format = OpenAPIFormatDateTime
	case "long":
		typeFormat.Type = OpenAPITypeInteger
		typeFormat.Format = OpenAPIFormatInt64
	case "boolean":
		typeFormat.Type = OpenAPITypeBoolean
	case "double":
		typeFormat.Type = OpenAPITypeNumber
		typeFormat.Format = OpenAPIFormatDouble
	default:
		name := getOpenAPINameFromOVHAPI("", ovhType)
		if _, ok := enums[name]; ok {
			typeFormat.EnumName = name
		} else {
			typeFormat.IsRef = true
			typeFormat.Type = name

			if strings.Contains(baseType, "<") {
				typeFormat.IsGenerics = true
			}
		}
	}

	return typeFormat
}

// Return a Open API enum from a OVH API enum.
func getOpenAPIEnumFromOVHAPIEnum(OVHAPIEnum OVHAPITypeEnum) (*OpenAPISchema, string) {
	enum := &OpenAPISchema{}

	enum.Description = OVHAPIEnum.Description

	typeFormat := getOpenAPITypeFormatFromOVHAPIType(OVHAPIEnum.EnumType)
	enum.Type = typeFormat.Type
	enum.Format = typeFormat.Format

	for _, value := range OVHAPIEnum.Enum {
		var enumValue interface{}

		switch enum.Type {
		case OpenAPITypeInteger:
			enumValue, _ = strconv.ParseInt(value, 10, 64)
		case OpenAPITypeNumber:
			enumValue, _ = strconv.ParseFloat(value, 64)
		case OpenAPITypeBoolean:
			enumValue, _ = strconv.ParseBool(value)
		default:
			enumValue = value
		}

		enum.Enum = append(enum.Enum, enumValue)
	}

	referredEnum := ""
	if len(typeFormat.EnumName) > 0 {
		referredEnum = typeFormat.EnumName
	}
	if typeFormat.IsRef {
		referredEnum = typeFormat.Type
	}

	return enum, referredEnum
}

// Return a Open API schema object from a Open API type format.
func getOpenAPISchemaFromTypeFormat(typeFormat OpenAPITypeFormat) OpenAPISchema {
	schema := OpenAPISchema{}

	// Array of ...
	if typeFormat.IsArray {
		schema.Type = OpenAPITypeArray
		schema.Items = &OpenAPIItem{}

		// Array of $ref
		if typeFormat.IsRef {
			schema.Items.Ref = getOpenAPIRefFromOVHAPI("", typeFormat.Type, OpenAPIRefTypeDefinitions)

			// Array of enum
		} else if len(typeFormat.EnumName) > 0 {
			if enum, ok := enums[typeFormat.EnumName]; ok {
				schema.Items.Type = enum.Type
				schema.Items.Format = enum.Format
				schema.Items.Enum = enum.Enum
			} else {
				logWarn(fmt.Sprintf("Unknown 'enum': (%s)", typeFormat.EnumName))
			}

			// Array of simple type
		} else {
			schema.Items.Type = typeFormat.Type
			schema.Items.Format = typeFormat.Format
		}

		// Enum
	} else if len(typeFormat.EnumName) > 0 {
		if enum, ok := enums[typeFormat.EnumName]; ok {
			schema.Type = enum.Type
			schema.Format = enum.Format
			schema.Enum = enum.Enum
			schema.Description = enum.Description
		} else {
			logWarn(fmt.Sprintf("Unknown 'enum': (%s)", typeFormat.EnumName))
		}

		// Simple type
	} else if !typeFormat.IsRef {
		schema.Type = typeFormat.Type
		schema.Format = typeFormat.Format
	}

	return schema
}

// Return a Open API object from a OVH API object.
func getOpenAPIObjectFromOVHAPIObject(OVHAPIObject OVHAPITypeObject, definitionName string, oapi *OpenAPI) *OpenAPISchema {
	// If this object contains some generic variables it is not considered as a real API object.
	// It is saved to generate the real API objects.
	if len(OVHAPIObject.Generics) > 0 {
		generics[fmt.Sprintf("%s.%s", OVHAPIObject.Namespace, OVHAPIObject.ID)] = OVHAPIObject
		return nil
	}

	return generateOpenAPIObjectFromOVHAPIObjectAndGenerics(OVHAPIObject, nil, definitionName, oapi)
}

// Return a Open API parameter object from a OVH API parameter object.
func getOpenAPIParameterFromOVHAPIParameter(APIParameter OVHAPIParameter, oapi *OpenAPI) *OpenAPIParameter {
	typeFormat := getOpenAPITypeFormatFromOVHAPIType(APIParameter.DataType)

	// Common properties
	parameter := &OpenAPIParameter{}
	parameter.Name = APIParameter.Name
	parameter.In = APIParameter.ParamType

	switch t := APIParameter.Required.(type) {
	case bool:
		parameter.Required = APIParameter.Required.(bool)
	case float64:
		parameter.Required = APIParameter.Required.(float64) == 1.0
	case nil:
		parameter.Required = false
	default:
		logWarn(fmt.Sprintf("Unhandled type of 'required': %T (value: %+v)", t, APIParameter.Required))
	}

	defaultValue := func(defaultValue interface{}, defaultValueType string) interface{} {
		if defaultValueType == OpenAPITypeBoolean {
			switch defaultValue {
			case 1.0, 1, "1":
				return true
			default:
				return false
			}
		}

		return defaultValue
	}

	// Different properties if the parameter is in "body" or not
	if parameter.In == OpenAPIParameterInBody {
		// a schema/ref must only be present with a parameter in body
		if typeFormat.IsRef && !typeFormat.IsArray {
			parameter.Schema.Ref = getOpenAPIRefFromOVHAPI("", APIParameter.DataType, OpenAPIRefTypeDefinitions)
			if len(parameter.Name) == 0 {
				// https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#parameterObject
				// Body - The payload that's appended to the HTTP request. Since there can only be one payload, there can only be one body parameter.
				// The name of the body parameter has no effect on the parameter itself and is used for documentation purposes only.
				// Since Form parameters are also in the payload, body and form parameters cannot exist together for the same operation.
				parameter.Name = OpenAPIBodyParameterName
			}

			if typeFormat.IsGenerics {
				createOpenAPIDefinitionFromOVHAPIComplexType(APIParameter.DataType, oapi)
			}
		} else {
			parameter.Schema = getOpenAPISchemaFromTypeFormat(typeFormat)
			parameter.Schema.Default = defaultValue(APIParameter.Default, parameter.Schema.Type)
		}
	} else {
		if parameter.In == OpenAPIParameterInPath {
			parameter.Required = true
		}

		schema := getOpenAPISchemaFromTypeFormat(typeFormat)
		parameter.Type = schema.Type
		parameter.Format = schema.Format
		parameter.Enum = schema.Enum
		parameter.Items = schema.Items
		parameter.Default = defaultValue(APIParameter.Default, parameter.Type)
	}

	return parameter
}

// Return a Open API response object from a OVH API response object.
func getOpenAPIResponseFromOVHAPIResponseType(responseType string, oapi *OpenAPI) interface{} {
	var response interface{}

	// Void response
	if responseType == OVHAPIResponseTypeVoid {
		r := OpenAPIResponse{}
		r.Description = fmt.Sprintf("return '%s'", OVHAPIResponseTypeVoid)
		response = r

		// Existing response
	} else {
		typeFormat := getOpenAPITypeFormatFromOVHAPIType(responseType)

		// $ref to a response object -> $ref to a definition object
		if typeFormat.IsRef && !typeFormat.IsArray {
			r := OpenAPIRef{}
			r.Ref = getOpenAPIRefFromOVHAPI("", responseType, OpenAPIRefTypeResponses)
			response = r

			// Add the reference to the object definitions
			typeName := getOpenAPINameFromOVHAPI("", responseType)

			found := false
			for string := range oapi.Responses {
				if string == typeName {
					found = true
					break
				}
			}

			if !found {
				response := OpenAPIResponse{}
				response.Description = fmt.Sprintf("description of '%s' response", typeName)
				response.Schema.Ref = getOpenAPIRefFromOVHAPI("", responseType, OpenAPIRefTypeDefinitions)
				oapi.Responses[typeName] = response
			}

			// Complete response object
		} else {
			r := OpenAPIResponse{}
			r.Description = "return value"
			r.Schema = getOpenAPISchemaFromTypeFormat(typeFormat)
			response = r
		}

		// Create a generic if needed
		if typeFormat.IsGenerics {
			createOpenAPIDefinitionFromOVHAPIComplexType(responseType, oapi)
		}
	}

	return response
}

// Add to a Open API object a Open API definition object from a OVH API complex type.
func createOpenAPIDefinitionFromOVHAPIComplexType(responseType string, oapi *OpenAPI) {
	OVHAPIObjectNameSeparatorIndex := strings.Index(responseType, "<")
	OVHAPIObjectName := responseType[:OVHAPIObjectNameSeparatorIndex]

	if OVHAPIObject, ok := generics[OVHAPIObjectName]; ok {
		complexTypesString := responseType[OVHAPIObjectNameSeparatorIndex:]
		complexTypesString = strings.Replace(complexTypesString, "<", "", -1)
		complexTypesString = strings.Replace(complexTypesString, ">", "", -1)
		complexTypesString = strings.Replace(complexTypesString, "[", "", -1)
		complexTypesString = strings.Replace(complexTypesString, "]", "", -1)
		complexTypes := strings.Split(complexTypesString, ",")

		definitionName := getOpenAPINameFromOVHAPI("", responseType)
		object := generateOpenAPIObjectFromOVHAPIObjectAndGenerics(OVHAPIObject, complexTypes, definitionName, oapi)
		if object != nil {
			oapi.Definitions[definitionName] = *object
		}
	} else {
		found := false

		for _, undefinedGeneric := range undefinedGenerics {
			if undefinedGeneric == responseType {
				found = true
				break
			}
		}

		if !found {
			undefinedGenerics = append(undefinedGenerics, responseType)
		}
	}
}

// Return a Open API schema object from a OVH API generic object.
func generateOpenAPIObjectFromOVHAPIObjectAndGenerics(OVHAPIObject OVHAPITypeObject, genericTypes []string, definitionName string, oapi *OpenAPI) *OpenAPISchema {
	schema := &OpenAPISchema{}
	schema.Type = OpenAPITypeObject
	schema.Description = OVHAPIObject.Description
	schema.Properties = map[string]*OpenAPISchema{}

	for name, objectProperty := range OVHAPIObject.Properties {
		propertyName := getOpenAPINameFromOVHAPI("", name)

		// https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#schemaObject:
		// Properties marked as readOnly being true SHOULD NOT be in the required list of the defined schema.
		if objectProperty.ReadOnly == "1" && (objectProperty.CanBeNull == "0") {
			schema.Required = append(schema.Required, propertyName)
		}

		typeFormat := getOpenAPITypeFormatFromOVHAPIType(objectProperty.Type)

		// In this case, maybe a generic type is present: replace it with the real type
		if typeFormat.IsRef && genericTypes != nil {
			index := -1
			for i, objectGenericType := range OVHAPIObject.Generics {
				if objectGenericType == typeFormat.Type {
					index = i
					break
				}
			}

			if index > -1 && len(genericTypes) >= index {
				wasArray := typeFormat.IsArray
				genericType := genericTypes[index]
				typeFormat = getOpenAPITypeFormatFromOVHAPIType(genericType)
				typeFormat.IsArray = wasArray
			}
		}

		property := getOpenAPISchemaFromTypeFormat(typeFormat)

		if typeFormat.IsRef {
			if typeFormat.IsGenerics {
				createOpenAPIDefinitionFromOVHAPIComplexType(objectProperty.Type, oapi)
			}

			if !typeFormat.IsArray {
				if typeFormat.IsGenerics {
					dependanceDefinitionName := getOpenAPINameFromOVHAPI("", objectProperty.Type)
					if object, ok := oapi.Definitions[dependanceDefinitionName]; ok {
						property = object
					} else {
						incompleteDefinitions = append(incompleteDefinitions, incompleteDefinition{
							name:         definitionName,
							object:       OVHAPIObject,
							genericTypes: genericTypes,
						})
						return nil
					}
				} else {
					schema := OpenAPISchema{}
					schema.Ref = getOpenAPIRefFromOVHAPI("", typeFormat.Type, OpenAPIRefTypeDefinitions)
					property = schema
				}
			}
		}

		if len(property.Ref) == 0 {
			property.Description = objectProperty.Description

			if objectProperty.ReadOnly == "1" {
				property.ReadOnly = true
			}
		}

		schema.Properties[propertyName] = &property
	}

	return schema
}

// Add a 'body' parameter to a Open API operation object.
func addBodyParameterToOperation(parameter *OpenAPIParameter, operation *OpenAPIOperation) {
	// Must be only one body parameter.
	// So the all the body parameters must be group on one parameter object.
	if parameter.In != OpenAPIParameterInBody || parameter.Name == OpenAPIBodyParameterName {
		operation.Parameters = append(operation.Parameters, *parameter)
		return
	}

	// Search for the body parameter.
	var bodyParameter *OpenAPIParameter
	for i, operationParameter := range operation.Parameters {
		switch operationParameter.(type) {
		case OpenAPIParameter:
			p := operationParameter.(OpenAPIParameter)
			if p.In == OpenAPIParameterInBody && p.Name == OpenAPIBodyParameterName {
				bodyParameter = &p
				operation.Parameters = append(operation.Parameters[:i], operation.Parameters[i+1:]...)
				break
			}
		}
	}

	// Create the body parameter if it does not exist.
	if bodyParameter == nil {
		bodyParameter = &OpenAPIParameter{}
		bodyParameter.In = OpenAPIParameterInBody
		bodyParameter.Name = OpenAPIBodyParameterName
		bodyParameter.Schema.Type = OpenAPITypeObject
		bodyParameter.Schema.Properties = map[string]*OpenAPISchema{}
	}

	parameter.Schema.Description = parameter.Description
	bodyParameter.Schema.Properties[parameter.Name] = &parameter.Schema

	if parameter.Required {
		bodyParameter.Schema.Required = append(bodyParameter.Schema.Required, parameter.Name)
	}

	operation.Parameters = append(operation.Parameters, *bodyParameter)
}

// Format an array of strings.
func formatStrings(parts []string) []string {
	for i, part := range parts {
		if replace, ok := nameReplaces[part]; ok {
			parts[i] = replace
			part = replace
		}
		if i > 0 {
			parts[i] = fmt.Sprintf("%s%s", strings.ToTitle(part[:1]), part[1:])
		}
	}

	return parts
}
