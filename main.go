package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
)

// TODO: handle or not the namespaces (arg: -ns)

var (
	inputPath             string
	outputPath            string
	keepInternalEndpoints = false
)

func main() {
	usage := `ovhapi2openapi

Usage:
  ovhapi2openapi -i PATH -o PATH [-I]

Options:
  -h --help		Show this help
  -i PATH       Local path of the yaml API info file
  -o PATH       Local path to save the Open API file
  -I			Generate the internal endpoints
`

	args := os.Args

	if len(args) == 1 {
		fmt.Println(usage)
		os.Exit(0)
	}

	// Parse the command arguments
	for i, arg := range args {
		switch arg {
		case "-h":
		case "--help":
			fmt.Println(usage)
			os.Exit(0)
		case "-i":
			inputPath = args[i+1]
		case "-o":
			outputPath = args[i+1]
		case "-I":
			keepInternalEndpoints = true
		default:
		}
	}

	if len(inputPath) == 0 {
		fmt.Println("-i arg must be provided.")
		os.Exit(1)
	}

	if len(outputPath) == 0 {
		fmt.Println("-o arg must be provided.")
		os.Exit(1)
	}

	// Closures.
	printErrorAndExit := func(err error) {
		fmt.Printf("    error: %+v\n", err)
		os.Exit(0)
	}

	printDone := func() {
		fmt.Print("    done\n")
	}

	printStep := func(message string) {
		fmt.Printf("--- %s\n", message)
	}

	// Vars
	var err error
	var APIInfos *APIInfos
	var filteredRoutes []string
	var definition *OVHAPIDefinition
	var content []byte

	// Load the API informations.
	printStep("Load the API informations from the file: " + inputPath)
	if APIInfos, err = NewAPIInfosFromPath(inputPath); err != nil {
		printErrorAndExit(err)
	}
	printDone()

	// Load the Open API object.
	printStep("Create the Open API struct")
	OpenAPI := OpenAPIFromAPIInformations(APIInfos)
	printDone()

	// Load the routes from the API.
	API := NewOVHAPI(APIInfos.API.Path)
	printStep("Get the routes from API: " + API.basePath)
	if filteredRoutes, err = API.GetRouteList(APIInfos.API.Routes); err != nil {
		printErrorAndExit(err)
	}
	printDone()

	// Load the definitions.
	for _, route := range filteredRoutes {
		printStep("Get the definitions from API: " + API.basePath + route)
		if definition, err = API.GetDefinition(route); err != nil {
			printErrorAndExit(err)
		}
		printDone()

		printStep("Add the definitions to the Open API struct")
		if err = AddOVHAPIDefinitionToOpenAPI(definition, OpenAPI, keepInternalEndpoints); err != nil {
			printErrorAndExit(err)
		}
		printDone()
	}

	// Clean the Open API object.
	printStep("Clean the Open API struct")
	CleanOpenAPI(OpenAPI)
	printDone()

	// Save the Open API file.
	if len(outputPath) > 0 {
		printStep("Save the Open API file: " + outputPath)
		if content, err = yaml.Marshal(OpenAPI); err != nil {
			printErrorAndExit(err)
		}
		if err = ioutil.WriteFile(outputPath, content, 0644); err != nil {
			printErrorAndExit(err)
		}
		printDone()
	}
}
