Translate an OVH API schema to a Open API schema (swagger)

## Requirements

### System

*nix systems should be ok.

### Dependencies

Go must be installed.

## Usage

- Create a `.yaml` file containing metadata about the API and the routes to merge. See into the directory `Examples` to get the yaml structure.

- Run `go get -v && go install -v`

- Execute `ovhapi2openapi -i [PATH_TO_YAML_FILE] -o [PATH_TO_THE_OPENAPI_FILE]`
