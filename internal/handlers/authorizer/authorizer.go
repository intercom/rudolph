package authorizer

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

var (
	errBlankRequestBody = errors.New("Request body is blank")
)

type authorizerEnvironment struct {
	Region           string
	GatewayID        string
	AccountID        string
	SyncTokenSSMPath string
}

var (
	authorizerEnv authorizerEnvironment
	syncToken     string
)

func init() {
	authorizerEnv = authorizerEnvironment{
		Region:           os.Getenv("REGION"),
		GatewayID:        os.Getenv("GATEWAY_ID"),
		AccountID:        os.Getenv("ACCOUNT_ID"),
		SyncTokenSSMPath: os.Getenv("SYNC_TOKEN_SSM_PATH"),
	}

	if authorizerEnv.SyncTokenSSMPath != "" {
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(authorizerEnv.Region))
		if err != nil {
			log.Fatalf("failed to load AWS config for SSM: %v", err)
		}
		client := ssm.NewFromConfig(cfg)
		result, err := client.GetParameter(context.Background(), &ssm.GetParameterInput{
			Name:           aws.String(authorizerEnv.SyncTokenSSMPath),
			WithDecryption: aws.Bool(true),
		})
		if err != nil {
			log.Fatalf("failed to fetch sync token from SSM path %s: %v", authorizerEnv.SyncTokenSSMPath, err)
		}
		syncToken = aws.ToString(result.Parameter.Value)
		log.Printf("sync token loaded from SSM successfully")
	}
}

// HandleAuthorizerRequest is the handler to be used by the authorizer function
func HandleAuthorizerRequest(request events.APIGatewayProxyRequest) (*events.APIGatewayCustomAuthorizerResponse, error) {
	log.Printf("lambda request - HandleAuthorizerRequest:\n%+v\n", request)

	if request.HTTPMethod == "GET" && request.Path == "/health" {
		return allowResponse("HEALTH_CHECK"), nil
	}

	if request.HTTPMethod != "POST" {
		return denyResponse("Incorrect Method"), nil
	}

	machineID, ok := request.PathParameters["machine_id"]
	if !ok {
		return denyResponse("Incorrect Request URI"), nil
	}

	// Validate the pre-shared sync token if one is configured.
	// Santa sends it via SyncExtraHeaders: { "Authorization": "Bearer <token>" }
	if syncToken != "" {
		authHeader := request.Headers["Authorization"]
		if authHeader == "" {
			authHeader = request.Headers["authorization"]
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" || token == authHeader || token != syncToken {
			return denyResponse("Invalid token"), nil
		}
	}

	return allowResponse(machineID), nil
}

func denyResponse(denyReason string) *events.APIGatewayCustomAuthorizerResponse {
	context := make(map[string]interface{}, 1)
	context["DenyReason"] = denyReason

	return &events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: "UNKNOWN_SENSOR",
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   "Deny",
					Resource: []string{"arn:aws:execute-api:*:*:*/*/*/*"},
				},
			},
		},
		Context:            context,
		UsageIdentifierKey: "UNKNOWN_SENSOR",
	}
}

func allowResponse(machineID string) *events.APIGatewayCustomAuthorizerResponse {
	context := make(map[string]interface{}, 1)
	context["MachineID"] = machineID

	resourceArn := fmt.Sprintf("arn:aws:execute-api:%s:%s:%s/*/*/*/*", authorizerEnv.Region, authorizerEnv.AccountID, authorizerEnv.GatewayID)
	return &events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: "ValidSantaEndpoint",
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   "Allow",
					Resource: []string{resourceArn},
				},
			},
		},
		Context:            context,
		UsageIdentifierKey: machineID,
	}
}
