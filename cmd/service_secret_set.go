package cmd

import (
	"github.com/jpignata/fargate/console"
	ECS "github.com/jpignata/fargate/ecs"
	"github.com/spf13/cobra"
)

type ServiceSecretSetOperation struct {
	ServiceName string
	SecretVars  []ECS.EnvVar
}

func (o *ServiceSecretSetOperation) Validate() {
	if len(o.SecretVars) == 0 {
		console.IssueExit("No environment variables specified")
	}
}

func (o *ServiceSecretSetOperation) SetSecretVars(inputEnvVars []string) {
	o.SecretVars = extractEnvVars(inputEnvVars)
}

var flagServiceSecretSetEnvVars []string

var serviceSecretSetCmd = &cobra.Command{
	Use:   "set --secret <key=value> [--secret <key=value] ...",
	Short: "Set secret variables",
	Long:  `Set secret variables`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		operation := &ServiceSecretSetOperation{
			ServiceName: args[0],
		}

		operation.SetSecretVars(flagServiceSecretSetEnvVars)
		operation.Validate()
		serviceSecretSet(operation)
	},
}

func init() {
	serviceSecretSetCmd.Flags().StringSliceVarP(&flagServiceEnvSetEnvVars, "secret", "s", []string{}, "Environment variables to set [e.g. KEY=value]")

	serviceSecretCmd.AddCommand(serviceSecretSetCmd)
}

func serviceSecretSet(operation *ServiceSecretSetOperation) {
	ecs := ECS.New(sess, clusterName)
	service := ecs.DescribeService(operation.ServiceName)
	taskDefinitionArn := ecs.AddSecretVarsToTaskDefinition(service.TaskDefinitionArn, operation.SecretVars)

	ecs.UpdateServiceTaskDefinition(operation.ServiceName, taskDefinitionArn)

	console.Info("Set %s environment variables:", operation.ServiceName)

	for _, envVar := range operation.SecretVars {
		console.Info("- %s=%s", envVar.Key, envVar.Value)
	}

}
