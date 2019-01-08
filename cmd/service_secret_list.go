package cmd

import (
	"fmt"

	ECS "github.com/jpignata/fargate/ecs"
	"github.com/spf13/cobra"
)

type ServiceSecretListOperation struct {
	ServiceName string
}

var serviceSecretListCmd = &cobra.Command{
	Use:   "list <service-name>",
	Short: "Show secret variables",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		operation := &ServiceSecretListOperation{
			ServiceName: args[0],
		}

		serviceSecretList(operation)
	},
}

func init() {
	serviceSecretCmd.AddCommand(serviceSecretListCmd)
}

func serviceSecretList(operation *ServiceSecretListOperation) {
	ecs := ECS.New(sess, clusterName)
	service := ecs.DescribeService(operation.ServiceName)
	envVars := ecs.GetSecretVarsFromTaskDefinition(service.TaskDefinitionArn)

	for _, envVar := range envVars {
		fmt.Printf("%s=%s\n", envVar.Key, envVar.Value)
	}
}
