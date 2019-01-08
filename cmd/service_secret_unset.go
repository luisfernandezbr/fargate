package cmd

import (
	"strings"

	"github.com/jpignata/fargate/console"
	ECS "github.com/jpignata/fargate/ecs"
	"github.com/spf13/cobra"
)

type ServiceSecretUnsetOperation struct {
	ServiceName string
	Keys        []string
}

func (o *ServiceSecretUnsetOperation) Validate() {
	if len(o.Keys) == 0 {
		console.IssueExit("No keys specified")
	}
}

func (o *ServiceSecretUnsetOperation) SetKeys(keys []string) {
	o.Keys = Map(keys, strings.ToUpper)
}

var serviceSecretUnsetCmd = &cobra.Command{
	Use:   "unset --key <key-name> [--key <key-name>] ...",
	Short: "Unset secret variables",
	Long:  `Unset secret variables`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		operation := &ServiceSecretUnsetOperation{
			ServiceName: args[0],
		}

		operation.SetKeys(flagServiceSecretUnsetKeys)
		operation.Validate()
		serviceSecretUnset(operation)
	},
}

var flagServiceSecretUnsetKeys []string

func init() {
	serviceSecretUnsetCmd.Flags().StringSliceVarP(&flagServiceSecretUnsetKeys, "key", "k", []string{}, "Secret variable keys to unset [e.g. KEY, NGINX_PORT]")

	serviceSecretCmd.AddCommand(serviceSecretUnsetCmd)
}

func serviceSecretUnset(operation *ServiceSecretUnsetOperation) {
	ecs := ECS.New(sess, clusterName)
	service := ecs.DescribeService(operation.ServiceName)
	taskDefinitionArn := ecs.RemoveSecretVarsFromTaskDefinition(service.TaskDefinitionArn, operation.Keys)

	ecs.UpdateServiceTaskDefinition(operation.ServiceName, taskDefinitionArn)

	console.Info("Unset %s environment variables:", operation.ServiceName)

	for _, key := range operation.Keys {
		console.Info("- %s", key)
	}
}
