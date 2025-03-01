# yProbe Example Files

This directory contains example Kubernetes YAML manifests that demonstrate various security patterns and issues that yProbe can detect.

## Organization

The examples are organized into categories:

- **pods/**: Pod manifests with various security configurations
- **deployments/**: Deployment resources with different security settings
- **cronjobs/**: CronJob examples with secure and insecure configurations
- **roles/**: Role and RoleBinding examples
- **clusterroles/**: ClusterRole and ClusterRoleBinding examples
- **other/**: Other resource types like StatefulSets, DaemonSets, etc.

## Security Levels

Examples include both secure and insecure patterns:

- **Secure examples**: Follow Kubernetes security best practices
- **Insecure examples**: Demonstrate common security issues
- **Mixed examples**: Show a combination of secure and insecure patterns

## How to Use

Drag and drop any of these files into yProbe to see how the security scanner works. You can also use these examples to test your own security scanning tools.