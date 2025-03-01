import _ from 'lodash';

/**
 * Security recommendations that can be applied to fix issues
 */
export const SECURITY_RECOMMENDATIONS = [
  {
    id: 'nonRoot',
    title: 'Run as Non-Root User',
    description: 'Set container to run as a non-root user (UID 1000)',
    apply: (data) => {
      if (!data) return data;
      const podData = _.cloneDeep(data);
      
      // Helper function to apply to containers
      const applyToContainers = (containers) => {
        if (!containers) return;
        containers.forEach(container => {
          if (!container.securityContext) container.securityContext = {};
          container.securityContext.runAsUser = 1000;
          container.securityContext.runAsNonRoot = true;
        });
      };
      
      // Apply to deployments, statefulsets, etc.
      if (podData.spec?.template?.spec) {
        applyToContainers(podData.spec.template.spec.containers);
        applyToContainers(podData.spec.template.spec.initContainers);
      }
      
      // Apply to direct pod specs
      if (podData.spec?.containers) {
        applyToContainers(podData.spec.containers);
        applyToContainers(podData.spec.initContainers);
      }
      
      return podData;
    }
  },
  {
    id: 'disablePrivilegeEscalation',
    title: 'Disable Privilege Escalation',
    description: 'Prevent containers from gaining more privileges than their parent process',
    apply: (data) => {
      if (!data) return data;
      const podData = _.cloneDeep(data);
      
      // Helper function to apply to containers
      const applyToContainers = (containers) => {
        if (!containers) return;
        containers.forEach(container => {
          if (!container.securityContext) container.securityContext = {};
          container.securityContext.allowPrivilegeEscalation = false;
        });
      };
      
      // Apply to deployments, statefulsets, etc.
      if (podData.spec?.template?.spec) {
        applyToContainers(podData.spec.template.spec.containers);
        applyToContainers(podData.spec.template.spec.initContainers);
      }
      
      // Apply to direct pod specs
      if (podData.spec?.containers) {
        applyToContainers(podData.spec.containers);
        applyToContainers(podData.spec.initContainers);
      }
      
      return podData;
    }
  },
  {
    id: 'readOnlyRootFilesystem',
    title: 'Read-Only Root Filesystem',
    description: 'Mount root filesystem as read-only to prevent modifications',
    apply: (data) => {
      if (!data) return data;
      const podData = _.cloneDeep(data);
      
      // Helper function to apply to containers
      const applyToContainers = (containers) => {
        if (!containers) return;
        containers.forEach(container => {
          if (!container.securityContext) container.securityContext = {};
          container.securityContext.readOnlyRootFilesystem = true;
        });
      };
      
      // Apply to deployments, statefulsets, etc.
      if (podData.spec?.template?.spec) {
        applyToContainers(podData.spec.template.spec.containers);
        applyToContainers(podData.spec.template.spec.initContainers);
      }
      
      // Apply to direct pod specs
      if (podData.spec?.containers) {
        applyToContainers(podData.spec.containers);
        applyToContainers(podData.spec.initContainers);
      }
      
      return podData;
    }
  },
  {
    id: 'dropCapabilities',
    title: 'Drop All Capabilities',
    description: 'Remove all Linux capabilities and only add necessary ones',
    apply: (data) => {
      if (!data) return data;
      const podData = _.cloneDeep(data);
      
      // Helper function to apply to containers
      const applyToContainers = (containers) => {
        if (!containers) return;
        containers.forEach(container => {
          if (!container.securityContext) container.securityContext = {};
          if (!container.securityContext.capabilities) container.securityContext.capabilities = {};
          container.securityContext.capabilities.drop = ["ALL"];
          // If add capabilities exist and is empty, delete it
          if (container.securityContext.capabilities.add && 
              container.securityContext.capabilities.add.length === 0) {
            delete container.securityContext.capabilities.add;
          }
        });
      };
      
      // Apply to deployments, statefulsets, etc.
      if (podData.spec?.template?.spec) {
        applyToContainers(podData.spec.template.spec.containers);
        applyToContainers(podData.spec.template.spec.initContainers);
      }
      
      // Apply to direct pod specs
      if (podData.spec?.containers) {
        applyToContainers(podData.spec.containers);
        applyToContainers(podData.spec.initContainers);
      }
      
      return podData;
    }
  }
];

/**
 * Get a recommendation for a specific security issue
 * @param {Object} issue - The security issue
 * @returns {Object|null} - The recommendation or null if not found
 */
export const getRecommendationForIssue = (issue) => {
  if (!issue) return null;
  
  const { key, category, value } = issue;
  
  // For privilege escalation issues
  if (category === 'PrivilegeEscalation' || !category) {
    switch (key) {
      case 'runAsUser':
        return SECURITY_RECOMMENDATIONS.find(rec => rec.id === 'nonRoot');
      case 'allowPrivilegeEscalation':
        return SECURITY_RECOMMENDATIONS.find(rec => rec.id === 'disablePrivilegeEscalation');
      case 'hostPath':
        return {
          id: 'removeHostPath',
          title: 'Remove Host Path Mounts',
          description: 'Replace hostPath volume mounts with emptyDir or other volume types'
        };
      case 'hostNetwork':
      case 'hostPID':
      case 'hostIPC':
        return {
          id: 'disableHostNamespaces',
          title: 'Disable Host Namespaces',
          description: 'Disable access to host namespaces to prevent container escapes'
        };
      case 'privileged':
        return {
          id: 'disablePrivileged',
          title: 'Disable Privileged Mode',
          description: 'Run containers without privileged mode to prevent potential container escapes'
        };
      default:
        // Check for dangerous capability
        if (key === 'SYS_ADMIN' || key === 'NET_ADMIN' || key === 'ALL' || 
            (value && typeof value === 'string' && (value.includes('SYS_ADMIN') || value.includes('NET_ADMIN') || value === 'ALL'))) {
          return SECURITY_RECOMMENDATIONS.find(rec => rec.id === 'dropCapabilities');
        }
        return null;
    }
  }
  
  // For RBAC issues - no direct fix recommendations
  if (category === 'RBAC') {
    return {
      id: 'limitRBACPermissions',
      title: 'Limit RBAC Permissions',
      description: 'Restrict RBAC rules to only what is necessary following principle of least privilege'
    };
  }
  
  return null;
};

/**
 * Apply all security recommendations to a Kubernetes resource
 * @param {Object} data - The Kubernetes resource data
 * @returns {Object} - The fixed resource data
 */
export const applyAllRecommendations = (data) => {
  if (!data) return data;
  
  // Create a deep clone to avoid modifying the original
  let updatedData = _.cloneDeep(data);
  
  // Apply each recommendation in sequence
  SECURITY_RECOMMENDATIONS.forEach(recommendation => {
    updatedData = recommendation.apply(updatedData);
  });
  
  return updatedData;
};