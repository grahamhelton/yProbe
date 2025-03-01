/**
 * Security scanning utilities for Kubernetes manifests
 */
import _ from 'lodash';

// Known dangerous RBAC verb-resource combinations
export const DANGEROUS_RBAC_VERBS = {
  // Critical permissions
  'create': {
    '*': 'Critical',
    'pods': 'Critical',
    'deployments': 'Critical',
    'daemonsets': 'Critical',
    'statefulsets': 'Critical',
    'jobs': 'Critical',
    'cronjobs': 'Critical'
  },
  'patch': {
    '*': 'Critical',
    'pods': 'Critical',
    'deployments': 'Critical',
    'daemonsets': 'Critical',
    'statefulsets': 'Critical',
    'roles': 'Critical',
    'clusterroles': 'Critical',
    'rolebindings': 'Critical',
    'clusterrolebindings': 'Critical'
  },
  'update': {
    '*': 'Critical',
    'roles': 'Critical',
    'clusterroles': 'Critical',
    'rolebindings': 'Critical',
    'clusterrolebindings': 'Critical'
  },
  'bind': {
    '*': 'Critical'
  },
  'escalate': {
    '*': 'Critical'
  },
  'impersonate': {
    '*': 'Critical'
  },
  'delete': {
    '*': 'High',
    'pods': 'High',
    'deployments': 'High',
    'daemonsets': 'High',
    'statefulsets': 'High'
  },
  // Sensitive but sometimes necessary
  'get': {
    'secrets': 'Medium',
    'configmaps': 'Low'
  },
  'list': {
    'secrets': 'Medium',
    'configmaps': 'Low'
  },
  'watch': {
    'secrets': 'Medium'
  }
};

// Wild card resources that are especially dangerous
export const CRITICAL_WILDCARD_RESOURCES = ['*', 'pods', 'deployments', 'daemonsets', 'statefulsets', 'jobs', 'cronjobs', 'secrets', 'roles', 'clusterroles', 'rolebindings', 'clusterrolebindings'];

/**
 * Fix a specific security issue in Kubernetes manifests
 * @param {Object} data - YAML data to fix
 * @param {Object} issue - The security issue to fix
 * @returns {Object} - Fixed YAML data
 */
export const fixSingleSecurityIssue = (data, issue) => {
  const clonedData = _.cloneDeep(data);
  
  // Special case handling for different issue types
  switch(issue.key) {
    case 'hostNetwork':
    case 'hostPID':
    case 'hostIPC':
      return fixHostNamespaceIssue(clonedData, issue);
    
    case 'privileged':
      return fixPrivilegedIssue(clonedData, issue);
      
    case 'allowPrivilegeEscalation':
      return fixPrivilegeEscalationIssue(clonedData, issue);
      
    case 'runAsUser':
      // Skip runAsUser fixing when it's from the Fix All button unless it's actually a root user issue
      if (issue.fromFixAllButton && !hasRunAsRootIssue(clonedData, issue)) {
        return clonedData; // Don't fix what's not broken
      }
      return fixRunAsRootIssue(clonedData, issue);
      
    case 'hostPath':
      return fixHostPathIssue(clonedData, issue);
      
    case 'SYS_ADMIN':
    case 'NET_ADMIN':
    case 'ALL':
      return fixCapabilityIssue(clonedData, issue);
      
    case 'automountServiceAccountToken':
      return fixServiceAccountTokenIssue(clonedData, issue);
      
    default:
      return clonedData;
  }
};

/**
 * Check if a container actually has a runAsRoot issue
 */
const hasRunAsRootIssue = (data, issue) => {
  // Get container context based on resource type and container index
  const containerIndex = issue.containerIndex;
  
  // Handle cronjob containers
  if (data.kind === 'CronJob' && data.spec?.jobTemplate?.spec?.template?.spec?.containers) {
    if (containerIndex !== undefined && containerIndex < data.spec.jobTemplate.spec.template.spec.containers.length) {
      // Check if this specific container has runAsUser: 0
      const container = data.spec.jobTemplate.spec.template.spec.containers[containerIndex];
      return container.securityContext?.runAsUser === 0;
    } else if (containerIndex === undefined) {
      // Check if any container has runAsUser: 0
      return data.spec.jobTemplate.spec.template.spec.containers.some(container => 
        container.securityContext?.runAsUser === 0);
    }
  }
  // Handle main containers
  else if (data.kind === 'Pod' && data.spec?.containers) {
    if (containerIndex !== undefined && containerIndex < data.spec.containers.length) {
      // Check if this specific container has runAsUser: 0
      const container = data.spec.containers[containerIndex];
      return container.securityContext?.runAsUser === 0;
    } else if (containerIndex === undefined) {
      // Check if any container has runAsUser: 0
      return data.spec.containers.some(container => container.securityContext?.runAsUser === 0);
    }
  } 
  // Handle init containers in cronjob
  else if (data.kind === 'CronJob' && data.spec?.jobTemplate?.spec?.template?.spec?.initContainers && containerIndex !== undefined) {
    const initContainerOffset = data.spec.jobTemplate.spec.template.spec.containers?.length || 0;
    const initContainerIndex = containerIndex - initContainerOffset;
    
    if (initContainerIndex >= 0 && initContainerIndex < data.spec.jobTemplate.spec.template.spec.initContainers.length) {
      const container = data.spec.jobTemplate.spec.template.spec.initContainers[initContainerIndex];
      return container.securityContext?.runAsUser === 0;
    }
  }
  // Handle init containers in pod
  else if (data.kind === 'Pod' && data.spec?.initContainers && containerIndex !== undefined) {
    const initContainerOffset = data.spec.containers?.length || 0;
    const initContainerIndex = containerIndex - initContainerOffset;
    
    if (initContainerIndex >= 0 && initContainerIndex < data.spec.initContainers.length) {
      const container = data.spec.initContainers[initContainerIndex];
      return container.securityContext?.runAsUser === 0;
    }
  } 
  // Handle main containers in deployments
  else if (data.spec?.template?.spec?.containers) {
    if (containerIndex !== undefined && containerIndex < data.spec.template.spec.containers.length) {
      // Check if this specific container has runAsUser: 0
      const container = data.spec.template.spec.containers[containerIndex];
      return container.securityContext?.runAsUser === 0;
    } else if (containerIndex === undefined) {
      // Check if any container has runAsUser: 0
      return data.spec.template.spec.containers.some(container => 
        container.securityContext?.runAsUser === 0);
    }
  }
  // Handle init containers in deployments
  else if (data.spec?.template?.spec?.initContainers && containerIndex !== undefined) {
    const initContainerOffset = data.spec.template.spec.containers?.length || 0;
    const initContainerIndex = containerIndex - initContainerOffset;
    
    if (initContainerIndex >= 0 && initContainerIndex < data.spec.template.spec.initContainers.length) {
      const container = data.spec.template.spec.initContainers[initContainerIndex];
      return container.securityContext?.runAsUser === 0;
    }
  }
  
  return false;
};

/**
 * Fix host namespace issues (hostNetwork, hostPID, hostIPC)
 */
const fixHostNamespaceIssue = (data, issue) => {
  const hostKey = issue.key;
  
  // Only set false if it's currently true, to avoid adding unnecessary fields
  // Find pod spec based on the kind and set the specific host namespace to false
  if (data.kind === 'Pod' && data.spec) {
    if (data.spec[hostKey] === true) {
      data.spec[hostKey] = false;
    }
  } 
  // For CronJob resources
  else if (data.kind === 'CronJob' && data.spec?.jobTemplate?.spec?.template?.spec) {
    if (data.spec.jobTemplate.spec.template.spec[hostKey] === true) {
      data.spec.jobTemplate.spec.template.spec[hostKey] = false;
    }
  }
  // For Deployments and similar workloads
  else if (data.spec?.template?.spec) {
    if (data.spec.template.spec[hostKey] === true) {
      data.spec.template.spec[hostKey] = false;
    }
  }
  
  return data;
};

/**
 * Fix privileged container issues
 */
const fixPrivilegedIssue = (data, issue) => {
  // Helper function to fix containers - only fix privileged mode
  const fixContainer = (container, containerIndex) => {
    // Skip containers that aren't the target when containerIndex is specified
    if (issue.containerIndex !== undefined && containerIndex !== issue.containerIndex) {
      return;
    }
    
    // Only fix if the container has privileged: true
    if (container.securityContext?.privileged === true) {
      if (!container.securityContext) {
        container.securityContext = {};
      }
      container.securityContext.privileged = false;
      
      // Clean up empty securityContext
      if (Object.keys(container.securityContext).length === 0) {
        delete container.securityContext;
      }
    }
  };
  
  // Apply to appropriate containers based on resource type
  if (data.kind === 'Pod' && data.spec) {
    if (data.spec.containers) {
      data.spec.containers.forEach((container, index) => {
        fixContainer(container, index);
      });
    }
    if (data.spec.initContainers) {
      data.spec.initContainers.forEach((container, index) => {
        // For init containers, we use an offset to distinguish from regular containers
        const initContainerIndex = index + (data.spec.containers?.length || 0);
        fixContainer(container, initContainerIndex);
      });
    }
  }
  // For CronJob resources
  else if (data.kind === 'CronJob' && data.spec?.jobTemplate?.spec?.template?.spec) {
    if (data.spec.jobTemplate.spec.template.spec.containers) {
      data.spec.jobTemplate.spec.template.spec.containers.forEach((container, index) => {
        fixContainer(container, index);
      });
    }
    if (data.spec.jobTemplate.spec.template.spec.initContainers) {
      data.spec.jobTemplate.spec.template.spec.initContainers.forEach((container, index) => {
        // For init containers, we use an offset to distinguish from regular containers
        const initContainerIndex = index + (data.spec.jobTemplate.spec.template.spec.containers?.length || 0);
        fixContainer(container, initContainerIndex);
      });
    }
  }
  // For Deployments and similar workloads
  else if (data.spec?.template?.spec) {
    if (data.spec.template.spec.containers) {
      data.spec.template.spec.containers.forEach((container, index) => {
        fixContainer(container, index);
      });
    }
    if (data.spec.template.spec.initContainers) {
      data.spec.template.spec.initContainers.forEach((container, index) => {
        // For init containers, we use an offset to distinguish from regular containers
        const initContainerIndex = index + (data.spec.template.spec.containers?.length || 0);
        fixContainer(container, initContainerIndex);
      });
    }
  }
  
  return data;
};

/**
 * Fix privilege escalation issues
 */
const fixPrivilegeEscalationIssue = (data, issue) => {
  // Helper function to fix containers - only fix allowPrivilegeEscalation
  const fixContainer = (container, containerIndex) => {
    // Skip containers that aren't the target when containerIndex is specified
    if (issue.containerIndex !== undefined && containerIndex !== issue.containerIndex) {
      return;
    }
    
    // Only fix if the container has allowPrivilegeEscalation: true
    if (container.securityContext?.allowPrivilegeEscalation === true) {
      if (!container.securityContext) {
        container.securityContext = {};
      }
      container.securityContext.allowPrivilegeEscalation = false;
      
      // Clean up empty securityContext
      if (Object.keys(container.securityContext).length === 0) {
        delete container.securityContext;
      }
    }
  };
  
  // Apply to appropriate containers based on resource type
  if (data.kind === 'Pod' && data.spec) {
    if (data.spec.containers) {
      data.spec.containers.forEach((container, index) => {
        fixContainer(container, index);
      });
    }
    if (data.spec.initContainers) {
      data.spec.initContainers.forEach((container, index) => {
        // For init containers, we use an offset to distinguish from regular containers
        const initContainerIndex = index + (data.spec.containers?.length || 0);
        fixContainer(container, initContainerIndex);
      });
    }
  }
  // For CronJob resources
  else if (data.kind === 'CronJob' && data.spec?.jobTemplate?.spec?.template?.spec) {
    if (data.spec.jobTemplate.spec.template.spec.containers) {
      data.spec.jobTemplate.spec.template.spec.containers.forEach((container, index) => {
        fixContainer(container, index);
      });
    }
    if (data.spec.jobTemplate.spec.template.spec.initContainers) {
      data.spec.jobTemplate.spec.template.spec.initContainers.forEach((container, index) => {
        // For init containers, we use an offset to distinguish from regular containers
        const initContainerIndex = index + (data.spec.jobTemplate.spec.template.spec.containers?.length || 0);
        fixContainer(container, initContainerIndex);
      });
    }
  }
  // For Deployments and similar workloads
  else if (data.spec?.template?.spec) {
    if (data.spec.template.spec.containers) {
      data.spec.template.spec.containers.forEach((container, index) => {
        fixContainer(container, index);
      });
    }
    if (data.spec.template.spec.initContainers) {
      data.spec.template.spec.initContainers.forEach((container, index) => {
        // For init containers, we use an offset to distinguish from regular containers
        const initContainerIndex = index + (data.spec.template.spec.containers?.length || 0);
        fixContainer(container, initContainerIndex);
      });
    }
  }
  
  return data;
};

/**
 * Fix runAsUser:0 (root) issues
 */
const fixRunAsRootIssue = (data, issue) => {
  // Helper function to fix containers - ONLY fix runAsUser if it's explicitly 0 (root)
  const fixContainer = (container, containerIndex) => {
    // Skip containers that aren't the target when containerIndex is specified
    if (issue.containerIndex !== undefined && containerIndex !== issue.containerIndex) {
      return;
    }
    
    // CRITICAL: Only change runAsUser if it's EXPLICITLY set to 0
    // Do not add runAsUser if it doesn't exist or has another value
    if (container.securityContext?.runAsUser === 0) {
      // Ensure securityContext exists
      if (!container.securityContext) {
        container.securityContext = {};
      }
      
      // Change only what needs to be fixed - the root user
      container.securityContext.runAsUser = 1000;
      container.securityContext.runAsNonRoot = true;
    }
    
    // Clean up empty securityContext
    if (container.securityContext && Object.keys(container.securityContext).length === 0) {
      delete container.securityContext;
    }
  };
  
  // Apply to appropriate containers based on resource type
  if (data.kind === 'Pod' && data.spec) {
    if (data.spec.containers) {
      data.spec.containers.forEach((container, index) => {
        fixContainer(container, index);
      });
    }
    if (data.spec.initContainers) {
      data.spec.initContainers.forEach((container, index) => {
        // For init containers, we use an offset to distinguish from regular containers
        const initContainerIndex = index + (data.spec.containers?.length || 0);
        fixContainer(container, initContainerIndex);
      });
    }
  }
  // For CronJob resources
  else if (data.kind === 'CronJob' && data.spec?.jobTemplate?.spec?.template?.spec) {
    if (data.spec.jobTemplate.spec.template.spec.containers) {
      data.spec.jobTemplate.spec.template.spec.containers.forEach((container, index) => {
        fixContainer(container, index);
      });
    }
    if (data.spec.jobTemplate.spec.template.spec.initContainers) {
      data.spec.jobTemplate.spec.template.spec.initContainers.forEach((container, index) => {
        // For init containers, we use an offset to distinguish from regular containers
        const initContainerIndex = index + (data.spec.jobTemplate.spec.template.spec.containers?.length || 0);
        fixContainer(container, initContainerIndex);
      });
    }
  } 
  // For Deployments and similar workloads
  else if (data.spec?.template?.spec) {
    if (data.spec.template.spec.containers) {
      data.spec.template.spec.containers.forEach((container, index) => {
        fixContainer(container, index);
      });
    }
    if (data.spec.template.spec.initContainers) {
      data.spec.template.spec.initContainers.forEach((container, index) => {
        // For init containers, we use an offset to distinguish from regular containers
        const initContainerIndex = index + (data.spec.template.spec.containers?.length || 0);
        fixContainer(container, initContainerIndex);
      });
    }
  }
  
  return data;
};

/**
 * Fix hostPath volume issues
 */
const fixHostPathIssue = (data, issue) => {
  // Function to fix volumes - only volumes with hostPath
  const fixVolumes = (volumes) => {
    if (!volumes || !Array.isArray(volumes)) return;
    
    volumes.forEach(volume => {
      if (volume.hostPath) {
        delete volume.hostPath;
        volume.emptyDir = {};
      }
    });
  };
  
  // Apply to appropriate spec based on resource type
  if (data.kind === 'Pod' && data.spec?.volumes) {
    fixVolumes(data.spec.volumes);
  }
  // For CronJob resources
  else if (data.kind === 'CronJob' && data.spec?.jobTemplate?.spec?.template?.spec?.volumes) {
    fixVolumes(data.spec.jobTemplate.spec.template.spec.volumes);
  }
  // For Deployments and similar workloads 
  else if (data.spec?.template?.spec?.volumes) {
    fixVolumes(data.spec.template.spec.volumes);
  }
  
  return data;
};

/**
 * Fix capability issues
 */
const fixCapabilityIssue = (data, issue) => {
  const capToRemove = issue.value || issue.key;
  
  // Helper function to fix container capabilities - only remove the specific capability
  const fixContainer = (container, containerIndex) => {
    // Skip containers that aren't the target when containerIndex is specified
    if (issue.containerIndex !== undefined && containerIndex !== issue.containerIndex) {
      return;
    }
    
    if (container.securityContext?.capabilities?.add) {
      // Check if the capability to remove exists
      const hasCapability = container.securityContext.capabilities.add.includes(capToRemove);
      
      if (hasCapability) {
        // Remove the specific dangerous capability
        container.securityContext.capabilities.add = 
          container.securityContext.capabilities.add.filter(cap => cap !== capToRemove);
        
        // Clean up if empty
        if (container.securityContext.capabilities.add.length === 0) {
          delete container.securityContext.capabilities.add;
        }
        
        // Add drop: ["ALL"] only if removing a capability
        if (!container.securityContext.capabilities.drop) {
          container.securityContext.capabilities.drop = ["ALL"];
        }
        
        // Clean up if capabilities has no properties
        if (!container.securityContext.capabilities.add && 
            !container.securityContext.capabilities.drop) {
          delete container.securityContext.capabilities;
        }
        
        // Clean up empty securityContext
        if (Object.keys(container.securityContext).length === 0) {
          delete container.securityContext;
        }
      }
    }
  };
  
  // Apply to appropriate containers based on resource type
  if (data.kind === 'Pod' && data.spec) {
    if (data.spec.containers) {
      data.spec.containers.forEach((container, index) => {
        fixContainer(container, index);
      });
    }
    if (data.spec.initContainers) {
      data.spec.initContainers.forEach((container, index) => {
        // For init containers, we use an offset to distinguish from regular containers
        const initContainerIndex = index + (data.spec.containers?.length || 0);
        fixContainer(container, initContainerIndex);
      });
    }
  }
  // For CronJob resources
  else if (data.kind === 'CronJob' && data.spec?.jobTemplate?.spec?.template?.spec) {
    if (data.spec.jobTemplate.spec.template.spec.containers) {
      data.spec.jobTemplate.spec.template.spec.containers.forEach((container, index) => {
        fixContainer(container, index);
      });
    }
    if (data.spec.jobTemplate.spec.template.spec.initContainers) {
      data.spec.jobTemplate.spec.template.spec.initContainers.forEach((container, index) => {
        // For init containers, we use an offset to distinguish from regular containers
        const initContainerIndex = index + (data.spec.jobTemplate.spec.template.spec.containers?.length || 0);
        fixContainer(container, initContainerIndex);
      });
    }
  }
  // For Deployments and similar workloads
  else if (data.spec?.template?.spec) {
    if (data.spec.template.spec.containers) {
      data.spec.template.spec.containers.forEach((container, index) => {
        fixContainer(container, index);
      });
    }
    if (data.spec.template.spec.initContainers) {
      data.spec.template.spec.initContainers.forEach((container, index) => {
        // For init containers, we use an offset to distinguish from regular containers
        const initContainerIndex = index + (data.spec.template.spec.containers?.length || 0);
        fixContainer(container, initContainerIndex);
      });
    }
  }
  
  return data;
};

/**
 * Fix automountServiceAccountToken issues
 */
const fixServiceAccountTokenIssue = (data, issue) => {
  // Apply to appropriate spec based on resource type - only if it's currently true
  if (data.kind === 'Pod' && data.spec) {
    // Only set if it's true
    if (data.spec.automountServiceAccountToken === true) {
      data.spec.automountServiceAccountToken = false;
    }
  }
  // For CronJob resources
  else if (data.kind === 'CronJob' && data.spec?.jobTemplate?.spec?.template?.spec) {
    // Only set if it's true
    if (data.spec.jobTemplate.spec.template.spec.automountServiceAccountToken === true) {
      data.spec.jobTemplate.spec.template.spec.automountServiceAccountToken = false;
    }
  }
  // For Deployments and similar workloads 
  else if (data.spec?.template?.spec) {
    // Only set if it's true
    if (data.spec.template.spec.automountServiceAccountToken === true) {
      data.spec.template.spec.automountServiceAccountToken = false;
    }
  }
  
  return data;
};

/**
 * Fix all security issues in a manifest
 * @param {Object} data - YAML data to fix
 * @returns {Object} - Fixed YAML data
 * 
 * NOTE: This function is kept for compatibility but is no longer used for the Fix Pod Issues button.
 * The button now uses individual issue fixes via fixSingleSecurityIssue instead.
 */
export const fixAllSecurityIssues = (data) => {
  if (!data || typeof data !== 'object') return data;
  
  // Create a deep clone of the data to avoid modifying original
  const fixedData = _.cloneDeep(data);
  
  // Fix security issues in pod specs
  if (data.kind === 'Pod' || data.spec?.template || (data.kind === 'CronJob' && data.spec?.jobTemplate?.spec?.template)) {
    let podSpec;
    if (data.kind === 'Pod') {
      podSpec = fixedData.spec;
    } else if (data.kind === 'CronJob') {
      podSpec = fixedData.spec?.jobTemplate?.spec?.template?.spec;
    } else {
      podSpec = fixedData.spec?.template?.spec;
    }
    
    if (podSpec) {
      // Fix host namespaces only if they're true
      if (podSpec.hostNetwork === true) podSpec.hostNetwork = false;
      if (podSpec.hostPID === true) podSpec.hostPID = false;
      if (podSpec.hostIPC === true) podSpec.hostIPC = false;
      
      // Fix automountServiceAccountToken only if it's true
      if (podSpec.automountServiceAccountToken === true) {
        podSpec.automountServiceAccountToken = false;
      }
      
      // Fix containers
      if (podSpec.containers) {
        podSpec.containers.forEach(container => {
          // Only create securityContext if needed
          const needsSecurityContext = 
            container.securityContext?.privileged === true ||
            container.securityContext?.allowPrivilegeEscalation === true ||
            container.securityContext?.runAsUser === 0 ||
            container.securityContext?.capabilities?.add?.some(cap => 
              ['SYS_ADMIN', 'NET_ADMIN', 'ALL'].includes(cap));
          
          if (needsSecurityContext) {
            if (!container.securityContext) {
              container.securityContext = {};
            }
            
            // Fix privileged mode only if true
            if (container.securityContext.privileged === true) {
              container.securityContext.privileged = false;
            }
            
            // Fix allowPrivilegeEscalation only if true
            if (container.securityContext.allowPrivilegeEscalation === true) {
              container.securityContext.allowPrivilegeEscalation = false;
            }
            
            // Fix running as root - ONLY if explicitly set to 0
            if (container.securityContext.runAsUser === 0) {
              container.securityContext.runAsUser = 1000;
              container.securityContext.runAsNonRoot = true;
            }
            
            // Fix capabilities only if dangerous ones exist
            if (container.securityContext.capabilities?.add?.some(cap => 
                ['SYS_ADMIN', 'NET_ADMIN', 'ALL'].includes(cap))) {
              
              if (!container.securityContext.capabilities) {
                container.securityContext.capabilities = {};
              }
              
              // Set drop: ["ALL"] if removing capabilities
              if (!container.securityContext.capabilities.drop) {
                container.securityContext.capabilities.drop = ["ALL"];
              }
              
              // Remove dangerous capabilities
              if (container.securityContext.capabilities.add) {
                const dangerousCaps = ['SYS_ADMIN', 'NET_ADMIN', 'ALL'];
                container.securityContext.capabilities.add = 
                  container.securityContext.capabilities.add.filter(cap => !dangerousCaps.includes(cap));
                
                // If all capabilities were removed, delete the add property
                if (container.securityContext.capabilities.add.length === 0) {
                  delete container.securityContext.capabilities.add;
                }
                
                // Clean up empty capabilities
                if (Object.keys(container.securityContext.capabilities).length === 0) {
                  delete container.securityContext.capabilities;
                }
              }
            }
            
            // Clean up empty securityContext
            if (Object.keys(container.securityContext).length === 0) {
              delete container.securityContext;
            }
          }
        });
      }
      
      // Apply same fixes to initContainers if they exist
      if (podSpec.initContainers) {
        podSpec.initContainers.forEach(container => {
          // Only create securityContext if needed
          const needsSecurityContext = 
            container.securityContext?.privileged === true ||
            container.securityContext?.allowPrivilegeEscalation === true ||
            container.securityContext?.runAsUser === 0 ||
            container.securityContext?.capabilities?.add?.some(cap => 
              ['SYS_ADMIN', 'NET_ADMIN', 'ALL'].includes(cap));
          
          if (needsSecurityContext) {
            if (!container.securityContext) {
              container.securityContext = {};
            }
            
            // Fix privileged mode only if true
            if (container.securityContext.privileged === true) {
              container.securityContext.privileged = false;
            }
            
            // Fix allowPrivilegeEscalation only if true
            if (container.securityContext.allowPrivilegeEscalation === true) {
              container.securityContext.allowPrivilegeEscalation = false;
            }
            
            // Fix running as root - ONLY if explicitly set to 0
            if (container.securityContext.runAsUser === 0) {
              container.securityContext.runAsUser = 1000;
              container.securityContext.runAsNonRoot = true;
            }
            
            // Fix capabilities only if dangerous ones exist
            if (container.securityContext.capabilities?.add?.some(cap => 
                ['SYS_ADMIN', 'NET_ADMIN', 'ALL'].includes(cap))) {
              
              if (!container.securityContext.capabilities) {
                container.securityContext.capabilities = {};
              }
              
              // Set drop: ["ALL"] if removing capabilities
              if (!container.securityContext.capabilities.drop) {
                container.securityContext.capabilities.drop = ["ALL"];
              }
              
              // Remove dangerous capabilities
              if (container.securityContext.capabilities.add) {
                const dangerousCaps = ['SYS_ADMIN', 'NET_ADMIN', 'ALL'];
                container.securityContext.capabilities.add = 
                  container.securityContext.capabilities.add.filter(cap => !dangerousCaps.includes(cap));
                
                // If all capabilities were removed, delete the add property
                if (container.securityContext.capabilities.add.length === 0) {
                  delete container.securityContext.capabilities.add;
                }
                
                // Clean up empty capabilities
                if (Object.keys(container.securityContext.capabilities).length === 0) {
                  delete container.securityContext.capabilities;
                }
              }
            }
            
            // Clean up empty securityContext
            if (Object.keys(container.securityContext).length === 0) {
              delete container.securityContext;
            }
          }
        });
      }
      
      // Fix volumes with hostPath
      if (podSpec.volumes) {
        podSpec.volumes.forEach(volume => {
          if (volume.hostPath) {
            // Replace hostPath with emptyDir
            delete volume.hostPath;
            volume.emptyDir = {};
          }
        });
      }
    }
  }
  
  return fixedData;
};

/**
 * Group security issues by severity
 * @param {Array} issues - List of security issues
 * @returns {Object} - Issues grouped by severity
 */
export const groupSecurityIssuesBySeverity = (issues) => {
  return issues.reduce((acc, issue) => {
    if (!acc[issue.severity]) {
      acc[issue.severity] = [];
    }
    acc[issue.severity].push(issue);
    return acc;
  }, {});
};

/**
 * Group security issues by category
 * @param {Array} issues - List of security issues
 * @returns {Object} - Issues grouped by category
 */
export const groupSecurityIssuesByCategory = (issues) => {
  return issues.reduce((acc, issue) => {
    const category = issue.category || 'Other';
    if (!acc[category]) {
      acc[category] = [];
    }
    acc[category].push(issue);
    return acc;
  }, {});
};