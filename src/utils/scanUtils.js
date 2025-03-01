/**
 * Security scanning utilities for Kubernetes manifests
 */
import { DANGEROUS_RBAC_VERBS, CRITICAL_WILDCARD_RESOURCES } from './securityUtils';

/**
 * Scan Kubernetes manifests for security issues
 * @param {Object|Array} data - YAML data to scan
 * @param {boolean} isMultiDoc - Whether the data is multiple documents
 * @returns {Array} - Array of security issues
 */
export const scanForSecurityIssues = (data, isMultiDoc = false) => {
  let issues = [];
  
  if (isMultiDoc && Array.isArray(data)) {
    // For multiple documents, scan each one and track document index
    data.forEach((doc, docIndex) => {
      const docIssues = scanDocument(doc);
      // Add document index to each issue for reference
      docIssues.forEach(issue => {
        issue.documentIndex = docIndex;
        issue.path = `document[${docIndex}].${issue.path}`;
      });
      issues = [...issues, ...docIssues];
    });
  } else {
    // Single document scan
    issues = scanDocument(data);
  }
  
  return issues;
};

/**
 * Scan a single document for security issues
 * @param {Object} data - Single document to scan
 * @returns {Array} - Security issues found in the document
 */
const scanDocument = (data) => {
  if (!data || typeof data !== 'object') return [];
  
  const issues = [];
  
  // Check Kind-specific security issues
  if (data.kind) {
    // Check RBAC resources (Role, ClusterRole)
    if (data.kind === 'Role' || data.kind === 'ClusterRole') {
      issues.push(...scanRBACIssues(data));
    }
    
    // Check Pod and resources that contain Pod templates
    if (data.kind === 'Pod' || data.spec?.template || (data.kind === 'CronJob' && data.spec?.jobTemplate?.spec?.template)) {
      issues.push(...scanPodSecurityIssues(data));
    }
  }
  
  return issues;
};

/**
 * Scan RBAC resources for security issues
 * @param {Object} data - RBAC resource to scan
 * @returns {Array} - Security issues found
 */
const scanRBACIssues = (data) => {
  const issues = [];
  
  // Check rules for dangerous permissions
  if (data.rules && Array.isArray(data.rules)) {
    data.rules.forEach((rule, ruleIndex) => {
      const apiGroups = rule.apiGroups || [];
      const resources = rule.resources || [];
      const verbs = rule.verbs || [];
      const nonResourceURLs = rule.nonResourceURLs || [];
      
      // Ensure compatibility with both single and multi-document YAMLs
      
      // Check 1: Look for wildcard resources - this is a critical security issue
      if (resources.includes('*')) {
        // Add a rule-level issue for the wildcard resource
        issues.push({
          path: `rules[${ruleIndex}]`,
          key: 'rules',
          value: '*',
          issue: 'Wildcard resources RBAC permissions',
          severity: 'Critical',
          category: 'RBAC',
          description: 'This role grants permissions to all resources (*) which effectively provides access to potentially sensitive resources. This is dangerous and violates principle of least privilege.'
        });
        
        // Find the wildcard resource in the array
        const wildcardIndex = resources.indexOf('*');
        if (wildcardIndex !== -1) {
          // Add an issue specifically for the wildcard resource
          issues.push({
            path: `rules[${ruleIndex}].resources[${wildcardIndex}]`,
            key: 'resources',
            value: '*',
            issue: 'Wildcard resources access',
            severity: 'Critical',
            category: 'RBAC',
            description: 'The wildcard resource (*) grants access to all resources in the API group, including potentially sensitive ones like secrets, configmaps, and more.'
          });
        }
      }
      
      // Check for wildcarded API groups
      const hasWildcardApiGroup = apiGroups.includes('*');
      
      // Check for wildcarded verbs
      const hasWildcardVerb = verbs.includes('*');
      if (hasWildcardVerb) {
        const wildcardIndex = verbs.indexOf('*');
        if (wildcardIndex !== -1) {
          // Add an issue specifically for the wildcard verb
          issues.push({
            path: `rules[${ruleIndex}].verbs[${wildcardIndex}]`,
            key: 'verbs',
            value: '*',
            issue: 'Wildcard verb access',
            severity: 'Critical',
            category: 'RBAC',
            description: 'The wildcard verb (*) grants all possible actions on the specified resources, which is a significant security risk and violates the principle of least privilege.'
          });
        }
      }
      
      // Check for wildcarded resources
      const hasWildcardResource = resources.includes('*');
      
      // Check wildcard combinations - the most dangerous
      if (hasWildcardApiGroup && hasWildcardResource && hasWildcardVerb) {
        issues.push({
          path: `rules[${ruleIndex}]`,
          key: 'rules',
          value: '*',
          issue: 'Full wildcard RBAC permissions',
          severity: 'Critical',
          category: 'RBAC',
          description: 'This role grants full wildcard permissions (*/*/*), effectively providing full access to the cluster. This is extremely dangerous and violates principle of least privilege.'
        });
        
        // Add issue for the wildcard verb specifically
        const wildcardIndex = verbs.indexOf('*');
        if (wildcardIndex !== -1) {
          issues.push({
            path: `rules[${ruleIndex}].verbs[${wildcardIndex}]`,
            key: 'verbs',
            value: '*',
            issue: 'Wildcard verb with full permissions',
            severity: 'Critical',
            category: 'RBAC',
            description: 'The wildcard verb (*) combined with wildcarded resources and API groups grants full access to everything in the cluster. This is extremely dangerous and violates principle of least privilege.'
          });
        }
        
        return; // Skip further checks for this rule
      }
      
      // Check for dangerous non-resource URL permissions
      if (nonResourceURLs && nonResourceURLs.includes('*')) {
        issues.push({
          path: `rules[${ruleIndex}].nonResourceURLs`,
          key: 'nonResourceURLs',
          value: '*',
          issue: 'Wildcard non-resource URL access',
          severity: 'High',
          category: 'RBAC',
          description: 'This role grants access to all non-resource URLs, which can include sensitive API server endpoints. This permission should be limited to specific URLs only.'
        });
      }
      
      // Check specific combinations of verbs and resources
      if (!hasWildcardVerb) {
        verbs.forEach((verb, verbIndex) => {
          // Check if this verb is in our dangerous list
          if (DANGEROUS_RBAC_VERBS[verb]) {
            // If resources are wildcarded, check against all dangerous resources for this verb
            if (hasWildcardResource) {
              if (DANGEROUS_RBAC_VERBS[verb]['*']) {
                issues.push({
                  path: `rules[${ruleIndex}]`,
                  key: 'rules',
                  value: `${verb} *`,
                  issue: `Dangerous RBAC permission: ${verb} on all resources`,
                  severity: DANGEROUS_RBAC_VERBS[verb]['*'],
                  category: 'RBAC',
                  description: `The '${verb}' permission on all resources is extremely risky and provides excessive access that violates the principle of least privilege.`
                });
                
                // Add specific issue for the verb
                issues.push({
                  path: `rules[${ruleIndex}].verbs[${verbIndex}]`,
                  key: 'verbs',
                  value: verb,
                  issue: `Dangerous verb: ${verb} on all resources`,
                  severity: DANGEROUS_RBAC_VERBS[verb]['*'],
                  category: 'RBAC',
                  description: `The '${verb}' permission on all resources is extremely risky and provides excessive access that violates the principle of least privilege.`
                });
              } else {
                // Check all known dangerous resources for this verb
                Object.keys(DANGEROUS_RBAC_VERBS[verb]).forEach(resource => {
                  if (resource !== '*') {
                    issues.push({
                      path: `rules[${ruleIndex}]`,
                      key: 'rules',
                      value: `${verb} *.${resource}`,
                      issue: `Dangerous RBAC permission: ${verb} ${resource}`,
                      severity: DANGEROUS_RBAC_VERBS[verb][resource],
                      category: 'RBAC',
                      description: `The '${verb}' permission on all '${resource}' is risky. This allows a user to ${verb} any ${resource}, which could lead to privilege escalation or sensitive data exposure.`
                    });
                  }
                });
              }
            } else {
              // Check specific resources against dangerous verb
              resources.forEach((resource, resourceIndex) => {
                // Strip subresources for matching
                const baseResource = resource.split('/')[0];
                
                // Check if this resource is dangerous with this verb
                if (DANGEROUS_RBAC_VERBS[verb][baseResource]) {
                  // Add rule-level issue
                  issues.push({
                    path: `rules[${ruleIndex}]`,
                    key: 'rules',
                    value: `${verb} ${resource}`,
                    issue: `Sensitive RBAC permission: ${verb} ${resource}`,
                    severity: DANGEROUS_RBAC_VERBS[verb][baseResource],
                    category: 'RBAC',
                    description: `The '${verb}' permission on '${resource}' can be risky. This allows a user to ${verb} ${resource}, which could lead to ${DANGEROUS_RBAC_VERBS[verb][baseResource] === 'Critical' ? 
                      'severe security issues including privilege escalation.' : 
                      'potential security concerns depending on usage context.'}`
                  });
                  
                  // Add verb-specific issue
                  issues.push({
                    path: `rules[${ruleIndex}].verbs[${verbIndex}]`,
                    key: 'verbs',
                    value: verb,
                    issue: `Dangerous verb: ${verb} on ${resource}`,
                    severity: DANGEROUS_RBAC_VERBS[verb][baseResource],
                    category: 'RBAC',
                    description: `The '${verb}' permission on '${resource}' can be risky. This allows a user to ${verb} ${resource}, which could lead to ${DANGEROUS_RBAC_VERBS[verb][baseResource] === 'Critical' ?
                      'severe security issues including privilege escalation.' :
                      'potential security concerns depending on usage context.'}`
                  });
                  
                  // Add resource-specific issue to highlight the resource
                  issues.push({
                    path: `rules[${ruleIndex}].resources[${resourceIndex}]`,
                    key: 'resources',
                    value: resource,
                    issue: `Sensitive resource: ${resource} with ${verb}`,
                    severity: DANGEROUS_RBAC_VERBS[verb][baseResource],
                    category: 'RBAC',
                    description: `The resource '${resource}' can be sensitive when accessed with '${verb}'. This could expose confidential information or provide a pathway for privilege escalation.`
                  });
                } else if (DANGEROUS_RBAC_VERBS[verb]['*']) {
                  // This verb is dangerous on any resource
                  issues.push({
                    path: `rules[${ruleIndex}]`,
                    key: 'rules',
                    value: `${verb} ${resource}`,
                    issue: `Dangerous RBAC permission: ${verb} ${resource}`,
                    severity: DANGEROUS_RBAC_VERBS[verb]['*'],
                    category: 'RBAC',
                    description: `The '${verb}' permission is highly privileged on any resource. Using it on '${resource}' could lead to security issues.`
                  });
                  
                  // Add verb-specific issue
                  issues.push({
                    path: `rules[${ruleIndex}].verbs[${verbIndex}]`,
                    key: 'verbs',
                    value: verb,
                    issue: `Dangerous verb: ${verb} on ${resource}`,
                    severity: DANGEROUS_RBAC_VERBS[verb]['*'],
                    category: 'RBAC',
                    description: `The '${verb}' permission is highly privileged on any resource. Using it on '${resource}' could lead to security issues.`
                  });
                }
              });
            }
          }
        });
      } else {
        // Wildcard verb with specific resources
        resources.forEach(resource => {
          const baseResource = resource.split('/')[0];
          if (CRITICAL_WILDCARD_RESOURCES.includes(baseResource)) {
            issues.push({
              path: `rules[${ruleIndex}]`,
              key: 'rules',
              value: `* ${resource}`,
              issue: `Dangerous RBAC permission: all verbs on ${resource}`,
              severity: resource === '*' ? 'Critical' : 'High',
              category: 'RBAC',
              description: `Granting all verbs on '${resource}' is extremely dangerous. This effectively gives complete control over ${resource}, which could be used for privilege escalation.`
            });
            
            // Add wildcard verb-specific issue
            const wildcardIndex = verbs.indexOf('*');
            if (wildcardIndex !== -1) {
              issues.push({
                path: `rules[${ruleIndex}].verbs[${wildcardIndex}]`,
                key: 'verbs',
                value: '*',
                issue: `Dangerous wildcard verb: * on ${resource}`,
                severity: resource === '*' ? 'Critical' : 'High',
                category: 'RBAC',
                description: `The wildcard (*) verb grants all possible actions on '${resource}'. This effectively gives complete control over ${resource}, which could be used for privilege escalation.`
              });
            }
          }
        });
      }
    });
  }
  
  return issues;
};

/**
 * Scan Pod resources for security issues
 * @param {Object} data - Pod or workload resource to scan
 * @returns {Array} - Security issues found
 */
const scanPodSecurityIssues = (data) => {
  const issues = [];
  
  // Determine the pod spec location based on the kind
  let podSpec;
  if (data.kind === 'Pod') {
    podSpec = data.spec;
  } else if (data.kind === 'CronJob') {
    podSpec = data.spec?.jobTemplate?.spec?.template?.spec;
  } else {
    podSpec = data.spec?.template?.spec;
  }
  
  if (podSpec) {
    // Check for host namespaces
    if (podSpec.hostNetwork === true) {
      let path;
      if (data.kind === 'Pod') {
        path = 'spec.hostNetwork';
      } else if (data.kind === 'CronJob') {
        path = 'spec.jobTemplate.spec.template.spec.hostNetwork';
      } else {
        path = 'spec.template.spec.hostNetwork';
      }
      
      issues.push({
        path,
        key: 'hostNetwork',
        value: true,
        issue: 'Host network used',
        severity: 'High',
        category: 'PrivilegeEscalation',
        description: 'Using the host network stack gives the pod access to all network interfaces and loopback services on the host. This allows pods to sniff network traffic, access localhost services, and potentially bypass network policies.'
      });
    }
    
    if (podSpec.hostPID === true) {
      let path;
      if (data.kind === 'Pod') {
        path = 'spec.hostPID';
      } else if (data.kind === 'CronJob') {
        path = 'spec.jobTemplate.spec.template.spec.hostPID';
      } else {
        path = 'spec.template.spec.hostPID';
      }
      
      issues.push({
        path,
        key: 'hostPID',
        value: true,
        issue: 'Host PID namespace used',
        severity: 'High',
        category: 'PrivilegeEscalation',
        description: 'Using the host PID namespace allows the pod to see and interact with all processes on the host. This can be used to kill, trace, or modify host processes, view sensitive process information, and potentially access host credentials.'
      });
    }
    
    if (podSpec.hostIPC === true) {
      let path;
      if (data.kind === 'Pod') {
        path = 'spec.hostIPC';
      } else if (data.kind === 'CronJob') {
        path = 'spec.jobTemplate.spec.template.spec.hostIPC';
      } else {
        path = 'spec.template.spec.hostIPC';
      }
      
      issues.push({
        path,
        key: 'hostIPC',
        value: true,
        issue: 'Host IPC namespace used',
        severity: 'High',
        category: 'PrivilegeEscalation',
        description: 'Using the host IPC namespace allows the pod to use inter-process communication with processes on the host. This can be used to read and modify shared memory segments of host processes, potentially leading to memory corruption or sensitive data exposure.'
      });
    }
    
    // Check for automountServiceAccountToken
    if (podSpec.automountServiceAccountToken === true) {
      let path;
      if (data.kind === 'Pod') {
        path = 'spec.automountServiceAccountToken';
      } else if (data.kind === 'CronJob') {
        path = 'spec.jobTemplate.spec.template.spec.automountServiceAccountToken';
      } else {
        path = 'spec.template.spec.automountServiceAccountToken';
      }
      
      issues.push({
        path,
        key: 'automountServiceAccountToken',
        value: true,
        issue: 'Service account token automatically mounted',
        severity: 'Low',
        category: 'PrivilegeEscalation',
        description: 'Automatically mounting the service account token gives pods access to the Kubernetes API. If the service account has excessive permissions, attackers who can compromise the pod may be able to access or modify cluster resources. Only grant this when API access is required.'
      });
    }
    
    // Check containers
    const containers = [...(podSpec.containers || []), ...(podSpec.initContainers || [])];
    containers.forEach((container, index) => {
      let containerPath;
      if (data.kind === 'Pod') {
        containerPath = `spec.containers[${index}]`;
      } else if (data.kind === 'CronJob') {
        containerPath = `spec.jobTemplate.spec.template.spec.containers[${index}]`;
      } else {
        containerPath = `spec.template.spec.containers[${index}]`;
      }
      
      // Check for privileged containers
      if (container.securityContext?.privileged === true) {
        issues.push({
          path: `${containerPath}.securityContext.privileged`,
          key: 'privileged',
          value: true,
          issue: 'Privileged container',
          severity: 'Critical',
          category: 'PrivilegeEscalation',
          description: 'Privileged containers have full, unrestricted access to the host system with all capabilities enabled and all device access. This effectively gives root-level access to the host, allowing container escape and complete system compromise. Never use in production.'
        });
      }
      
      // Check for allowPrivilegeEscalation
      if (container.securityContext?.allowPrivilegeEscalation === true) {
        issues.push({
          path: `${containerPath}.securityContext.allowPrivilegeEscalation`,
          key: 'allowPrivilegeEscalation',
          value: true,
          issue: 'Privilege escalation allowed',
          severity: 'Low',
          category: 'PrivilegeEscalation',
          description: 'Setting allowPrivilegeEscalation to true permits processes to gain more privileges than their parent process. For example, this allows setuid binaries to add capabilities and execute as root, even if the container starts as non-root. Always set to false unless absolutely necessary.'
        });
      }
      
      // Check for dangerous capabilities
      const dangerousCaps = ['SYS_ADMIN', 'NET_ADMIN', 'ALL'];
      if (container.securityContext?.capabilities?.add) {
        container.securityContext.capabilities.add.forEach((cap, capIndex) => {
          if (dangerousCaps.includes(cap)) {
            // Different descriptions for each capability type
            let capDescription = "";
            
            if (cap === 'SYS_ADMIN') {
              capDescription = "The SYS_ADMIN capability gives a container nearly all permissions of the root user. It allows mounting filesystems, creating special files, and managing system configuration. Attackers can use this to escape container isolation by mounting host directories or modifying kernel parameters.";
            } else if (cap === 'NET_ADMIN') {
              capDescription = "The NET_ADMIN capability grants control over host network configurations. It allows modifying routing tables, network interfaces, and firewall rules. Attackers can use this to intercept network traffic, bypass security controls, or perform man-in-the-middle attacks.";
            } else if (cap === 'ALL') {
              capDescription = "The ALL capability gives a container all Linux capabilities at once. This provides almost unrestricted access equivalent to root privileges on the host. It completely breaks container isolation and should never be used in production environments.";
            }
            
            issues.push({
              path: `${containerPath}.securityContext.capabilities.add[${capIndex}]`,
              key: cap,
              value: cap,
              issue: `Dangerous capability: ${cap}`,
              severity: 'High',
              category: 'PrivilegeEscalation',
              description: capDescription
            });
          }
        });
      }
      
      // Check for running as root
      if (container.securityContext?.runAsUser === 0) {
        issues.push({
          path: `${containerPath}.securityContext.runAsUser`,
          key: 'runAsUser',
          value: 0,
          issue: 'Container running as root',
          severity: 'Medium',
          category: 'PrivilegeEscalation',
          description: 'Running containers as root (UID 0) gives processes elevated privileges within the container. Combined with kernel vulnerabilities or volume mounts, processes running as root have a higher chance of escaping the container. Use a non-root user ID and add runAsNonRoot:true to prevent privilege abuse.'
        });
      }
    });
    
    // Check for hostPath volumes
    if (podSpec.volumes) {
      podSpec.volumes.forEach((volume, vIndex) => {
        if (volume.hostPath) {
          issues.push({
            path: data.kind === 'Pod' 
              ? `spec.volumes[${vIndex}].hostPath` 
              : `spec.template.spec.volumes[${vIndex}].hostPath`,
            key: 'hostPath',
            value: volume.hostPath.path,
            issue: 'Host path volume mount',
            severity: 'High',
            category: 'PrivilegeEscalation',
            description: 'Host path volume mounts give containers direct access to the host filesystem. This can lead to container escapes by accessing sensitive host files, modifying system configurations, creating device files, or installing backdoors. Use ephemeral volumes, configMaps, or persistent volumes instead.'
          });
        }
      });
    }
  }
  
  return issues;
};