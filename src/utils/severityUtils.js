/**
 * Utility functions for managing severity colors and styling
 */

// Color schemes for different severity levels
export const SEVERITY_COLORS = {
  Critical: {
    borderClass: 'border-purple-600',
    ringClass: 'ring-purple-400',
    iconClass: 'text-purple-400',
    bgClass: 'bg-purple-900/40',
    textClass: 'text-purple-200',
    color: '#9333ea',
    shadow: 'rgba(147, 51, 234, 0.4)',
    fill: '#a855f7'
  },
  High: {
    borderClass: 'border-red-600',
    ringClass: 'ring-red-400',
    iconClass: 'text-red-400',
    bgClass: 'bg-red-900/40',
    textClass: 'text-red-200',
    color: '#dc2626',
    shadow: 'rgba(220, 38, 38, 0.4)',
    fill: '#ef4444'
  },
  Medium: {
    borderClass: 'border-yellow-500',
    ringClass: 'ring-yellow-500',
    iconClass: 'text-yellow-500',
    bgClass: 'bg-transparent',
    textClass: 'text-yellow-500',
    color: '#eab308',
    shadow: 'rgba(234, 179, 8, 0.8)',
    fill: '#f59e0b'
  },
  Low: {
    borderClass: 'border-yellow-400',
    ringClass: 'ring-yellow-400',
    iconClass: 'text-yellow-400',
    bgClass: 'bg-transparent',
    textClass: 'text-yellow-400',
    color: '#ca8a04',
    shadow: 'rgba(202, 138, 4, 0.4)',
    fill: '#eab308'
  },
  // Default as fallback
  default: {
    borderClass: 'border-gray-600',
    ringClass: 'ring-gray-400',
    iconClass: 'text-gray-400',
    bgClass: 'bg-gray-900/40',
    textClass: 'text-gray-200',
    color: 'rgba(75, 85, 99, 0.8)',
    shadow: 'rgba(75, 85, 99, 0.3)',
    fill: 'rgba(75, 85, 99, 0.8)'
  }
};

/**
 * Get color styling for a severity level
 */
export const getSeverityColors = (severity) => {
  return SEVERITY_COLORS[severity] || SEVERITY_COLORS.default;
};

/**
 * Get icon component based on issue category
 */
export const getCategoryIcon = (category) => {
  if (category === 'RBAC') {
    return {
      path: "M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z",
      type: 'lock'
    };
  }
  
  return {
    path: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z",
    type: 'warning'
  };
};

/**
 * Get security recommendation text based on the issue
 */
export const getSecurityRecommendation = (issue) => {
  const { category, key, severity, issue: issueText } = issue;
  
  if (category === 'RBAC') {
    if (severity === 'Critical') {
      if (issueText.includes('wildcard')) {
        return "Replace wildcards (*) with specific resources and verbs. Wildcard permissions grant excessive access to your cluster. Follow the principle of least privilege by explicitly listing only the exact API resources and verbs that your application needs to function.";
      } else {
        return "Restrict this dangerous RBAC permission by specifying narrower resource types and verbs. For example, instead of access to all pods, limit to specific namespaces or use resourceNames to specify exact resources. Never grant permissions beyond what's explicitly required.";
      }
    } else if (severity === 'High') {
      return "Review this permission carefully and consider restricting it to more specific resources or using a more limited verb set. High-risk permissions like 'create', 'update', 'patch', and 'delete' should be tightly scoped and only granted when necessary to limit potential security impact.";
    } else {
      return "This permission may be necessary for normal operation, but ensure it follows the principle of least privilege. Check that it's only granted to ServiceAccounts that explicitly need this access, and consider using resourceNames to further limit scope to specific objects when possible.";
    }
  } else {
    // PrivilegeEscalation recommendations
    if (key === 'privileged') {
      return "Remove 'privileged: true' from the security context. If specific privileged operations are needed, use more fine-grained capabilities instead. Running in privileged mode gives containers close to full root access to the host, effectively bypassing all container isolation.";
    } else if (key === 'hostNetwork') {
      return `Remove 'hostNetwork: true' from the pod spec. This gives containers direct access to the host network stack, allowing them to sniff host network traffic, access all network interfaces, and bind to privileged ports. It also bypasses network policies applied to pod communications.`;
    } else if (key === 'hostPID') {
      return `Remove 'hostPID: true' from the pod spec. This allows containers to see and interact with all processes on the host, not just those in the container. Attackers can use this to monitor host processes, kill system services, or attach debuggers to critical processes.`;
    } else if (key === 'hostIPC') {
      return `Remove 'hostIPC: true' from the pod spec. This allows containers to access the host's inter-process communication namespace, enabling direct access to shared memory segments of host processes. This can lead to memory corruption or information leakage from host applications.`;
    } else if (key === 'allowPrivilegeEscalation') {
      return "Set 'allowPrivilegeEscalation: false' in the security context. This prevents processes from gaining additional privileges (like through setuid binaries).";
    } else if (key === 'runAsUser' && issue.value === 0) {
      return "Set 'runAsUser' to a non-zero value (e.g., 1000) and add 'runAsNonRoot: true' to the security context. Running as a non-root user is a fundamental best practice that limits the impact of container compromises and helps prevent container escapes.";
    } else if (key === 'SYS_ADMIN') {
      return "Remove the SYS_ADMIN capability by removing it from securityContext.capabilities.add and adding it to capabilities.drop. Instead, identify the specific operations your container needs and use more limited capabilities. For filesystem operations, consider using a dedicated volume or sidecar pattern rather than direct host access.";
    } else if (key === 'NET_ADMIN') {
      return "Remove the NET_ADMIN capability by removing it from securityContext.capabilities.add. For legitimate network functionality, consider using the NetworkPolicy resource to define precise ingress/egress rules, or implement a service mesh for advanced networking features rather than granting this powerful capability.";
    } else if (key === 'ALL') {
      return "Remove the ALL capability immediately - this effectively gives the container root access to the host. Replace with capabilities.drop: [\"ALL\"] and only add the minimal specific capabilities your application actually needs, like NET_BIND_SERVICE for binding to ports below 1024.";
    } else if (key === 'capabilities') {
      return "Remove dangerous capabilities from the container. Use 'capabilities.drop: [\"ALL\"]' by default and only add specific minimal capabilities if absolutely required. Carefully audit any capabilities your application needs, as many can lead to container escapes or privilege escalation.";
    } else if (key === 'hostPath') {
      return "Replace hostPath volumes with more secure volume types like emptyDir, configMap, or persistent volumes. Direct access to host filesystems is a common container escape vector. If host access is necessary, use read-only mounts with minimal scope and specific paths.";
    } else if (key === 'automountServiceAccountToken') {
      return "Set 'automountServiceAccountToken: false' for pods that don't need API access. The service account token gives containers access to the Kubernetes API with the permissions of the associated service account. Only enable this for pods that specifically need to interact with the Kubernetes API.";
    } else {
      return "Apply Kubernetes security best practices by removing potentially dangerous settings and following the principle of least privilege. Consider using tools like Trivy, Kube-hunter, or OPA Gatekeeper to enforce security policies across your cluster.";
    }
  }
};