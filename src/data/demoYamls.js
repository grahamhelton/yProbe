/**
 * Demo YAML examples for the application
 * Example files also available in the examples directory
 */
const DEMO_YAMLS = {
  secure: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-nginx
  labels:
    app: secure-nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secure-nginx
  template:
    metadata:
      labels:
        app: secure-nginx
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: nginx
        image: nginx:1.19
        ports:
        - containerPort: 80
        securityContext:
          allowPrivilegeEscalation: false
          runAsUser: 1000
          capabilities:
            drop: ["ALL"]
          readOnlyRootFilesystem: true
        resources:
          limits:
            cpu: 500m
            memory: 512Mi
          requests:
            cpu: 100m
            memory: 128Mi`,
  insecure: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-nginx
  labels:
    app: insecure-nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: insecure-nginx
  template:
    metadata:
      labels:
        app: insecure-nginx
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      containers:
      - name: nginx
        image: nginx:1.19
        ports:
        - containerPort: 80
        securityContext:
          privileged: true
          allowPrivilegeEscalation: true
          runAsUser: 0
          capabilities:
            add: ["SYS_ADMIN", "NET_ADMIN"]
        volumeMounts:
        - name: host-fs
          mountPath: /host
      volumes:
      - name: host-fs
        hostPath:
          path: /`,
  rbac: `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dangerous-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dangerous-binding
subjects:
- kind: ServiceAccount
  name: webapp
  namespace: default
roleRef:
  kind: ClusterRole
  name: dangerous-role
  apiGroup: rbac.authorization.k8s.io`,
};

export default DEMO_YAMLS;