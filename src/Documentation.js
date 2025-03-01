import React from 'react';

function Documentation({ onClose }) {
  return (
    <div className="fixed inset-0 bg-transparent z-50 overflow-y-auto p-4">
      <div className="max-w-2xl mx-auto bg-black rounded-lg shadow-xl border border-gray-700">
        <header className="sticky top-0 z-10 border-b border-gray-700 p-3 bg-black rounded-t-lg">
          <div className="flex justify-between items-center">
            <h1 className="text-xl font-bold text-green-400">YAML Manifest Viewer</h1>
            <button 
              onClick={onClose}
              className="px-2 py-1 bg-green-700 text-white rounded hover:bg-green-600 transition-all text-sm"
            >
              Close
            </button>
          </div>
        </header>
        
        <div className="p-4 overflow-y-auto">
          <div className="space-y-4">
            <section>
              <h2 className="text-lg font-bold text-blue-400 mb-2">About</h2>
              <p className="mb-2 text-sm text-gray-300">
                This tool scans Kubernetes YAML manifests for security issues in Pod workloads and RBAC resources.
              </p>
            </section>

            <section>
              <h2 className="text-lg font-bold text-blue-400 mb-2">Security Checks</h2>
              <div className="mb-1 text-sm">
                <h3 className="font-semibold text-purple-400 mb-1">Critical Severity</h3>
                <ul className="list-disc ml-4 text-gray-300">
                  <li><span className="text-purple-400">privileged: true</span> - Gives container full access to host</li>
                </ul>
              </div>
              
              <div className="mb-1 text-sm">
                <h3 className="font-semibold text-red-400 mb-1">High Severity</h3>
                <ul className="list-disc ml-4 text-gray-300">
                  <li><span className="text-red-400">hostPID: true</span> - Access to host process namespace</li>
                  <li><span className="text-red-400">hostNetwork: true</span> - Access to host network stack</li>
                  <li><span className="text-red-400">hostIPC: true</span> - Access to host IPC namespace</li>
                  <li><span className="text-red-400">hostPath volumes</span> - Mount host filesystem</li>
                  <li><span className="text-red-400">capabilities: add</span> - Dangerous Linux capabilities (SYS_ADMIN, NET_ADMIN, ALL)</li>
                </ul>
              </div>
              
              <div className="mb-1 text-sm">
                <h3 className="font-semibold text-yellow-500 mb-1">Medium Severity</h3>
                <ul className="list-disc ml-4 text-gray-300">
                  <li><span className="text-yellow-500">allowPrivilegeEscalation: true</span> - Allow gaining more privileges</li>
                  <li><span className="text-yellow-500">runAsUser: 0</span> - Run as root user</li>
                </ul>
              </div>
            </section>

            <section>
              <h2 className="text-lg font-bold text-blue-400 mb-2">RBAC Checks</h2>
              <div className="mb-1 text-sm">
                <h3 className="font-semibold text-purple-400 mb-1">Critical Severity</h3>
                <ul className="list-disc ml-4 text-gray-300">
                  <li><span className="text-purple-400">Wildcard permissions (*/*/*)</span> - Full access to cluster</li>
                  <li><span className="text-purple-400">verbs: ["*"]</span> - All actions on sensitive resources</li>
                  <li><span className="text-purple-400">resources: ["*"]</span> - Access to all resources</li>
                </ul>
              </div>
              
              <div className="mb-1 text-sm">
                <h3 className="font-semibold text-red-400 mb-1">High Severity</h3>
                <ul className="list-disc ml-4 text-gray-300">
                  <li><span className="text-red-400">create/update/patch pods</span> - Can create workloads</li>
                  <li><span className="text-red-400">bind/escalate roles</span> - Can increase permissions</li>
                </ul>
              </div>
            </section>

            <section>
              <h2 className="text-lg font-bold text-blue-400 mb-2">Supported Resources</h2>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div>
                  <h3 className="font-semibold text-green-400 mb-1">Pod Workloads</h3>
                  <ul className="list-disc ml-4 text-gray-300">
                    <li>Pod, Deployment</li>
                    <li>StatefulSet, DaemonSet</li>
                    <li>ReplicaSet, Job, CronJob</li>
                  </ul>
                </div>
                
                <div>
                  <h3 className="font-semibold text-green-400 mb-1">RBAC Resources</h3>
                  <ul className="list-disc ml-4 text-gray-300">
                    <li>Role, ClusterRole (fully scanned)</li>
                    <li>RoleBinding, ClusterRoleBinding (only displayed, not scanned)</li>
                  </ul>
                </div>
              </div>
            </section>

            <section>
              <h2 className="text-lg font-bold text-blue-400 mb-2">Color Coding</h2>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div className="flex items-center">
                  <span className="w-3 h-3 bg-purple-500 rounded mr-2"></span>
                  <span className="text-purple-400">Purple = Critical</span>
                </div>
                <div className="flex items-center">
                  <span className="w-3 h-3 bg-red-500 rounded mr-2"></span>
                  <span className="text-red-400">Red = High</span>
                </div>
                <div className="flex items-center">
                  <span className="w-3 h-3 bg-yellow-500 rounded mr-2"></span>
                  <span className="text-yellow-500">Yellow = Medium</span>
                </div>
                <div className="flex items-center">
                  <span className="w-3 h-3 bg-yellow-300 rounded mr-2"></span>
                  <span className="text-yellow-400">Light Yellow = Low</span>
                </div>
              </div>
            </section>

            <section>
              <h2 className="text-lg font-bold text-blue-400 mb-2">Using the Tool</h2>
              <div className="space-y-1 text-sm text-gray-300">
                <p><strong className="text-green-400">Load files:</strong> Drag & drop YAML files or paste content</p>
                <p><strong className="text-green-400">Review issues:</strong> Hover over highlighted sections</p>
                <p><strong className="text-green-400">Fix issues:</strong> Use "Fix All Issues" or fix individually</p>
                <p><strong className="text-green-400">Export:</strong> Copy or download the fixed YAML</p>
              </div>
            </section>
          </div>

          <footer className="mt-4 pt-3 border-t border-gray-700 text-center text-gray-500 text-xs">
            <button 
              onClick={onClose}
              className="text-blue-400 hover:text-blue-300 bg-transparent border-none cursor-pointer underline p-0"
            >
              Return to Application
            </button>
          </footer>
        </div>
      </div>
    </div>
  );
}

export default Documentation;
