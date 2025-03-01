import React from 'react';

/**
 * Documentation modal with simplified usage instructions
 */
const Documentation = ({ onClose }) => {
  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 overflow-auto">
      <div className="bg-gray-900 p-5 rounded-lg border border-gray-700 shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-bold text-green-400">YAML Manifest Viewer Guide</h2>
          <button 
            onClick={onClose}
            className="text-gray-400 hover:text-white"
            aria-label="Close dialog"
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        
        <div className="text-sm text-gray-300 space-y-4">
          <div>
            <h3 className="text-blue-400 font-medium mb-1">Loading YAML</h3>
            <ul className="list-disc ml-5 space-y-1">
              <li>Drag & drop a YAML file onto the viewer</li>
              <li>Paste YAML content with Ctrl/Cmd+V</li>
              <li>Try the demo examples on the home screen</li>
            </ul>
          </div>
          
          <div>
            <h3 className="text-blue-400 font-medium mb-1">Security Features</h3>
            <ul className="list-disc ml-5 space-y-1">
              <li>Each document shows security issues in its header</li>
              <li>Hover over highlighted items for details and fixes</li>
              <li>Use "Fix Pod Security Issues" button to apply all recommendations</li>
              <li>View changes with the "Show Diff" button (for single documents)</li>
            </ul>
          </div>
          
          <div>
            <h3 className="text-blue-400 font-medium mb-1">Supported Resources</h3>
            <ul className="list-disc ml-5">
              <li><span className="text-white">Pod Workloads:</span> Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob</li>
              <li><span className="text-white">RBAC Resources:</span> Role, ClusterRole</li>
            </ul>
          </div>
          
          <div className="bg-blue-900/20 p-2 rounded border border-blue-800/30">
            <p className="text-blue-300 font-medium">Security Categories</p>
            <ul className="list-disc ml-5 mt-1">
              <li><span className="text-red-300">Pod Security:</span> Privileged containers, host namespaces, dangerous capabilities</li>
              <li><span className="text-purple-300">RBAC Analysis:</span> Overly permissive roles and dangerous permissions</li>
            </ul>
          </div>
          
          <div className="mt-3 text-yellow-500/80 text-xs italic border-t border-gray-700 pt-3">
            <strong>Disclaimer:</strong> This tool is a proof of concept and does not provide a comprehensive analysis of all possible security issues. 
            Always use specialized security scanning tools and follow Kubernetes security best practices for production environments.
          </div>
        </div>
      </div>
    </div>
  );
};

export default Documentation;