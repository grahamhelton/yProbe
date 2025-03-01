import React from 'react';

/**
 * Component for the drop zone / file input area
 */
const DropZone = ({ 
  isDragging, 
  error, 
  onDrop, 
  onPaste, 
  onClickDemo, 
  onClickDocs 
}) => {
  return (
    <div className="text-center h-full flex flex-col items-center justify-center">
      <div className="text-6xl mb-4 text-green-400 opacity-80">📄</div>
      <h2 className="text-xl font-semibold mb-2 text-green-300">Drop your YAML manifest here</h2>
      <p className="text-gray-400 mb-4">or paste YAML content (Ctrl+V / Cmd+V)</p>
      <p className="text-blue-300 text-sm mb-2">
        Supports: Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, Job, CronJob, Role, ClusterRole
      </p>
      
      {/* Demo Buttons */}
      <div className="mt-4 mb-4">
        <p className="text-gray-300 mb-2">Or try a demo:</p>
        <div className="flex gap-2 justify-center">
          <button 
            className="px-3 py-1 bg-green-700 text-white rounded hover:bg-green-600 transition-all text-sm"
            onClick={() => onClickDemo('secure')}
          >
            Secure Example
          </button>
          <button 
            className="px-3 py-1 bg-red-700 text-white rounded hover:bg-red-600 transition-all text-sm"
            onClick={() => onClickDemo('insecure')}
          >
            Insecure Example
          </button>
          <button 
            className="px-3 py-1 bg-purple-700 text-white rounded hover:bg-purple-600 transition-all text-sm"
            onClick={() => onClickDemo('rbac')}
          >
            RBAC Example
          </button>
        </div>
        
        {/* Documentation Link */}
        <p className="mt-4 text-gray-400 text-sm">
          <button 
            onClick={onClickDocs}
            className="text-blue-400 hover:text-blue-300 underline bg-transparent border-none cursor-pointer p-0"
          >
            Documentation and User Guide
          </button>
        </p>
      </div>
      
      {/* Error Message */}
      {error && (
        <p className={`mt-4 p-2 rounded border ${error.startsWith('Warning:') ? 'text-yellow-400 bg-yellow-900/30 border-yellow-600' : 'text-red-400 bg-red-900/30 border-red-700'}`}>
          {error}
        </p>
      )}
    </div>
  );
};

export default DropZone;