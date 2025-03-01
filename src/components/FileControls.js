import React from 'react';

/**
 * Component for YAML file action buttons (copy, download, clear, etc)
 */
const FileControls = ({ 
  showDiff,
  onToggleDiff,
  onCopyYaml,
  onDownloadYaml,
  onClear,
  onUndo,
  copySuccess,
  fixSuccess,
  fixedCount,
  isMultiDoc = false,
  canUndo = false
}) => {
  return (
    <div className="flex gap-2">
      {/* Toggle diff view button - only show if diff view is possible, not a multi-document, and not Role/ClusterRole */}
      {showDiff !== undefined && !isMultiDoc && (
        <button 
          className={`px-3 py-1 ${showDiff ? 'bg-purple-700' : 'bg-gray-700'} text-white rounded hover:bg-gray-600 transition-all text-sm flex items-center`}
          onClick={onToggleDiff}
        >
          <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
          </svg>
          {showDiff ? 'Hide Diff' : 'Show Diff'}
        </button>
      )}
      
      {/* Fix All button removed to avoid duplication */}

      {/* Copy button removed - now available per document */}
      
      {/* Download YAML button */}
      <button 
        className="px-3 py-1 bg-purple-700 text-white rounded hover:bg-purple-600 transition-all text-sm flex items-center"
        onClick={onDownloadYaml}
        title="Download YAML file"
      >
        <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
        </svg>
        Download
      </button>
      
      {/* Undo button - only show if undo is available */}
      {canUndo && onUndo && (
        <button 
          className="px-3 py-1 bg-indigo-700 text-white rounded hover:bg-indigo-600 transition-all text-sm flex items-center"
          onClick={onUndo}
          title="Undo last security fix"
        >
          <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6" />
          </svg>
          Undo Last Fix
        </button>
      )}
      
      {/* Clear button */}
      <button 
        className="px-3 py-1 bg-green-700 text-white rounded hover:bg-green-600 transition-all text-sm"
        onClick={onClear}
        title="Clear current YAML content"
      >
        Clear
      </button>
    </div>
  );
};

export default FileControls;