import React, { useState, useRef, useEffect } from 'react';

/**
 * Background starfield component that creates a parallax effect
 * based on mouse movement
 */
const Starfield = () => {
  const [stars, setStars] = useState([]);
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });
  const containerRef = useRef(null);
  
  // Generate stars on component mount
  useEffect(() => {
    const generateStars = () => {
      const starCount = 50; // Number of stars in the field
      const newStars = [];
      
      // Create different star types with varying properties
      for (let i = 0; i < starCount; i++) {
        // Determine star type - distant or medium
        const starType = Math.random();
        let size, opacity, depth, color;
        
        if (starType < 0.7) { // 70% distant stars
          size = Math.random() * 1.2 + 0.3;
          opacity = Math.random() * 0.25 + 0.1;
          depth = Math.random() * 1 + 0.5;
          
          // Give some stars a slight warm tint instead of pure white
          const warmTint = Math.random() > 0.5;
          color = warmTint
            ? `rgba(255, 253, 245, ${opacity})` 
            : `rgba(255, 255, 255, ${opacity})`;
        } else { // 30% medium stars
          size = Math.random() * 1.5 + 0.8;
          opacity = Math.random() * 0.3 + 0.2;
          depth = Math.random() * 1.5 + 1;
          
          // Slight warm tint for some stars to reduce blue appearance
          const warmish = Math.random() > 0.7;
          color = warmish 
            ? `rgba(255, 250, 240, ${opacity})` 
            : `rgba(255, 255, 255, ${opacity})`;
        }
        
        newStars.push({
          id: i,
          x: Math.random() * 100, // Position as percentage
          y: Math.random() * 100, // Position as percentage
          size,
          opacity,
          depth,
          color
        });
      }
      
      setStars(newStars);
    };
    
    generateStars();
  }, []);
  
  // Update mouse position for parallax effect
  useEffect(() => {
    const handleMouseMove = (e) => {
      if (!containerRef.current) return;
      
      const rect = containerRef.current.getBoundingClientRect();
      // Calculate position from -0.5 to 0.5 (center = 0,0)
      const x = ((e.clientX - rect.left) / rect.width) - 0.5;
      const y = ((e.clientY - rect.top) / rect.height) - 0.5;
      
      setMousePosition({ x, y });
    };
    
    window.addEventListener('mousemove', handleMouseMove);
    
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
    };
  }, []);
  
  return (
    <div 
      ref={containerRef}
      className="fixed inset-0 z-0 overflow-hidden pointer-events-none"
      style={{ background: '#111111' }}
    >
      {/* Render the stars */}
      {stars.map(star => (
        <div 
          key={star.id}
          className="absolute rounded-full"
          style={{
            left: `calc(${star.x}% + ${mousePosition.x * star.depth * -8}px)`,
            top: `calc(${star.y}% + ${mousePosition.y * star.depth * -8}px)`,
            width: `${star.size}px`,
            height: `${star.size}px`,
            backgroundColor: star.color || 'white',
            boxShadow: `0 0 ${star.size}px rgba(255, 255, 255, ${star.opacity / 2})`,
            transition: 'left 0.4s ease-out, top 0.4s ease-out',
            transform: `scale(${1 + Math.abs(mousePosition.x * mousePosition.y) * 0.02 * star.depth})`
          }}
        />
      ))}
      
      {/* Occasionally add twinkling effect to some stars */}
      {stars.filter(star => star.id % 8 === 0).map(star => (
        <div 
          key={`twinkle-${star.id}`}
          className="absolute rounded-full animate-pulse"
          style={{
            left: `calc(${star.x}% + ${mousePosition.x * star.depth * -8}px)`,
            top: `calc(${star.y}% + ${mousePosition.y * star.depth * -8}px)`,
            width: `${star.size * 1.2}px`,
            height: `${star.size * 1.2}px`,
            backgroundColor: 'transparent',
            boxShadow: `0 0 ${star.size * 2}px rgba(255, 255, 255, ${star.opacity * 0.3})`,
            opacity: star.opacity * 0.6,
            transition: 'left 0.4s ease-out, top 0.4s ease-out',
            animationDuration: `${4 + star.id % 5}s`
          }}
        />
      ))}
    </div>
  );
};

export default Starfield;