import { useLocation } from "react-router-dom";
import { useEffect } from "react";

const NotFound = () => {
  const location = useLocation();

  useEffect(() => {
    console.error("404: Route not found →", location.pathname);
  }, [location]);

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center relative overflow-hidden">
      {/* Animated background */}
      <div className="absolute inset-0">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-green-500/5 rounded-full blur-3xl animate-float" />
        <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-emerald-500/5 rounded-full blur-3xl animate-float" style={{ animationDelay: '-2s' }} />
      </div>
      
      <div className="text-center relative z-10 animate-scale-in">
        <div className="mb-6">
          <span className="text-9xl font-black bg-gradient-to-r from-green-400 via-emerald-400 to-teal-400 bg-clip-text text-transparent">
            404
          </span>
        </div>
        <p className="text-xl text-gray-400 mb-8">Oops! This page doesn't exist.</p>
        <a 
          href="/" 
          className="inline-flex items-center gap-2 px-6 py-3 btn-primary-glow text-gray-900 font-semibold rounded-xl transition-all duration-300 hover:scale-105"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
          Return Home
        </a>
      </div>
    </div>
  );
};

export default NotFound;