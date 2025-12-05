/**
 * PostCSS Configuration
 * 
 * PostCSS processes CSS files and applies transformations
 * Used in the build pipeline to process Tailwind CSS and add vendor prefixes
 */
module.exports = {
  plugins: {
    // Tailwind CSS plugin - processes @tailwind directives and generates utility classes
    tailwindcss: {},
    
    // Autoprefixer - automatically adds vendor prefixes (e.g., -webkit-, -moz-) for browser compatibility
    autoprefixer: {},
  },
};

