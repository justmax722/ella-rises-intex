/**
 * Tailwind CSS Configuration
 * 
 * Customizes Tailwind CSS for the Ella Rises application
 * Defines custom colors, fonts, and design tokens that match the brand
 */

/** @type {import('tailwindcss').Config} */
module.exports = {
  // Dark mode support (class-based, not system preference)
  darkMode: 'class',
  
  // Files to scan for Tailwind class usage (purge unused styles in production)
  content: ['./views/**/*.ejs', './public/**/*.js'],
  
  theme: {
    // Container settings for responsive layouts
    container: {
      center: true,
      padding: '2rem',
      screens: {
        '2xl': '1400px',
      },
    },
    extend: {
      // Custom font families
      // Montserrat for body text, DM Serif Display for headings
      fontFamily: {
        sans: ['Montserrat', 'sans-serif'],
        serif: ['DM Serif Display', 'serif'],
      },
      
      // Custom color palette
      // Colors are defined as HSL CSS variables for easy theming
      colors: {
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
        },
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))',
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))',
        },
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))',
        },
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))',
        },
        popover: {
          DEFAULT: 'hsl(var(--popover))',
          foreground: 'hsl(var(--popover-foreground))',
        },
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))',
        },
        'dusty-blue': {
          DEFAULT: 'hsl(var(--dusty-blue))',
          foreground: 'hsl(var(--dusty-blue-foreground))',
        },
        purple: {
          DEFAULT: 'hsl(var(--purple))',
          foreground: 'hsl(var(--purple-foreground))',
        },
        peach: {
          DEFAULT: 'hsl(var(--peach))',
          foreground: 'hsl(var(--peach-foreground))',
        },
        coral: {
          DEFAULT: 'hsl(var(--coral))',
          foreground: 'hsl(var(--coral-foreground))',
        },
        magenta: {
          DEFAULT: 'hsl(var(--magenta))',
          foreground: 'hsl(var(--magenta-foreground))',
        },
        chart: {
          1: 'hsl(var(--chart-1))',
          2: 'hsl(var(--chart-2))',
          3: 'hsl(var(--chart-3))',
          4: 'hsl(var(--chart-4))',
          5: 'hsl(var(--chart-5))',
        },
        // Brand-specific colors
        sage: {
          DEFAULT: 'hsl(var(--sage))',
          foreground: 'hsl(var(--sage-foreground))',
        },
        cream: 'hsl(var(--cream))',
      },
      
      // Custom border radius values
      // Uses CSS variables for consistent rounded corners
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
    },
  },
  
  // Plugins for additional Tailwind functionality
  // tailwindcss-animate provides animation utilities
  plugins: [require('tailwindcss-animate')],
};

