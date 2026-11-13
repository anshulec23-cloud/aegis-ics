# Aegis ICS - Frontend UI Components

This directory contains reusable frontend user interface components and visual styling modules for the Aegis ICS operator web console.

## Components Overview

| File | Component | Description |
|---|---|---|
| [`pixel_swap.js`](pixel_swap.js) | `PixelSwap` (Vanilla JS) | High-performance canvas/DOM pixel-swap visualizer used for rendering real-time sensor matrix transitions, trust status gradients, and alert animations without layout thrashing. |
| [`PixelSwap.jsx`](PixelSwap.jsx) | `PixelSwap` (React/JSX) | React component wrapper for modular UI integration, managing dynamic component state, transition hooks, and telemetry visual feedback. |
| [`PixelSwap.css`](PixelSwap.css) | Component Stylesheet | Scoped CSS styles, animation keyframes, and theme variables for pixel transition effects and indicator pulses. |

## Usage

In standard browser environments using the vanilla JavaScript module:
```html
<script src="/static/components/pixel_swap.js"></script>
<link rel="stylesheet" href="/static/components/PixelSwap.css">
```

Or within modern React applications:
```jsx
import PixelSwap from './components/PixelSwap';
import './components/PixelSwap.css';

<PixelSwap activeSensor={sensorId} trustScore={trust} />
```
