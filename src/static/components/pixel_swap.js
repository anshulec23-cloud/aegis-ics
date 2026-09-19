/**
 * Aegis ICS - PixelSwap Transition Engine (Vanilla DOM & Web Animations API)
 * Direct mathematical implementation of React Bits PixelSwap component.
 * Performs high-performance pixelated view transitions with inverse transforms.
 */

(function (global) {
  const MAX_PIXELS = 220;
  const KEYFRAME_STEPS = 14;

  const PATTERNS = {
    random: () => null,
    center: (x, y) => Math.hypot(x - 0.5, y - 0.5) / Math.SQRT1_2,
    edges: (x, y) => Math.min(x, 1 - x, y, 1 - y) * 2,
    'left-to-right': x => x,
    'right-to-left': x => 1 - x,
    'top-to-bottom': (_x, y) => y,
    'bottom-to-top': (_x, y) => 1 - y,
    diagonal: (x, y) => (x + y) / 2,
    spiral: (x, y) => {
      const angle = (Math.atan2(y - 0.5, x - 0.5) + Math.PI) / (Math.PI * 2);
      const radius = Math.hypot(x - 0.5, y - 0.5) / Math.SQRT1_2;
      return (angle + radius) % 1;
    }
  };

  const EASINGS = {
    linear: [0, 0, 1, 1],
    ease: [0.25, 0.1, 0.25, 1],
    'ease-in': [0.42, 0, 1, 1],
    'ease-out': [0, 0, 0.58, 1],
    'ease-in-out': [0.42, 0, 0.58, 1]
  };

  const clamp = (value, min, max) => Math.min(Math.max(value, min), max);

  const noise = seed => {
    const value = Math.sin(seed * 127.1 + 311.7) * 43758.5453;
    return value - Math.floor(value);
  };

  const makeEasing = value => {
    const match = /cubic-bezier\(([^)]+)\)/.exec(value);
    const points = match ? match[1].split(',').map(Number) : EASINGS[value];
    if (!points || points.length !== 4 || points.some(Number.isNaN)) return makeEasing('ease');

    const [x1, y1, x2, y2] = points;
    if (x1 === y1 && x2 === y2) return progress => progress;

    const cx = 3 * x1;
    const bx = 3 * (x2 - x1) - cx;
    const ax = 1 - cx - bx;
    const cy = 3 * y1;
    const by = 3 * (y2 - y1) - cy;
    const ay = 1 - cy - by;

    return progress => {
      let t = progress;
      for (let i = 0; i < 5; i += 1) {
        const slope = (3 * ax * t + 2 * bx) * t + cx;
        if (!slope) break;
        t -= (((ax * t + bx) * t + cx) * t - progress) / slope;
      }
      t = clamp(t, 0, 1);
      return ((ay * t + by) * t + cy) * t;
    };
  };

  const coverScale = (size, gap, radius) => {
    const p = clamp(radius, 0, 50) / 100;
    const corner = Math.SQRT1_2 / (Math.SQRT2 * (0.5 - p) + p);
    return ((size + gap) / size) * Math.max(1, corner);
  };

  const buildGrid = ({ width, height, pixelSize, gap, pattern, randomness }) => {
    let size = pixelSize;
    let columns = Math.max(1, Math.ceil((width + gap) / (size + gap)));
    let rows = Math.max(1, Math.ceil((height + gap) / (size + gap)));

    if (columns * rows > MAX_PIXELS) {
      size = Math.ceil(size * Math.sqrt((columns * rows) / MAX_PIXELS));
      columns = Math.max(1, Math.ceil((width + gap) / (size + gap)));
      rows = Math.max(1, Math.ceil((height + gap) / (size + gap)));
    }

    const stride = size + gap;
    const originX = (width - (columns * stride - gap)) / 2;
    const originY = (height - (rows * stride - gap)) / 2;
    const order = PATTERNS[pattern] || PATTERNS.random;
    const mix = clamp(randomness, 0, 1);
    const pixels = [];

    for (let row = 0; row < rows; row += 1) {
      for (let column = 0; column < columns; column += 1) {
        const index = row * columns + column;
        const x = columns <= 1 ? 0.5 : column / (columns - 1);
        const y = rows <= 1 ? 0.5 : row / (rows - 1);
        const base = order(x, y);
        const random = noise(index + 1);

        pixels.push({
          id: index,
          left: originX + column * stride,
          top: originY + row * stride,
          offset: base === null ? random : base * (1 - mix) + random * mix
        });
      }
    }

    return { pixels, size, gap, width, height };
  };

  const buildKeyframes = ({ ease, startScale, endScale, spin, fade }) => {
    const windowKeyframes = [];
    const contentKeyframes = [];

    for (let step = 0; step <= KEYFRAME_STEPS; step += 1) {
      const progress = step / KEYFRAME_STEPS;
      const eased = ease(progress);
      const scale = startScale + (endScale - startScale) * eased;
      const angle = spin * (1 - eased);

      windowKeyframes.push({
        offset: progress,
        opacity: fade ? Math.min(1, eased * 1.6) : 1,
        transform: `rotate(${angle}deg) scale(${scale})`
      });
      contentKeyframes.push({
        offset: progress,
        transform: `scale(${1 / scale}) rotate(${-angle}deg)`
      });
    }

    return { windowKeyframes, contentKeyframes };
  };

  /**
   * Execute a PixelSwap transition between two DOM elements inside a container.
   */
  function swapViews(container, sourceElement, targetElement, options = {}) {
    if (!container || !targetElement) return;

    const {
      pixelSize = 56,
      gap = 0,
      pixelRadius = 0,
      pixelSpin = 0,
      pixelScale = 0.35,
      fade = true,
      duration = 450,
      pixelDuration = 260,
      pattern = 'left-to-right',
      randomness = 0.05,
      easing = 'cubic-bezier(0.22, 1, 0.36, 1)',
      onComplete = null
    } = options;

    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      if (sourceElement) sourceElement.classList.add('hidden');
      targetElement.classList.remove('hidden');
      if (typeof onComplete === 'function') onComplete();
      return;
    }

    const width = container.clientWidth || window.innerWidth;
    const height = Math.max(container.clientHeight, 400);

    const grid = buildGrid({
      width,
      height,
      pixelSize: Math.max(12, Math.round(pixelSize)),
      gap: Math.max(0, Math.round(gap)),
      pattern,
      randomness
    });

    const gridContainer = document.createElement('div');
    gridContainer.className = 'pixel-swap__grid';
    gridContainer.style.position = 'absolute';
    gridContainer.style.inset = '0';
    gridContainer.style.zIndex = '40';
    gridContainer.style.pointerEvents = 'none';
    gridContainer.style.overflow = 'hidden';

    const total = Math.max(200, duration);
    const pixelMs = clamp(pixelDuration, 60, total);
    const spread = Math.max(0, total - pixelMs);
    const endScale = coverScale(grid.size, grid.gap, pixelRadius);
    const { windowKeyframes, contentKeyframes } = buildKeyframes({
      ease: makeEasing(easing),
      startScale: clamp(pixelScale, 0.05, 1) * endScale,
      endScale,
      spin: pixelSpin,
      fade
    });

    // Make target element active in the DOM behind the transition grid
    targetElement.classList.remove('hidden');
    targetElement.style.opacity = '1';

    const animations = [];

    grid.pixels.forEach(pixel => {
      const pixelEl = document.createElement('div');
      pixelEl.className = 'pixel-swap__pixel';
      pixelEl.style.position = 'absolute';
      pixelEl.style.left = `${pixel.left}px`;
      pixelEl.style.top = `${pixel.top}px`;
      pixelEl.style.width = `${grid.size}px`;
      pixelEl.style.height = `${grid.size}px`;
      pixelEl.style.borderRadius = `${clamp(pixelRadius, 0, 50)}%`;
      pixelEl.style.overflow = 'hidden';
      pixelEl.style.opacity = '0';
      pixelEl.style.contain = 'paint';

      const content = document.createElement('div');
      content.className = 'pixel-swap__pixel-content';
      content.style.position = 'absolute';
      content.style.left = `${-pixel.left}px`;
      content.style.top = `${-pixel.top}px`;
      content.style.width = `${grid.width}px`;
      content.style.height = `${grid.height}px`;

      const originX = pixel.left + grid.size / 2;
      const originY = pixel.top + grid.size / 2;
      content.style.transformOrigin = `${originX}px ${originY}px`;

      const clone = targetElement.cloneNode(true);
      clone.classList.remove('hidden');
      clone.style.opacity = '1';
      content.appendChild(clone);
      pixelEl.appendChild(content);
      gridContainer.appendChild(pixelEl);

      const timing = {
        duration: pixelMs,
        delay: pixel.offset * spread,
        easing: 'linear',
        fill: 'both'
      };

      animations.push(pixelEl.animate(windowKeyframes, timing));
      animations.push(content.animate(contentKeyframes, timing));
    });

    container.style.position = 'relative';
    container.appendChild(gridContainer);

    setTimeout(() => {
      animations.forEach(anim => anim.cancel());
      if (gridContainer.parentNode) {
        gridContainer.parentNode.removeChild(gridContainer);
      }
      if (sourceElement && sourceElement !== targetElement) {
        sourceElement.classList.add('hidden');
      }
      if (typeof onComplete === 'function') {
        onComplete();
      }
    }, total + 30);
  }

  global.PixelSwapEngine = {
    swapViews,
    PATTERNS
  };
})(typeof window !== 'undefined' ? window : this);
