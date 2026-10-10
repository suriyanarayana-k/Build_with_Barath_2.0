import { useEffect, useRef } from 'react';
import { layout, prepare } from '@chenglou/pretext';

// Only the minimum height is measured: native wrapping remains available as a fallback.
export default function MeasuredText({ children, className = '' }: { children: string; className?: string }) {
  const ref = useRef<HTMLParagraphElement>(null);
  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    let disposed = false;
    let observer: ResizeObserver | undefined;
    void document.fonts.ready.then(() => {
      if (disposed) return;
      const style = getComputedStyle(element);
      const prepared = prepare(children, style.font || style.fontSize + ' ' + style.fontFamily);
      const measure = () => {
        if (disposed || !element.clientWidth) return;
        const result = layout(prepared, element.clientWidth, parseFloat(style.lineHeight) || parseFloat(style.fontSize) * 1.5);
        element.style.minHeight = Math.ceil(result.height) + 'px';
      };
      measure(); observer = new ResizeObserver(measure); observer.observe(element);
    });
    return () => { disposed = true; observer?.disconnect(); };
  }, [children]);
  return <p ref={ref} className={className}>{children}</p>;
}
