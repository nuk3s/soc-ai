import { useEffect, useRef, useState } from 'react';

/** The width of an element in pixels, read again when the element resizes.
 *  A chart lays its marks out in pixels, so its text stays the size the page
 *  sets. `fallback` is the width before the first read and in a runtime with
 *  no ResizeObserver. */
export function useElementWidth<T extends HTMLElement>(fallback = 960): [React.RefObject<T>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(fallback);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const read = () => {
      const next = Math.floor(el.getBoundingClientRect().width);
      if (next > 0) setWidth(next);
    };
    read();
    if (typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(read);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);
  return [ref, width];
}
