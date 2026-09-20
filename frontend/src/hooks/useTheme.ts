import { useCallback, useEffect, useState } from 'react';

type Theme = 'dark' | 'light';

const STORAGE_KEY = 'nes-theme';

function readStored(): Theme {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'light' || stored === 'dark') return stored;
  } catch {
    // Private mode or blocked storage - fall through to the default.
  }
  return 'dark';
}

export function useTheme() {
  const [theme, setTheme] = useState<Theme>(readStored);

  useEffect(() => {
    document.documentElement.classList.toggle('light', theme === 'light');
    document.documentElement.classList.toggle('dark', theme === 'dark');
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      // Not persisting a theme preference is survivable.
    }
  }, [theme]);

  const toggle = useCallback(() => {
    setTheme((current) => (current === 'dark' ? 'light' : 'dark'));
  }, []);

  return { theme, toggle };
}
