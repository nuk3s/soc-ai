import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { App } from './App';
import { ShellProvider } from './shell/ShellContext';
import './index.css';

// Served under /app, so the router shares that basename (BASE_URL is '/app/').
const basename = import.meta.env.BASE_URL.replace(/\/$/, '');

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter basename={basename}>
      <ShellProvider>
        <App />
      </ShellProvider>
    </BrowserRouter>
  </StrictMode>
);
