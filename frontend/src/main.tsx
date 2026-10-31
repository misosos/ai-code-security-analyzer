import React from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './app/App';
import './styles.css';
import './readability.css';
import './ui-d2.css';
import './app-shell-d5a.css';

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>);
