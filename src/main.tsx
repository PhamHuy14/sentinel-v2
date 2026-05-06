import React from 'react';
import ReactDOM from 'react-dom/client';
import { initOrchestrator } from './ai/llm/hybridOrchestrator';
import { buildLLMRouter } from './ai/llm/providerRegistry';
import App from './App';
import './index.css';
import './styles/ai-chat.css';

initOrchestrator(buildLLMRouter());

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
