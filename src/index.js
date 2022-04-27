// scroll bar
import { HelmetProvider } from 'react-helmet-async';
import { BrowserRouter } from 'react-router-dom';
import ReactDOM from 'react-dom';
import 'simplebar/src/simplebar.css';
import { QueryClient, QueryClientProvider } from 'react-query';
import { TndevProvider } from './contexts/TndevContext';

//
import App from './App';
import * as serviceWorker from './serviceWorker';
import reportWebVitals from './reportWebVitals';

// ----------------------------------------------------------------------
const queryClient = new QueryClient();

ReactDOM.render(
  <HelmetProvider>
    <QueryClientProvider client={queryClient}>
      <TndevProvider>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </TndevProvider>
    </QueryClientProvider>
  </HelmetProvider>,
  document.getElementById('root')
);

// If you want to enable client cache, register instead.
serviceWorker.unregister();

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
