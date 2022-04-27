// import FormData from "form-data";
import React, { createContext, useContext, useState, useMemo } from 'react';
import axios from 'axios';
import Cookies from 'js-cookie';

export const TndevContext = createContext(null);

export const TndevCtx = () => useContext(TndevContext);

const BASE_URL_SERVER = 'http://localhost:8000/api';
const api = axios.create({
  // baseURL: process.env.BASE_URL,
  baseURL: BASE_URL_SERVER
});

api.interceptors.request.use(function (config) {
  config.headers = { 'X-Requested-With': 'XMLHttpRequest' };
  config.headers = { Accept: 'application/json' };
  config.headers = { 'content-type': 'application/json' };

  const token = Cookies.get('token') ? Cookies.get('token') : null;
  config.headers.Authorization = token ? `Bearer ${token}` : '';
  return config;
});

// checkerController user and auth handler

export const apiListeArticles = async () => {
  const { data } = await api.get('/articles');
  return data;
};
export const testContext = () => {
  const data = 'hi context ok ';
  return data;
};

const authMethods = {
  apiListeArticles,
  testContext
};

export const TndevProvider = ({ children }) => {
  const [openDrawer, setOpenDrawer] = useState(false);

  const [states] = useState({
    openDrawer,
    setOpenDrawer
  });

  const [methods] = useState({
    authMethods
  });

  const moyens = useMemo(() => [methods, states], [states, methods]);

  return <TndevContext.Provider value={moyens}>{children}</TndevContext.Provider>;
};
