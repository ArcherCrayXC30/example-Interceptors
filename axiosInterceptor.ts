import axios from 'axios';
import { Store } from 'redux';

import { authAction } from '../actions';
import { IAppState } from '../types/AppState';
import { IAuthLogoutSuccessAction } from '../types/Auth';

let subscribers: Array<((token: string) => void)> = [];

type RefreshCallback = (token: string, error?: Error) => void;

function onAccessTokenFetched(token: string, error?: Error) {
  subscribers = subscribers.filter((callback: RefreshCallback) => callback(token, error));
}

function addSubscriber(callback: RefreshCallback) {
  subscribers.push(callback);
}

export function initAxiosInterceptor(
  store: Store<IAppState>, parsedTokens?: { accessToken: string; refreshToken: string; }
) {
  const host = process.env.HOST || '';
  const port = Number(process.env.PORT);

  axios.defaults.proxy = { host, port };
  axios.interceptors.request.use(
    (config) => {
      const storeTokens = store.getState().auth.tokens;
      const token = storeTokens && storeTokens.accessToken
        ? storeTokens.accessToken
        : parsedTokens && parsedTokens.accessToken;

      if (!config.headers.Authorization && token) {
        config.headers.Authorization = `Bearer ${token}`;
      }

      return config;
    },
    (error) => {
      return Promise.reject(error);
    });

  axios.interceptors.response.use(
    (response) => {
      return response;
    },
    (error) => {
      const { isTokensRefreshing, tokens } = store.getState().auth;
      const { config, response } = error;
      const originalRequest = config;
      const refreshToken = tokens && tokens.refreshToken
        ? tokens.refreshToken
        : parsedTokens && parsedTokens.refreshToken;

      if (response && response.status === 401 && refreshToken && !originalRequest._retry) {
        originalRequest._retry = true;

        if (!isTokensRefreshing) {
          authAction.refreshTokens(refreshToken, store.dispatch)
            .then(refreshedTokens => onAccessTokenFetched(refreshedTokens.accessToken))
            .catch((refreshError) => {
              const authLogoutSuccessAction: IAuthLogoutSuccessAction = { type: 'AUTH_LOGOUT_SUCCESS' };

              store.dispatch(authLogoutSuccessAction);

              onAccessTokenFetched('', refreshError);
            });
        }

        const retryOriginalRequest = new Promise((resolve, reject) => {
          addSubscriber((token, refreshError) => {
            if (!!refreshError) {
              return reject(refreshError);
            }

            originalRequest.headers.Authorization = `Bearer ${token}`;

            return resolve(axios(originalRequest));
          });
        });

        return retryOriginalRequest;
      }

      return Promise.reject(error);
    });
}
