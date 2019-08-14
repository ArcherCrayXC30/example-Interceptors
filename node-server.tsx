import * as React from 'react';

import axios from 'axios';
import bodyParser from 'body-parser';
import chalk from 'chalk';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import express, { Request, Response } from 'express';
import fs from 'fs';
import helmet from 'helmet';
import hpp from 'hpp';
import jwt from 'jsonwebtoken';
import MobileDetect from 'mobile-detect';
import logger from 'morgan';
import path from 'path';
import { renderToString } from 'react-dom/server';
import Helmet from 'react-helmet';
import Loadable from 'react-loadable';
import { getBundles } from 'react-loadable/webpack';
import { Provider } from 'react-redux';
import { StaticRouterContext } from 'react-router';
import { MatchedRoute, matchRoutes, renderRoutes } from 'react-router-config';
import { StaticRouter } from 'react-router-dom';
import { AnyAction } from 'redux';
import favicon from 'serve-favicon';

import { authAction, routeAction } from './actions';
import apiRouter from './api/routers/';
import routes from './routes';
import { IAuthSuccessAction } from './types/Auth';
import { IUser } from './types/UserInfo';
import { initAxiosInterceptor } from './utils/axiosInterceptor';
import configureStore from './utils/configureStore';
import findAncestors from './utils/findAncestors';
import renderHtml from './utils/renderHtml';

import { version } from '../package.json';

const host = process.env.HOST;
const port = Number(process.env.PORT);

const isDev = process.env.NODE_ENV === 'development';

const app = express();
app.disable('x-powered-by');

// Use helmet to secure Express with various HTTP headers
app.use(helmet());
// Prevent HTTP parameter pollution
app.use(hpp({ whitelist: ['ancestors', 'createdAt'] }));
// Compress all requests
app.use(compression());

app.use(cookieParser());

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use('/api', apiRouter);

// Use for http request debug (show errors only)
app.use(logger('dev', { skip: (_req, res) => res.statusCode < 400 }));

app.use(favicon(path.resolve(process.cwd(), 'public/favicon.ico')));

if (!isDev) {
  app.use('/assets', express.static(path.resolve(process.cwd(), `public/releases/${version}/assets`)));
}

app.use(express.static(path.resolve(process.cwd(), 'public')));

if (isDev) {
  /* Run express as webpack dev server */
  const webpack = require('webpack');
  const webpackConfig = require('../tools/webpack/config.babel');
  const compiler = webpack(webpackConfig);

  compiler.apply(new webpack.ProgressPlugin());

  app.use(
    require('webpack-dev-middleware')(compiler, {
      headers: { 'Access-Control-Allow-Origin': '*' },
      hot: true,
      noInfo: true,
      publicPath: webpackConfig.output.publicPath,
      quiet: true, // Turn it on for friendly-errors-webpack-plugin
      serverxSideRender: true,
      stats: 'minimal',
    })
  );

  app.use(
    require('webpack-hot-middleware')(compiler, {
      log: false, // Turn it off for friendly-errors-webpack-plugin
    })
  );
}

// url to lowercase redirect
app.use((req, res, next) => {
  if (/[A-Z]/.test(req.url)) {
    res.redirect(301, req.url.toLowerCase());
  } else {
    next();
  }
});

const redirectToLogin = (req: Request, res: Response) => {
  if (req.path !== '/admin/login') {
    res.redirect(`/admin/login?next=${req.path}`);
  }
};

// url trailing slashes redirect
app.get('\\S+\/$', (req, res) => {
  return res.redirect(301, req.path.slice(0, -1) + req.url.slice(req.path.length));
});

// Register server-side rendering middleware
app.get('*', async (req, res) => {
  const md = new MobileDetect(req.headers['user-agent']!);
  const settings = {
    mobile: md.mobile(),
    os: md.os(),
    tablet: md.tablet(),
    versionWin: md.versionStr('Windows NT'),
    versioniOS: md.versionStr('iOS'),
  };
  const { store } = configureStore({ initialState: { settings }, url: req.url });
  const cookiesTokens = req.cookies.tokens;

  if (cookiesTokens && req.path !== '/admin/login' && req.path.startsWith('/admin')) {
    const parsedTokens = JSON.parse(cookiesTokens);
    const { id, exp: accessExp }: any = jwt.decode(parsedTokens.accessToken);
    const { exp: refreshExp }: any = jwt.decode(parsedTokens.refreshToken.split('::')[1]);
    const currentDate = Date.now() / 1000;
    let tokens = parsedTokens;

    if (currentDate < refreshExp) {
      try {
        if (currentDate >= accessExp) {
          tokens = await authAction.refreshTokens(parsedTokens.refreshToken, store.dispatch);
        }

        initAxiosInterceptor(store, tokens);

        const { data }: { data: IUser } = await axios.get(`/api/users/${id}`);
        const authSuccessAction: IAuthSuccessAction = {
          tokens,
          type: 'AUTH_SUCCESS',
          user: data,
        };

        await store.dispatch(authSuccessAction);
      } catch (err) {
        redirectToLogin(req, res);
        return;
      }
    } else {
      redirectToLogin(req, res);
      return;
    }
  } else {
    initAxiosInterceptor(store);
  }

  await store.dispatch(routeAction.fetchRoutesIfNeeded() as unknown as AnyAction);

  const routesList = store.getState().routes.list;
  const allRoutes = routes(routesList);
  let dynamicPageId: number = 0;
  // The method for loading data from server-side
  const loadBranchData = () => {
    const branch = matchRoutes(allRoutes, req.path);
    const page = branch[1].route as IRouteConfig;
    const promises = branch.map(({ route, match }: MatchedRoute<{}>) => {
      if (route.loadData) {
        return Promise.all(
          route
            .loadData({ params: match.params, getState: store.getState })
            .map((item: AnyAction) => store.dispatch(item))
        );
      }

      return Promise.resolve(null);
    });

    if (page.pageId) {
      dynamicPageId = page.pageId;
      const route = routesList!.find(r => r.id === dynamicPageId);
      const ancestors = route ? findAncestors(route.parent, routesList!) : [];

      promises.push(store.dispatch(routeAction.fetchRouteInfo(dynamicPageId, ancestors) as any));
    }

    return Promise.all(promises);
  };

  (async () => {
    try {
      // Load data from server-side first
      await loadBranchData();

      const modules: string[] = [];
      const staticContext: StaticRouterContext = {};
      const AppComponent = (
        // tslint:disable-next-line: jsx-no-lambda
        <Loadable.Capture report={moduleName => modules.push(moduleName)}>
          <Provider store={store}>
            {/* Setup React-Router server-side rendering */}
            <StaticRouter location={req.path} context={staticContext}>
              {renderRoutes(allRoutes)}
            </StaticRouter>
          </Provider>
        </Loadable.Capture>
      );

      const initialState = store.getState();
      const htmlContent = renderToString(AppComponent);
      // head must be placed after "renderToString"
      // see: https://github.com/nfl/react-helmet#server-usage
      const head = Helmet.renderStatic();
      const loadableManifest = JSON.parse(
        fs.readFileSync(
          path.resolve(process.cwd(), `${isDev ? 'public' : `public/releases/${version}`}/loadable-assets.json`),
          'utf-8'
        )
      );
      const bundles = getBundles(loadableManifest, modules).filter(Boolean);
      const mapFn = ({ publicPath }: {publicPath: string}) =>
        !publicPath.includes('main') ? publicPath : '';

      const fonts = settings.mobile ?
      settings.os === 'iOS' ? '/assets/sf_text.css' : '/assets/robo.css' :
      settings.versioniOS ? '/assets/sf_display.css' :
      settings.versionWin ? '/assets/segoe-ui.css' : '/assets/robo.css';

      let assets = bundles
        .map(mapFn)
        // In development, main.css and main.js are webpack default file bundling name
        // we put these files into assets with publicPath
        .concat(['/assets/main.css', fonts, '/assets/main.js']);
      if (!isDev) {
        const webpackManifest = JSON.parse(
          fs.readFileSync(
            path.resolve(process.cwd(), `${isDev ? 'public' : `public/releases/${version}`}/webpack-assets.json`),
            'utf-8'
          )
        );

        assets = bundles.map(mapFn).concat(
          Object.keys(webpackManifest)
            .map(key => webpackManifest[key])
            .reverse(),
          fonts
        );
      }

      // Check if the render result contains a redirect, if so we need to set
      // the specific status and redirect header and end the response
      if (staticContext.url) {
        res.status(301).setHeader('Location', staticContext.url);
        res.end();

        return;
      }

      // Check page status
      const status = staticContext.statusCode === 404 ? 404 : 200;
      const dynamicScripts = dynamicPageId ?
        store.getState().routeInfo[dynamicPageId].info!.meta.scripts :
        '';

      // Pass the route and initial state into html template
      res
        .status(status)
        .send(renderHtml(head, assets, dynamicScripts, htmlContent, initialState));
    } catch (err) {
      res.status(404).send('Not Found :(');

      // tslint:disable-next-line: no-console
      console.error(chalk.red(`==> 😭  Rendering routes error: ${err}`));
    }
  })();
});

if (host && port) {
  Loadable.preloadAll().then(() => {
    app.listen(port, host, (err: string) => {
      const url = `http://${host}:${port}`;

      // tslint:disable-next-line: no-console
      if (err) console.error(chalk.red(`==> 😭  OMG!!! ${err}`));

      // tslint:disable-next-line: no-console
      console.info(chalk.green(`==> 🌎  Listening at ${url}`));

    });
  });
} else {
  // tslint:disable-next-line: no-console
  console.error(
    chalk.red('==> 😭  OMG!!! No PORT or HOST environment variable has been specified')
  );
}
